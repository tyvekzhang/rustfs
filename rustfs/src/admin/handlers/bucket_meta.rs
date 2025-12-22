// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 标准库依赖
use std::{
    collections::HashMap,      // 哈希映射，用于存储桶元数据的键值对
    io::{Cursor, Read as _, Write as _}, // IO操作相关，Cursor用于内存中的读写，Read/Write trait
};

// 内部模块依赖
use crate::{
    admin::{auth::validate_admin_request, router::Operation}, // 管理员认证和操作路由
    auth::{check_key_valid, get_session_token}, // 密钥验证和会话令牌获取
};
use http::{HeaderMap, StatusCode}; // HTTP头和状态码
use matchit::Params; // 路由参数解析
use rustfs_config::MAX_BUCKET_METADATA_IMPORT_SIZE; // 桶元数据导入的最大尺寸限制
use rustfs_ecstore::{
    StorageAPI, // 存储层API
    bucket::{
        metadata::{
            // 桶元数据配置文件常量
            BUCKET_LIFECYCLE_CONFIG, BUCKET_NOTIFICATION_CONFIG, BUCKET_POLICY_CONFIG, BUCKET_QUOTA_CONFIG_FILE,
            BUCKET_REPLICATION_CONFIG, BUCKET_SSECONFIG, BUCKET_TAGGING_CONFIG, BUCKET_TARGETS_FILE, BUCKET_VERSIONING_CONFIG,
            BucketMetadata, OBJECT_LOCK_CONFIG,
        },
        metadata_sys, // 桶元数据系统操作模块
        quota::BucketQuota, // 桶配额配置结构
        target::BucketTargets, // 桶目标配置结构
    },
    error::StorageError, // 存储层错误类型
    new_object_layer_fn, // 获取对象存储层实例的函数
    store_api::BucketOptions, // 桶操作选项
};
use rustfs_ecstore::{
    bucket::utils::{deserialize, serialize}, // 桶配置序列化/反序列化工具
    store_api::MakeBucketOptions, // 创建桶的选项
};
use rustfs_policy::policy::{
    BucketPolicy, // 桶策略配置结构
    action::{Action, AdminAction}, // 操作权限枚举
};
use rustfs_utils::path::{SLASH_SEPARATOR, path_join_buf}; // 路径处理工具
use s3s::{
    Body, S3Request, S3Response, S3Result, // S3协议相关的请求/响应/结果类型
    dto::{
        // S3数据传输对象（DTO），对应各类桶配置
        BucketLifecycleConfiguration, ObjectLockConfiguration, ReplicationConfiguration, ServerSideEncryptionConfiguration,
        Tagging, VersioningConfiguration,
    },
    header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE}, // HTTP头常量
    s3_error, // S3错误构造函数
};
use serde::Deserialize; // 反序列化trait
use serde_urlencoded::from_bytes; // URL编码数据反序列化
use time::OffsetDateTime; // 时间处理，带时区的日期时间
use tracing::warn; // 日志警告级别
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions}; // ZIP压缩/解压缩工具

/// 导出桶元数据的查询参数结构
/// 用于解析请求URL中的查询参数
#[derive(Debug, Default, serde::Deserialize)]
pub struct ExportBucketMetadataQuery {
    /// 要导出的桶名称，为空时导出所有桶
    pub bucket: String,
}

/// 导出桶元数据的操作结构体
/// 实现Operation trait处理具体的导出逻辑
pub struct ExportBucketMetadata {}

#[async_trait::async_trait]
impl Operation for ExportBucketMetadata {
    /// 处理导出桶元数据的请求
    /// 参数:
    /// - req: S3请求对象，包含请求头、查询参数、请求体等
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含状态码和ZIP格式的元数据内容
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                // 将URL编码的查询参数反序列化为结构体
                let input: ExportBucketMetadataQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取查询参数失败"))?;
                input
            } else {
                // 无查询参数时使用默认值（导出所有桶）
                ExportBucketMetadataQuery::default()
            }
        };

        // 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性，获取凭证和所有者信息
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限，确保请求者有导出桶元数据的权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ExportBucketMetadataAction)],
        )
        .await?;

        // 获取对象存储层实例
        let Some(store) = new_object_layer_fn() else {
            return Err(s3_error!(InvalidRequest, "对象存储层未初始化"));
        };

        // 根据查询参数获取要导出的桶列表
        let buckets = if query.bucket.is_empty() {
            // 无指定桶时，列出所有桶
            store
                .list_bucket(&BucketOptions::default())
                .await
                .map_err(|e| s3_error!(InternalError, "列出桶失败: {e}"))?
        } else {
            // 指定桶时，获取该桶的信息
            let bucket = store
                .get_bucket_info(&query.bucket, &BucketOptions::default())
                .await
                .map_err(|e| s3_error!(InternalError, "获取桶信息失败: {e}"))?;
            vec![bucket]
        };

        // 初始化ZIP写入器，将数据写入内存中的Vec
        let mut zip_writer = ZipWriter::new(Cursor::new(Vec::new()));

        // 定义需要导出的桶配置文件列表
        let confs = [
            BUCKET_POLICY_CONFIG,          // 桶策略配置
            BUCKET_NOTIFICATION_CONFIG,    // 桶通知配置
            BUCKET_LIFECYCLE_CONFIG,       // 桶生命周期配置
            BUCKET_SSECONFIG,              // 服务器端加密配置
            BUCKET_TAGGING_CONFIG,         // 桶标签配置
            BUCKET_QUOTA_CONFIG_FILE,      // 桶配额配置
            OBJECT_LOCK_CONFIG,            // 对象锁定配置
            BUCKET_VERSIONING_CONFIG,      // 版本控制配置
            BUCKET_REPLICATION_CONFIG,     // 复制配置
            BUCKET_TARGETS_FILE,           // 桶目标配置
        ];

        // 遍历每个桶，导出其配置文件
        for bucket in buckets {
            for &conf in confs.iter() {
                // 拼接配置文件的路径（桶名/配置文件名）
                let conf_path = path_join_buf(&[bucket.name.as_str(), conf]);
                match conf {
                    // 处理桶策略配置（JSON格式）
                    BUCKET_POLICY_CONFIG => {
                        let config: BucketPolicy = match metadata_sys::get_bucket_policy(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                // 配置不存在时跳过，其他错误返回
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        // 序列化为JSON字节
                        let config_json =
                            serde_json::to_vec(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;
                        // 在ZIP中创建文件
                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        // 写入配置内容
                        zip_writer
                            .write_all(&config_json)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理桶通知配置（XML格式）
                    BUCKET_NOTIFICATION_CONFIG => {
                        let config: s3s::dto::NotificationConfiguration =
                            match metadata_sys::get_notification_config(&bucket.name).await {
                                Ok(Some(res)) => res,
                                Err(e) => {
                                    if e == StorageError::ConfigNotFound {
                                        continue;
                                    }
                                    return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                                }
                                Ok(None) => continue,
                            };

                        // 序列化为XML字节
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理桶生命周期配置（XML格式）
                    BUCKET_LIFECYCLE_CONFIG => {
                        let config: BucketLifecycleConfiguration = match metadata_sys::get_lifecycle_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理桶标签配置（XML格式）
                    BUCKET_TAGGING_CONFIG => {
                        let config: Tagging = match metadata_sys::get_tagging_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理桶配额配置（JSON格式）
                    BUCKET_QUOTA_CONFIG_FILE => {
                        let config: BucketQuota = match metadata_sys::get_quota_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_json =
                            serde_json::to_vec(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_json)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理对象锁定配置（XML格式）
                    OBJECT_LOCK_CONFIG => {
                        let config = match metadata_sys::get_object_lock_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理服务器端加密配置（XML格式）
                    BUCKET_SSECONFIG => {
                        let config = match metadata_sys::get_sse_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理版本控制配置（XML格式）
                    BUCKET_VERSIONING_CONFIG => {
                        let config = match metadata_sys::get_versioning_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理复制配置（XML格式）
                    BUCKET_REPLICATION_CONFIG => {
                        let config = match metadata_sys::get_replication_config(&bucket.name).await {
                            Ok((res, _)) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };
                        let config_xml =
                            serialize(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_xml)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 处理桶目标配置（JSON格式）
                    BUCKET_TARGETS_FILE => {
                        let config: BucketTargets = match metadata_sys::get_bucket_targets_config(&bucket.name).await {
                            Ok(res) => res,
                            Err(e) => {
                                if e == StorageError::ConfigNotFound {
                                    continue;
                                }
                                return Err(s3_error!(InternalError, "获取桶元数据失败: {e}"));
                            }
                        };

                        let config_json =
                            serde_json::to_vec(&config).map_err(|e| s3_error!(InternalError, "序列化配置失败: {e}"))?;

                        zip_writer
                            .start_file(conf_path, SimpleFileOptions::default())
                            .map_err(|e| s3_error!(InternalError, "创建ZIP文件失败: {e}"))?;
                        zip_writer
                            .write_all(&config_json)
                            .map_err(|e| s3_error!(InternalError, "写入ZIP文件失败: {e}"))?;
                    }
                    // 未知配置文件，跳过
                    _ => {}
                }
            }
        }

        // 完成ZIP写入，获取压缩后的字节数据
        let zip_bytes = zip_writer
            .finish()
            .map_err(|e| s3_error!(InternalError, "完成ZIP压缩失败: {e}"))?;
        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/zip".parse().unwrap()); // 内容类型为ZIP
        header.insert(CONTENT_DISPOSITION, "attachment; filename=bucket-meta.zip".parse().unwrap()); // 附件下载，指定文件名
        header.insert(CONTENT_LENGTH, zip_bytes.get_ref().len().to_string().parse().unwrap()); // 内容长度

        // 返回成功响应，包含ZIP数据和响应头
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(zip_bytes.into_inner())), header))
    }
}

/// 导入桶元数据的查询参数结构
/// 用于解析请求URL中的查询参数
#[derive(Debug, Default, Deserialize)]
pub struct ImportBucketMetadataQuery {
    #[allow(dead_code)]
    /// 要导入的桶名称（当前未使用，导入ZIP中所有桶）
    pub bucket: String,
}

/// 导入桶元数据的操作结构体
/// 实现Operation trait处理具体的导入逻辑
pub struct ImportBucketMetadata {}

#[async_trait::async_trait]
impl Operation for ImportBucketMetadata {
    /// 处理导入桶元数据的请求
    /// 参数:
    /// - req: S3请求对象，包含ZIP格式的元数据请求体
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，导入成功返回200
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数（当前未使用）
        let _query = {
            if let Some(query) = req.uri.query() {
                let input: ImportBucketMetadataQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取查询参数失败"))?;
                input
            } else {
                ImportBucketMetadataQuery::default()
            }
        };

        // 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限，确保请求者有导入桶元数据的权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ImportBucketMetadataAction)],
        )
        .await?;

        // 读取请求体（ZIP文件），限制最大尺寸
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_BUCKET_METADATA_IMPORT_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("读取请求体失败，错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "桶元数据导入请求体过大或读取失败"));
            }
        };

        // 初始化ZIP读取器
        let mut zip_reader = ZipArchive::new(Cursor::new(body)).map_err(|e| s3_error!(InternalError, "解析ZIP文件失败: {e}"))?;

        // 第一遍遍历：将所有ZIP内的文件内容读取到内存中
        let mut file_contents = Vec::new();
        for i in 0..zip_reader.len() {
            // 获取ZIP中的第i个文件
            let mut file = zip_reader
                .by_index(i)
                .map_err(|e| s3_error!(InternalError, "读取ZIP内文件失败: {e}"))?;
            let file_path = file.name().to_string();

            // 读取文件内容到内存
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| s3_error!(InternalError, "读取文件内容失败: {e}"))?;

            // 保存文件路径和内容
            file_contents.push((file_path, content));
        }

        // 提取所有涉及的桶名称
        let mut bucket_names = Vec::new();
        for (file_path, _) in &file_contents {
            // 按路径分隔符拆分文件路径（格式：桶名/配置文件名）
            let file_path_split = file_path.split(SLASH_SEPARATOR).collect::<Vec<&str>>();

            // 路径格式无效时跳过并记录警告
            if file_path_split.len() < 2 {
                warn!("文件路径格式无效: {}", file_path);
                continue;
            }

            // 提取桶名并去重
            let bucket_name = file_path_split[0].to_string();
            if !bucket_names.contains(&bucket_name) {
                bucket_names.push(bucket_name);
            }
        }

        // 获取现有桶的元数据，存储到哈希映射中
        let mut bucket_metadatas: HashMap<String, BucketMetadata> = HashMap::new();
        for bucket_name in bucket_names {
            match metadata_sys::get_config_from_disk(&bucket_name).await {
                Ok(res) => {
                    // 成功获取则存入映射
                    bucket_metadatas.insert(bucket_name, res);
                }
                Err(e) => {
                    // 配置不存在时仅警告，其他错误也警告并跳过
                    if e == StorageError::ConfigNotFound {
                        warn!("桶元数据不存在: {e}");
                        continue;
                    }
                    warn!("获取桶元数据失败: {e}");
                    continue;
                }
            };
        }

        // 获取对象存储层实例
        let Some(store) = new_object_layer_fn() else {
            return Err(s3_error!(InvalidRequest, "对象存储层未初始化"));
        };

        // 记录配置更新时间（UTC当前时间）
        let update_at = OffsetDateTime::now_utc();

        // 第二遍遍历：处理每个配置文件的内容，更新桶元数据
        for (file_path, content) in file_contents {
            // 拆分文件路径
            let file_path_split = file_path.split(SLASH_SEPARATOR).collect::<Vec<&str>>();

            // 路径格式无效时跳过
            if file_path_split.len() < 2 {
                warn!("文件路径格式无效: {}", file_path);
                continue;
            }

            // 提取桶名和配置文件名
            let bucket_name = file_path_split[0];
            let conf_name = file_path_split[1];

            // 如果桶不存在，则创建桶
            if !bucket_metadatas.contains_key(bucket_name) {
                if let Err(e) = store
                    .make_bucket(
                        bucket_name,
                        &MakeBucketOptions {
                            force_create: true, // 强制创建（即使存在同名桶也不报错）
                            ..Default::default()
                        },
                    )
                    .await
                {
                    warn!("创建桶失败: {e}");
                    continue;
                }

                // 获取新创建桶的元数据并存入映射
                let metadata = metadata_sys::get(bucket_name).await.unwrap_or_default();
                bucket_metadatas.insert(bucket_name.to_string(), (*metadata).clone());
            }

            // 根据配置文件名处理不同类型的配置
            match conf_name {
                // 处理桶策略配置
                BUCKET_POLICY_CONFIG => {
                    // 反序列化JSON配置
                    let config: BucketPolicy = match serde_json::from_slice(&content) {
                        Ok(config) => config,
                        Err(e) => {
                            warn!("反序列化配置失败: {e}");
                            continue;
                        }
                    };

                    // 版本为空时跳过
                    if config.version.is_empty() {
                        continue;
                    }

                    // 更新元数据中的策略配置和更新时间
                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.policy_config_json = content;
                    metadata.policy_config_updated_at = update_at;
                }
                // 处理桶通知配置
                BUCKET_NOTIFICATION_CONFIG => {
                    // 验证XML配置格式（仅反序列化检查，不使用结果）
                    if let Err(e) = deserialize::<s3s::dto::NotificationConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    // 更新元数据中的通知配置和更新时间
                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.notification_config_xml = content;
                    metadata.notification_config_updated_at = update_at;
                }

                // 处理桶生命周期配置
                BUCKET_LIFECYCLE_CONFIG => {
                    if let Err(e) = deserialize::<BucketLifecycleConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.lifecycle_config_xml = content;
                    metadata.lifecycle_config_updated_at = update_at;
                }

                // 处理服务器端加密配置
                BUCKET_SSECONFIG => {
                    if let Err(e) = deserialize::<ServerSideEncryptionConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.encryption_config_xml = content;
                    metadata.encryption_config_updated_at = update_at;
                }

                // 处理桶标签配置
                BUCKET_TAGGING_CONFIG => {
                    if let Err(e) = deserialize::<Tagging>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.tagging_config_xml = content;
                    metadata.tagging_config_updated_at = update_at;
                }

                // 处理桶配额配置
                BUCKET_QUOTA_CONFIG_FILE => {
                    if let Err(e) = serde_json::from_slice::<BucketQuota>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.quota_config_json = content;
                    metadata.quota_config_updated_at = update_at;
                }

                // 处理对象锁定配置
                OBJECT_LOCK_CONFIG => {
                    if let Err(e) = deserialize::<ObjectLockConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.object_lock_config_xml = content;
                    metadata.object_lock_config_updated_at = update_at;
                }

                // 处理版本控制配置
                BUCKET_VERSIONING_CONFIG => {
                    if let Err(e) = deserialize::<VersioningConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.versioning_config_xml = content;
                    metadata.versioning_config_updated_at = update_at;
                }

                // 处理复制配置
                BUCKET_REPLICATION_CONFIG => {
                    if let Err(e) = deserialize::<ReplicationConfiguration>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.replication_config_xml = content;
                    metadata.replication_config_updated_at = update_at;
                }

                // 处理桶目标配置
                BUCKET_TARGETS_FILE => {
                    if let Err(e) = serde_json::from_slice::<BucketTargets>(&content) {
                        warn!("反序列化配置失败: {e}");
                        continue;
                    }

                    let metadata = bucket_metadatas.get_mut(bucket_name).unwrap();
                    metadata.bucket_targets_config_json = content;
                    metadata.bucket_targets_config_updated_at = update_at;
                }

                // 未知配置文件，跳过
                _ => {}
            }
        }

        // TODO: 站点复制通知（待实现）

        // 构建成功响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap()); // 内容类型为JSON
        header.insert(CONTENT_LENGTH, "0".parse().unwrap()); // 响应体为空，长度0

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}