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

//! KMS动态配置管理员API处理器
//! 提供KMS服务的配置、启动、停止、状态查询、重新配置等管理接口

// 导入上级模块的Operation trait
use super::Operation;
// 管理员请求权限验证函数
use crate::admin::auth::validate_admin_request;
// 认证相关函数：密钥验证、会话令牌获取
use crate::auth::{check_key_valid, get_session_token};
// HTTP状态码
use hyper::StatusCode;
// 路由参数解析工具
use matchit::Params;
// 配置常量：管理员请求体最大尺寸
use rustfs_config::MAX_ADMIN_REQUEST_BODY_SIZE;
// 集群配置读写函数
use rustfs_ecstore::config::com::{read_config, save_config};
// 获取对象存储层实例函数
use rustfs_ecstore::new_object_layer_fn;
// KMS相关结构体和函数
use rustfs_kms::{
    ConfigureKmsRequest,  // KMS配置请求结构体
    ConfigureKmsResponse, // KMS配置响应结构体
    KmsConfig,            // KMS完整配置结构体
    KmsConfigSummary,     // KMS配置摘要（脱敏）
    KmsServiceStatus,     // KMS服务状态枚举
    KmsStatusResponse,    // KMS状态查询响应结构体
    StartKmsRequest,      // KMS启动请求结构体
    StartKmsResponse,     // KMS启动响应结构体
    StopKmsResponse,      // KMS停止响应结构体
    get_global_kms_service_manager, // 获取全局KMS服务管理器
};
// 权限策略相关：操作权限枚举
use rustfs_policy::policy::action::{Action, AdminAction};
// S3协议相关：请求/响应/结果类型、请求体、错误构造函数
use s3s::{Body, S3Request, S3Response, S3Result, s3_error};
// 日志相关：不同级别日志
use tracing::{error, info, warn};

/// KMS配置在集群元数据中的存储路径
/// 该路径用于持久化KMS配置到集群存储中
const KMS_CONFIG_PATH: &str = "config/kms_config.json";

/// 将KMS配置持久化到集群存储
/// 参数:
/// - config: 待保存的KMS配置结构体
/// 返回: 成功返回Ok(())，失败返回包含错误信息的String
async fn save_kms_config(config: &KmsConfig) -> Result<(), String> {
    // 获取对象存储层实例
    let Some(store) = new_object_layer_fn() else {
        return Err("存储层未初始化".to_string());
    };

    // 将配置序列化为JSON字节数组
    let data = serde_json::to_vec(config).map_err(|e| format!("序列化KMS配置失败: {e}"))?;

    // 将配置保存到集群存储指定路径
    save_config(store, KMS_CONFIG_PATH, data)
        .await
        .map_err(|e| format!("将KMS配置保存到存储失败: {e}"))?;

    info!("KMS配置已持久化到集群存储，路径: {}", KMS_CONFIG_PATH);
    Ok(())
}

/// 从集群存储加载KMS配置
/// 返回: 成功返回Some(KmsConfig)，失败/未找到返回None
pub async fn load_kms_config() -> Option<KmsConfig> {
    // 获取对象存储层实例
    let Some(store) = new_object_layer_fn() else {
        warn!("存储层未初始化，无法加载KMS配置");
        return None;
    };

    // 从集群存储读取配置文件
    match read_config(store, KMS_CONFIG_PATH).await {
        Ok(data) => match serde_json::from_slice::<KmsConfig>(&data) {
            // 反序列化成功，返回配置
            Ok(config) => {
                info!("从集群存储加载KMS配置成功");
                Some(config)
            }
            // 反序列化失败，记录错误并返回None
            Err(e) => {
                error!("反序列化KMS配置失败: {}", e);
                None
            }
        },
        Err(e) => {
            // 配置未找到属于首次运行的正常情况
            if e.to_string().contains("ConfigNotFound") || e.to_string().contains("not found") {
                info!("未找到持久化的KMS配置（首次运行或尚未配置）");
            } else {
                warn!("从存储加载KMS配置失败: {}", e);
            }
            None
        }
    }
}

/// KMS服务配置处理器
/// 实现Operation trait，处理KMS服务的配置请求（创建/更新配置）
pub struct ConfigureKmsHandler;

#[async_trait::async_trait]
impl Operation for ConfigureKmsHandler {
    /// 处理KMS配置请求
    /// 参数:
    /// - req: S3请求对象，包含凭证、请求体、请求头等
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含配置结果和KMS服务状态
    async fn call(&self, mut req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 1. 验证请求凭证是否存在
        let Some(cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "需要身份验证"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred.access_key).await?;

        // 3. 验证管理员权限（需要服务器信息管理权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        // 4. 读取并限制请求体大小（防止过大的请求体）
        let body = req
            .input
            .store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE)
            .await
            .map_err(|e| s3_error!(InvalidRequest, "读取请求体失败: {}", e))?;

        // 5. 解析配置请求体
        let configure_request: ConfigureKmsRequest = if body.is_empty() {
            // 请求体为空，返回400错误
            return Ok(S3Response::new((
                StatusCode::BAD_REQUEST,
                Body::from("请求体不能为空".to_string()),
            )));
        } else {
            // 将请求体反序列化为配置请求结构体
            match serde_json::from_slice(&body) {
                Ok(req) => req,
                Err(e) => {
                    error!("配置请求JSON格式无效: {}", e);
                    return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from(format!("无效的JSON格式: {e}")))));
                }
            }
        };

        info!("开始配置KMS服务，请求参数: {:?}", configure_request);

        // 6. 获取全局KMS服务管理器（未初始化则初始化）
        let service_manager = get_global_kms_service_manager().unwrap_or_else(|| {
            warn!("KMS服务管理器未初始化，正在作为降级方案初始化");
            // 初始化全局KMS服务管理器
            rustfs_kms::init_global_kms_service_manager()
        });

        // 7. 将请求转换为KMS配置结构体
        let kms_config = configure_request.to_kms_config();

        // 8. 配置KMS服务并持久化配置
        let (success, message, status) = match service_manager.configure(kms_config.clone()).await {
            Ok(()) => {
                // 配置成功，尝试持久化到集群存储
                if let Err(e) = save_kms_config(&kms_config).await {
                    let error_msg = format!("KMS配置已在内存中生效，但持久化失败: {e}");
                    error!("{}", error_msg);
                    let status = service_manager.get_status().await;
                    (false, error_msg, status)
                } else {
                    let status = service_manager.get_status().await;
                    info!("KMS配置成功并已持久化，当前状态: {:?}", status);
                    (true, "KMS配置成功".to_string(), status)
                }
            }
            Err(e) => {
                // 配置失败
                let error_msg = format!("配置KMS失败: {e}");
                error!("{}", error_msg);
                let status = service_manager.get_status().await;
                (false, error_msg, status)
            }
        };

        // 9. 构建配置响应结构体
        let response = ConfigureKmsResponse {
            success,
            message,
            status,
        };

        // 10. 将响应序列化为JSON
        let json_response = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!("序列化响应失败: {}", e);
                return Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("序列化错误".to_string()),
                )));
            }
        };

        // 11. 返回成功响应（200 OK）
        Ok(S3Response::new((StatusCode::OK, Body::from(json_response))))
    }
}

/// KMS服务启动处理器
/// 实现Operation trait，处理启动KMS服务的请求（支持强制重启）
pub struct StartKmsHandler;

#[async_trait::async_trait]
impl Operation for StartKmsHandler {
    /// 处理KMS服务启动请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含启动结果和KMS服务状态
    async fn call(&self, mut req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 1. 验证请求凭证
        let Some(cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "需要身份验证"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred.access_key).await?;

        // 3. 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        // 4. 读取并解析启动请求体
        let body = req
            .input
            .store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE)
            .await
            .map_err(|e| s3_error!(InvalidRequest, "读取请求体失败: {}", e))?;

        // 解析启动请求（空请求体默认force=false）
        let start_request: StartKmsRequest = if body.is_empty() {
            StartKmsRequest { force: None }
        } else {
            match serde_json::from_slice(&body) {
                Ok(req) => req,
                Err(e) => {
                    error!("启动请求JSON格式无效: {}", e);
                    return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from(format!("无效的JSON格式: {e}")))));
                }
            }
        };

        info!("启动KMS服务，强制标志: {:?}", start_request.force);

        // 5. 获取KMS服务管理器
        let service_manager = get_global_kms_service_manager().unwrap_or_else(|| {
            warn!("KMS服务管理器未初始化，正在作为降级方案初始化");
            rustfs_kms::init_global_kms_service_manager()
        });

        // 6. 检查当前状态，避免重复启动（未指定force=true时）
        let current_status = service_manager.get_status().await;
        if matches!(current_status, KmsServiceStatus::Running) && !start_request.force.unwrap_or(false) {
            warn!("KMS服务已处于运行状态");
            let response = StartKmsResponse {
                success: false,
                message: "KMS服务已在运行中。使用force=true参数可重启服务。".to_string(),
                status: current_status,
            };
            let json_response = match serde_json::to_string(&response) {
                Ok(json) => json,
                Err(e) => {
                    error!("序列化响应失败: {}", e);
                    return Ok(S3Response::new((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Body::from("序列化错误".to_string()),
                    )));
                }
            };
            return Ok(S3Response::new((StatusCode::OK, Body::from(json_response))));
        }

        // 7. 执行启动/重启操作
        let (success, message, status) =
            if start_request.force.unwrap_or(false) && matches!(current_status, KmsServiceStatus::Running) {
                // 7.1 强制重启：先停止再启动
                match service_manager.stop().await {
                    Ok(()) => match service_manager.start().await {
                        Ok(()) => {
                            let status = service_manager.get_status().await;
                            info!("KMS服务重启成功");
                            (true, "KMS服务重启成功".to_string(), status)
                        }
                        Err(e) => {
                            let error_msg = format!("重启KMS服务失败: {e}");
                            error!("{}", error_msg);
                            let status = service_manager.get_status().await;
                            (false, error_msg, status)
                        }
                    },
                    Err(e) => {
                        let error_msg = format!("停止KMS服务以进行重启失败: {e}");
                        error!("{}", error_msg);
                        let status = service_manager.get_status().await;
                        (false, error_msg, status)
                    }
                }
            } else {
                // 7.2 正常启动：直接启动
                match service_manager.start().await {
                    Ok(()) => {
                        let status = service_manager.get_status().await;
                        info!("KMS服务启动成功");
                        (true, "KMS服务启动成功".to_string(), status)
                    }
                    Err(e) => {
                        let error_msg = format!("启动KMS服务失败: {e}");
                        error!("{}", error_msg);
                        let status = service_manager.get_status().await;
                        (false, error_msg, status)
                    }
                }
            };

        // 8. 构建并返回启动响应
        let response = StartKmsResponse {
            success,
            message,
            status,
        };

        let json_response = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!("序列化响应失败: {}", e);
                return Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("序列化错误".to_string()),
                )));
            }
        };

        Ok(S3Response::new((StatusCode::OK, Body::from(json_response))))
    }
}

/// KMS服务停止处理器
/// 实现Operation trait，处理停止KMS服务的请求
pub struct StopKmsHandler;

#[async_trait::async_trait]
impl Operation for StopKmsHandler {
    /// 处理KMS服务停止请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含停止结果和KMS服务状态
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 1. 验证请求凭证
        let Some(cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "需要身份验证"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred.access_key).await?;

        // 3. 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        info!("停止KMS服务");

        // 4. 获取KMS服务管理器
        let service_manager = get_global_kms_service_manager().unwrap_or_else(|| {
            warn!("KMS服务管理器未初始化，正在作为降级方案初始化");
            rustfs_kms::init_global_kms_service_manager()
        });

        // 5. 执行停止操作
        let (success, message, status) = match service_manager.stop().await {
            Ok(()) => {
                let status = service_manager.get_status().await;
                info!("KMS服务停止成功");
                (true, "KMS服务停止成功".to_string(), status)
            }
            Err(e) => {
                let error_msg = format!("停止KMS服务失败: {e}");
                error!("{}", error_msg);
                let status = service_manager.get_status().await;
                (false, error_msg, status)
            }
        };

        // 6. 构建并返回停止响应
        let response = StopKmsResponse {
            success,
            message,
            status,
        };

        let json_response = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!("序列化响应失败: {}", e);
                return Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("序列化错误".to_string()),
                )));
            }
        };

        Ok(S3Response::new((StatusCode::OK, Body::from(json_response))))
    }
}

/// KMS状态查询处理器
/// 实现Operation trait，处理查询KMS服务状态的请求
pub struct GetKmsStatusHandler;

#[async_trait::async_trait]
impl Operation for GetKmsStatusHandler {
    /// 处理KMS状态查询请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含KMS服务状态、后端类型、健康状态、配置摘要等信息
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 1. 验证请求凭证
        let Some(cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "需要身份验证"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred.access_key).await?;

        // 3. 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        info!("查询KMS服务状态");

        // 4. 获取KMS服务管理器
        let service_manager = get_global_kms_service_manager().unwrap_or_else(|| {
            warn!("KMS服务管理器未初始化，正在作为降级方案初始化");
            rustfs_kms::init_global_kms_service_manager()
        });

        // 5. 获取KMS核心状态信息
        let status = service_manager.get_status().await;       // 服务运行状态
        let config = service_manager.get_config().await;       // 完整配置（可能为None）

        // 6. 提取后端类型和健康状态
        let backend_type = config.as_ref().map(|c| c.backend.clone());  // 后端类型（如AWS KMS/本地KMS）
        let healthy = if matches!(status, KmsServiceStatus::Running) {
            // 运行中时执行健康检查
            match service_manager.health_check().await {
                Ok(healthy) => Some(healthy),
                Err(_) => Some(false),
            }
        } else {
            // 非运行状态不返回健康状态
            None
        };

        // 7. 生成配置摘要（脱敏，不含敏感信息）
        let config_summary = config.as_ref().map(KmsConfigSummary::from);

        // 8. 构建状态响应结构体
        let response = KmsStatusResponse {
            status,          // 服务状态
            backend_type,    // 后端类型
            healthy,         // 健康状态
            config_summary,  // 配置摘要
        };

        info!("KMS服务状态: {:?}", response);

        // 9. 序列化并返回响应
        let json_response = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!("序列化响应失败: {}", e);
                return Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("序列化错误".to_string()),
                )));
            }
        };

        Ok(S3Response::new((StatusCode::OK, Body::from(json_response))))
    }
}

/// KMS服务重新配置处理器
/// 实现Operation trait，处理重新配置KMS服务的请求（停止→重新配置→启动）
pub struct ReconfigureKmsHandler;

#[async_trait::async_trait]
impl Operation for ReconfigureKmsHandler {
    /// 处理KMS重新配置请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含重新配置结果和KMS服务状态
    async fn call(&self, mut req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 1. 验证请求凭证
        let Some(cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "需要身份验证"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred.access_key).await?;

        // 3. 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        // 4. 读取并解析重新配置请求体
        let body = req
            .input
            .store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE)
            .await
            .map_err(|e| s3_error!(InvalidRequest, "读取请求体失败: {}", e))?;

        let configure_request: ConfigureKmsRequest = if body.is_empty() {
            return Ok(S3Response::new((
                StatusCode::BAD_REQUEST,
                Body::from("请求体不能为空".to_string()),
            )));
        } else {
            match serde_json::from_slice(&body) {
                Ok(req) => req,
                Err(e) => {
                    error!("重新配置请求JSON格式无效: {}", e);
                    return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from(format!("无效的JSON格式: {e}")))));
                }
            }
        };

        info!("重新配置KMS服务，请求参数: {:?}", configure_request);

        // 5. 获取KMS服务管理器
        let service_manager = get_global_kms_service_manager().unwrap_or_else(|| {
            warn!("KMS服务管理器未初始化，正在作为降级方案初始化");
            rustfs_kms::init_global_kms_service_manager()
        });

        // 6. 转换请求为KMS配置结构体
        let kms_config = configure_request.to_kms_config();

        // 7. 执行重新配置（停止→配置→启动）
        let (success, message, status) = match service_manager.reconfigure(kms_config.clone()).await {
            Ok(()) => {
                // 配置成功，持久化到集群存储
                if let Err(e) = save_kms_config(&kms_config).await {
                    let error_msg = format!("KMS配置已在内存中生效，但持久化失败: {e}");
                    error!("{}", error_msg);
                    let status = service_manager.get_status().await;
                    (false, error_msg, status)
                } else {
                    let status = service_manager.get_status().await;
                    info!("KMS重新配置成功并已持久化，当前状态: {:?}", status);
                    (true, "KMS重新配置并重启成功".to_string(), status)
                }
            }
            Err(e) => {
                // 配置失败
                let error_msg = format!("重新配置KMS失败: {e}");
                error!("{}", error_msg);
                let status = service_manager.get_status().await;
                (false, error_msg, status)
            }
        };

        // 8. 构建并返回配置响应
        let response = ConfigureKmsResponse {
            success,
            message,
            status,
        };

        let json_response = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                error!("序列化响应失败: {}", e);
                return Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("序列化错误".to_string()),
                )));
            }
        };

        Ok(S3Response::new((StatusCode::OK, Body::from(json_response))))
    }
}