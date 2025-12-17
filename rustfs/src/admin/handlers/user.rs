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

// 导入核心模块
use crate::{
    admin::{auth::validate_admin_request, router::Operation, utils::has_space_be}, // 管理员认证、操作路由、工具函数
    auth::{check_key_valid, constant_time_eq, get_session_token}, // 密钥验证、常量时间比较、会话token获取
};
use http::{HeaderMap, StatusCode}; // HTTP头和状态码
use matchit::Params; // 路由参数解析
use rustfs_config::{MAX_ADMIN_REQUEST_BODY_SIZE, MAX_IAM_IMPORT_SIZE}; // 配置常量：管理员请求体最大尺寸、IAM导入最大尺寸
use rustfs_ecstore::global::get_global_action_cred; // 获取全局系统凭证
use rustfs_iam::{
    store::{GroupInfo, MappedPolicy, UserType}, // IAM存储相关结构体：组信息、策略映射、用户类型
    sys::NewServiceAccountOpts, // 服务账户创建选项
};
use rustfs_madmin::{
    AccountStatus, AddOrUpdateUserReq, IAMEntities, IAMErrEntities, IAMErrEntity, IAMErrPolicyEntity,
    user::{ImportIAMResult, SRSessionPolicy, SRSvcAccCreate}, // 管理员相关结构体：账户状态、用户请求、IAM实体、导入结果等
};
use rustfs_policy::policy::action::{Action, AdminAction}; // 策略动作枚举
use rustfs_utils::path::path_join_buf; // 路径拼接工具
use s3s::{
    Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result,
    header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE}, // S3协议相关类型和头信息
    s3_error, // S3错误构造宏
};
use serde::Deserialize; // JSON反序列化
use serde_urlencoded::from_bytes; // URL编码数据解析
use std::io::{Read as _, Write}; // IO操作
use std::{collections::HashMap, io::Cursor, str::from_utf8}; // 集合、游标、UTF8处理
use tracing::warn; // 日志警告
use zip::{ZipArchive, ZipWriter, result::ZipError, write::SimpleFileOptions}; // ZIP压缩/解压缩

/// 添加用户的查询参数结构体
#[derive(Debug, Deserialize, Default)]
pub struct AddUserQuery {
    #[serde(rename = "accessKey")]
    pub access_key: Option<String>, // 访问密钥
    pub status: Option<String>,     // 账户状态
}

/// 添加用户操作处理器
pub struct AddUser {}

#[async_trait::async_trait]
impl Operation for AddUser {
    /// 处理添加用户请求
    /// 参数:
    /// - req: S3请求对象，包含请求头、体、凭证等
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应结果，包含状态码和响应体
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                // 解析URL编码的查询参数
                let input: AddUserQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取请求参数失败1"))?;
                input
            } else {
                // 使用默认值
                AddUserQuery::default()
            }
        };

        // 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性，获取凭证和所有者信息
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 获取访问密钥（为空则使用默认空字符串）
        let ak = query.access_key.as_deref().unwrap_or_default();

        // 校验访问密钥非空
        if ak.is_empty() {
            return Err(s3_error!(InvalidArgument, "访问密钥为空"));
        }

        // 读取请求体（限制最大尺寸）
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("读取请求体失败, 错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "读取请求体失败"));
            }
        };

        // 反序列化请求体为用户创建参数（注：原代码中解密逻辑被注释）
        let args: AddOrUpdateUserReq = serde_json::from_slice(&body)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("解析请求体失败: {e}")))?;

        // 校验秘钥非空
        if args.secret_key.is_empty() {
            return Err(s3_error!(InvalidArgument, "秘钥为空"));
        }

        // 校验不能使用系统访问密钥创建用户
        if let Some(sys_cred) = get_global_action_cred() {
            if constant_time_eq(&sys_cred.access_key, ak) {
                return Err(s3_error!(InvalidArgument, "不能使用系统访问密钥创建用户"));
            }
        }

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 校验用户是否已存在，且不能使用服务账户/临时账户密钥创建用户
        if let Some(user) = iam_store.get_user(ak).await {
            if (user.credentials.is_temp() || user.credentials.is_service_account()) && cred.parent_user == ak {
                return Err(s3_error!(InvalidArgument, "不能使用服务账户访问密钥创建用户"));
            }
        } else if has_space_be(ak) {
            // 校验访问密钥不含空格
            return Err(s3_error!(InvalidArgument, "访问密钥包含空格"));
        }

        // 校验访问密钥是UTF8编码
        if from_utf8(ak.as_bytes()).is_err() {
            return Err(s3_error!(InvalidArgument, "访问密钥非UTF8编码"));
        }

        // 标记是否为当前用户（禁止自身操作）
        let deny_only = ak == cred.access_key;
        // 验证管理员权限（创建用户权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            deny_only,
            vec![Action::AdminAction(AdminAction::CreateUserAdminAction)],
        )
        .await?;

        // 创建用户
        iam_store
            .create_user(ak, &args)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("创建用户失败: {e}")))?;

        // 构建成功响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 设置用户状态操作处理器
pub struct SetUserStatus {}

#[async_trait::async_trait]
impl Operation for SetUserStatus {
    /// 处理设置用户状态请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddUserQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取请求参数失败"))?;
                input
            } else {
                AddUserQuery::default()
            }
        };

        // 提取访问密钥并校验非空
        let ak = query.access_key.as_deref().unwrap_or_default();
        if ak.is_empty() {
            return Err(s3_error!(InvalidArgument, "访问密钥为空"));
        }

        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 禁止修改自身状态
        if constant_time_eq(&input_cred.access_key, ak) {
            return Err(s3_error!(InvalidArgument, "不能修改自身状态"));
        }

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限（启用/禁用用户权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::EnableUserAdminAction)],
        )
        .await?;

        // 解析账户状态参数
        let status = AccountStatus::try_from(query.status.as_deref().unwrap_or_default())
            .map_err(|e| S3Error::with_message(S3ErrorCode::InvalidArgument, e))?;

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 更新用户状态
        iam_store
            .set_user_status(ak, status)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("设置用户状态失败: {e}")))?;

        // 构建成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 桶查询参数结构体
#[derive(Debug, Deserialize, Default)]
pub struct BucketQuery {
    #[serde(rename = "bucket")]
    pub bucket: String, // 桶名称
}

/// 列出用户操作处理器
pub struct ListUsers {}

#[async_trait::async_trait]
impl Operation for ListUsers {
    /// 处理列出用户请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限（列出用户权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ListUsersAdminAction)],
        )
        .await?;

        // 解析桶查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: BucketQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取请求参数失败"))?;
                input
            } else {
                BucketQuery::default()
            }
        };

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 根据桶参数查询用户（指定桶则查该桶用户，否则查所有用户）
        let users = {
            if !query.bucket.is_empty() {
                iam_store
                    .list_bucket_users(query.bucket.as_str())
                    .await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            } else {
                iam_store
                    .list_users()
                    .await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            }
        };

        // 序列化用户列表为JSON
        let data = serde_json::to_vec(&users)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化用户列表失败: {e}")))?;

        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 删除用户操作处理器
pub struct RemoveUser {}

#[async_trait::async_trait]
impl Operation for RemoveUser {
    /// 处理删除用户请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限（删除用户权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::DeleteUserAdminAction)],
        )
        .await?;

        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddUserQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取请求参数失败"))?;
                input
            } else {
                AddUserQuery::default()
            }
        };

        // 提取访问密钥并校验非空
        let ak = query.access_key.as_deref().unwrap_or_default();
        if ak.is_empty() {
            return Err(s3_error!(InvalidArgument, "访问密钥为空"));
        }

        // 获取系统凭证并校验不能删除系统用户/自身/父用户
        let sys_cred = get_global_action_cred()
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::InternalError, "获取全局系统凭证失败"))?;

        if ak == sys_cred.access_key || ak == cred.access_key || cred.parent_user == ak {
            return Err(s3_error!(InvalidArgument, "不能删除自身用户"));
        }

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 校验不能删除临时用户
        let (is_temp, _) = iam_store
            .is_temp_user(ak)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("检查临时用户失败: {e}")))?;
        if is_temp {
            return Err(s3_error!(InvalidArgument, "不能删除临时用户"));
        }

        // 校验不能删除服务账户
        let (is_service_account, _) = iam_store
            .is_service_account(ak)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("检查服务账户失败: {e}")))?;
        if is_service_account {
            return Err(s3_error!(InvalidArgument, "不能删除服务账户"));
        }

        // 删除用户
        iam_store
            .delete_user(ak, true)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("删除用户失败: {e}")))?;

        // TODO: IAM变更钩子（待实现）

        // 构建成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 获取用户信息操作处理器
pub struct GetUserInfo {}

#[async_trait::async_trait]
impl Operation for GetUserInfo {
    /// 处理获取用户信息请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddUserQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "获取请求参数失败"))?;
                input
            } else {
                AddUserQuery::default()
            }
        };

        // 提取访问密钥并校验非空
        let ak = query.access_key.as_deref().unwrap_or_default();
        if ak.is_empty() {
            return Err(s3_error!(InvalidArgument, "访问密钥为空"));
        }

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 标记是否为当前用户
        let deny_only = ak == cred.access_key;
        // 验证管理员权限（获取用户信息权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            deny_only,
            vec![Action::AdminAction(AdminAction::GetUserAdminAction)],
        )
        .await?;

        // 获取用户详细信息
        let info = iam_store
            .get_user_info(ak)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        // 序列化用户信息为JSON
        let data = serde_json::to_vec(&info)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化用户信息失败: {e}")))?;

        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

// IAM导出文件常量定义
const ALL_POLICIES_FILE: &str = "policies.json"; // 所有策略文件
const ALL_USERS_FILE: &str = "users.json"; // 所有用户文件
const ALL_GROUPS_FILE: &str = "groups.json"; // 所有组文件
const ALL_SVC_ACCTS_FILE: &str = "svcaccts.json"; // 所有服务账户文件
const USER_POLICY_MAPPINGS_FILE: &str = "user_mappings.json"; // 用户策略映射文件
const GROUP_POLICY_MAPPINGS_FILE: &str = "group_mappings.json"; // 组策略映射文件
const STS_USER_POLICY_MAPPINGS_FILE: &str = "stsuser_mappings.json"; // STS用户策略映射文件

const IAM_ASSETS_DIR: &str = "iam-assets"; // IAM资源目录名

// IAM导出文件列表
const IAM_EXPORT_FILES: &[&str] = &[
    ALL_POLICIES_FILE,
    ALL_USERS_FILE,
    ALL_GROUPS_FILE,
    ALL_SVC_ACCTS_FILE,
    USER_POLICY_MAPPINGS_FILE,
    GROUP_POLICY_MAPPINGS_FILE,
    STS_USER_POLICY_MAPPINGS_FILE,
];

/// 导出IAM数据操作处理器
pub struct ExportIam {}

#[async_trait::async_trait]
impl Operation for ExportIam {
    /// 处理导出IAM数据请求（生成ZIP压缩包）
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限（导出IAM权限）
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::ExportIAMAction)])
            .await?;

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 创建ZIP写入器（内存中）
        let mut zip_writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default();

        // 遍历所有需要导出的文件
        for &file in IAM_EXPORT_FILES {
            // 拼接ZIP内文件路径
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, file]);
            match file {
                // 导出策略文件
                ALL_POLICIES_FILE => {
                    let policies: HashMap<String, rustfs_policy::policy::Policy> = iam_store
                        .list_polices("")
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    let json_str = serde_json::to_vec(&policies)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    // 创建ZIP内文件
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    // 写入策略数据
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出用户文件
                ALL_USERS_FILE => {
                    let mut users = HashMap::new();
                    // 加载普通用户
                    iam_store
                        .load_users(UserType::Reg, &mut users)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                    // 转换用户数据格式
                    let users: HashMap<String, AddOrUpdateUserReq> = users
                        .into_iter()
                        .map(|(k, v)| {
                            (
                                k,
                                AddOrUpdateUserReq {
                                    secret_key: v.credentials.secret_key,
                                    status: {
                                        if v.credentials.status == "off" {
                                            AccountStatus::Disabled
                                        } else {
                                            AccountStatus::Enabled
                                        }
                                    },
                                    policy: None,
                                },
                            )
                        })
                        .collect::<HashMap<String, AddOrUpdateUserReq>>();

                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&users)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出组文件
                ALL_GROUPS_FILE => {
                    let mut groups: HashMap<String, GroupInfo> = HashMap::new();
                    // 加载所有组
                    iam_store
                        .load_groups(&mut groups)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&groups)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出服务账户文件
                ALL_SVC_ACCTS_FILE => {
                    let mut service_accounts = HashMap::new();
                    // 加载服务账户
                    iam_store
                        .load_users(UserType::Svc, &mut service_accounts)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                    let mut svc_accts: HashMap<String, SRSvcAccCreate> = HashMap::new();
                    // 转换服务账户数据格式
                    for (k, acc) in service_accounts {
                        // 跳过站点复制器服务账户
                        if k == "siteReplicatorSvcAcc" {
                            continue;
                        }

                        // 获取服务账户声明
                        let claims = iam_store
                            .get_claims_for_svc_acc(&acc.credentials.access_key)
                            .await
                            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                        // 获取服务账户和策略信息
                        let (sa, police) = iam_store
                            .get_service_account(&acc.credentials.access_key)
                            .await
                            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                        // 序列化策略
                        let police_json = if let Some(police) = police {
                            serde_json::to_string(&police)
                                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
                        } else {
                            "null".to_string()
                        };

                        // 构建服务账户创建请求对象
                        let svc_acc_create_req = SRSvcAccCreate {
                            parent: acc.credentials.parent_user,
                            access_key: k.clone(),
                            secret_key: acc.credentials.secret_key,
                            groups: acc.credentials.groups.unwrap_or_default(),
                            claims,
                            session_policy: SRSessionPolicy::from_json(&police_json).unwrap_or_default(),
                            status: acc.credentials.status,
                            name: sa.name.unwrap_or_default(),
                            description: sa.description.unwrap_or_default(),
                            expiration: sa.expiration,
                            api_version: None,
                        };
                        svc_accts.insert(k.clone(), svc_acc_create_req);
                    }

                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&svc_accts)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出用户策略映射文件
                USER_POLICY_MAPPINGS_FILE => {
                    let mut user_policy_mappings: HashMap<String, MappedPolicy> = HashMap::new();
                    // 加载普通用户策略映射
                    iam_store
                        .load_mapped_policies(UserType::Reg, false, &mut user_policy_mappings)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&user_policy_mappings)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出组策略映射文件
                GROUP_POLICY_MAPPINGS_FILE => {
                    let mut group_policy_mappings = HashMap::new();
                    // 加载组策略映射
                    iam_store
                        .load_mapped_policies(UserType::Reg, true, &mut group_policy_mappings)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&group_policy_mappings)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 导出STS用户策略映射文件
                STS_USER_POLICY_MAPPINGS_FILE => {
                    let mut sts_user_policy_mappings: HashMap<String, MappedPolicy> = HashMap::new();
                    // 加载STS用户策略映射
                    iam_store
                        .load_mapped_policies(UserType::Sts, false, &mut sts_user_policy_mappings)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    // 序列化并写入ZIP
                    let json_str = serde_json::to_vec(&sts_user_policy_mappings)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .start_file(file_path, options)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    zip_writer
                        .write_all(&json_str)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                }
                // 未知文件跳过
                _ => continue,
            }
        }

        // 完成ZIP写入并获取字节数据
        let zip_bytes = zip_writer
            .finish()
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
        
        // 构建响应头（ZIP文件下载）
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/zip".parse().unwrap());
        header.insert(CONTENT_DISPOSITION, "attachment; filename=iam-assets.zip".parse().unwrap());
        header.insert(CONTENT_LENGTH, zip_bytes.get_ref().len().to_string().parse().unwrap());
        
        // 返回ZIP文件响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(zip_bytes.into_inner())), header))
    }
}

/// 导入IAM数据操作处理器
pub struct ImportIam {}

#[async_trait::async_trait]
impl Operation for ImportIam {
    /// 处理导入IAM数据请求（解析ZIP压缩包并导入）
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证请求凭证存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限（导出/导入IAM权限，此处复用了ExportIAMAction）
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::ExportIAMAction)])
            .await?;

        // 读取导入的ZIP文件（限制最大尺寸）
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_IAM_IMPORT_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("读取请求体失败, 错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "读取请求体失败"));
            }
        };

        // 创建ZIP读取器
        let mut zip_reader =
            ZipArchive::new(Cursor::new(body)).map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "IAM模块未初始化"));
        };

        // 初始化导入结果统计
        let skipped = IAMEntities::default(); // 跳过的实体
        let mut removed = IAMEntities::default(); // 删除的实体
        let mut added = IAMEntities::default(); // 添加的实体
        let mut failed = IAMErrEntities::default(); // 失败的实体

        // 1. 导入策略文件
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, ALL_POLICIES_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None, // 文件不存在则跳过
                Err(_) => return Err(s3_error!(InvalidRequest, "获取策略文件失败")),
                Ok(file) => {
                    // 读取文件内容
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化策略数据
                let policies: HashMap<String, rustfs_policy::policy::Policy> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历策略并导入
                for (name, policy) in policies {
                    if policy.is_empty() {
                        // 空策略则删除
                        let res = iam_store.delete_policy(&name, true).await;
                        removed.policies.push(name.clone());
                        if let Err(e) = res {
                            return Err(s3_error!(InternalError, "删除策略失败, 名称: {name}, 错误: {e}"));
                        }
                        continue;
                    }

                    // 设置策略
                    let res = iam_store.set_policy(&name, policy).await;
                    added.policies.push(name.clone());
                    if let Err(e) = res {
                        return Err(s3_error!(InternalError, "设置策略失败, 名称: {name}, 错误: {e}"));
                    }
                }
            }
        }

        // 获取系统凭证（用于校验）
        let Some(sys_cred) = get_global_action_cred() else {
            return Err(s3_error!(InvalidRequest, "获取系统凭证失败"));
        };

        // 2. 导入用户文件
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, ALL_USERS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取用户文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化用户数据
                let users: HashMap<String, AddOrUpdateUserReq> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历用户并创建
                for (ak, req) in users {
                    // 禁止创建系统用户
                    if ak == sys_cred.access_key {
                        return Err(s3_error!(InvalidArgument, "不能创建系统访问密钥用户"));
                    }

                    // 校验用户类型
                    if let Some(u) = iam_store.get_user(&ak).await {
                        if u.credentials.is_temp() || u.credentials.is_service_account() {
                            return Err(s3_error!(InvalidArgument, "不能创建服务账户/临时账户用户"));
                        }
                    } else if has_space_be(&ak) {
                        return Err(s3_error!(InvalidArgument, "访问密钥包含空格"));
                    }

                    // 创建用户（失败则记录错误）
                    if let Err(e) = iam_store.create_user(&ak, &req).await {
                        failed.users.push(IAMErrEntity {
                            name: ak.clone(),
                            error: e.to_string(),
                        });
                    } else {
                        added.users.push(ak.clone());
                    }
                }
            }
        }

        // 3. 导入组文件
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, ALL_GROUPS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取组文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化组数据
                let groups: HashMap<String, GroupInfo> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历组并添加用户
                for (group_name, group_info) in groups {
                    // 校验组存在且名称合法
                    if let Err(e) = iam_store.get_group_description(&group_name).await {
                        if matches!(e, rustfs_iam::error::Error::NoSuchGroup(_)) || has_space_be(&group_name) {
                            return Err(s3_error!(InvalidArgument, "组不存在或名称包含空格"));
                        }
                    }

                    // 向组中添加用户（失败则记录错误）
                    if let Err(e) = iam_store.add_users_to_group(&group_name, group_info.members.clone()).await {
                        failed.groups.push(IAMErrEntity {
                            name: group_name.clone(),
                            error: e.to_string(),
                        });
                    } else {
                        added.groups.push(group_name.clone());
                    }
                }
            }
        }

        // 4. 导入服务账户文件
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, ALL_SVC_ACCTS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取服务账户文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化服务账户数据
                let svc_accts: HashMap<String, SRSvcAccCreate> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历服务账户并创建/更新
                for (ak, req) in svc_accts {
                    // 跳过已标记的服务账户
                    if skipped.service_accounts.contains(&ak) {
                        continue;
                    }

                    // 解析会话策略
                    let sp = if let Some(ps) = req.session_policy.as_str() {
                        let sp = rustfs_policy::policy::Policy::parse_config(ps.as_bytes())
                            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                        Some(sp)
                    } else {
                        None
                    };

                    // 校验访问密钥名称
                    if has_space_be(&ak) {
                        return Err(s3_error!(InvalidArgument, "访问密钥包含空格: {ak}"));
                    }

                    // 判断是否需要更新（存在则先删除）
                    let mut update = true;
                    if let Err(e) = iam_store.get_service_account(&req.access_key).await {
                        if !matches!(e, rustfs_iam::error::Error::NoSuchServiceAccount(_)) {
                            return Err(s3_error!(InvalidArgument, "获取服务账户失败: {ak} {e}"));
                        }
                        update = false;
                    }

                    if update {
                        // 删除原有服务账户
                        iam_store.delete_service_account(&req.access_key, true).await.map_err(|e| {
                            S3Error::with_message(
                                S3ErrorCode::InternalError,
                                format!("删除服务账户失败: {ak} {e}"),
                            )
                        })?;
                    }

                    // 构建服务账户创建选项
                    let opts = NewServiceAccountOpts {
                        session_policy: sp,
                        access_key: ak.clone(),
                        secret_key: req.secret_key,
                        name: Some(req.name),
                        description: Some(req.description),
                        expiration: req.expiration,
                        allow_site_replicator_account: false,
                        claims: Some(req.claims),
                    };

                    // 处理组信息
                    let groups = if req.groups.is_empty() { None } else { Some(req.groups) };

                    // 创建服务账户（失败则记录错误）
                    if let Err(e) = iam_store.new_service_account(&req.parent, groups, opts).await {
                        failed.service_accounts.push(IAMErrEntity {
                            name: ak.clone(),
                            error: e.to_string(),
                        });
                    } else {
                        added.service_accounts.push(ak.clone());
                    }
                }
            }
        }

        // 5. 导入用户策略映射
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, USER_POLICY_MAPPINGS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取用户策略映射文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化用户策略映射
                let user_policy_mappings: HashMap<String, MappedPolicy> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历用户策略映射并设置
                for (user_name, policies) in user_policy_mappings {
                    // 校验是否为临时用户（禁止为临时用户设置策略）
                    let has_temp = match iam_store.is_temp_user(&user_name).await {
                        Ok((has_temp, _)) => has_temp,
                        Err(e) => {
                            if !matches!(e, rustfs_iam::error::Error::NoSuchUser(_)) {
                                return Err(s3_error!(InternalError, "检查临时用户失败, 名称: {user_name}, 错误: {e}"));
                            }
                            false
                        }
                    };

                    if has_temp {
                        return Err(s3_error!(InvalidArgument, "不能为临时用户设置策略: {user_name}"));
                    }

                    // 设置用户策略（失败则记录错误）
                    if let Err(e) = iam_store
                        .policy_db_set(&user_name, UserType::Reg, false, &policies.policies)
                        .await
                    {
                        failed.user_policies.push(IAMErrPolicyEntity {
                            name: user_name.clone(),
                            error: e.to_string(),
                            policies: policies.policies.split(',').map(|s| s.to_string()).collect(),
                        });
                    } else {
                        added.user_policies.push(HashMap::from([(
                            user_name.clone(),
                            policies.policies.split(',').map(|s| s.to_string()).collect(),
                        )]));
                    }
                }
            }
        }

        // 6. 导入组策略映射
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, GROUP_POLICY_MAPPINGS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取组策略映射文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化组策略映射
                let group_policy_mappings: HashMap<String, MappedPolicy> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历组策略映射并设置
                for (group_name, policies) in group_policy_mappings {
                    // 跳过已标记的组
                    if skipped.groups.contains(&group_name) {
                        continue;
                    }

                    // 设置组策略（失败则记录错误）
                    if let Err(e) = iam_store
                        .policy_db_set(&group_name, UserType::None, true, &policies.policies)
                        .await
                    {
                        failed.group_policies.push(IAMErrPolicyEntity {
                            name: group_name.clone(),
                            error: e.to_string(),
                            policies: policies.policies.split(',').map(|s| s.to_string()).collect(),
                        });
                    } else {
                        added.group_policies.push(HashMap::from([(
                            group_name.clone(),
                            policies.policies.split(',').map(|s| s.to_string()).collect(),
                        )]));
                    }
                }
            }
        }

        // 7. 导入STS用户策略映射
        {
            let file_path = path_join_buf(&[IAM_ASSETS_DIR, STS_USER_POLICY_MAPPINGS_FILE]);
            let file_content = match zip_reader.by_name(file_path.as_str()) {
                Err(ZipError::FileNotFound) => None,
                Err(_) => return Err(s3_error!(InvalidRequest, "获取STS用户策略映射文件失败")),
                Ok(file) => {
                    let mut file = file;
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content)
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    Some(file_content)
                }
            };

            if let Some(file_content) = file_content {
                // 反序列化STS用户策略映射
                let sts_user_policy_mappings: HashMap<String, MappedPolicy> = serde_json::from_slice(&file_content)
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                // 遍历STS用户策略映射并设置
                for (user_name, policies) in sts_user_policy_mappings {
                    // 跳过已标记的用户
                    if skipped.users.contains(&user_name) {
                        continue;
                    }

                    // 校验是否为临时用户（禁止为临时用户设置策略）
                    let has_temp = match iam_store.is_temp_user(&user_name).await {
                        Ok((has_temp, _)) => has_temp,
                        Err(e) => {
                            if !matches!(e, rustfs_iam::error::Error::NoSuchUser(_)) {
                                return Err(s3_error!(InternalError, "检查临时用户失败, 名称: {user_name}, 错误: {e}"));
                            }
                            false
                        }
                    };

                    if has_temp {
                        return Err(s3_error!(InvalidArgument, "不能为临时用户设置策略: {user_name}"));
                    }

                    // 设置STS用户策略（失败则记录错误）
                    if let Err(e) = iam_store
                        .policy_db_set(&user_name, UserType::Sts, false, &policies.policies)
                        .await
                    {
                        failed.sts_policies.push(IAMErrPolicyEntity {
                            name: user_name.clone(),
                            error: e.to_string(),
                            policies: policies.policies.split(',').map(|s| s.to_string()).collect(),
                        });
                    } else {
                        added.sts_policies.push(HashMap::from([(
                            user_name.clone(),
                            policies.policies.split(',').map(|s| s.to_string()).collect(),
                        )]));
                    }
                }
            }
        }

        // 构建导入结果
        let ret = ImportIAMResult {
            skipped,
            removed,
            added,
            failed,
        };

        // 序列化导入结果为JSON
        let body = serde_json::to_vec(&ret).map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        // 返回导入结果响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(body)), header))
    }
}