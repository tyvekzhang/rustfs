// 版权所有 2024 RustFS 团队
//
// 根据 Apache 许可证 2.0 版本授权（"许可证"）;
// 除非符合许可证，否则不得使用此文件。
// 您可以在以下网址获取许可证副本：
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，否则根据许可证分发的软件
// 均按"原样"分发，不附带任何明示或暗示的担保或条件。
// 请参阅许可证了解特定语言的权限和限制。
#![allow(unused_variables, unused_mut, unused_must_use)]

use crate::{
    admin::{auth::validate_admin_request, router::Operation},
    auth::{check_key_valid, get_session_token},
};
use http::{HeaderMap, StatusCode};
use matchit::Params;
use rustfs_config::MAX_ADMIN_REQUEST_BODY_SIZE;
use rustfs_ecstore::{
    config::storageclass,
    global::GLOBAL_TierConfigMgr,
    tier::{
        tier::{ERR_TIER_BACKEND_IN_USE, ERR_TIER_BACKEND_NOT_EMPTY, ERR_TIER_MISSING_CREDENTIALS},
        tier_admin::TierCreds,
        tier_config::{TierConfig, TierType},
        tier_handlers::{
            ERR_TIER_ALREADY_EXISTS, ERR_TIER_CONNECT_ERR, ERR_TIER_INVALID_CREDENTIALS, ERR_TIER_NAME_NOT_UPPERCASE,
            ERR_TIER_NOT_FOUND,
        },
    },
};
use rustfs_policy::policy::action::{Action, AdminAction};
use s3s::{
    Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    s3_error,
};
use serde_urlencoded::from_bytes;
use time::OffsetDateTime;
use tracing::{debug, warn};

// 添加存储层查询参数结构体
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct AddTierQuery {
    #[serde(rename = "accessKey")]
    #[allow(dead_code)]
    pub access_key: Option<String>,  // 访问密钥
    #[allow(dead_code)]
    pub status: Option<String>,      // 状态
    #[serde(rename = "secretKey")]
    #[allow(dead_code)]
    pub secret_key: Option<String>,  // 密钥
    #[serde(rename = "serviceName")]
    #[allow(dead_code)]
    pub service_name: Option<String>, // 服务名称
    #[serde(rename = "sessionToken")]
    #[allow(dead_code)]
    pub session_token: Option<String>, // 会话令牌
    pub tier: Option<String>,         // 存储层名称
    #[serde(rename = "tierName")]
    #[allow(dead_code)]
    pub tier_name: Option<String>,    // 存储层名称
    #[serde(rename = "tierType")]
    #[allow(dead_code)]
    pub tier_type: Option<String>,    // 存储层类型
    pub force: Option<String>,        // 强制操作标志
}

// 添加存储层操作结构体
pub struct AddTier {}
#[async_trait::async_trait]
impl Operation for AddTier {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                AddTierQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::SetTierAction)]).await?;

        // 读取请求体
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("获取请求体失败, 错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "存储层配置体过大或读取失败"));
            }
        };

        // 解析存储层配置
        let mut args: TierConfig = serde_json::from_slice(&body)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("解析请求体失败 {e}")))?;

        // 根据存储层类型设置名称
        match args.tier_type {
            TierType::S3 => {
                args.name = args.s3.clone().unwrap().name;
            }
            TierType::RustFS => {
                args.name = args.rustfs.clone().unwrap().name;
            }
            TierType::MinIO => {
                args.name = args.minio.clone().unwrap().name;
            }
            TierType::Aliyun => {
                args.name = args.aliyun.clone().unwrap().name;
            }
            TierType::Tencent => {
                args.name = args.tencent.clone().unwrap().name;
            }
            TierType::Huaweicloud => {
                args.name = args.huaweicloud.clone().unwrap().name;
            }
            TierType::Azure => {
                args.name = args.azure.clone().unwrap().name;
            }
            TierType::GCS => {
                args.name = args.gcs.clone().unwrap().name;
            }
            TierType::R2 => {
                args.name = args.r2.clone().unwrap().name;
            }
            _ => (),
        }
        debug!("添加存储层参数 {:?}", args);

        // 解析强制操作标志
        let mut force: bool = false;
        let force_str = query.force.clone().unwrap_or_default();
        if !force_str.is_empty() {
            force = force_str.parse().map_err(|e| {
                warn!("解析force参数失败, 错误: {:?}", e);
                s3_error!(InvalidRequest, "解析force参数失败")
            })?;
        }
        
        // 检查是否为保留名称
        match args.name.as_str() {
            storageclass::STANDARD | storageclass::RRS => {
                warn!("存储层使用保留名称, 参数名: {}", args.name);
                return Err(s3_error!(InvalidRequest, "不能使用保留的存储层名称"));
            }
            &_ => (),
        }

        // 获取存储层配置管理器并添加存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.write().await;
        if let Err(err) = tier_config_mgr.add(args, force).await {
            return if err.code == ERR_TIER_ALREADY_EXISTS.code {
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierNameAlreadyExist".into()),
                    "存储层名称已存在!",
                ))
            } else if err.code == ERR_TIER_NAME_NOT_UPPERCASE.code {
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierNameNotUppercase".into()),
                    "存储层名称不是大写!",
                ))
            } else if err.code == ERR_TIER_BACKEND_IN_USE.code {
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierNameBackendInUse!".into()),
                    "存储层后端正在使用中!",
                ))
            } else if err.code == ERR_TIER_CONNECT_ERR.code {
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierConnectError".into()),
                    "存储层连接错误!",
                ))
            } else if err.code == ERR_TIER_INVALID_CREDENTIALS.code {
                Err(S3Error::with_message(S3ErrorCode::Custom(err.code.clone().into()), err.message.clone()))
            } else {
                warn!("存储层配置管理器添加失败, 错误: {:?}", err);
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierAddFailed".into()),
                    format!("存储层添加失败. {err}"),
                ))
            };
        }
        
        // 保存配置
        if let Err(e) = tier_config_mgr.save().await {
            warn!("存储层配置管理器保存失败, 错误: {:?}", e);
            return Err(S3Error::with_message(S3ErrorCode::Custom("TierAddFailed".into()), "存储层保存失败"));
        }

        // 返回成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

// 编辑存储层操作结构体
pub struct EditTier {}
#[async_trait::async_trait]
impl Operation for EditTier {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                AddTierQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::SetTierAction)]).await?;

        // 读取请求体
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("获取请求体失败, 错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "存储层配置体过大或读取失败"));
            }
        };

        // 解析存储层凭证
        let creds: TierCreds = serde_json::from_slice(&body)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("解析请求体失败 {e}")))?;

        debug!("编辑存储层参数 {:?}", creds);

        // 获取存储层名称
        let tier_name = params.get("tiername").map(|s| s.to_string()).unwrap_or_default();

        // 获取存储层配置管理器并编辑存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.write().await;
        if let Err(err) = tier_config_mgr.edit(&tier_name, creds).await {
            return if err.code == ERR_TIER_NOT_FOUND.code {
                Err(S3Error::with_message(S3ErrorCode::Custom("TierNotFound".into()), "存储层未找到!"))
            } else if err.code == ERR_TIER_MISSING_CREDENTIALS.code {
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierMissingCredentials".into()),
                    "存储层缺少凭证!",
                ))
            } else {
                warn!("存储层配置管理器编辑失败, 错误: {:?}", err);
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierEditFailed".into()),
                    format!("存储层编辑失败. {err}"),
                ))
            };
        }
        
        // 保存配置
        if let Err(e) = tier_config_mgr.save().await {
            warn!("存储层配置管理器保存失败, 错误: {:?}", e);
            return Err(S3Error::with_message(S3ErrorCode::Custom("TierEditFailed".into()), "存储层保存失败"));
        }

        // 返回成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

// 桶查询参数结构体
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct BucketQuery {
    #[serde(rename = "bucket")]
    #[allow(dead_code)]
    pub bucket: String,  // 桶名称
}

// 列出存储层操作结构体
pub struct ListTiers {}
#[async_trait::async_trait]
impl Operation for ListTiers {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: BucketQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                BucketQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::ListTierAction)]).await?;

        // 获取存储层配置管理器并列出存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.read().await;
        let tiers = tier_config_mgr.list_tiers();

        // 序列化存储层列表
        let data = serde_json::to_vec(&tiers)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化存储层列表失败 {e}")))?;

        // 返回响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

// 删除存储层操作结构体
pub struct RemoveTier {}
#[async_trait::async_trait]
impl Operation for RemoveTier {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                AddTierQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::SetTierAction)]).await?;

        // 解析强制操作标志
        let mut force: bool = false;
        let force_str = query.force.clone().unwrap_or_default();
        if !force_str.is_empty() {
            force = force_str.parse().map_err(|e| {
                warn!("解析force参数失败, 错误: {:?}", e);
                s3_error!(InvalidRequest, "解析force参数失败")
            })?;
        }

        // 获取存储层名称
        let tier_name = params.get("tiername").map(|s| s.to_string()).unwrap_or_default();

        // 获取存储层配置管理器并删除存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.write().await;
        if let Err(err) = tier_config_mgr.remove(&tier_name, force).await {
            return if err.code == ERR_TIER_NOT_FOUND.code {
                Err(S3Error::with_message(S3ErrorCode::Custom("TierNotFound".into()), "存储层未找到."))
            } else if err.code == ERR_TIER_BACKEND_NOT_EMPTY.code {
                Err(S3Error::with_message(S3ErrorCode::Custom("TierNameBackendInUse".into()), "存储层正在使用中."))
            } else {
                warn!("存储层配置管理器删除失败, 错误: {:?}", err);
                Err(S3Error::with_message(
                    S3ErrorCode::Custom("TierRemoveFailed".into()),
                    format!("存储层删除失败. {err}"),
                ))
            };
        }

        // 保存配置
        if let Err(e) = tier_config_mgr.save().await {
            warn!("存储层配置管理器保存失败, 错误: {:?}", e);
            return Err(S3Error::with_message(S3ErrorCode::Custom("TierRemoveFailed".into()), "存储层保存失败"));
        }

        // 返回成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

// 验证存储层操作结构体（暂时未使用）
#[allow(dead_code)]
pub struct VerifyTier {}
#[async_trait::async_trait]
impl Operation for VerifyTier {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                AddTierQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::ListTierAction)]).await?;

        // 获取存储层配置管理器并验证存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.write().await;
        tier_config_mgr.verify(&query.tier.unwrap()).await;

        // 返回成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

// 获取存储层信息操作结构体
pub struct GetTierInfo {}
#[async_trait::async_trait]
impl Operation for GetTierInfo {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::ListTierAction)]).await?;

        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: AddTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                AddTierQuery::default()
            }
        };

        // 获取存储层配置管理器并获取存储层信息
        let tier_config_mgr = GLOBAL_TierConfigMgr.read().await;
        let info = tier_config_mgr.get(&query.tier.unwrap());

        // 序列化存储层信息
        let data = serde_json::to_vec(&info)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化存储层信息失败 {e}")))?;

        // 返回响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

// 清除存储层查询参数结构体
#[derive(Debug, serde::Deserialize, Default)]
pub struct ClearTierQuery {
    pub rand: Option<String>,  // 随机验证字符串
    pub force: String,         // 强制操作标志
}

// 清除存储层操作结构体
pub struct ClearTier {}
#[async_trait::async_trait]
impl Operation for ClearTier {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: ClearTierQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                ClearTierQuery::default()
            }
        };

        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员请求权限
        validate_admin_request(&req.headers, &cred, owner, false, vec![Action::AdminAction(AdminAction::SetTierAction)]).await?;

        // 解析强制操作标志
        let mut force: bool = false;
        let force_str = query.force;
        if !force_str.is_empty() {
            force = force_str.parse().unwrap();
        }

        // 生成并验证随机字符串（安全验证）
        let t = OffsetDateTime::now_utc();
        let mut rand = "AGD1R25GI3I1GJGUGJFD7FBS4DFAASDF".to_string();
        rand.insert_str(3, &t.day().to_string());
        rand.insert_str(17, &t.month().to_string());
        rand.insert_str(23, &t.year().to_string());
        warn!("存储层配置管理器随机字符串: {}", rand);
        if query.rand != Some(rand) {
            return Err(s3_error!(InvalidRequest, "随机字符串验证失败"));
        };

        // 获取存储层配置管理器并清除存储层
        let mut tier_config_mgr = GLOBAL_TierConfigMgr.write().await;
        if let Err(err) = tier_config_mgr.clear_tier(force).await {
            warn!("存储层配置管理器清除失败, 错误: {:?}", err);
            return Err(S3Error::with_message(
                S3ErrorCode::Custom("TierClearFailed".into()),
                format!("存储层清除失败. {err}"),
            ));
        }
        
        // 保存配置
        if let Err(e) = tier_config_mgr.save().await {
            warn!("存储层配置管理器保存失败, 错误: {:?}", e);
            return Err(S3Error::with_message(S3ErrorCode::Custom("TierEditFailed".into()), "存储层保存失败"));
        }

        // 返回成功响应
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}