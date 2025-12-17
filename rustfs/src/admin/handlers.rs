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

// 导入必要的模块和依赖
use super::router::Operation;
use crate::admin::auth::validate_admin_request;
use crate::auth::check_key_valid;
use crate::auth::get_condition_values;
use crate::auth::get_session_token;
use crate::error::ApiError;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http::{HeaderMap, HeaderValue, Uri};
use hyper::StatusCode;
use matchit::Params;
use rustfs_common::heal_channel::HealOpts;
use rustfs_config::{MAX_ADMIN_REQUEST_BODY_SIZE, MAX_HEAL_REQUEST_SIZE};
use rustfs_ecstore::admin_server_info::get_server_info;
use rustfs_ecstore::bucket::bucket_target_sys::BucketTargetSys;
use rustfs_ecstore::bucket::metadata::BUCKET_TARGETS_FILE;
use rustfs_ecstore::bucket::metadata_sys;
use rustfs_ecstore::bucket::target::BucketTarget;
use rustfs_ecstore::bucket::versioning_sys::BucketVersioningSys;
use rustfs_ecstore::data_usage::{
    aggregate_local_snapshots, compute_bucket_usage, load_data_usage_from_backend, store_data_usage_in_backend,
};
use rustfs_ecstore::error::StorageError;
use rustfs_ecstore::global::get_global_action_cred;
use rustfs_ecstore::global::global_rustfs_port;
use rustfs_ecstore::metrics_realtime::{CollectMetricsOpts, MetricType, collect_local_metrics};
use rustfs_ecstore::new_object_layer_fn;
use rustfs_ecstore::pools::{get_total_usable_capacity, get_total_usable_capacity_free};
use rustfs_ecstore::store::is_valid_object_prefix;
use rustfs_ecstore::store_api::BucketOptions;
use rustfs_ecstore::store_api::StorageAPI;
use rustfs_ecstore::store_utils::is_reserved_or_invalid_bucket;
use rustfs_iam::store::MappedPolicy;
use rustfs_madmin::metrics::RealtimeMetrics;
use rustfs_madmin::utils::parse_duration;
use rustfs_policy::policy::Args;
use rustfs_policy::policy::BucketPolicy;
use rustfs_policy::policy::action::Action;
use rustfs_policy::policy::action::AdminAction;
use rustfs_policy::policy::action::S3Action;
use rustfs_policy::policy::default::DEFAULT_POLICIES;
use rustfs_utils::path::path_join;
use s3s::header::CONTENT_TYPE;
use s3s::stream::{ByteStream, DynByteStream};
use s3s::{Body, S3Error, S3Request, S3Response, S3Result, s3_error};
use s3s::{S3ErrorCode, StdError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration as std_Duration;
use tokio::sync::mpsc::{self};
use tokio::time::interval;
use tokio::{select, spawn};
use tokio_stream::wrappers::ReceiverStream;
use tracing::debug;
use tracing::{error, info, warn};
use url::Host;

// 导入子模块
pub mod bucket_meta;
pub mod event;
pub mod group;
pub mod kms;
pub mod kms_dynamic;
pub mod kms_keys;
pub mod policies;
pub mod pools;
pub mod profile;
pub mod rebalance;
pub mod service_account;
pub mod sts;
pub mod tier;
pub mod trace;
pub mod user;

/// 管理员状态响应结构体
#[derive(Debug, Serialize)]
pub struct IsAdminResponse {
    pub is_admin: bool,           // 是否是管理员
    pub access_key: String,       // 访问密钥
    pub message: String,          // 状态消息
}

/// 账户信息结构体
#[allow(dead_code)]
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "PascalCase", default)]  // JSON字段名使用PascalCase格式
pub struct AccountInfo {
    pub account_name: String,     // 账户名称
    pub server: rustfs_madmin::BackendInfo,  // 后端服务器信息
    pub policy: BucketPolicy,     // 存储桶策略
}

/// 健康检查处理器
pub struct HealthCheckHandler {}

#[async_trait::async_trait]
impl Operation for HealthCheckHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        use serde_json::json;

        // 提取原始的HTTP方法（被s3s封装到S3Request中）
        let method = req.method;

        // 只允许GET和HEAD方法
        if method != http::Method::GET && method != http::Method::HEAD {
            // 405 方法不允许
            let mut headers = HeaderMap::new();
            headers.insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return Ok(S3Response::with_headers(
                (StatusCode::METHOD_NOT_ALLOWED, Body::from("Method Not Allowed".to_string())),
                headers,
            ));
        }

        // 构建健康检查信息
        let health_info = json!({
            "status": "ok",
            "service": "rustfs-endpoint",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "version": env!("CARGO_PKG_VERSION")
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if method == http::Method::HEAD {
            // HEAD方法：只返回头部和状态码，不返回响应体
            return Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), headers));
        }

        // GET方法：正常返回JSON响应体
        let body_str = serde_json::to_string(&health_info).unwrap_or_else(|_| "{}".to_string());
        let body = Body::from(body_str);

        Ok(S3Response::with_headers((StatusCode::OK, body), headers))
    }
}

/// 管理员状态检查处理器
pub struct IsAdminHandler {}

#[async_trait::async_trait]
impl Operation for IsAdminHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 从请求中获取凭证信息
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        // 验证访问密钥的有效性
        let (cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        let access_key_to_check = input_cred.access_key.clone();

        // 通过比较全局凭证来检查用户是否是管理员
        let is_admin = if let Some(sys_cred) = get_global_action_cred() {
            crate::auth::constant_time_eq(&access_key_to_check, &sys_cred.access_key)
                || crate::auth::constant_time_eq(&cred.parent_user, &sys_cred.access_key)
        } else {
            false
        };

        // 构建响应
        let response = IsAdminResponse {
            is_admin,
            access_key: access_key_to_check,
            message: format!("User is {}an administrator", if is_admin { "" } else { "not " }),
        };

        // 序列化响应数据
        let data = serde_json::to_vec(&response)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse IsAdminResponse failed"))?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 账户信息处理器
pub struct AccountInfoHandler {}

#[async_trait::async_trait]
impl Operation for AccountInfoHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 获取对象存储层
        let Some(store) = new_object_layer_fn() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not init".to_string()));
        };

        // 获取凭证信息
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        // 验证密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 获取IAM存储
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "iam not init"));
        };

        let default_claims = HashMap::new();
        let claims = cred.claims.as_ref().unwrap_or(&default_claims);

        // 获取条件值用于策略评估
        let cred_clone = cred.clone();
        let conditions = get_condition_values(&req.headers, &cred_clone, None, None);
        let cred_clone = Arc::new(cred_clone);
        let conditions = Arc::new(conditions);

        // 创建检查权限的闭包
        let is_allow = Box::new({
            let iam_clone = Arc::clone(&iam_store);
            let cred_clone = Arc::clone(&cred_clone);
            let conditions = Arc::clone(&conditions);
            move |name: String| {
                let iam_clone = Arc::clone(&iam_clone);
                let cred_clone = Arc::clone(&cred_clone);
                let conditions = Arc::clone(&conditions);
                async move {
                    let (mut rd, mut wr) = (false, false);
                    
                    // 检查ListBucket权限
                    if !iam_clone
                        .is_allowed(&Args {
                            account: &cred_clone.access_key,
                            groups: &cred_clone.groups,
                            action: Action::S3Action(S3Action::ListBucketAction),
                            bucket: &name,
                            conditions: &conditions,
                            is_owner: owner,
                            object: "",
                            claims,
                            deny_only: false,
                        })
                        .await
                    {
                        rd = true
                    }

                    // 检查GetBucketLocation权限
                    if !iam_clone
                        .is_allowed(&Args {
                            account: &cred_clone.access_key,
                            groups: &cred_clone.groups,
                            action: Action::S3Action(S3Action::GetBucketLocationAction),
                            bucket: &name,
                            conditions: &conditions,
                            is_owner: owner,
                            object: "",
                            claims,
                            deny_only: false,
                        })
                        .await
                    {
                        rd = true
                    }

                    // 检查PutObject权限
                    if !iam_clone
                        .is_allowed(&Args {
                            account: &cred_clone.access_key,
                            groups: &cred_clone.groups,
                            action: Action::S3Action(S3Action::PutObjectAction),
                            bucket: &name,
                            conditions: &conditions,
                            is_owner: owner,
                            object: "",
                            claims,
                            deny_only: false,
                        })
                        .await
                    {
                        wr = true
                    }

                    (rd, wr)
                }
            }
        });

        // 确定账户名称
        let account_name = if cred.is_temp() || cred.is_service_account() {
            cred.parent_user.clone()
        } else {
            cred.access_key.clone()
        };

        // 构建参数用于从声明中获取角色ARN
        let claims_args = Args {
            account: "",
            groups: &None,
            action: Action::None,
            bucket: "",
            conditions: &HashMap::new(),
            is_owner: false,
            object: "",
            claims,
            deny_only: false,
        };

        let role_arn = claims_args.get_role_arn();

        // 获取全局管理员凭证
        let Some(admin_cred) = get_global_action_cred() else {
            return Err(S3Error::with_message(
                S3ErrorCode::InternalError,
                "get_global_action_cred failed".to_string(),
            ));
        };

        let mut effective_policy: rustfs_policy::policy::Policy = Default::default();

        // 根据账户类型确定有效策略
        if account_name == admin_cred.access_key {
            // 管理员使用consoleAdmin策略
            for (name, p) in DEFAULT_POLICIES.iter() {
                if *name == "consoleAdmin" {
                    effective_policy = p.clone();
                    break;
                }
            }
        } else if let Some(arn) = role_arn {
            // 角色账户使用角色策略
            let (_, policy_name) = iam_store
                .get_role_policy(arn)
                .await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

            let policies = MappedPolicy::new(&policy_name).to_slice();
            effective_policy = iam_store.get_combined_policy(&policies).await;
        } else {
            // 普通账户使用分配的权限策略
            let policies = iam_store
                .policy_db_get(&account_name, &cred.groups)
                .await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("get policy failed: {e}")))?;

            effective_policy = iam_store.get_combined_policy(&policies).await;
        };

        // 序列化策略
        let policy_str = serde_json::to_string(&effective_policy)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse policy failed"))?;

        // 构建账户信息
        let mut account_info = rustfs_madmin::AccountInfo {
            account_name,
            server: store.backend_info().await,
            policy: serde_json::Value::String(policy_str),
            ..Default::default()
        };

        // 获取存储桶列表并检查访问权限
        let buckets = store
            .list_bucket(&BucketOptions {
                cached: true,
                ..Default::default()
            })
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        for bucket in buckets.iter() {
            let (rd, wr) = is_allow(bucket.name.clone()).await;
            if rd || wr {
                // 有访问权限的存储桶添加到账户信息中
                account_info.buckets.push(rustfs_madmin::BucketAccessInfo {
                    name: bucket.name.clone(),
                    details: Some(rustfs_madmin::BucketDetails {
                        versioning: BucketVersioningSys::enabled(bucket.name.as_str()).await,
                        versioning_suspended: BucketVersioningSys::suspended(bucket.name.as_str()).await,
                        ..Default::default()
                    }),
                    created: bucket.created,
                    access: rustfs_madmin::AccountAccess { read: rd, write: wr },
                    ..Default::default()
                });
            }
        }

        // 序列化账户信息
        let data = serde_json::to_vec(&account_info)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse accountInfo failed"))?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 服务处理器（未实现）
pub struct ServiceHandle {}

#[async_trait::async_trait]
impl Operation for ServiceHandle {
    async fn call(&self, _req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle ServiceHandle");

        Err(s3_error!(NotImplemented))
    }
}

/// 服务器信息处理器
pub struct ServerInfoHandler {}

#[async_trait::async_trait]
impl Operation for ServerInfoHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 验证凭证
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ServerInfoAdminAction)],
        )
        .await?;

        // 获取服务器信息
        let info = get_server_info(true).await;

        let data = serde_json::to_vec(&info)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse serverInfo failed"))?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 数据检查处理器（未实现）
pub struct InspectDataHandler {}

#[async_trait::async_trait]
impl Operation for InspectDataHandler {
    async fn call(&self, _req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle InspectDataHandler");

        Err(s3_error!(NotImplemented))
    }
}

/// 存储信息处理器
pub struct StorageInfoHandler {}

#[async_trait::async_trait]
impl Operation for StorageInfoHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle StorageInfoHandler");

        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::StorageInfoAdminAction)],
        )
        .await?;

        let Some(store) = new_object_layer_fn() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not init".to_string()));
        };

        // 获取存储信息
        let info = store.storage_info().await;

        let data = serde_json::to_vec(&info)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse accountInfo failed"))?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 数据使用信息处理器
pub struct DataUsageInfoHandler {}

#[async_trait::async_trait]
impl Operation for DataUsageInfoHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle DataUsageInfoHandler");

        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 验证管理员权限
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![
                Action::AdminAction(AdminAction::DataUsageInfoAdminAction),
                Action::S3Action(S3Action::ListBucketAction),
            ],
        )
        .await?;

        let Some(store) = new_object_layer_fn() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not init".to_string()));
        };

        // 聚合本地快照获取数据使用信息
        let (disk_statuses, mut info) = match aggregate_local_snapshots(store.clone()).await {
            Ok((statuses, usage)) => (statuses, usage),
            Err(err) => {
                warn!("aggregate_local_snapshots failed: {:?}", err);
                // 从后端加载数据使用信息
                (
                    Vec::new(),
                    load_data_usage_from_backend(store.clone()).await.map_err(|e| {
                        error!("load_data_usage_from_backend failed {:?}", e);
                        s3_error!(InternalError, "load_data_usage_from_backend failed")
                    })?,
                )
            }
        };

        // 检查是否有快照可用
        let snapshots_available = disk_statuses.iter().any(|status| status.snapshot_exists);
        if !snapshots_available {
            if let Ok(fallback) = load_data_usage_from_backend(store.clone()).await {
                let mut fallback_info = fallback;
                fallback_info.disk_usage_status = disk_statuses.clone();
                info = fallback_info;
            }
        } else {
            info.disk_usage_status = disk_statuses.clone();
        }

        // 检查数据是否过时
        let last_update_age = info.last_update.and_then(|ts| ts.elapsed().ok());
        let data_missing = info.objects_total_count == 0 && info.buckets_count == 0;
        let stale = last_update_age
            .map(|elapsed| elapsed > std::time::Duration::from_secs(300))
            .unwrap_or(true);

        // 数据缺失时进行实时收集
        if data_missing {
            info!("No data usage statistics found, attempting real-time collection");

            if let Err(e) = collect_realtime_data_usage(&mut info, store.clone()).await {
                warn!("Failed to collect real-time data usage: {}", e);
            } else if let Err(e) = store_data_usage_in_backend(info.clone(), store.clone()).await {
                warn!("Failed to persist refreshed data usage: {}", e);
            }
        } else if stale {
            // 数据过时，异步刷新
            info!(
                "Data usage statistics are stale (last update {:?} ago), refreshing asynchronously",
                last_update_age
            );

            let mut info_for_refresh = info.clone();
            let store_for_refresh = store.clone();
            spawn(async move {
                if let Err(e) = collect_realtime_data_usage(&mut info_for_refresh, store_for_refresh.clone()).await {
                    warn!("Background data usage refresh failed: {}", e);
                    return;
                }

                if let Err(e) = store_data_usage_in_backend(info_for_refresh, store_for_refresh).await {
                    warn!("Background data usage persistence failed: {}", e);
                }
            });
        }

        info.disk_usage_status = disk_statuses;

        // 设置容量信息
        let sinfo = store.storage_info().await;
        info.total_capacity = get_total_usable_capacity(&sinfo.disks, &sinfo) as u64;
        info.total_free_capacity = get_total_usable_capacity_free(&sinfo.disks, &sinfo) as u64;
        if info.total_capacity > info.total_free_capacity {
            info.total_used_capacity = info.total_capacity - info.total_free_capacity;
        }

        let data = serde_json::to_vec(&info)
            .map_err(|_e| S3Error::with_message(S3ErrorCode::InternalError, "parse DataUsageInfo failed"))?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 指标参数结构体
#[derive(Debug, Serialize, Deserialize)]
struct MetricsParams {
    disks: String,            // 磁盘列表
    hosts: String,           // 主机列表
    #[serde(rename = "interval")]
    tick: String,            // 收集间隔
    n: u64,                  // 收集次数
    types: u32,              // 指标类型
    #[serde(rename = "by-disk")]
    by_disk: String,         // 按磁盘分组
    #[serde(rename = "by-host")]
    by_host: String,         // 按主机分组
    #[serde(rename = "by-jobID")]
    by_job_id: String,       // 按任务ID分组
    #[serde(rename = "by-depID")]
    by_dep_id: String,       // 按部门ID分组
}

impl Default for MetricsParams {
    fn default() -> Self {
        Self {
            disks: Default::default(),
            hosts: Default::default(),
            tick: Default::default(),
            n: u64::MAX,
            types: Default::default(),
            by_disk: Default::default(),
            by_host: Default::default(),
            by_job_id: Default::default(),
            by_dep_id: Default::default(),
        }
    }
}

/// 从URI中提取指标参数
fn extract_metrics_init_params(uri: &Uri) -> MetricsParams {
    let mut mp = MetricsParams::default();
    if let Some(query) = uri.query() {
        let params: Vec<&str> = query.split('&').collect();
        for param in params {
            let mut parts = param.split('=');
            if let Some(key) = parts.next() {
                if key == "disks" {
                    if let Some(value) = parts.next() {
                        mp.disks = value.to_string();
                    }
                }
                if key == "hosts" {
                    if let Some(value) = parts.next() {
                        mp.hosts = value.to_string();
                    }
                }
                if key == "interval" {
                    if let Some(value) = parts.next() {
                        mp.tick = value.to_string();
                    }
                }
                if key == "n" {
                    if let Some(value) = parts.next() {
                        mp.n = value.parse::<u64>().unwrap_or(u64::MAX);
                    }
                }
                if key == "types" {
                    if let Some(value) = parts.next() {
                        mp.types = value.parse::<u32>().unwrap_or_default();
                    }
                }
                if key == "by-disk" {
                    if let Some(value) = parts.next() {
                        mp.by_disk = value.to_string();
                    }
                }
                if key == "by-host" {
                    if let Some(value) = parts.next() {
                        mp.by_host = value.to_string();
                    }
                }
                if key == "by-jobID" {
                    if let Some(value) = parts.next() {
                        mp.by_job_id = value.to_string();
                    }
                }
                if key == "by-depID" {
                    if let Some(value) = parts.next() {
                        mp.by_dep_id = value.to_string();
                    }
                }
            }
        }
    }
    mp
}

/// 指标流结构体
struct MetricsStream {
    inner: ReceiverStream<Result<Bytes, StdError>>,  // 接收器流
}

impl Stream for MetricsStream {
    type Item = Result<Bytes, StdError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        info!("MetricsStream poll_next");
        let this = Pin::into_inner(self);
        this.inner.poll_next_unpin(cx)
    }
}

impl ByteStream for MetricsStream {}

/// 指标处理器
pub struct MetricsHandler {}

#[async_trait::async_trait]
impl Operation for MetricsHandler {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        info!("handle MetricsHandler, req: {:?}, params: {:?}", req, params);
        let Some(cred) = req.credentials else { return Err(s3_error!(InvalidRequest, "get cred failed")) };
        info!("cred: {:?}", cred);

        // 提取指标参数
        let mp = extract_metrics_init_params(&req.uri);
        info!("mp: {:?}", mp);

        // 解析间隔时间
        let tick = parse_duration(&mp.tick).unwrap_or_else(|_| std_Duration::from_secs(3));

        let mut n = mp.n;
        if n == 0 {
            n = u64::MAX;
        }

        // 设置指标类型
        let types = if mp.types != 0 {
            MetricType::new(mp.types)
        } else {
            MetricType::ALL
        };

        // 解析逗号分隔的字符串为集合
        fn parse_comma_separated(s: &str) -> HashSet<String> {
            s.split(',').filter(|part| !part.is_empty()).map(String::from).collect()
        }

        let disks = parse_comma_separated(&mp.disks);
        let by_disk = mp.by_disk == "true";
        let disk_map = disks;

        let job_id = mp.by_job_id;
        let hosts = parse_comma_separated(&mp.hosts);
        let by_host = mp.by_host == "true";
        let host_map = hosts;

        let d_id = mp.by_dep_id;
        let mut interval = interval(tick);

        // 构建指标收集选项
        let opts = CollectMetricsOpts {
            hosts: host_map,
            disks: disk_map,
            job_id,
            dep_id: d_id,
        };
        
        // 创建通道用于流式传输指标数据
        let (tx, rx) = mpsc::channel(10);
        let in_stream: DynByteStream = Box::pin(MetricsStream {
            inner: ReceiverStream::new(rx),
        });
        let body = Body::from(in_stream);
        
        // 启动异步任务收集指标
        spawn(async move {
            while n > 0 {
                info!("loop, n: {n}");
                let mut m = RealtimeMetrics::default();
                let m_local = collect_local_metrics(types, &opts).await;
                m.merge(m_local);

                // 根据选项过滤数据
                if !by_host {
                    m.by_host = HashMap::new();
                }
                if !by_disk {
                    m.by_disk = HashMap::new();
                }

                m.finally = n <= 1;

                // 序列化并发送指标数据
                match serde_json::to_vec(&m) {
                    Ok(re) => {
                        info!("got metrics, send it to client, m: {m:?}");
                        let _ = tx.send(Ok(Bytes::from(re))).await;
                    }
                    Err(e) => {
                        error!("MetricsHandler: json encode failed, err: {:?}", e);
                        return;
                    }
                }

                n -= 1;
                if n == 0 {
                    break;
                }

                // 等待下一个收集间隔或通道关闭
                select! {
                    _ = tx.closed() => { return; }
                    _ = interval.tick() => {}
                }
            }
        });

        Ok(S3Response::new((StatusCode::OK, body)))
    }
}

/// 修复初始化参数结构体
#[derive(Debug, Default, Serialize, Deserialize)]
struct HealInitParams {
    bucket: String,          // 存储桶名称
    obj_prefix: String,      // 对象前缀
    hs: HealOpts,            // 修复选项
    client_token: String,    // 客户端令牌
    force_start: bool,       // 强制开始
    force_stop: bool,        // 强制停止
}

/// 提取修复初始化参数
fn extract_heal_init_params(body: &Bytes, uri: &Uri, params: Params<'_, '_>) -> S3Result<HealInitParams> {
    let mut hip = HealInitParams {
        bucket: params.get("bucket").map(|s| s.to_string()).unwrap_or_default(),
        obj_prefix: params.get("prefix").map(|s| s.to_string()).unwrap_or_default(),
        ..Default::default()
    };
    
    // 验证参数有效性
    if hip.bucket.is_empty() && !hip.obj_prefix.is_empty() {
        return Err(s3_error!(InvalidRequest, "invalid bucket name"));
    }
    if is_reserved_or_invalid_bucket(&hip.bucket, false) {
        return Err(s3_error!(InvalidRequest, "invalid bucket name"));
    }
    if !is_valid_object_prefix(&hip.obj_prefix) {
        return Err(s3_error!(InvalidRequest, "invalid object name"));
    }

    // 从查询参数中提取其他参数
    if let Some(query) = uri.query() {
        let params: Vec<&str> = query.split('&').collect();
        for param in params {
            let mut parts = param.split('=');
            if let Some(key) = parts.next() {
                if key == "clientToken" {
                    if let Some(value) = parts.next() {
                        hip.client_token = value.to_string();
                    }
                }
                if key == "forceStart" && parts.next().is_some() {
                    hip.force_start = true;
                }
                if key == "forceStop" && parts.next().is_some() {
                    hip.force_stop = true;
                }
            }
        }
    }

    // 验证参数组合的有效性
    if (hip.force_start && hip.force_stop) || (!hip.client_token.is_empty() && (hip.force_start || hip.force_stop)) {
        return Err(s3_error!(InvalidRequest, ""));
    }

    // 如果客户端令牌为空，从请求体中解析修复选项
    if hip.client_token.is_empty() {
        hip.hs = serde_json::from_slice(body).map_err(|e| {
            info!("err request body parse, err: {:?}", e);
            s3_error!(InvalidRequest, "err request body parse")
        })?;
    }

    Ok(hip)
}

/// 修复处理器
pub struct HealHandler {}

#[async_trait::async_trait]
impl Operation for HealHandler {
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle HealHandler, req: {:?}, params: {:?}", req, params);
        let Some(cred) = req.credentials else { return Err(s3_error!(InvalidRequest, "get cred failed")) };
        info!("cred: {:?}", cred);
        
        // 读取请求体
        let mut input = req.input;
        let bytes = match input.store_all_limited(MAX_HEAL_REQUEST_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("get body failed, e: {:?}", e);
                return Err(s3_error!(InvalidRequest, "heal request body too large or failed to read"));
            }
        };
        info!("bytes: {:?}", bytes);
        
        // 提取修复参数
        let hip = extract_heal_init_params(&bytes, &req.uri, params)?;
        info!("body: {:?}", hip);

        /// 修复响应结构体
        #[derive(Default)]
        struct HealResp {
            resp_bytes: Vec<u8>,          // 响应字节
            _api_err: Option<StorageError>, // API错误
            _err_body: String,            // 错误消息
        }

        // 构建修复路径
        let heal_path = path_join(&[PathBuf::from(hip.bucket.clone()), PathBuf::from(hip.obj_prefix.clone())]);
        let (tx, mut rx) = mpsc::channel(1);

        // 根据操作类型执行不同的修复操作
        if !hip.client_token.is_empty() && !hip.force_start && !hip.force_stop {
            // 查询修复状态
            let tx_clone = tx.clone();
            let heal_path_str = heal_path.to_str().unwrap_or_default().to_string();
            let client_token = hip.client_token.clone();
            spawn(async move {
                match rustfs_common::heal_channel::query_heal_status(heal_path_str, client_token).await {
                    Ok(_) => {
                        // TODO: 从通道获取实际响应
                        let _ = tx_clone
                            .send(HealResp {
                                resp_bytes: vec![],
                                ..Default::default()
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx_clone
                            .send(HealResp {
                                _api_err: Some(StorageError::other(e)),
                                ..Default::default()
                            })
                            .await;
                    }
                }
            });
        } else if hip.force_stop {
            // 取消修复任务
            let tx_clone = tx.clone();
            let heal_path_str = heal_path.to_str().unwrap_or_default().to_string();
            spawn(async move {
                match rustfs_common::heal_channel::cancel_heal_task(heal_path_str).await {
                    Ok(_) => {
                        // TODO: 从通道获取实际响应
                        let _ = tx_clone
                            .send(HealResp {
                                resp_bytes: vec![],
                                ..Default::default()
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = tx_clone
                            .send(HealResp {
                                _api_err: Some(StorageError::other(e)),
                                ..Default::default()
                            })
                            .await;
                    }
                }
            });
        } else if hip.client_token.is_empty() {
            // 使用新的修复通道机制
            let tx_clone = tx.clone();
            spawn(async move {
                // 通过通道创建修复请求
                let heal_request = rustfs_common::heal_channel::create_heal_request(
                    hip.bucket.clone(),
                    if hip.obj_prefix.is_empty() {
                        None
                    } else {
                        Some(hip.obj_prefix.clone())
                    },
                    hip.force_start,
                    Some(rustfs_common::heal_channel::HealChannelPriority::Normal),
                );

                match rustfs_common::heal_channel::send_heal_request(heal_request).await {
                    Ok(_) => {
                        // 成功 - 发送空响应
                        let _ = tx_clone
                            .send(HealResp {
                                resp_bytes: vec![],
                                ..Default::default()
                            })
                            .await;
                    }
                    Err(e) => {
                        // 错误 - 发送错误响应
                        let _ = tx_clone
                            .send(HealResp {
                                _api_err: Some(StorageError::other(e)),
                                ..Default::default()
                            })
                            .await;
                    }
                }
            });
        }

        // 等待修复结果
        match rx.recv().await {
            Some(result) => Ok(S3Response::new((StatusCode::OK, Body::from(result.resp_bytes)))),
            None => Ok(S3Response::new((StatusCode::INTERNAL_SERVER_ERROR, Body::from(vec![])))),
        }
    }
}

/// 后台修复状态处理器（未实现）
pub struct BackgroundHealStatusHandler {}

#[async_trait::async_trait]
impl Operation for BackgroundHealStatusHandler {
    async fn call(&self, _req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("handle BackgroundHealStatusHandler");

        Err(s3_error!(NotImplemented))
    }
}

/// 从URI中提取查询参数
fn extract_query_params(uri: &Uri) -> HashMap<String, String> {
    let mut params = HashMap::new();

    if let Some(query) = uri.query() {
        query.split('&').for_each(|pair| {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(key.to_string(), value.to_string());
            }
        });
    }

    params
}

#[allow(dead_code)]
/// 检查是否本地主机（未实现）
fn is_local_host(_host: String) -> bool {
    false
}

/// 获取复制指标处理器
// awscurl --service s3 --region us-east-1 --access_key rustfsadmin --secret_key rustfsadmin "http://:9000/rustfs/admin/v3/replicationmetrics?bucket=1"
pub struct GetReplicationMetricsHandler {}

#[async_trait::async_trait]
impl Operation for GetReplicationMetricsHandler {
    async fn call(&self, _req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        error!("GetReplicationMetricsHandler");
        let queries = extract_query_params(&_req.uri);
        if let Some(bucket) = queries.get("bucket") {
            error!("get bucket:{} metrics", bucket);
        }
        // TODO: 实现复制指标获取逻辑
        Ok(S3Response::new((StatusCode::OK, Body::from("Ok".to_string()))))
    }
}

/// 设置远程目标处理器
pub struct SetRemoteTargetHandler {}

#[async_trait::async_trait]
impl Operation for SetRemoteTargetHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let queries = extract_query_params(&req.uri);

        let Some(bucket) = queries.get("bucket") else {
            return Err(s3_error!(InvalidRequest, "bucket is required"));
        };

        let update = queries.get("update").is_some_and(|v| v == "true");

        warn!("set remote target, bucket: {}, update: {}", bucket, update);

        if bucket.is_empty() {
            return Err(s3_error!(InvalidRequest, "bucket is required"));
        }

        let Some(store) = new_object_layer_fn() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not init".to_string()));
        };

        // 验证存储桶存在
        store
            .get_bucket_info(bucket, &BucketOptions::default())
            .await
            .map_err(ApiError::from)?;

        // 读取请求体
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("get body failed, e: {:?}", e);
                return Err(s3_error!(InvalidRequest, "remote target configuration body too large or failed to read"));
            }
        };

        // 解析远程目标配置
        let mut remote_target: BucketTarget = serde_json::from_slice(&body).map_err(|e| {
            error!("Failed to parse BucketTarget from body: {}", e);
            ApiError::other(e)
        })?;

        // 验证目标URL
        let Ok(target_url) = remote_target.url() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Invalid target url".to_string()));
        };

        // 检查是否为本地目标
        let same_target = rustfs_utils::net::is_local_host(
            target_url.host().unwrap_or(Host::Domain("localhost")),
            target_url.port().unwrap_or(80),
            global_rustfs_port(),
        )
        .unwrap_or_default();

        if same_target && bucket == &remote_target.target_bucket {
            return Err(S3Error::with_message(S3ErrorCode::IncorrectEndpoint, "Same target".to_string()));
        }

        remote_target.source_bucket = bucket.clone();

        let bucket_target_sys = BucketTargetSys::get();

        // 如果不是更新操作，检查是否已存在
        if !update {
            let (arn, exist) = bucket_target_sys.get_remote_arn(bucket, Some(&remote_target), "").await;
            remote_target.arn = arn.clone();
            if exist && !arn.is_empty() {
                let arn_str = serde_json::to_string(&arn).unwrap_or_default();

                warn!("return exists, arn: {}", arn_str);
                return Ok(S3Response::new((StatusCode::OK, Body::from(arn_str))));
            }
        }

        if remote_target.arn.is_empty() {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "ARN is empty".to_string()));
        }

        // 更新操作：获取现有目标并更新
        if update {
            let Some(mut target) = bucket_target_sys
                .get_remote_bucket_target_by_arn(bucket, &remote_target.arn)
                .await
            else {
                return Err(S3Error::with_message(S3ErrorCode::InternalError, "Target not found".to_string()));
            };

            // 更新目标配置
            target.credentials = remote_target.credentials;
            target.endpoint = remote_target.endpoint;
            target.secure = remote_target.secure;
            target.target_bucket = remote_target.target_bucket;

            target.path = remote_target.path;
            target.replication_sync = remote_target.replication_sync;
            target.bandwidth_limit = remote_target.bandwidth_limit;
            target.health_check_duration = remote_target.health_check_duration;

            warn!("update target, target: {:?}", target);
            remote_target = target;
        }

        let arn = remote_target.arn.clone();

        // 设置目标
        bucket_target_sys
            .set_target(bucket, &remote_target, update)
            .await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        // 更新存储桶元数据
        let targets = bucket_target_sys.list_bucket_targets(bucket).await.map_err(|e| {
            error!("Failed to list bucket targets: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to list bucket targets".to_string())
        })?;
        let json_targets = serde_json::to_vec(&targets).map_err(|e| {
            error!("Serialization error: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to serialize targets".to_string())
        })?;

        metadata_sys::update(bucket, BUCKET_TARGETS_FILE, json_targets)
            .await
            .map_err(|e| {
                error!("Failed to update bucket targets: {}", e);
                S3Error::with_message(S3ErrorCode::InternalError, format!("Failed to update bucket targets: {e}"))
            })?;

        let arn_str = serde_json::to_string(&arn).unwrap_or_default();

        Ok(S3Response::new((StatusCode::OK, Body::from(arn_str))))
    }
}

/// 列出远程目标处理器
pub struct ListRemoteTargetHandler {}

#[async_trait::async_trait]
impl Operation for ListRemoteTargetHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let queries = extract_query_params(&req.uri);
        let Some(_cred) = req.credentials else {
            error!("credentials null");
            return Err(s3_error!(InvalidRequest, "get cred failed"));
        };

        // 如果指定了存储桶，列出该存储桶的远程目标
        if let Some(bucket) = queries.get("bucket") {
            if bucket.is_empty() {
                error!("bucket parameter is empty");
                return Ok(S3Response::new((
                    StatusCode::BAD_REQUEST,
                    Body::from("Bucket parameter is required".to_string()),
                )));
            }

            let Some(store) = new_object_layer_fn() else {
                return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not initialized".to_string()));
            };

            // 验证存储桶存在
            if let Err(err) = store.get_bucket_info(bucket, &BucketOptions::default()).await {
                error!("Error fetching bucket info: {:?}", err);
                return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from("Invalid bucket".to_string()))));
            }

            let sys = BucketTargetSys::get();
            let targets = sys.list_targets(bucket, "").await;

            let json_targets = serde_json::to_vec(&targets).map_err(|e| {
                error!("Serialization error: {}", e);
                S3Error::with_message(S3ErrorCode::InternalError, "Failed to serialize targets".to_string())
            })?;

            let mut header = HeaderMap::new();
            header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

            return Ok(S3Response::with_headers((StatusCode::OK, Body::from(json_targets)), header));
        }

        // 未指定存储桶，返回空列表
        let targets: Vec<BucketTarget> = Vec::new();

        let json_targets = serde_json::to_vec(&targets).map_err(|e| {
            error!("Serialization error: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to serialize targets".to_string())
        })?;

        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Ok(S3Response::with_headers((StatusCode::OK, Body::from(json_targets)), header))
    }
}

/// 移除远程目标处理器
pub struct RemoveRemoteTargetHandler {}

#[async_trait::async_trait]
impl Operation for RemoveRemoteTargetHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        debug!("remove remote target called");
        let queries = extract_query_params(&req.uri);
        let Some(bucket) = queries.get("bucket") else {
            return Ok(S3Response::new((
                StatusCode::BAD_REQUEST,
                Body::from("Bucket parameter is required".to_string()),
            )));
        };

        let Some(arn_str) = queries.get("arn") else {
            return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from("ARN is required".to_string()))));
        };

        let Some(store) = new_object_layer_fn() else {
            return Err(S3Error::with_message(S3ErrorCode::InternalError, "Not initialized".to_string()));
        };

        // 验证存储桶存在
        if let Err(err) = store.get_bucket_info(bucket, &BucketOptions::default()).await {
            error!("Error fetching bucket info: {:?}", err);
            return Ok(S3Response::new((StatusCode::BAD_REQUEST, Body::from("Invalid bucket".to_string()))));
        }

        let sys = BucketTargetSys::get();

        // 移除目标
        sys.remove_target(bucket, arn_str).await.map_err(|e| {
            error!("Failed to remove target: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to remove target".to_string())
        })?;

        // 更新存储桶元数据
        let targets = sys.list_bucket_targets(bucket).await.map_err(|e| {
            error!("Failed to list bucket targets: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to list bucket targets".to_string())
        })?;

        let json_targets = serde_json::to_vec(&targets).map_err(|e| {
            error!("Serialization error: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, "Failed to serialize targets".to_string())
        })?;

        metadata_sys::update(bucket, BUCKET_TARGETS_FILE, json_targets)
            .await
            .map_err(|e| {
                error!("Failed to update bucket targets: {}", e);
                S3Error::with_message(S3ErrorCode::InternalError, format!("Failed to update bucket targets: {e}"))
            })?;

        Ok(S3Response::new((StatusCode::NO_CONTENT, Body::from("".to_string()))))
    }
}

/// 实时数据收集函数
async fn collect_realtime_data_usage(
    info: &mut rustfs_common::data_usage::DataUsageInfo,
    store: Arc<rustfs_ecstore::store::ECStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 获取存储桶列表并收集基本统计信息
    let buckets = store.list_bucket(&BucketOptions::default()).await?;

    info.buckets_count = buckets.len() as u64;
    info.last_update = Some(std::time::SystemTime::now());
    info.buckets_usage.clear();
    info.bucket_sizes.clear();
    info.disk_usage_status.clear();
    info.objects_total_count = 0;
    info.objects_total_size = 0;
    info.versions_total_count = 0;
    info.delete_markers_total_count = 0;

    let mut total_objects = 0u64;
    let mut total_versions = 0u64;
    let mut total_size = 0u64;
    let mut total_delete_markers = 0u64;

    // 为每个存储桶尝试获取对象计数
    for bucket_info in buckets {
        let bucket_name = &bucket_info.name;

        // 跳过系统存储桶
        if bucket_name.starts_with('.') {
            continue;
        }

        match compute_bucket_usage(store.clone(), bucket_name).await {
            Ok(bucket_usage) => {
                total_objects = total_objects.saturating_add(bucket_usage.objects_count);
                total_versions = total_versions.saturating_add(bucket_usage.versions_count);
                total_size = total_size.saturating_add(bucket_usage.size);
                total_delete_markers = total_delete_markers.saturating_add(bucket_usage.delete_markers_count);

                info.buckets_usage.insert(bucket_name.clone(), bucket_usage.clone());
                info.bucket_sizes.insert(bucket_name.clone(), bucket_usage.size);
            }
            Err(e) => {
                warn!("Failed to compute bucket usage for {}: {}", bucket_name, e);
            }
        }
    }

    info.objects_total_count = total_objects;
    info.objects_total_size = total_size;
    info.versions_total_count = total_versions;
    info.delete_markers_total_count = total_delete_markers;

    Ok(())
}

/// 性能分析处理器
pub struct ProfileHandler {}

#[async_trait::async_trait]
impl Operation for ProfileHandler {
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        #[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
        {
            // 不支持的平台返回错误
            let requested_url = req.uri.to_string();
            let target_os = std::env::consts::OS;
            let target_arch = std::env::consts::ARCH;
            let target_env = option_env!("CARGO_CFG_TARGET_ENV").unwrap_or("unknown");
            let msg = format!(
                "CPU profiling is not supported on this platform. target_os={target_os}, target_env={target_env}, target_arch={target_arch}, requested_url={requested_url}"
            );
            return Ok(S3Response::new((StatusCode::NOT_IMPLEMENTED, Body::from(msg))));
        }

        #[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
        {
            use rustfs_config::{DEFAULT_CPU_FREQ, ENV_CPU_FREQ};
            use rustfs_utils::get_env_usize;

            let queries = extract_query_params(&req.uri);
            let seconds = queries.get("seconds").and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);
            let format = queries.get("format").cloned().unwrap_or_else(|| "protobuf".to_string());

            if seconds > 300 {
                return Ok(S3Response::new((
                    StatusCode::BAD_REQUEST,
                    Body::from("Profile duration cannot exceed 300 seconds".to_string()),
                )));
            }

            match format.as_str() {
                "protobuf" | "pb" => match crate::profiling::dump_cpu_pprof_for(std::time::Duration::from_secs(seconds)).await {
                    Ok(path) => match tokio::fs::read(&path).await {
                        Ok(bytes) => {
                            let mut headers = HeaderMap::new();
                            headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                            Ok(S3Response::with_headers((StatusCode::OK, Body::from(bytes)), headers))
                        }
                        Err(e) => Ok(S3Response::new((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Body::from(format!("Failed to read profile file: {e}")),
                        ))),
                    },
                    Err(e) => Ok(S3Response::new((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Body::from(format!("Failed to collect CPU profile: {e}")),
                    ))),
                },
                "flamegraph" | "svg" => {
                    // 火焰图格式
                    let freq = get_env_usize(ENV_CPU_FREQ, DEFAULT_CPU_FREQ) as i32;
                    let guard = match pprof::ProfilerGuard::new(freq) {
                        Ok(g) => g,
                        Err(e) => {
                            return Ok(S3Response::new((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Body::from(format!("Failed to create profiler: {e}")),
                            )));
                        }
                    };

                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;

                    let report = match guard.report().build() {
                        Ok(r) => r,
                        Err(e) => {
                            return Ok(S3Response::new((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Body::from(format!("Failed to build profile report: {e}")),
                            )));
                        }
                    };

                    let mut flamegraph_buf = Vec::new();
                    if let Err(e) = report.flamegraph(&mut flamegraph_buf) {
                        return Ok(S3Response::new((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Body::from(format!("Failed to generate flamegraph: {e}")),
                        )));
                    }

                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_TYPE, "image/svg+xml".parse().unwrap());
                    Ok(S3Response::with_headers((StatusCode::OK, Body::from(flamegraph_buf)), headers))
                }
                _ => Ok(S3Response::new((
                    StatusCode::BAD_REQUEST,
                    Body::from("Unsupported format. Use 'protobuf' or 'flamegraph'".to_string()),
                ))),
            }
        }
    }
}

/// 性能分析状态处理器
pub struct ProfileStatusHandler {}

#[async_trait::async_trait]
impl Operation for ProfileStatusHandler {
    async fn call(&self, _req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        use std::collections::HashMap;

        #[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
        let message = format!("CPU profiling is not supported on {} platform", std::env::consts::OS);
        #[cfg(not(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")))]
        let status = HashMap::from([
            ("enabled", "false"),
            ("status", "not_supported"),
            ("platform", std::env::consts::OS),
            ("message", message.as_str()),
        ]);

        #[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
        let status = {
            use rustfs_config::{DEFAULT_ENABLE_PROFILING, ENV_ENABLE_PROFILING};
            use rustfs_utils::get_env_bool;

            let enabled = get_env_bool(ENV_ENABLE_PROFILING, DEFAULT_ENABLE_PROFILING);
            if enabled {
                HashMap::from([
                    ("enabled", "true"),
                    ("status", "running"),
                    ("supported_formats", "protobuf, flamegraph"),
                    ("max_duration_seconds", "300"),
                    ("endpoint", "/rustfs/admin/debug/pprof/profile"),
                ])
            } else {
                HashMap::from([
                    ("enabled", "false"),
                    ("status", "disabled"),
                    ("message", "Set RUSTFS_ENABLE_PROFILING=true to enable profiling"),
                ])
            }
        };

        match serde_json::to_string(&status) {
            Ok(json) => {
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
                Ok(S3Response::with_headers((StatusCode::OK, Body::from(json)), headers))
            }
            Err(e) => {
                error!("Failed to serialize status: {}", e);
                Ok(S3Response::new((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from("Failed to serialize status".to_string()),
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_common::heal_channel::HealOpts;
    use rustfs_madmin::BackendInfo;
    use rustfs_policy::policy::BucketPolicy;
    use serde_json::json;

    #[test]
    fn test_account_info_structure() {
        // 测试AccountInfo结构体创建和序列化
        let account_info = AccountInfo {
            account_name: "test-account".to_string(),
            server: BackendInfo::default(),
            policy: BucketPolicy::default(),
        };

        assert_eq!(account_info.account_name, "test-account");

        // 测试JSON序列化（PascalCase重命名）
        let json_str = serde_json::to_string(&account_info).unwrap();
        assert!(json_str.contains("AccountName"));
    }

    #[test]
    fn test_account_info_default() {
        // 测试AccountInfo可以使用默认值创建
        let default_info = AccountInfo::default();

        assert!(default_info.account_name.is_empty());
    }

    #[test]
    fn test_handler_struct_creation() {
        // 测试处理器结构体可以被创建
        let _account_handler = AccountInfoHandler {};
        let _service_handler = ServiceHandle {};
        let _server_info_handler = ServerInfoHandler {};
        let _inspect_data_handler = InspectDataHandler {};
        let _storage_info_handler = StorageInfoHandler {};
        let _data_usage_handler = DataUsageInfoHandler {};
        let _metrics_handler = MetricsHandler {};
        let _heal_handler = HealHandler {};
        let _bg_heal_handler = BackgroundHealStatusHandler {};
        let _replication_metrics_handler = GetReplicationMetricsHandler {};
        let _set_remote_target_handler = SetRemoteTargetHandler {};
        let _list_remote_target_handler = ListRemoteTargetHandler {};
        let _remove_remote_target_handler = RemoveRemoteTargetHandler {};

        // 只需验证它们可以被创建而不panic
        // 如果到达此点而没有panic，测试通过
    }

    #[test]
    fn test_heal_opts_serialization() {
        // 测试HealOpts可以被正确反序列化
        let heal_opts_json = json!({
            "recursive": true,
            "dryRun": false,
            "remove": true,
            "recreate": false,
            "scanMode": 2,
            "updateParity": true,
            "nolock": false
        });

        let json_str = serde_json::to_string(&heal_opts_json).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["recursive"], true);
        assert_eq!(parsed["scanMode"], 2);
    }

    #[test]
    fn test_heal_opts_url_encoding() {
        // 测试HealOpts的URL编码/解码
        let opts = HealOpts {
            recursive: true,
            dry_run: false,
            remove: true,
            recreate: false,
            scan_mode: rustfs_common::heal_channel::HealScanMode::Normal,
            update_parity: false,
            no_lock: true,
            pool: Some(1),
            set: Some(0),
        };

        let encoded = serde_urlencoded::to_string(opts).unwrap();
        assert!(encoded.contains("recursive=true"));
        assert!(encoded.contains("remove=true"));

        // 测试往返转换
        let decoded: HealOpts = serde_urlencoded::from_str(&encoded).unwrap();
        assert_eq!(decoded.recursive, opts.recursive);
        assert_eq!(decoded.scan_mode, opts.scan_mode);
    }

    #[ignore] // FIXME: 在GitHub Actions中失败 - 保留原始测试
    #[test]
    fn test_decode() {
        let b = b"{\"recursive\":false,\"dryRun\":false,\"remove\":false,\"recreate\":false,\"scanMode\":1,\"updateParity\":false,\"nolock\":false}";
        let s: HealOpts = serde_urlencoded::from_bytes(b).unwrap();
        debug!("Parsed HealOpts: {:?}", s);
    }

    // 注意：测试实际的异步处理器实现需要：
    // 1. 具有适当头部、URI和凭证的S3Request设置
    // 2. 全局对象存储初始化
    // 3. IAM系统初始化
    // 4. 模拟或真实的后端服务
    // 5. 身份验证和授权设置
    //
    // 这些更适合使用适当的测试基础设施进行集成测试。
    // 当前的测试专注于可以在没有复杂依赖的情况下单独测试的数据结构和基本功能。
}