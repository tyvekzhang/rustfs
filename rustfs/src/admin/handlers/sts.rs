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

use crate::{
    admin::router::Operation,  // 导入管理员路由操作 trait
    auth::{check_key_valid, get_session_token},  // 导入密钥验证和会话令牌获取函数
};
use http::StatusCode;  // 导入HTTP状态码
use matchit::Params;  // 导入路由参数解析器
use rustfs_config::MAX_ADMIN_REQUEST_BODY_SIZE;  // 导入管理员请求体最大尺寸配置
use rustfs_ecstore::bucket::utils::serialize;  // 导入序列化工具函数
use rustfs_iam::{manager::get_token_signing_key, sys::SESSION_POLICY_NAME};  // 导入令牌签名密钥和会话策略名称
use rustfs_policy::{auth::get_new_credentials_with_metadata, policy::Policy};  // 导入凭证生成和策略相关
use s3s::{
    Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result,
    dto::{AssumeRoleOutput, Credentials, Timestamp},  // 导入S3协议相关数据结构
    s3_error,  // 导入S3错误构造宏
};
use serde::Deserialize;  // 导入反序列化 trait
use serde_json::Value;  // 导入JSON值类型
use serde_urlencoded::from_bytes;  // 导入URL编码数据解析函数
use std::collections::HashMap;  // 导入哈希映射
use time::{Duration, OffsetDateTime};  // 导入时间处理相关
use tracing::{error, info, warn};  // 导入日志工具

const ASSUME_ROLE_ACTION: &str = "AssumeRole";  // 定义角色假设动作常量
const ASSUME_ROLE_VERSION: &str = "2011-06-15";  // 定义角色假设版本常量

/// 角色假设请求结构体
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct AssumeRoleRequest {
    pub action: String,  // 动作名称
    pub duration_seconds: usize,  // 有效期（秒）
    pub version: String,  // 版本号
    pub role_arn: String,  // 角色ARN
    pub role_session_name: String,  // 角色会话名称
    pub policy: String,  // 策略
    pub external_id: String,  // 外部ID
}

/// 角色假设操作处理器
pub struct AssumeRoleHandle {}

#[async_trait::async_trait]
impl Operation for AssumeRoleHandle {
    /// 处理角色假设请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("处理AssumeRoleHandle请求");

        // 验证请求凭证是否存在
        let Some(user) = req.credentials else { return Err(s3_error!(InvalidRequest, "获取凭证失败")) };

        // 检查会话令牌（不允许使用会话令牌进行角色假设）
        let session_token = get_session_token(&req.uri, &req.headers);
        if session_token.is_some() {
            return Err(s3_error!(InvalidRequest, "AccessDenied1"));
        }

        // 验证访问密钥有效性
        let (cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &user.access_key).await?;

        // 检查权限：不允许临时凭证或服务账户使用STS
        if cred.is_temp() || cred.is_service_account() {
            return Err(s3_error!(InvalidRequest, "AccessDenied"));
        }

        // 读取请求体（限制最大尺寸）
        let mut input = req.input;
        let bytes = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("获取请求体失败, 错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "STS请求体过大或读取失败"));
            }
        };

        // 解析请求体为角色假设请求结构体
        let body: AssumeRoleRequest = from_bytes(&bytes).map_err(|_e| s3_error!(InvalidRequest, "无效的STS请求格式"))?;

        // 验证动作是否支持
        if body.action.as_str() != ASSUME_ROLE_ACTION {
            return Err(s3_error!(InvalidArgument, "不支持的动作"));
        }

        // 验证版本是否支持
        if body.version.as_str() != ASSUME_ROLE_VERSION {
            return Err(s3_error!(InvalidArgument, "不支持的版本"));
        }

        // 初始化声明（从现有凭证复制或创建新的）
        let mut claims = cred.claims.unwrap_or_default();

        // 填充会话策略
        populate_session_policy(&mut claims, &body.policy)?;

        // 确定有效期（默认3600秒）
        let exp = {
            if body.duration_seconds > 0 {
                body.duration_seconds
            } else {
                3600
            }
        };

        // 设置过期时间声明
        claims.insert(
            "exp".to_string(),
            Value::Number(serde_json::Number::from(OffsetDateTime::now_utc().unix_timestamp() + exp as i64)),
        );

        // 设置父用户声明
        claims.insert("parent".to_string(), Value::String(cred.access_key.clone()));

        // 获取IAM存储实例
        let Ok(iam_store) = rustfs_iam::get() else {
            return Err(s3_error!(InvalidRequest, "iam未初始化"));
        };

        // 验证用户策略
        if let Err(_err) = iam_store.policy_db_get(&cred.access_key, &cred.groups).await {
            error!(
                "获取角色假设策略失败, 错误: {:?}, access_key: {:?}, groups: {:?}",
                _err, cred.access_key, cred.groups
            );
            return Err(s3_error!(InvalidArgument, "无效的策略参数"));
        }

        // 获取令牌签名密钥
        let Some(secret) = get_token_signing_key() else {
            return Err(s3_error!(InvalidArgument, "全局活动签名密钥未初始化"));
        };

        info!("角色假设声明: {:?}", &claims);

        // 生成新的临时凭证
        let mut new_cred = get_new_credentials_with_metadata(&claims, &secret)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("生成新凭证失败 {e}")))?;

        // 设置父用户
        new_cred.parent_user = cred.access_key.clone();

        info!("生成的新临时凭证: {:?}", &new_cred);

        // 存储临时用户
        if let Err(_err) = iam_store.set_temp_user(&new_cred.access_key, &new_cred, None).await {
            return Err(s3_error!(InternalError, "设置临时用户失败"));
        }

        // TODO: 全局站点复制系统处理

        // 构建角色假设响应
        let resp = AssumeRoleOutput {
            credentials: Some(Credentials {
                access_key_id: new_cred.access_key,
                expiration: Timestamp::from(
                    new_cred
                        .expiration
                        .unwrap_or(OffsetDateTime::now_utc().saturating_add(Duration::seconds(3600))),
                ),
                secret_access_key: new_cred.secret_key,
                session_token: new_cred.session_token,
            }),
            ..Default::default()
        };

        // 序列化响应
        let output = serialize::<AssumeRoleOutput>(&resp).unwrap();

        Ok(S3Response::new((StatusCode::OK, Body::from(output))))
    }
}

/// 填充会话策略到声明中
pub fn populate_session_policy(claims: &mut HashMap<String, Value>, policy: &str) -> S3Result<()> {
    if !policy.is_empty() {
        // 解析策略配置
        let session_policy = Policy::parse_config(policy.as_bytes())
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("解析策略错误 {e}")))?;
        if session_policy.version.is_empty() {
            return Err(s3_error!(InvalidRequest, "无效的策略"));
        }

        // 序列化策略
        let policy_buf = serde_json::to_vec(&session_policy)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化策略错误 {e}")))?;

        // 检查策略大小（最大2048字节）
        if policy_buf.len() > 2048 {
            return Err(s3_error!(InvalidRequest, "策略过大"));
        }

        // 将策略添加到声明中（Base64URL编码）
        claims.insert(
            SESSION_POLICY_NAME.to_string(),
            Value::String(base64_simd::URL_SAFE_NO_PAD.encode_to_string(&policy_buf)),
        );
    }

    Ok(())
}