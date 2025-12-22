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

// 导入内部模块
use crate::{
    admin::{
        auth::validate_admin_request,  // 管理员请求权限验证函数
        router::Operation,             // 管理员操作路由trait
        utils::has_space_be            // 辅助函数：检查字符串是否包含空格
    },
    auth::{
        check_key_valid,   // 验证访问密钥有效性
        constant_time_eq,  // 常量时间比较（防止时序攻击）
        get_session_token  // 获取会话令牌
    },
};
// HTTP协议相关：请求头、状态码
use http::{HeaderMap, StatusCode};
// 路由参数解析工具
use matchit::Params;
// 配置常量：管理员请求体最大尺寸限制
use rustfs_config::MAX_ADMIN_REQUEST_BODY_SIZE;
// 全局凭证获取函数
use rustfs_ecstore::global::get_global_action_cred;
// IAM错误处理辅助函数：检查是否为"用户不存在"/"组不存在"错误
use rustfs_iam::error::{is_err_no_such_group, is_err_no_such_user};
// IAM组操作结构体：添加/移除组成员
use rustfs_madmin::GroupAddRemove;
// 权限策略相关：操作权限枚举
use rustfs_policy::policy::action::{Action, AdminAction};
// S3协议相关依赖
use s3s::{
    Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result,  // S3请求/响应/错误类型
    header::{CONTENT_LENGTH, CONTENT_TYPE},                        // HTTP头常量
    s3_error,                                                     // S3错误构造函数
};
// 反序列化trait
use serde::Deserialize;
// URL编码数据反序列化
use serde_urlencoded::from_bytes;
// 日志警告级别
use tracing::warn;

/// IAM组查询参数结构体
/// 用于解析查询IAM组相关接口的URL查询参数
#[derive(Debug, Deserialize, Default)]
pub struct GroupQuery {
    /// 组名称
    pub group: String,
    /// 组状态（启用/禁用），可选参数
    pub status: Option<String>,
}

/// 列出所有IAM组的操作结构体
/// 实现Operation trait，处理查询所有IAM组的请求
pub struct ListGroups {}

#[async_trait::async_trait]
impl Operation for ListGroups {
    /// 处理列出所有IAM组的请求
    /// 参数:
    /// - req: S3请求对象，包含凭证、请求头、URI等信息
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含所有IAM组信息的JSON数据
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("开始处理ListGroups请求");

        // 1. 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 验证管理员权限（需要列出组的权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::ListGroupsAdminAction)],
        )
        .await?;

        // 4. 获取IAM存储层实例
        let Ok(iam_store) = rustfs_iam::get() else { 
            return Err(s3_error!(InternalError, "IAM模块未初始化"));
        };

        // 5. 加载并列出所有IAM组
        let groups = iam_store.list_groups_load().await.map_err(|e| {
            warn!("列出IAM组失败，错误: {:?}", e);
            S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
        })?;

        // 6. 将组列表序列化为JSON响应体
        let body = serde_json::to_vec(&groups).map_err(|e| {
            s3_error!(InternalError, "序列化响应体失败，错误: {:?}", e)
        })?;

        // 7. 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());  // 设置响应内容类型为JSON

        // 8. 返回成功响应（200 OK）
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(body)), header))
    }
}

/// 获取指定IAM组详情的操作结构体
/// 实现Operation trait，处理查询单个IAM组信息的请求
pub struct GetGroup {}

#[async_trait::async_trait]
impl Operation for GetGroup {
    /// 处理获取指定IAM组详情的请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，包含指定IAM组的详细信息
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("开始处理GetGroup请求");

        // 1. 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 验证管理员权限（需要获取组详情的权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::GetGroupAdminAction)],
        )
        .await?;

        // 4. 解析URL查询参数（获取要查询的组名称）
        let query = {
            if let Some(query) = req.uri.query() {
                // 将URL编码的查询参数反序列化为GroupQuery结构体
                let input: GroupQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                // 无查询参数时使用默认值
                GroupQuery::default()
            }
        };

        // 5. 获取IAM存储层实例
        let Ok(iam_store) = rustfs_iam::get() else { 
            return Err(s3_error!(InternalError, "IAM模块未初始化"));
        };

        // 6. 获取指定组的详细描述信息
        let g = iam_store.get_group_description(&query.group).await.map_err(|e| {
            warn!("获取IAM组信息失败，错误: {:?}", e);
            S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
        })?;

        // 7. 将组信息序列化为JSON响应体
        let body = serde_json::to_vec(&g).map_err(|e| {
            s3_error!(InternalError, "序列化响应体失败，错误: {:?}", e)
        })?;

        // 8. 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        // 9. 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(body)), header))
    }
}

/// 设置IAM组状态的操作结构体
/// 实现Operation trait，处理启用/禁用IAM组的请求
pub struct SetGroupStatus {}

#[async_trait::async_trait]
impl Operation for SetGroupStatus {
    /// 处理设置IAM组状态（启用/禁用）的请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，成功返回200 OK
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("开始处理SetGroupStatus请求");

        // 1. 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 验证管理员权限（需要启用/禁用组的权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::EnableGroupAdminAction)],
        )
        .await?;

        // 4. 解析URL查询参数（组名称和目标状态）
        let query = {
            if let Some(query) = req.uri.query() {
                let input: GroupQuery =
                    from_bytes(query.as_bytes()).map_err(|_e| s3_error!(InvalidArgument, "解析查询参数失败"))?;
                input
            } else {
                GroupQuery::default()
            }
        };

        // 5. 验证组名称是否为空
        if query.group.is_empty() {
            return Err(s3_error!(InvalidArgument, "组名称为必填项"));
        }

        // 6. 获取IAM存储层实例
        let Ok(iam_store) = rustfs_iam::get() else { 
            return Err(s3_error!(InternalError, "IAM模块未初始化"));
        };

        // 7. 处理状态设置逻辑
        if let Some(status) = query.status {
            match status.as_str() {
                // 启用组
                "enabled" => {
                    iam_store.set_group_status(&query.group, true).await.map_err(|e| {
                        warn!("启用IAM组失败，错误: {:?}", e);
                        S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
                    })?;
                }
                // 禁用组
                "disabled" => {
                    iam_store.set_group_status(&query.group, false).await.map_err(|e| {
                        warn!("禁用IAM组失败，错误: {:?}", e);
                        S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
                    })?;
                }
                // 无效的状态值
                _ => {
                    return Err(s3_error!(InvalidArgument, "无效的状态值（仅支持enabled/disabled）"));
                }
            }
        } else {
            // 状态参数为空
            return Err(s3_error!(InvalidArgument, "状态为必填项"));
        }

        // 8. 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());  // 响应体为空，长度为0

        // 9. 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 更新IAM组成员的操作结构体
/// 实现Operation trait，处理添加/移除IAM组成员的请求
pub struct UpdateGroupMembers {}

#[async_trait::async_trait]
impl Operation for UpdateGroupMembers {
    /// 处理更新IAM组成员（添加/移除）的请求
    /// 参数:
    /// - req: S3请求对象，请求体包含要添加/移除的成员信息
    /// - _params: 路由参数（此处未使用）
    /// 返回: S3响应，成功返回200 OK
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        warn!("开始处理UpdateGroupMembers请求");

        // 1. 验证请求凭证是否存在
        let Some(input_cred) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "获取凭证失败"));
        };

        // 2. 验证访问密钥有效性
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 验证管理员权限（需要添加用户到组的权限）
        validate_admin_request(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::AdminAction(AdminAction::AddUserToGroupAdminAction)],
        )
        .await?;

        // 4. 读取并限制请求体大小（防止过大的请求体）
        let mut input = req.input;
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("读取请求体失败，错误: {:?}", e);
                return Err(s3_error!(InvalidRequest, "组配置请求体过大或读取失败"));
            }
        };

        // 5. 将请求体反序列化为GroupAddRemove结构体（包含组名、成员列表、操作类型）
        let args: GroupAddRemove = serde_json::from_slice(&body)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("反序列化请求体错误: {e}")))?;

        warn!("UpdateGroupMembers请求参数: {:?}", args);

        // 6. 获取IAM存储层实例
        let Ok(iam_store) = rustfs_iam::get() else { 
            return Err(s3_error!(InternalError, "IAM模块未初始化"));
        };

        // 7. 验证要操作的成员合法性
        for member in args.members.iter() {
            // 7.1 检查是否为临时用户（临时用户不允许添加到组）
            match iam_store.is_temp_user(member).await {
                Ok((is_temp, _)) => {
                    if is_temp {
                        return Err(S3Error::with_message(
                            S3ErrorCode::MethodNotAllowed,
                            format!("不允许添加临时用户 {member} 到组"),
                        ));
                    }

                    // 7.2 检查是否为根用户（根用户不允许添加到组）
                    get_global_action_cred()
                        .map(|cred| {
                            if constant_time_eq(&cred.access_key, member) {
                                return Err(S3Error::with_message(
                                    S3ErrorCode::MethodNotAllowed,
                                    format!("不允许添加根用户 {member} 到组"),
                                ));
                            }
                            Ok(())
                        })
                        .unwrap_or_else(|| {
                            Err(S3Error::with_message(S3ErrorCode::InternalError, "获取全局凭证失败".to_string()))
                        })?;
                }
                // 7.3 忽略"用户不存在"错误（移除不存在的用户时允许），其他错误返回
                Err(e) => {
                    if !is_err_no_such_user(&e) {
                        return Err(S3Error::with_message(S3ErrorCode::InternalError, e.to_string()));
                    }
                }
            }
        }

        // 8. 执行成员更新操作
        if args.is_remove {
            // 8.1 移除组成员
            warn!("执行移除组成员操作");
            iam_store
                .remove_users_from_group(&args.group, args.members)
                .await
                .map_err(|e| {
                    warn!("移除组成员失败，错误: {:?}", e);
                    S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
                })?;
        } else {
            // 8.2 添加组成员
            warn!("执行添加组成员操作");

            // 验证组是否存在（组名包含空格且不存在时返回错误）
            if let Err(err) = iam_store.get_group_description(&args.group).await {
                if is_err_no_such_group(&err) && has_space_be(&args.group) {
                    return Err(s3_error!(InvalidArgument, "组不存在"));
                }
            }

            // 执行添加用户到组的操作
            iam_store.add_users_to_group(&args.group, args.members).await.map_err(|e| {
                warn!("添加组成员失败，错误: {:?}", e);
                S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
            })?;
        }

        // 9. 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());

        // 10. 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}