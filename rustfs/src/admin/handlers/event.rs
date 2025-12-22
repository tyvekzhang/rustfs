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

// 导入管理员路由操作相关模块
use crate::admin::router::Operation;
// 导入认证相关函数：密钥验证、会话令牌获取
use crate::auth::{check_key_valid, get_session_token};
// HTTP协议相关：头信息、状态码
use http::{HeaderMap, StatusCode};
// 路由参数解析工具
use matchit::Params;
// 通知配置常量：MQTT/WEBHOOK通知子系统标识
use rustfs_config::notify::{NOTIFY_MQTT_SUB_SYS, NOTIFY_WEBHOOK_SUB_SYS};
// 配置相关常量：启用状态键、启用状态枚举、管理员请求体最大尺寸
use rustfs_config::{ENABLE_KEY, EnableState, MAX_ADMIN_REQUEST_BODY_SIZE};
// MQTT代理可用性检查函数
use rustfs_targets::check_mqtt_broker_available;
// HTTP头常量：内容长度
use s3s::header::CONTENT_LENGTH;
// S3协议相关：请求体、错误类型、错误码、请求/响应/结果类型、内容类型头、错误构造函数
use s3s::{Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, header::CONTENT_TYPE, s3_error};
// 序列化/反序列化trait
use serde::{Deserialize, Serialize};
// 异步编程相关：Future trait
use std::future::Future;
// IO错误相关类型
use std::io::{Error, ErrorKind};
// 网络地址类型
use std::net::SocketAddr;
// 路径处理
use std::path::Path;
// DNS解析函数
use tokio::net::lookup_host;
// 时间相关：时长、睡眠函数
use tokio::time::{Duration, sleep};
// 日志相关：追踪span、不同级别日志
use tracing::{Span, debug, error, info, warn};
// URL解析工具
use url::Url;

/// 键值对结构体
/// 用于接收通知目标配置的键值参数
#[derive(Debug, Deserialize)]
pub struct KeyValue {
    /// 配置键名
    pub key: String,
    /// 配置值
    pub value: String,
}

/// 通知目标请求体结构体
/// 用于解析创建/更新通知目标的请求体
#[derive(Debug, Deserialize)]
pub struct NotificationTargetBody {
    /// 配置键值对列表
    pub key_values: Vec<KeyValue>,
}

/// 通知端点响应结构体
/// 用于构建ListNotificationTargets接口的响应数据
#[derive(Serialize, Debug)]
struct NotificationEndpoint {
    /// 账户ID
    account_id: String,
    /// 服务名称（通知目标名称）
    service: String,
    /// 状态（固定为online）
    status: String,
}

/// 通知端点列表响应结构体
/// 封装多个通知端点的响应数据
#[derive(Serialize, Debug)]
struct NotificationEndpointsResponse {
    /// 通知端点列表
    notification_endpoints: Vec<NotificationEndpoint>,
}

/// 带退避策略的重试函数
/// 对指定异步操作进行多次重试，每次重试延迟翻倍
/// 参数:
/// - operation: 待重试的异步操作函数
/// - max_attempts: 最大重试次数
/// - base_delay: 初始重试延迟
/// 返回: 操作成功则返回结果，失败则返回最后一次的错误
async fn retry_with_backoff<F, Fut, T>(mut operation: F, max_attempts: usize, base_delay: Duration) -> Result<T, Error>
where
    F: FnMut() -> Fut,          // 操作函数，返回Future
    Fut: Future<Output = Result<T, Error>>, // 异步操作的返回类型
{
    // 断言最大重试次数必须大于0
    assert!(max_attempts > 0, "max_attempts must be greater than 0");
    let mut attempts = 0;        // 当前重试次数
    let mut delay = base_delay;  // 当前重试延迟
    let mut last_err = None;     // 最后一次错误

    // 循环重试直到达到最大次数
    while attempts < max_attempts {
        match operation().await {
            // 操作成功，直接返回结果
            Ok(result) => return Ok(result),
            // 操作失败，记录错误并准备重试
            Err(e) => {
                last_err = Some(e);
                attempts += 1;
                // 未达到最大重试次数时，等待后重试
                if attempts < max_attempts {
                    warn!(
                        "重试尝试 {}/{} 失败: {}. 将在 {:?} 后重试",
                        attempts,
                        max_attempts,
                        last_err.as_ref().unwrap(),
                        delay
                    );
                    sleep(delay).await;
                    // 延迟时间翻倍（防止重试过于频繁）
                    delay = delay.saturating_mul(2);
                }
            }
        }
    }
    // 所有重试失败，返回最后一次错误（无错误则返回通用错误）
    Err(last_err.unwrap_or_else(|| Error::other("retry_with_backoff: unknown error")))
}

/// 带重试的文件元数据获取函数
/// 对指定路径执行3次元数据获取操作，初始延迟100ms
/// 参数: path - 要检查的文件路径
/// 返回: 成功返回Ok(())，失败返回错误
async fn retry_metadata(path: &str) -> Result<(), Error> {
    retry_with_backoff(
        || async { tokio::fs::metadata(path).await.map(|_| ()) }, // 实际操作：获取元数据并忽略结果
        3,                                                         // 最大重试次数
        Duration::from_millis(100)                                // 初始延迟
    ).await
}

/// 验证队列目录有效性
/// 检查队列目录是否为绝对路径，且具备访问权限
/// 参数: queue_dir - 队列目录路径
/// 返回: 成功返回Ok(())，失败返回S3错误
async fn validate_queue_dir(queue_dir: &str) -> S3Result<()> {
    // 目录路径非空时才验证
    if !queue_dir.is_empty() {
        // 检查是否为绝对路径
        if !Path::new(queue_dir).is_absolute() {
            return Err(s3_error!(InvalidArgument, "queue_dir必须是绝对路径"));
        }

        // 带重试获取目录元数据
        if let Err(e) = retry_metadata(queue_dir).await {
            // 根据错误类型返回对应S3错误
            return match e.kind() {
                ErrorKind::NotFound => Err(s3_error!(InvalidArgument, "queue_dir不存在")),
                ErrorKind::PermissionDenied => Err(s3_error!(InvalidArgument, "queue_dir存在但权限不足")),
                _ => Err(s3_error!(InvalidArgument, "访问queue_dir失败: {}", e)),
            };
        }
    }

    Ok(())
}

/// 验证证书和密钥对的有效性
/// 确保证书和密钥要么都提供，要么都不提供
/// 参数:
/// - cert: 客户端证书路径（可选）
/// - key: 客户端密钥路径（可选）
/// 返回: 成功返回Ok(())，失败返回S3错误
fn validate_cert_key_pair(cert: &Option<String>, key: &Option<String>) -> S3Result<()> {
    // 证书和密钥必须成对出现
    if cert.is_some() != key.is_some() {
        return Err(s3_error!(InvalidArgument, "client_cert和client_key必须成对指定"));
    }
    Ok(())
}

/// 通知目标设置操作结构体
/// 实现Operation trait，处理创建/更新通知目标的请求
/// 功能：Set (create or update) a notification target
pub struct NotificationTarget {}

#[async_trait::async_trait]
impl Operation for NotificationTarget {
    /// 处理通知目标设置请求
    /// 参数:
    /// - req: S3请求对象，包含请求头、请求体、凭证等
    /// - params: 路由参数，包含target_type和target_name
    /// 返回: S3响应，成功返回200状态码
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 获取当前追踪span并进入
        let span = Span::current();
        let _enter = span.enter();
        
        // 1. 解析路由参数（目标类型、目标名称）
        let (target_type, target_name) = extract_target_params(&params)?;

        // 2. 权限验证
        // 检查请求凭证是否存在
        let Some(input_cred) = &req.credentials else {
            return Err(s3_error!(InvalidRequest, "未找到凭证信息"));
        };
        // 验证访问密钥有效性
        let (_cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 获取通知系统实例
        let Some(ns) = rustfs_notify::notification_system() else {
            return Err(s3_error!(InternalError, "通知系统未初始化"));
        };

        // 4. 解析请求体（键值对列表）
        let mut input = req.input;
        // 读取请求体，限制最大尺寸
        let body = input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await.map_err(|e| {
            warn!("读取请求体失败: {:?}", e);
            s3_error!(InvalidRequest, "读取请求体失败")
        })?;

        // 4.1 获取当前目标类型允许的配置键集合
        let allowed_keys: std::collections::HashSet<&str> = match target_type {
            // WEBHOOK类型：使用WEBHOOK允许的键集合
            NOTIFY_WEBHOOK_SUB_SYS => rustfs_config::notify::NOTIFY_WEBHOOK_KEYS.iter().cloned().collect(),
            // MQTT类型：使用MQTT允许的键集合
            NOTIFY_MQTT_SUB_SYS => rustfs_config::notify::NOTIFY_MQTT_KEYS.iter().cloned().collect(),
            // 其他类型：理论上不会到达（extract_target_params已验证）
            _ => unreachable!(),
        };

        // 将请求体JSON反序列化为结构体
        let notification_body: NotificationTargetBody = serde_json::from_slice(&body)
            .map_err(|e| s3_error!(InvalidArgument, "目标配置JSON格式无效: {}", e))?;

        // 4.2 过滤验证配置键，并提取关键配置值
        let mut kvs_vec = Vec::new();          // 最终存储的键值对列表
        let mut endpoint_val = None;           // 端点地址（WEBHOOK）/MQTT代理地址
        let mut queue_dir_val = None;          // 队列目录
        let mut client_cert_val = None;        // 客户端证书路径
        let mut client_key_val = None;         // 客户端密钥路径
        let mut qos_val = None;                // MQTT QoS值
        let mut topic_val = String::new();     // MQTT主题

        // 遍历所有配置键值对
        for kv in notification_body.key_values.iter() {
            // 检查键是否在允许的范围内
            if !allowed_keys.contains(kv.key.as_str()) {
                return Err(s3_error!(
                    InvalidArgument,
                    "键'{}'不允许用于目标类型'{}'",
                    kv.key,
                    target_type
                ));
            }

            // 提取关键配置值
            if kv.key == "endpoint" {
                endpoint_val = Some(kv.value.clone());
            }

            // MQTT类型特殊处理
            if target_type == NOTIFY_MQTT_SUB_SYS {
                // MQTT代理地址对应键
                if kv.key == rustfs_config::MQTT_BROKER {
                    endpoint_val = Some(kv.value.clone());
                }
                // MQTT主题对应键
                if kv.key == rustfs_config::MQTT_TOPIC {
                    topic_val = kv.value.clone();
                }
            }

            // 提取队列目录
            if kv.key == "queue_dir" {
                queue_dir_val = Some(kv.value.clone());
            }
            // 提取客户端证书
            if kv.key == "client_cert" {
                client_cert_val = Some(kv.value.clone());
            }
            // 提取客户端密钥
            if kv.key == "client_key" {
                client_key_val = Some(kv.value.clone());
            }
            // 提取MQTT QoS值
            if kv.key == "qos" {
                qos_val = Some(kv.value.clone());
            }

            // 将键值对转换为存储层需要的KV结构体
            kvs_vec.push(rustfs_ecstore::config::KV {
                key: kv.key.clone(),
                value: kv.value.clone(),
                hidden_if_empty: false, // 空值不隐藏
            });
        }

        // 4.3 WEBHOOK类型目标特殊验证
        if target_type == NOTIFY_WEBHOOK_SUB_SYS {
            // 验证endpoint必须存在
            let endpoint = endpoint_val
                .clone()
                .ok_or_else(|| s3_error!(InvalidArgument, "endpoint是必填项"))?;
            // 解析endpoint为URL
            let url = Url::parse(&endpoint).map_err(|e| s3_error!(InvalidArgument, "endpoint URL无效: {}", e))?;
            // 验证URL包含主机
            let host = url
                .host_str()
                .ok_or_else(|| s3_error!(InvalidArgument, "endpoint缺少主机名"))?;
            // 验证URL包含端口
            let port = url
                .port_or_known_default()
                .ok_or_else(|| s3_error!(InvalidArgument, "endpoint缺少端口"))?;
            let addr = format!("{host}:{port}");
            
            // 验证地址有效性：先尝试解析为IP:端口，失败则尝试DNS解析
            if addr.parse::<SocketAddr>().is_err() {
                if lookup_host(&addr).await.is_err() {
                    return Err(s3_error!(InvalidArgument, "endpoint地址无效或无法解析"));
                }
            }

            // 验证队列目录（如果指定）
            if let Some(queue_dir) = queue_dir_val.clone() {
                validate_queue_dir(&queue_dir).await?;
            }

            // 验证证书密钥对
            validate_cert_key_pair(&client_cert_val, &client_key_val)?;
        }

        // 4.4 MQTT类型目标特殊验证
        if target_type == NOTIFY_MQTT_SUB_SYS {
            // 验证代理地址必须存在
            let endpoint = endpoint_val.ok_or_else(|| s3_error!(InvalidArgument, "broker endpoint是必填项"))?;
            // 验证主题必须存在
            if topic_val.is_empty() {
                return Err(s3_error!(InvalidArgument, "topic是必填项"));
            }
            
            // 检查MQTT代理可用性
            if let Err(e) = check_mqtt_broker_available(&endpoint, &topic_val).await {
                return Err(s3_error!(InvalidArgument, "MQTT代理不可用: {}", e));
            }

            // 验证队列目录（如果指定）
            if let Some(queue_dir) = queue_dir_val {
                validate_queue_dir(&queue_dir).await?;
                
                // 验证QoS值（指定队列目录时QoS必须为1或2）
                if let Some(qos) = qos_val {
                    match qos.parse::<u8>() {
                        // QoS为1或2：合法
                        Ok(qos_int) if qos_int == 1 || qos_int == 2 => {}
                        // QoS为0：指定队列目录时不允许
                        Ok(0) => {
                            return Err(s3_error!(InvalidArgument, "设置queue_dir时qos必须为1或2"));
                        }
                        // 其他值：非法
                        _ => {
                            return Err(s3_error!(InvalidArgument, "qos必须是0、1或2的整数"));
                        }
                    }
                }
            }
        }

        // 4.5 添加启用状态配置项
        kvs_vec.push(rustfs_ecstore::config::KV {
            key: ENABLE_KEY.to_string(),       // 启用状态键名
            value: EnableState::On.to_string(),// 启用状态值
            hidden_if_empty: false,
        });

        // 转换为存储层需要的KVS结构体
        let kvs = rustfs_ecstore::config::KVS(kvs_vec);

        // 5. 调用通知系统设置目标配置
        info!("设置目标配置，类型: '{}', 名称: '{}'", target_type, target_name);
        ns.set_target_config(target_type, target_name, kvs).await.map_err(|e| {
            error!("设置目标配置失败: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, format!("设置目标配置失败: {e}"))
        })?;

        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap()); // 内容类型JSON
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());               // 响应体长度0
        // 传递请求ID（如果有）
        if let Some(v) = req.headers.get("x-request-id") {
            header.insert("x-request-id", v.clone());
        }

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 通知目标列表查询操作结构体
/// 实现Operation trait，处理查询所有活跃通知目标的请求
/// 功能：Get a list of notification targets for all activities
pub struct ListNotificationTargets {}

#[async_trait::async_trait]
impl Operation for ListNotificationTargets {
    /// 处理通知目标列表查询请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（未使用）
    /// 返回: S3响应，包含活跃通知目标列表
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let span = Span::current();
        let _enter = span.enter();
        debug!("ListNotificationTargets调用开始，请求参数: {:?}", req.uri.query());

        // 1. 权限验证
        let Some(input_cred) = &req.credentials else {
            return Err(s3_error!(InvalidRequest, "未找到凭证信息"));
        };
        let (_cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 2. 获取通知系统实例
        let Some(ns) = rustfs_notify::notification_system() else {
            return Err(s3_error!(InternalError, "通知系统未初始化"));
        };

        // 3. 获取活跃目标列表
        let active_targets = ns.get_active_targets().await;

        debug!("ListNotificationTargets调用找到 {} 个活跃目标", active_targets.len());
        let mut notification_endpoints = Vec::new();
        // 转换为响应结构体
        for target_id in active_targets.iter() {
            notification_endpoints.push(NotificationEndpoint {
                account_id: target_id.id.clone(),
                service: target_id.name.to_string(),
                status: "online".to_string(),
            });
        }

        // 封装响应数据
        let response = NotificationEndpointsResponse { notification_endpoints };

        // 4. 序列化响应数据并返回
        let data = serde_json::to_vec(&response).map_err(|e| {
            error!("序列化通知目标响应失败: {:?}", response);
            S3Error::with_message(S3ErrorCode::InternalError, format!("序列化目标列表失败: {e}"))
        })?;
        debug!("ListNotificationTargets调用结束，响应数据长度: {}", data.len(),);
        
        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        if let Some(v) = req.headers.get("x-request-id") {
            header.insert("x-request-id", v.clone());
        }

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 通知目标ARN列表查询操作结构体
/// 实现Operation trait，处理查询所有活跃通知目标ARN的请求
/// 功能：Get a list of notification targets ARNs for all activities
pub struct ListTargetsArns {}

#[async_trait::async_trait]
impl Operation for ListTargetsArns {
    /// 处理通知目标ARN列表查询请求
    /// 参数:
    /// - req: S3请求对象
    /// - _params: 路由参数（未使用）
    /// 返回: S3响应，包含活跃通知目标的ARN列表
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let span = Span::current();
        let _enter = span.enter();
        debug!("ListTargetsArns调用开始，请求参数: {:?}", req.uri.query());

        // 1. 权限验证
        let Some(input_cred) = &req.credentials else {
            return Err(s3_error!(InvalidRequest, "未找到凭证信息"));
        };
        let (_cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 2. 获取通知系统实例
        let Some(ns) = rustfs_notify::notification_system() else {
            return Err(s3_error!(InternalError, "通知系统未初始化"));
        };

        // 3. 获取活跃目标列表
        let active_targets = ns.get_active_targets().await;

        debug!("ListTargetsArns调用找到 {} 个活跃目标", active_targets.len());

        // 获取区域信息（生成ARN必需）
        let region = match req.region.clone() {
            Some(region) => region,
            None => return Err(s3_error!(InvalidRequest, "未找到区域信息")),
        };
        let mut data_target_arn_list = Vec::new();

        // 转换目标为ARN格式
        for target_id in active_targets.iter() {
            data_target_arn_list.push(target_id.to_arn(&region).to_string());
        }

        // 4. 序列化响应数据并返回
        let data = serde_json::to_vec(&data_target_arn_list)
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, format!("序列化目标列表失败: {e}")))?;
        debug!("ListTargetsArns调用结束，响应数据长度: {}", data.len(),);
        
        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        if let Some(v) = req.headers.get("x-request-id") {
            header.insert("x-request-id", v.clone());
        }

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::from(data)), header))
    }
}

/// 通知目标删除操作结构体
/// 实现Operation trait，处理删除指定通知目标的请求
/// 功能：Delete a specified notification target
pub struct RemoveNotificationTarget {}

#[async_trait::async_trait]
impl Operation for RemoveNotificationTarget {
    /// 处理通知目标删除请求
    /// 参数:
    /// - req: S3请求对象
    /// - params: 路由参数，包含target_type和target_name
    /// 返回: S3响应，成功返回200状态码
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let span = Span::current();
        let _enter = span.enter();
        
        // 1. 解析路由参数（目标类型、目标名称）
        let (target_type, target_name) = extract_target_params(&params)?;

        // 2. 权限验证
        let Some(input_cred) = &req.credentials else {
            return Err(s3_error!(InvalidRequest, "未找到凭证信息"));
        };
        let (_cred, _owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &input_cred.access_key).await?;

        // 3. 获取通知系统实例
        let Some(ns) = rustfs_notify::notification_system() else {
            return Err(s3_error!(InternalError, "通知系统未初始化"));
        };

        // 4. 调用通知系统删除目标配置
        info!("删除目标配置，类型: '{}', 名称: '{}'", target_type, target_name);
        ns.remove_target_config(target_type, target_name).await.map_err(|e| {
            error!("删除目标配置失败: {}", e);
            S3Error::with_message(S3ErrorCode::InternalError, format!("删除目标配置失败: {e}"))
        })?;

        // 构建响应头
        let mut header = HeaderMap::new();
        header.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        header.insert(CONTENT_LENGTH, "0".parse().unwrap());
        if let Some(v) = req.headers.get("x-request-id") {
            header.insert("x-request-id", v.clone());
        }

        // 返回成功响应
        Ok(S3Response::with_headers((StatusCode::OK, Body::empty()), header))
    }
}

/// 提取路由参数
/// 从Params中获取指定键的参数值，不存在则返回错误
/// 参数:
/// - params: 路由参数对象
/// - key: 要提取的参数键名
/// 返回: 参数值或S3错误
fn extract_param<'a>(params: &'a Params<'_, '_>, key: &str) -> S3Result<&'a str> {
    params
        .get(key)
        .ok_or_else(|| s3_error!(InvalidArgument, "缺少必填参数: '{}'", key))
}

/// 提取通知目标相关参数
/// 验证并提取target_type和target_name参数，同时验证target_type的合法性
/// 参数:
/// - params: 路由参数对象
/// 返回: (目标类型, 目标名称) 或S3错误
fn extract_target_params<'a>(params: &'a Params<'_, '_>) -> S3Result<(&'a str, &'a str)> {
    // 提取目标类型
    let target_type = extract_param(params, "target_type")?;
    // 验证目标类型是否为支持的类型
    if target_type != NOTIFY_WEBHOOK_SUB_SYS && target_type != NOTIFY_MQTT_SUB_SYS {
        return Err(s3_error!(InvalidArgument, "不支持的目标类型: '{}'", target_type));
    }

    // 提取目标名称
    let target_name = extract_param(params, "target_name")?;
    Ok((target_type, target_name))
}