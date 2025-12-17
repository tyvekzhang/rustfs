use std::collections::HashMap; // 引入 HashMap，用于存储键值对
use std::sync::Arc; // 引入 Arc (原子引用计数)，用于共享所有权

use http::HeaderMap; // 引入 HeaderMap，用于处理 HTTP 请求头
use rustfs_iam::store::object::ObjectStore; // 引入 ObjectStore，可能是 IAM 系统的存储实现
use rustfs_iam::sys::IamSys; // 引入 IamSys，IAM (身份和访问管理) 系统的核心结构
use rustfs_policy::auth; // 引入 auth 模块，处理认证相关
use rustfs_policy::policy::Args; // 引入 Args，可能是策略评估的参数
use rustfs_policy::policy::action::Action; // 引入 Action，表示要执行的操作
use s3s::S3Result; // 引入 S3Result，S3 服务操作的结果类型
use s3s::s3_error; // 引入 s3_error! 宏，用于构造 S3 错误

use crate::auth::get_condition_values; // 从本地 auth 模块引入 get_condition_values 函数，用于获取条件值

/// 验证管理员请求的权限
///
/// 遍历给定的 actions 列表，只要其中有一个 action 被允许，则验证成功。
///
/// # 参数
/// * `headers`: HTTP 请求头
/// * `cred`: 认证凭证 (Credentials)
/// * `is_owner`: 是否是资源所有者
/// * `deny_only`: 是否只评估 Deny 策略 (即只检查是否有显式拒绝)
/// * `actions`: 可能的操作列表
///
/// # 返回
/// S3Result<()>，成功则返回 Ok(())，失败则返回 S3 错误 (AccessDenied)
pub async fn validate_admin_request(
    headers: &HeaderMap, // HTTP 请求头
    cred: &auth::Credentials, // 认证凭证
    is_owner: bool, // 是否是所有者
    deny_only: bool, // 是否只检查 Deny 策略
    actions: Vec<Action>, // 可能的操作列表
) -> S3Result<()> {
    // 尝试获取 IAM 存储实例
    let Ok(iam_store) = rustfs_iam::get() else {
        // 如果 IAM 存储未初始化，返回 InternalError
        return Err(s3_error!(InternalError, "iam not init"));
    };

    // 遍历所有可能的操作 (Action)
    for action in actions {
        // 检查当前操作的权限
        match check_admin_request_auth(iam_store.clone(), headers, cred, is_owner, deny_only, action).await {
            Ok(_) => {
                // 如果当前 action 检查通过 (被允许)，则整个请求通过，返回 Ok(())
                return Ok(());
            }
            Err(_) => {
                // 如果当前 action 检查失败 (被拒绝或出错)，则继续检查下一个 action
                continue;
            }
        }
    }

    // 如果所有 action 都未通过权限检查，则返回 AccessDenied 错误
    Err(s3_error!(AccessDenied, "Access Denied"))
}

/// 检查单个管理员请求操作的权限
///
/// 使用 IAM 系统检查给定的凭证和条件是否允许执行特定的操作。
///
/// # 参数
/// * `iam_store`: 共享的 IAM 系统实例
/// * `headers`: HTTP 请求头
/// * `cred`: 认证凭证
/// * `is_owner`: 是否是资源所有者
/// * `deny_only`: 是否只评估 Deny 策略
/// * `action`: 要检查的单个操作
///
/// # 返回
/// S3Result<()>，成功则返回 Ok(())，失败则返回 AccessDenied
async fn check_admin_request_auth(
    iam_store: Arc<IamSys<ObjectStore>>, // 共享的 IAM 系统实例
    headers: &HeaderMap, // HTTP 请求头
    cred: &auth::Credentials, // 认证凭证
    is_owner: bool, // 是否是所有者
    deny_only: bool, // 是否只检查 Deny 策略
    action: Action, // 要检查的单个操作
) -> S3Result<()> {
    // 从请求头和凭证中获取用于策略评估的条件值
    let conditions = get_condition_values(headers, cred, None, None);

    // 调用 IAM 系统的 is_allowed 方法进行权限评估
    if !iam_store
        .is_allowed(&Args { // 构建策略评估的参数 Args
            account: &cred.access_key, // 账户 ID (使用 access_key 作为标识)
            groups: &cred.groups, // 用户所属的组
            action, // 当前要检查的操作
            conditions: &conditions, // 策略条件值
            is_owner, // 是否是资源所有者
            claims: cred.claims.as_ref().unwrap_or(&HashMap::new()), // JWT Claims (如果存在)
            deny_only, // 是否只检查 Deny 策略
            bucket: "", // 管理员操作通常不针对特定的 bucket 或 object，所以为空
            object: "", // 管理员操作通常不针对特定的 bucket 或 object，所以为空
        })
        .await // 异步等待权限评估结果
    {
        // 如果未被允许 (is_allowed 返回 false)，则返回 AccessDenied 错误
        return Err(s3_error!(AccessDenied, "Access Denied"));
    }

    // 如果被允许，返回 Ok(())
    Ok(())
}