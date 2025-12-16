// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 认证模块
mod auth;
// 控制台管理模块
pub mod console;
// 请求处理程序（Handler）模块
pub mod handlers;
// 路由器模块
pub mod router;
// 远程过程调用（RPC）模块
mod rpc;
// 工具函数模块
pub mod utils;

// 仅在测试时编译控制台测试模块
#[cfg(test)]
mod console_test;

// 导入所有请求处理程序（Handlers）
use handlers::{
    // 复制指标
    GetReplicationMetricsHandler,
    // 健康检查
    HealthCheckHandler,
    // 是否为管理员
    IsAdminHandler,
    // 远程目标管理
    ListRemoteTargetHandler,
    RemoveRemoteTargetHandler,
    SetRemoteTargetHandler,
    // 存储桶元数据管理
    bucket_meta,
    // 事件通知管理
    event::{ListNotificationTargets, ListTargetsArns, NotificationTarget, RemoveNotificationTarget},
    // 用户组管理
    group,
    // KMS（密钥管理服务）相关
    kms,
    // 动态 KMS 配置
    kms_dynamic,
    // KMS 密钥管理
    kms_keys,
    // 策略管理
    policies,
    // 存储池管理
    pools,
    // 性能分析
    profile::{TriggerProfileCPU, TriggerProfileMemory},
    // 重平衡管理
    rebalance,
    // 服务账户管理
    service_account::{AddServiceAccount, DeleteServiceAccount, InfoServiceAccount, ListServiceAccount, UpdateServiceAccount},
    // STS（安全令牌服务）
    sts,
    // 存储分层（Tiering）管理
    tier,
    // 用户管理
    user,
};
// 导入 hyper 库中的 HTTP 方法
use hyper::Method;
// 导入自定义的 AdminOperation 和 S3Router
use router::{AdminOperation, S3Router};
// 导入 RPC 路由注册函数
use rpc::register_rpc_route;
// 导入 s3s 库的 S3Route trait
use s3s::route::S3Route;

// 管理 API 的前缀常量
const ADMIN_PREFIX: &str = "/rustfs/admin";
// const ADMIN_PREFIX: &str = "/minio/admin"; // 备选前缀（兼容 MinIO）

/// 创建管理路由
///
/// 根据 console_enabled 标志创建并配置所有管理 API 路由。
pub fn make_admin_route(console_enabled: bool) -> std::io::Result<impl S3Route> {
    // 初始化 S3 路由器，专门处理 AdminOperation
    let mut r: S3Router<AdminOperation> = S3Router::new(console_enabled);

    // --- 监控和性能分析端点 ---

    // 健康检查端点 (GET /health)
    r.insert(Method::GET, "/health", AdminOperation(&HealthCheckHandler {}))?;
    // 健康检查端点 (HEAD /health)
    r.insert(Method::HEAD, "/health", AdminOperation(&HealthCheckHandler {}))?;
    // 触发 CPU 性能分析 (GET /profile/cpu)
    r.insert(Method::GET, "/profile/cpu", AdminOperation(&TriggerProfileCPU {}))?;
    // 触发内存性能分析 (GET /profile/memory)
    r.insert(Method::GET, "/profile/memory", AdminOperation(&TriggerProfileMemory {}))?;

    // --- STS 端点 ---
    // 1. AssumeRole (POST /) - 用于获取临时安全凭证
    r.insert(Method::POST, "/", AdminOperation(&sts::AssumeRoleHandle {}))?;

    // --- 基本管理信息端点 ---
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/is-admin").as_str(),
        AdminOperation(&IsAdminHandler {}), // 检查是否为管理员
    )?;

    // 注册 RPC 路由
    register_rpc_route(&mut r)?;
    // 注册用户和身份管理路由
    register_user_route(&mut r)?;

    // --- 服务操作和信息端点 ---

    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/service").as_str(),
        AdminOperation(&handlers::ServiceHandle {}), // 服务操作 (重启, 停止等)
    )?;
    // 1. 获取服务器信息 (GET /v3/info)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/info").as_str(),
        AdminOperation(&handlers::ServerInfoHandler {}),
    )?;
    // 检查数据完整性 (GET /v3/inspect-data)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/inspect-data").as_str(),
        AdminOperation(&handlers::InspectDataHandler {}),
    )?;
    // 触发数据完整性检查 (POST /v3/inspect-data)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/inspect-data").as_str(),
        AdminOperation(&handlers::InspectDataHandler {}),
    )?;
    // 1. 获取存储信息 (GET /v3/storageinfo)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/storageinfo").as_str(),
        AdminOperation(&handlers::StorageInfoHandler {}),
    )?;
    // 1. 获取数据使用信息 (GET /v3/datausageinfo)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/datausageinfo").as_str(),
        AdminOperation(&handlers::DataUsageInfoHandler {}),
    )?;
    // 获取监控指标 (GET /v3/metrics)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/metrics").as_str(),
        AdminOperation(&handlers::MetricsHandler {}),
    )?;

    // --- 存储池 (Pools) 管理 ---

    // 1. 列出所有存储池 (GET /v3/pools/list)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/pools/list").as_str(),
        AdminOperation(&pools::ListPools {}),
    )?;
    // 1. 获取存储池状态 (GET /v3/pools/status)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/pools/status").as_str(),
        AdminOperation(&pools::StatusPool {}),
    )?;
    // todo: 启动存储池退役/停用 (POST /v3/pools/decommission)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/pools/decommission").as_str(),
        AdminOperation(&pools::StartDecommission {}),
    )?;
    // todo: 取消存储池退役/停用 (POST /v3/pools/cancel)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/pools/cancel").as_str(),
        AdminOperation(&pools::CancelDecommission {}),
    )?;

    // --- 数据重平衡 (Rebalance) 管理 ---

    // 启动数据重平衡 (POST /v3/rebalance/start)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/rebalance/start").as_str(),
        AdminOperation(&rebalance::RebalanceStart {}),
    )?;
    // 获取重平衡状态 (GET /v3/rebalance/status)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/rebalance/status").as_str(),
        AdminOperation(&rebalance::RebalanceStatus {}),
    )?;
    // 停止重平衡 (POST /v3/rebalance/stop)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/rebalance/stop").as_str(),
        AdminOperation(&rebalance::RebalanceStop {}),
    )?;

    // --- 自我修复 (Heal) 端点 ---
    // Some APIs are only available in EC mode (这些 API 通常只在纠删码 (EC) 模式下可用)
    // if is_dist_erasure().await || is_erasure().await {
    // 触发指定存储桶的修复 (POST /v3/heal/{bucket})
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/heal/{bucket}").as_str(),
        AdminOperation(&handlers::HealHandler {}),
    )?;
    // 触发指定存储桶和前缀的修复 (POST /v3/heal/{bucket}/{prefix})
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/heal/{bucket}/{prefix}").as_str(),
        AdminOperation(&handlers::HealHandler {}),
    )?;
    // 获取后台修复状态 (POST /v3/background-heal/status)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/background-heal/status").as_str(),
        AdminOperation(&handlers::BackgroundHealStatusHandler {}),
    )?;

    // --- 存储分层 (Tier) 管理 ---

    // ? 列出所有分层配置 (GET /v3/tier)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier").as_str(),
        AdminOperation(&tier::ListTiers {}),
    )?;
    // ? 获取分层统计信息 (GET /v3/tier-stats)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier-stats").as_str(),
        AdminOperation(&tier::GetTierInfo {}),
    )?;
    // ?force=xxx: 删除指定分层配置 (DELETE /v3/tier/{tiername})
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier/{tiername}").as_str(),
        AdminOperation(&tier::RemoveTier {}),
    )?;
    // ?force=xxx: 添加或更新分层配置 (PUT /v3/tier)
    // body: AddOrUpdateTierReq
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier").as_str(),
        AdminOperation(&tier::AddTier {}),
    )?;
    // ? (其他参数): 编辑指定分层配置 (POST /v3/tier/{tiername})
    // body: AddOrUpdateTierReq
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier/{tiername}").as_str(),
        AdminOperation(&tier::EditTier {}),
    )?;
    // 清除分层缓存/状态 (POST /v3/tier/clear)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/tier/clear").as_str(),
        AdminOperation(&tier::ClearTier {}),
    )?;

    // --- 存储桶元数据管理 ---

    // 导出存储桶元数据 (GET /export-bucket-metadata)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/export-bucket-metadata").as_str(),
        AdminOperation(&bucket_meta::ExportBucketMetadata {}),
    )?;

    // 导入存储桶元数据 (PUT /import-bucket-metadata)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/import-bucket-metadata").as_str(),
        AdminOperation(&bucket_meta::ImportBucketMetadata {}),
    )?;

    // --- 复制管理 ---

    // 列出远程目标 (GET /v3/list-remote-targets)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/list-remote-targets").as_str(),
        AdminOperation(&ListRemoteTargetHandler {}),
    )?;

    // 获取复制指标 (GET /v3/replicationmetrics)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/replicationmetrics").as_str(),
        AdminOperation(&GetReplicationMetricsHandler {}),
    )?;

    // 设置远程目标 (PUT /v3/set-remote-target)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/set-remote-target").as_str(),
        AdminOperation(&SetRemoteTargetHandler {}),
    )?;

    // 移除远程目标 (DELETE /v3/remove-remote-target)
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/remove-remote-target").as_str(),
        AdminOperation(&RemoveRemoteTargetHandler {}),
    )?;

    // --- 调试和性能分析端点 (仅限非 Windows 平台) ---
    // Performance profiling endpoints (available on all platforms, with platform-specific responses)
    // 触发性能分析并获取结果 (GET /debug/pprof/profile)
    #[cfg(not(target_os = "windows"))]
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/debug/pprof/profile").as_str(),
        AdminOperation(&handlers::ProfileHandler {}),
    )?;

    // 获取性能分析状态 (GET /debug/pprof/status)
    #[cfg(not(target_os = "windows"))]
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/debug/pprof/status").as_str(),
        AdminOperation(&handlers::ProfileStatusHandler {}),
    )?;

    // --- KMS（密钥管理服务）端点 ---

    // 创建 KMS 密钥 (POST /v3/kms/create-key)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/create-key").as_str(),
        AdminOperation(&kms::CreateKeyHandler {}),
    )?;

    // 描述 KMS 密钥 (GET /v3/kms/describe-key)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/describe-key").as_str(),
        AdminOperation(&kms::DescribeKeyHandler {}),
    )?;

    // 列出 KMS 密钥 (GET /v3/kms/list-keys)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/list-keys").as_str(),
        AdminOperation(&kms::ListKeysHandler {}),
    )?;

    // 生成数据密钥 (POST /v3/kms/generate-data-key)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/generate-data-key").as_str(),
        AdminOperation(&kms::GenerateDataKeyHandler {}),
    )?;

    // 获取 KMS 状态 (GET /v3/kms/status)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/status").as_str(),
        AdminOperation(&kms::KmsStatusHandler {}),
    )?;

    // 获取 KMS 配置 (GET /v3/kms/config)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/config").as_str(),
        AdminOperation(&kms::KmsConfigHandler {}),
    )?;

    // 清除 KMS 缓存 (POST /v3/kms/clear-cache)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/clear-cache").as_str(),
        AdminOperation(&kms::KmsClearCacheHandler {}),
    )?;

    // --- KMS 动态配置 API ---

    // 配置 KMS (POST /v3/kms/configure)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/configure").as_str(),
        AdminOperation(&kms_dynamic::ConfigureKmsHandler {}),
    )?;

    // 启动 KMS 服务 (POST /v3/kms/start)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/start").as_str(),
        AdminOperation(&kms_dynamic::StartKmsHandler {}),
    )?;

    // 停止 KMS 服务 (POST /v3/kms/stop)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/stop").as_str(),
        AdminOperation(&kms_dynamic::StopKmsHandler {}),
    )?;

    // 获取 KMS 服务状态 (GET /v3/kms/service-status)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/service-status").as_str(),
        AdminOperation(&kms_dynamic::GetKmsStatusHandler {}),
    )?;

    // 重新配置 KMS (POST /v3/kms/reconfigure)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/reconfigure").as_str(),
        AdminOperation(&kms_dynamic::ReconfigureKmsHandler {}),
    )?;

    // --- KMS 密钥管理端点 ---

    // 创建 KMS 密钥 (POST /v3/kms/keys)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/keys").as_str(),
        AdminOperation(&kms_keys::CreateKmsKeyHandler {}),
    )?;

    // 删除 KMS 密钥 (DELETE /v3/kms/keys/delete)
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/keys/delete").as_str(),
        AdminOperation(&kms_keys::DeleteKmsKeyHandler {}),
    )?;

    // 取消 KMS 密钥删除 (POST /v3/kms/keys/cancel-deletion)
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/keys/cancel-deletion").as_str(),
        AdminOperation(&kms_keys::CancelKmsKeyDeletionHandler {}),
    )?;

    // 列出 KMS 密钥 (GET /v3/kms/keys)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/keys").as_str(),
        AdminOperation(&kms_keys::ListKmsKeysHandler {}),
    )?;

    // 描述特定 KMS 密钥 (GET /v3/kms/keys/{key_id})
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/kms/keys/{key_id}").as_str(),
        AdminOperation(&kms_keys::DescribeKmsKeyHandler {}),
    )?;

    Ok(r)
}

/// 用户和身份管理路由器
fn register_user_route(r: &mut S3Router<AdminOperation>) -> std::io::Result<()> {
    // --- 用户和组管理 ---

    // 1. 获取账户信息 (GET /v3/accountinfo)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/accountinfo").as_str(),
        AdminOperation(&handlers::AccountInfoHandler {}),
    )?;

    // ?[bucket=xxx]: 列出所有用户 (GET /v3/list-users)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/list-users").as_str(),
        AdminOperation(&user::ListUsers {}),
    )?;

    // ?accessKey=xxx: 获取用户信息 (GET /v3/user-info)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/user-info").as_str(),
        AdminOperation(&user::GetUserInfo {}),
    )?;

    // ?accessKey=xxx: 移除用户 (DELETE /v3/remove-user)
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/remove-user").as_str(),
        AdminOperation(&user::RemoveUser {}),
    )?;

    // ?accessKey=xxx: 添加用户 (PUT /v3/add-user)
    // body: AddOrUpdateUserReq
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/add-user").as_str(),
        AdminOperation(&user::AddUser {}),
    )?;
    // ?accessKey=xxx&status=enabled: 设置用户状态 (PUT /v3/set-user-status)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/set-user-status").as_str(),
        AdminOperation(&user::SetUserStatus {}),
    )?;

    // 列出所有组 (GET /v3/groups)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/groups").as_str(),
        AdminOperation(&group::ListGroups {}),
    )?;

    // ?group=xxx: 获取组信息 (GET /v3/group)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/group").as_str(),
        AdminOperation(&group::GetGroup {}),
    )?;

    // ?group=xxx&status=xxx: 设置组状态 (PUT /v3/set-group-status)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/set-group-status").as_str(),
        AdminOperation(&group::SetGroupStatus {}),
    )?;

    // @body GroupAddRemove: 更新组成员 (PUT /v3/update-group-members)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/update-group-members").as_str(),
        AdminOperation(&group::UpdateGroupMembers {}),
    )?;

    // --- 服务账户 (Service Accounts) 管理 ---

    // ?accessKey=xxx: 更新服务账户 (POST /v3/update-service-account)
    // @body: UpdateServiceAccountReq
    r.insert(
        Method::POST,
        format!("{}{}", ADMIN_PREFIX, "/v3/update-service-account").as_str(),
        AdminOperation(&UpdateServiceAccount {}),
    )?;
    // ?accessKey=xxx: 获取服务账户信息 (GET /v3/info-service-account)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/info-service-account").as_str(),
        AdminOperation(&InfoServiceAccount {}),
    )?;

    // ?[user=xxx]: 列出服务账户 (GET /v3/list-service-accounts)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/list-service-accounts").as_str(),
        AdminOperation(&ListServiceAccount {}),
    )?;
    // ?accessKey=xxx: 删除服务账户 (DELETE /v3/delete-service-accounts)
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/delete-service-accounts").as_str(),
        AdminOperation(&DeleteServiceAccount {}),
    )?;
    // @body: AddServiceAccountReq: 添加服务账户 (PUT /v3/add-service-accounts)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/add-service-accounts").as_str(),
        AdminOperation(&AddServiceAccount {}),
    )?;

    // 导出 IAM 配置 (GET /v3/export-iam)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/export-iam").as_str(),
        AdminOperation(&user::ExportIam {}),
    )?;

    // 导入 IAM 配置 (PUT /v3/import-iam)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/import-iam").as_str(),
        AdminOperation(&user::ImportIam {}),
    )?;

    // --- 策略 (Policies) 管理 ---

    // list-canned-policies?bucket=xxx: 列出预定义策略 (GET /v3/list-canned-policies)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/list-canned-policies").as_str(),
        AdminOperation(&policies::ListCannedPolicies {}),
    )?;

    // info-canned-policy?name=xxx: 获取预定义策略信息 (GET /v3/info-canned-policy)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/info-canned-policy").as_str(),
        AdminOperation(&policies::InfoCannedPolicy {}),
    )?;

    // add-canned-policy?name=xxx: 添加预定义策略 (PUT /v3/add-canned-policy)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/add-canned-policy").as_str(),
        AdminOperation(&policies::AddCannedPolicy {}),
    )?;

    // remove-canned-policy?name=xxx: 移除预定义策略 (DELETE /v3/remove-canned-policy)
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/remove-canned-policy").as_str(),
        AdminOperation(&policies::RemoveCannedPolicy {}),
    )?;

    // set-user-or-group-policy?policyName=xxx&userOrGroup=xxx&isGroup=xxx: 设置用户或组的策略 (PUT /v3/set-user-or-group-policy)
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/set-user-or-group-policy").as_str(),
        AdminOperation(&policies::SetPolicyForUserOrGroup {}),
    )?;

    // --- 事件通知 (Notification) 管理 ---

    // 列出通知目标 (GET /v3/target/list)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/target/list").as_str(),
        AdminOperation(&ListNotificationTargets {}),
    )?;

    // 添加/更新通知目标 (PUT /v3/target/{target_type}/{target_name})
    r.insert(
        Method::PUT,
        format!("{}{}", ADMIN_PREFIX, "/v3/target/{target_type}/{target_name}").as_str(),
        AdminOperation(&NotificationTarget {}),
    )?;

    // 移除通知目标 (DELETE /v3/target/{target_type}/{target_name}/reset)
    // This endpoint removes a notification target based on its type and name.
    // * `target_type` - 目标类型，例如 "notify_webhook" 或 "notify_mqtt"。
    // * `target_name` - 目标的唯一名称，例如 "1"。
    r.insert(
        Method::DELETE,
        format!("{}{}", ADMIN_PREFIX, "/v3/target/{target_type}/{target_name}/reset").as_str(),
        AdminOperation(&RemoveNotificationTarget {}),
    )?;

    // 列出 ARN（Amazon Resource Name）列表 (GET /v3/target/arns)
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/target/arns").as_str(),
        AdminOperation(&ListTargetsArns {}),
    )?;

    Ok(())
}