// 版权所有 2024 RustFS 团队
//
// 根据 Apache 许可证 2.0 版本（"许可证"）授权；
// 除非符合许可证，否则不得使用此文件。
// 您可以在以下网址获取许可证副本：
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，本软件按"原样"分发，
// 不提供任何明示或暗示的担保或条件。
// 请参阅许可证了解具体的权限和限制。

use clap::Parser; // 命令行参数解析库
use const_str::concat; // 编译时字符串拼接宏
use std::string::ToString; // 字符串转换 trait
shadow_rs::shadow!(build); // 构建信息宏，收集编译时信息

pub mod workload_profiles; // 公开的工作负载配置文件模块

#[cfg(test)] // 仅测试时编译
mod config_test; // 配置测试模块

#[allow(clippy::const_is_empty)] // 忽略 clippy 警告
const SHORT_VERSION: &str = {
    // 定义短版本号常量（编译时确定）
    if !build::TAG.is_empty() {
        // 如果有 Git 标签，使用标签
        build::TAG
    } else if !build::SHORT_COMMIT.is_empty() {
        // 否则如果有短提交哈希，使用提交哈希
        concat!("@", build::SHORT_COMMIT)
    } else {
        // 否则使用包版本
        build::PKG_VERSION
    }
};

// 长版本信息常量，包含详细的构建信息
const LONG_VERSION: &str = concat!(
    concat!(SHORT_VERSION, "\n"),
    concat!("构建时间     : ", build::BUILD_TIME, "\n"),
    concat!("构建配置     : ", build::BUILD_RUST_CHANNEL, "\n"),
    concat!("构建操作系统 : ", build::BUILD_OS, "\n"),
    concat!("Rust 版本    : ", build::RUST_VERSION, "\n"),
    concat!("Rust 渠道    : ", build::RUST_CHANNEL, "\n"),
    concat!("Git 分支     : ", build::BRANCH, "\n"),
    concat!("Git 提交     : ", build::COMMIT_HASH, "\n"),
    concat!("Git 标签     : ", build::TAG, "\n"),
    concat!("Git 状态     :\n", build::GIT_STATUS_FILE),
);

#[derive(Debug, Parser, Clone)] // 派生调试、命令行解析和克隆 trait
#[command(version = SHORT_VERSION, long_version = LONG_VERSION)] // 设置命令行版本信息
pub struct Opt {
    // 存储卷路径，指向文件系统上的目录
    /// DIR 指向文件系统上的一个目录
    #[arg(required = true, env = "RUSTFS_VOLUMES")] // 必需参数，可从环境变量读取
    pub volumes: Vec<String>,

    // 绑定到特定的地址和端口
    /// 绑定到特定的 ADDRESS:PORT，ADDRESS 可以是 IP 或主机名
    #[arg(long, default_value_t = rustfs_config::DEFAULT_ADDRESS.to_string(), env = "RUSTFS_ADDRESS")]
    pub address: String,

    // 用于虚拟主机风格请求的域名
    /// 用于虚拟主机风格请求的域名
    #[arg(long, env = "RUSTFS_SERVER_DOMAINS")]
    pub server_domains: Vec<String>,

    // 用于身份验证的访问密钥
    /// 用于身份验证的访问密钥
    #[arg(long, default_value_t = rustfs_config::DEFAULT_ACCESS_KEY.to_string(), env = "RUSTFS_ACCESS_KEY")]
    pub access_key: String,

    // 用于身份验证的密钥
    /// 用于身份验证的密钥
    #[arg(long, default_value_t = rustfs_config::DEFAULT_SECRET_KEY.to_string(), env = "RUSTFS_SECRET_KEY")]
    pub secret_key: String,

    // 启用控制台服务器
    /// 启用控制台服务器
    #[arg(long, default_value_t = rustfs_config::DEFAULT_CONSOLE_ENABLE, env = "RUSTFS_CONSOLE_ENABLE")]
    pub console_enable: bool,

    // 控制台服务器绑定地址
    /// 控制台服务器绑定地址
    #[arg(long, default_value_t = rustfs_config::DEFAULT_CONSOLE_ADDRESS.to_string(), env = "RUSTFS_CONSOLE_ADDRESS")]
    pub console_address: String,

    // 用于追踪、指标和日志的可观测性端点
    /// 用于追踪、指标和日志的可观测性端点，仅支持 grpc 模式
    #[arg(long, default_value_t = rustfs_config::DEFAULT_OBS_ENDPOINT.to_string(), env = "RUSTFS_OBS_ENDPOINT")]
    pub obs_endpoint: String,

    // RustFS API 和控制台的 TLS 路径
    /// RustFS API 和控制台的 TLS 路径
    #[arg(long, env = "RUSTFS_TLS_PATH")]
    pub tls_path: Option<String>,

    // 许可证信息
    #[arg(long, env = "RUSTFS_LICENSE")]
    pub license: Option<String>,

    // 区域设置
    #[arg(long, env = "RUSTFS_REGION")]
    pub region: Option<String>,

    // 为服务器端加密启用 KMS 加密
    /// 为服务器端加密启用 KMS 加密
    #[arg(long, default_value_t = false, env = "RUSTFS_KMS_ENABLE")]
    pub kms_enable: bool,

    // KMS 后端类型
    /// KMS 后端类型（local 或 vault）
    #[arg(long, default_value_t = String::from("local"), env = "RUSTFS_KMS_BACKEND")]
    pub kms_backend: String,

    // 本地后端的 KMS 密钥目录
    /// 本地后端的 KMS 密钥目录
    #[arg(long, env = "RUSTFS_KMS_KEY_DIR")]
    pub kms_key_dir: Option<String>,

    // Vault 后端的 Vault 地址
    /// Vault 后端的 Vault 地址
    #[arg(long, env = "RUSTFS_KMS_VAULT_ADDRESS")]
    pub kms_vault_address: Option<String>,

    // Vault 后端的 Vault 令牌
    /// Vault 后端的 Vault 令牌
    #[arg(long, env = "RUSTFS_KMS_VAULT_TOKEN")]
    pub kms_vault_token: Option<String>,

    // 加密的默认 KMS 密钥 ID
    /// 加密的默认 KMS 密钥 ID
    #[arg(long, env = "RUSTFS_KMS_DEFAULT_KEY_ID")]
    pub kms_default_key_id: Option<String>,

    // 禁用自适应缓冲区大小调整的工作负载配置文件
    /// 禁用自适应缓冲区大小调整的工作负载配置文件
    /// 设置此标志以使用 PR #869 中的旧版固定大小缓冲区行为
    #[arg(long, default_value_t = false, env = "RUSTFS_BUFFER_PROFILE_DISABLE")]
    pub buffer_profile_disable: bool,

    // 自适应缓冲区大小调整的工作负载配置文件
    /// 自适应缓冲区大小调整的工作负载配置文件
    /// 选项：GeneralPurpose, AiTraining, DataAnalytics, WebWorkload, IndustrialIoT, SecureStorage
    #[arg(long, default_value_t = String::from("GeneralPurpose"), env = "RUSTFS_BUFFER_PROFILE")]
    pub buffer_profile: String,
}

// 全局配置的单例模式实现（已注释掉）
// lazy_static::lazy_static! {
//     pub(crate)  static ref OPT: OnceLock<Opt> = OnceLock::new();
// }

// pub fn init_config(opt: Opt) {
//     OPT.set(opt).expect("Failed to set global config");
// }

// pub fn get_config() -> &'static Opt {
//     OPT.get().expect("Global config not initialized")
// }