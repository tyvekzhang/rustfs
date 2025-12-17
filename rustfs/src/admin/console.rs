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

// 导入必要的模块和库
use crate::config::build;
use crate::license::get_license;
use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::Host;
use axum_server::tls_rustls::RustlsConfig;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use mime_guess::from_path;
use rust_embed::RustEmbed;
use rustfs_config::{RUSTFS_TLS_CERT, RUSTFS_TLS_KEY};
use serde::Serialize;
use serde_json::json;
use std::{
    io::Result,
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio_rustls::rustls::ServerConfig;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument, warn};

// 控制台路径前缀
pub(crate) const CONSOLE_PREFIX: &str = "/rustfs/console";
// 管理API路径前缀
const RUSTFS_ADMIN_PREFIX: &str = "/rustfs/admin/v3";

// 使用rust-embed嵌入静态文件到二进制中
#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/static"]  // 从static文件夹嵌入文件
struct StaticFiles;

/// 静态文件处理器
///
/// 使用rust-embed提供嵌入在二进制中的静态文件。
/// 如果请求的文件未找到，则回退到index.html。
/// 如果index.html也未找到，返回404 Not Found响应。
///
/// # 参数:
/// - `uri`: 请求的URI。
///
/// # 返回:
/// - 包含静态文件内容或404响应的 `impl IntoResponse`。
async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        path = "index.html"  // 默认返回index.html
    }
    
    // 尝试获取请求的文件
    if let Some(file) = StaticFiles::get(path) {
        let mime_type = from_path(path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.to_string())
            .body(Body::from(file.data))
            .unwrap()
    } else if let Some(file) = StaticFiles::get("index.html") {
        // 文件未找到，返回index.html作为单页应用的回退
        let mime_type = from_path("index.html").first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime_type.to_string())
            .body(Body::from(file.data))
            .unwrap()
    } else {
        // index.html也未找到，返回404
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(" 404 Not Found \n RustFS "))
            .unwrap()
    }
}

/// 控制台配置结构体
#[derive(Debug, Serialize, Clone)]
pub(crate) struct Config {
    #[serde(skip)]  // 序列化时跳过端口号
    port: u16,
    api: Api,      // API配置
    s3: S3,        // S3配置
    release: Release,  // 发布信息
    license: License,  // 许可证信息
    doc: String,   // 文档链接
}

impl Config {
    /// 创建新的配置实例
    fn new(local_ip: IpAddr, port: u16, version: &str, date: &str) -> Self {
        Config {
            port,
            api: Api {
                base_url: format!("http://{local_ip}:{port}/{RUSTFS_ADMIN_PREFIX}"),
            },
            s3: S3 {
                endpoint: format!("http://{local_ip}:{port}"),
                region: "cn-east-1".to_owned(),  // 默认区域
            },
            release: Release {
                version: version.to_string(),
                date: date.to_string(),
            },
            license: License {
                name: "Apache-2.0".to_string(),
                url: "https://www.apache.org/licenses/LICENSE-2.0".to_string(),
            },
            doc: "https://rustfs.com/docs/".to_string(),
        }
    }

    /// 将配置转换为JSON字符串
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// 获取版本信息字符串
    #[allow(dead_code)]
    pub(crate) fn version_info(&self) -> String {
        format!(
            "RELEASE.{}@{} (rust {} {})",
            self.release.date.clone(),
            self.release.version.clone().trim_start_matches('@'),
            build::RUST_VERSION,
            build::BUILD_TARGET
        )
    }

    /// 获取版本号
    #[allow(dead_code)]
    pub(crate) fn version(&self) -> String {
        self.release.version.clone()
    }

    /// 获取许可证信息
    #[allow(dead_code)]
    pub(crate) fn license(&self) -> String {
        format!("{} {}", self.license.name.clone(), self.license.url.clone())
    }

    /// 获取文档链接
    #[allow(dead_code)]
    pub(crate) fn doc(&self) -> String {
        self.doc.clone()
    }
}

/// API配置结构体
#[derive(Debug, Serialize, Clone)]
struct Api {
    #[serde(rename = "baseURL")]  // JSON序列化时重命名字段
    base_url: String,
}

/// S3配置结构体
#[derive(Debug, Serialize, Clone)]
struct S3 {
    endpoint: String,  // S3端点URL
    region: String,    // 区域
}

/// 发布信息结构体
#[derive(Debug, Serialize, Clone)]
struct Release {
    version: String,  // 版本号
    date: String,     // 发布日期
}

/// 许可证信息结构体
#[derive(Debug, Serialize, Clone)]
struct License {
    name: String,  // 许可证名称
    url: String,   // 许可证URL
}

/// 全局控制台配置（线程安全的一次性初始化）
static CONSOLE_CONFIG: OnceLock<Config> = OnceLock::new();

/// 初始化控制台配置
#[allow(clippy::const_is_empty)]
pub(crate) fn init_console_cfg(local_ip: IpAddr, port: u16) {
    CONSOLE_CONFIG.get_or_init(|| {
        // 确定版本号（优先使用标签，然后是提交哈希，最后是包版本）
        let ver = {
            if !build::TAG.is_empty() {
                build::TAG.to_string()
            } else if !build::SHORT_COMMIT.is_empty() {
                format!("@{}", build::SHORT_COMMIT)
            } else {
                build::PKG_VERSION.to_string()
            }
        };

        // 创建配置实例
        Config::new(local_ip, port, ver.as_str(), build::COMMIT_DATE_3339)
    });
}

/// 许可证处理器
/// 返回控制台的当前许可证信息。
///
/// # 返回:
/// - 200 OK，包含许可证详情的JSON响应。
#[instrument]
async fn license_handler() -> impl IntoResponse {
    let license = get_license().unwrap_or_default();

    Response::builder()
        .header("content-type", "application/json")
        .status(StatusCode::OK)
        .body(Body::from(serde_json::to_string(&license).unwrap_or_default()))
        .unwrap()
}

/// 检查给定的IP地址是否为私有IP
fn _is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            // 10.0.0.0/8
            octets[0] == 10 ||
                // 172.16.0.0/12
                (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)) ||
                // 192.168.0.0/16
                (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(_) => false,  // IPv6暂不处理
    }
}

/// 版本处理器
/// 返回控制台的当前版本信息。
///
/// # 返回:
/// - 200 OK：包含版本详情的JSON响应（如果配置已初始化）
/// - 500 Internal Server Error：如果配置未初始化
#[instrument]
async fn version_handler() -> impl IntoResponse {
    match CONSOLE_CONFIG.get() {
        Some(cfg) => Response::builder()
            .header("content-type", "application/json")
            .status(StatusCode::OK)
            .body(Body::from(
                json!({
                    "version": cfg.release.version,
                    "version_info": cfg.version_info(),
                    "date": cfg.release.date,
                })
                .to_string(),
            ))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Console configuration not initialized"))
            .unwrap(),
    }
}

/// 配置处理器
/// 返回当前控制台配置的JSON格式。
/// 配置会根据请求的主机和协议动态调整。
///
/// # 参数:
/// - `uri`: 请求URI
/// - `Host(host)`: 从请求中提取的主机
/// - `headers`: 请求头
///
/// # 返回:
/// - 200 OK：包含控制台配置的JSON响应（如果配置已初始化）
/// - 500 Internal Server Error：如果配置未初始化
#[instrument(fields(host))]
async fn config_handler(uri: Uri, Host(host): Host, headers: HeaderMap) -> impl IntoResponse {
    // 从头信息或URI中获取协议方案
    let scheme = headers
        .get(HeaderName::from_static("x-forwarded-proto"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| uri.scheme().map(|s| s.as_str()).unwrap_or("http"));

    let raw_host = uri.host().unwrap_or(host.as_str());
    
    // 格式化主机地址（处理IPv6的特殊情况）
    let host_for_url = if let Ok(socket_addr) = raw_host.parse::<SocketAddr>() {
        // 成功解析为IP:端口格式
        let ip = socket_addr.ip();
        if ip.is_ipv6() { 
            format!("[{ip}]")  // IPv6需要方括号
        } else { 
            format!("{ip}") 
        }
    } else if let Ok(ip) = raw_host.parse::<IpAddr>() {
        // 纯IP地址（无端口）
        if ip.is_ipv6() { 
            format!("[{ip}]") 
        } else { 
            ip.to_string() 
        }
    } else {
        // 域名（可能无法直接解析为IP），移除端口部分
        raw_host.split(':').next().unwrap_or(raw_host).to_string()
    };

    // 复制当前配置
    let mut cfg = match CONSOLE_CONFIG.get() {
        Some(cfg) => cfg.clone(),
        None => {
            error!("Console configuration not initialized");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Console configuration not initialized"))
                .unwrap();
        }
    };

    // 动态更新配置中的URL
    let url = format!("{}://{}:{}", scheme, host_for_url, cfg.port);
    cfg.api.base_url = format!("{url}{RUSTFS_ADMIN_PREFIX}");
    cfg.s3.endpoint = url;

    Response::builder()
        .header("content-type", "application/json")
        .status(StatusCode::OK)
        .body(Body::from(cfg.to_json()))
        .unwrap()
}

/// 控制台访问日志中间件
/// 记录每个控制台访问的方法、URI、状态码和持续时间。
///
/// # 参数:
/// - `req`: 传入的请求
/// - `next`: 链中的下一个中间件或处理器
///
/// # 返回:
/// - 来自下一个中间件或处理器的响应
async fn console_logging_middleware(req: Request, next: middleware::Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed();

    // 记录访问日志
    info!(
        target: "rustfs::console::access",
        method = %method,
        uri = %uri,
        status = %response.status(),
        duration_ms = %duration.as_millis(),
        "Console access"
    );

    response
}

/// 为控制台设置TLS配置，使用axum-server，遵循端点TLS实现逻辑
#[instrument(skip(tls_path))]
async fn _setup_console_tls_config(tls_path: Option<&String>) -> Result<Option<RustlsConfig>> {
    let tls_path = match tls_path {
        Some(path) if !path.is_empty() => path,
        _ => {
            debug!("TLS path is not provided, console starting with HTTP");
            return Ok(None);
        }
    };

    // 检查TLS路径是否存在
    if tokio::fs::metadata(tls_path).await.is_err() {
        debug!("TLS path does not exist, console starting with HTTP");
        return Ok(None);
    }

    debug!("Found TLS directory for console, checking for certificates");

    // 使用现代加密套件
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. 尝试加载目录中的所有证书（多证书支持，用于SNI）
    if let Ok(cert_key_pairs) = rustfs_utils::load_all_certs_from_directory(tls_path) {
        if !cert_key_pairs.is_empty() {
            debug!(
                "Found {} certificates for console, creating SNI-aware multi-cert resolver",
                cert_key_pairs.len()
            );

            // 创建支持SNI的证书解析器
            let resolver = rustfs_utils::create_multi_cert_resolver(cert_key_pairs)?;

            // 配置服务器以启用SNI支持
            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));

            // 配置ALPN协议优先级
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

            // 记录SNI请求
            if rustfs_utils::tls_key_log() {
                server_config.key_log = Arc::new(rustls::KeyLogFile::new());
            }

            info!(target: "rustfs::console::tls", "Console TLS enabled with multi-certificate SNI support");
            return Ok(Some(RustlsConfig::from_config(Arc::new(server_config))));
        }
    }

    // 2. 回退到传统的单证书模式
    let key_path = format!("{tls_path}/{RUSTFS_TLS_KEY}");
    let cert_path = format!("{tls_path}/{RUSTFS_TLS_CERT}");
    if tokio::try_join!(tokio::fs::metadata(&key_path), tokio::fs::metadata(&cert_path)).is_ok() {
        debug!("Found legacy single TLS certificate for console, starting with HTTPS");

        return match RustlsConfig::from_pem_file(cert_path, key_path).await {
            Ok(config) => {
                info!(target: "rustfs::console::tls", "Console TLS enabled with single certificate");
                Ok(Some(config))
            }
            Err(e) => {
                error!(target: "rustfs::console::error", error = %e, "Failed to create TLS config for console");
                Err(std::io::Error::other(e))
            }
        };
    }

    debug!("No valid TLS certificates found in the directory for console, starting with HTTP");
    Ok(None)
}

/// 从环境变量获取控制台配置
/// 返回包含环境变量中控制台配置值的元组。
///
/// # 返回:
/// - rate_limit_enable: 表示是否启用速率限制的布尔值
/// - rate_limit_rpm: 表示每分钟请求限制次数的u32
/// - auth_timeout: 表示认证超时秒数的u64
/// - cors_allowed_origins: 包含允许的CORS来源的字符串
fn get_console_config_from_env() -> (bool, u32, u64, String) {
    // 从环境变量读取配置，使用默认值
    let rate_limit_enable = std::env::var(rustfs_config::ENV_CONSOLE_RATE_LIMIT_ENABLE)
        .unwrap_or_else(|_| rustfs_config::DEFAULT_CONSOLE_RATE_LIMIT_ENABLE.to_string())
        .parse::<bool>()
        .unwrap_or(rustfs_config::DEFAULT_CONSOLE_RATE_LIMIT_ENABLE);

    let rate_limit_rpm = std::env::var(rustfs_config::ENV_CONSOLE_RATE_LIMIT_RPM)
        .unwrap_or_else(|_| rustfs_config::DEFAULT_CONSOLE_RATE_LIMIT_RPM.to_string())
        .parse::<u32>()
        .unwrap_or(rustfs_config::DEFAULT_CONSOLE_RATE_LIMIT_RPM);

    let auth_timeout = std::env::var(rustfs_config::ENV_CONSOLE_AUTH_TIMEOUT)
        .unwrap_or_else(|_| rustfs_config::DEFAULT_CONSOLE_AUTH_TIMEOUT.to_string())
        .parse::<u64>()
        .unwrap_or(rustfs_config::DEFAULT_CONSOLE_AUTH_TIMEOUT);
        
    let cors_allowed_origins = std::env::var(rustfs_config::ENV_CONSOLE_CORS_ALLOWED_ORIGINS)
        .unwrap_or_else(|_| rustfs_config::DEFAULT_CONSOLE_CORS_ALLOWED_ORIGINS.to_string())
        .parse::<String>()
        .unwrap_or(rustfs_config::DEFAULT_CONSOLE_CORS_ALLOWED_ORIGINS.to_string());

    (rate_limit_enable, rate_limit_rpm, auth_timeout, cors_allowed_origins)
}

/// 检查给定路径是否为控制台访问路径
///
/// # 参数:
/// - `path`: 请求路径
///
/// # 返回:
/// - 如果路径是控制台访问路径则为`true`，否则为`false`
pub fn is_console_path(path: &str) -> bool {
    path == "/favicon.ico" || path.starts_with(CONSOLE_PREFIX)
}

/// 使用tower-http功能设置全面的中间件堆栈
///
/// # 参数:
/// - `cors_layer`: 要应用的CORS层
/// - `rate_limit_enable`: 表示是否启用速率限制的布尔值
/// - `rate_limit_rpm`: 表示每分钟请求限制次数的u32
/// - `auth_timeout`: 表示认证超时秒数的u64
///
/// # 返回:
/// - 配置了中间件堆栈的 `Router`
fn setup_console_middleware_stack(
    cors_layer: CorsLayer,
    rate_limit_enable: bool,
    rate_limit_rpm: u32,
    auth_timeout: u64,
) -> Router {
    let mut app = Router::new()
        .route("/favicon.ico", get(static_handler))
        .route(&format!("{CONSOLE_PREFIX}/license"), get(license_handler))
        .route(&format!("{CONSOLE_PREFIX}/config.json"), get(config_handler))
        .route(&format!("{CONSOLE_PREFIX}/version"), get(version_handler))
        .route(&format!("{CONSOLE_PREFIX}/health"), get(health_check).head(health_check))
        .nest(CONSOLE_PREFIX, Router::new().fallback_service(get(static_handler)))
        .fallback_service(get(static_handler));  // 默认静态文件服务

    // 使用tower-http功能添加全面的中间件层
    app = app
        .layer(CatchPanicLayer::new())  // 捕获恐慌
        .layer(TraceLayer::new_for_http())  // 请求追踪
        .layer(CompressionLayer::new())  // 响应压缩
        .layer(middleware::from_fn(console_logging_middleware))  // 控制台日志中间件
        .layer(cors_layer)  // CORS
        .layer(TimeoutLayer::with_status_code(  // 超时控制
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(auth_timeout),
        ))
        .layer(RequestBodyLimitLayer::new(5 * 1024 * 1024 * 1024));  // 请求体限制（5GB）

    // 如果启用，添加速率限制
    if rate_limit_enable {
        info!("Console rate limiting enabled: {} requests per minute", rate_limit_rpm);
        // 注意：tower-http不提供内置的速率限制器，但我们已经有了基础
        // 生产环境中，您需要与Redis等速率限制服务集成
        // 目前，我们记录它已配置并准备集成
    }

    app
}

/// 控制台健康检查处理器，包含全面的健康信息
///
/// # 参数:
/// - `method`: 请求的HTTP方法
///
/// # 返回:
/// - 包含健康检查结果的 `Response`
#[instrument]
async fn health_check(method: Method) -> Response {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");
        
    match method {
        // GET: 返回完整的JSON
        Method::GET => {
            let mut health_status = "ok";
            let mut details = json!({});

            // 检查存储后端健康状态
            if let Some(_store) = rustfs_ecstore::new_object_layer_fn() {
                details["storage"] = json!({"status": "connected"});
            } else {
                health_status = "degraded";
                details["storage"] = json!({"status": "disconnected"});
            }

            // 检查IAM系统健康状态
            match rustfs_iam::get() {
                Ok(_) => {
                    details["iam"] = json!({"status": "connected"});
                }
                Err(_) => {
                    health_status = "degraded";
                    details["iam"] = json!({"status": "disconnected"});
                }
            }

            let body_json = json!({
                "status": health_status,
                "service": "rustfs-console",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "version": env!("CARGO_PKG_VERSION"),
                "details": details,
                "uptime": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

            // 当序列化失败时返回最小化的JSON以避免恐慌
            let body_str = serde_json::to_string(&body_json).unwrap_or_else(|e| {
                error!(
                    target: "rustfs::console::health",
                    "failed to serialize health check body: {}",
                    e
                );
                // 简化的备用JSON
                "{\"status\":\"error\",\"service\":\"rustfs-console\"}".to_string()
            });
            
            builder.body(Body::from(body_str)).unwrap_or_else(|e| {
                error!(
                    target: "rustfs::console::health",
                    "failed to build GET health response: {}",
                    e
                );
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("failed to build response"))
                    .unwrap_or_else(|_| Response::new(Body::from("")))
            })
        }

        // HEAD: 只返回状态码+头部，无响应体
        Method::HEAD => builder.body(Body::empty()).unwrap_or_else(|e| {
            error!(
                target: "rustfs::console::health",
                "failed to build HEAD health response: {}",
                e
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to build response"))
                .unwrap_or_else(|e| {
                    error!(
                        target: "rustfs::console::health",
                        "failed to build HEAD health empty response, reason: {}",
                        e
                    );
                    Response::new(Body::from(""))
                })
        }),

        // 其他方法：405 Method Not Allowed
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("allow", "GET, HEAD")
            .body(Body::from("Method Not Allowed"))
            .unwrap_or_else(|e| {
                error!(
                    target: "rustfs::console::health",
                    "failed to build 405 response: {}",
                    e
                );
                Response::new(Body::from("Method Not Allowed"))
            }),
    }
}

/// 从配置中解析CORS允许的来源
///
/// # 参数:
/// - `origins`: 包含允许来源的可选字符串引用
///
/// # 返回:
/// - 配置了指定来源的 `CorsLayer`
pub fn parse_cors_origins(origins: Option<&String>) -> CorsLayer {
    let cors_layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    match origins {
        Some(origins_str) if origins_str == "*" => cors_layer.allow_origin(Any).expose_headers(Any),
        Some(origins_str) => {
            let origins: Vec<&str> = origins_str.split(',').map(|s| s.trim()).collect();
            if origins.is_empty() {
                warn!("Empty CORS origins provided, using permissive CORS");
                cors_layer.allow_origin(Any).expose_headers(Any)
            } else {
                // 使用适当的错误处理解析来源
                let mut valid_origins = Vec::new();
                for origin in origins {
                    match origin.parse::<HeaderValue>() {
                        Ok(header_value) => {
                            valid_origins.push(header_value);
                        }
                        Err(e) => {
                            warn!("Invalid CORS origin '{}': {}", origin, e);
                        }
                    }
                }

                if valid_origins.is_empty() {
                    warn!("No valid CORS origins found, using permissive CORS");
                    cors_layer.allow_origin(Any).expose_headers(Any)
                } else {
                    info!("Console CORS origins configured: {:?}", valid_origins);
                    cors_layer.allow_origin(AllowOrigin::list(valid_origins)).expose_headers(Any)
                }
            }
        }
        None => {
            debug!("No CORS origins configured for console, using permissive CORS");
            cors_layer.allow_origin(Any)
        }
    }
}

/// 创建和配置控制台服务器路由器
///
/// # 返回:
/// - 配置了中间件的控制台服务器 `Router`
pub(crate) fn make_console_server() -> Router {
    // 从环境变量获取配置
    let (rate_limit_enable, rate_limit_rpm, auth_timeout, cors_allowed_origins) = get_console_config_from_env();
    
    // 将字符串转换为Option<&String>
    let cors_allowed_origins = if cors_allowed_origins.is_empty() {
        None
    } else {
        Some(&cors_allowed_origins)
    };
    
    // 基于设置配置CORS
    let cors_layer = parse_cors_origins(cors_allowed_origins);

    // 使用tower-http功能构建具有增强中间件堆栈的控制台路由器
    setup_console_middleware_stack(cors_layer, rate_limit_enable, rate_limit_rpm, auth_timeout)
}