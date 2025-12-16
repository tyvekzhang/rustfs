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

// 导入管理前缀常量
use crate::admin::ADMIN_PREFIX;
// 导入控制台路径判断函数
use crate::admin::console::is_console_path;
// 导入创建控制台服务器的函数
use crate::admin::console::make_console_server;
// 导入 RPC 前缀常量
use crate::admin::rpc::RPC_PREFIX;
// 导入 hyper 库中的 HeaderMap
use hyper::HeaderMap;
// 导入 hyper 库中的 Method (HTTP 方法)
use hyper::Method;
// 导入 hyper 库中的 StatusCode (HTTP 状态码)
use hyper::StatusCode;
// 导入 hyper 库中的 Uri (统一资源标识符)
use hyper::Uri;
// 导入 hyper 库中的 Extensions (请求扩展)
use hyper::http::Extensions;
// 导入 matchit 库中的 Params (路由参数)
use matchit::Params;
// 导入 matchit 库中的 Router (路由)
use matchit::Router;
// 导入 RPC 签名验证函数
use rustfs_ecstore::rpc::verify_rpc_signature;
// 导入 s3s 库中的 Body (请求/响应体)
use s3s::Body;
// 导入 s3s 库中的 S3Request (S3 请求)
use s3s::S3Request;
// 导入 s3s 库中的 S3Response (S3 响应)
use s3s::S3Response;
// 导入 s3s 库中的 S3Result (S3 结果类型)
use s3s::S3Result;
// 导入 s3s 库中的 header 模块
use s3s::header;
// 导入 s3s 库中的 S3Route trait
use s3s::route::S3Route;
// 导入 s3s 库中的 s3_error! 宏
use s3s::s3_error;
// 导入 tower 库中的 Service trait
use tower::Service;
// 导入 tracing 库中的 error! 宏
use tracing::error;

// S3Router 结构体，用于路由 S3 请求到对应的操作
pub struct S3Router<T> {
    // 路由，存储 HTTP 方法 + 路径 字符串到操作 T 的映射
    router: Router<T>,
    // 标志，指示控制台是否启用
    console_enabled: bool,
    // 可选的控制台路由服务
    console_router: Option<axum::routing::RouterIntoService<Body>>,
}

// S3Router 的实现块，T 必须实现 Operation trait
impl<T: Operation> S3Router<T> {
    // 构造函数
    pub fn new(console_enabled: bool) -> Self {
        // 创建新的 matchit 路由
        let router = Router::new();

        // 根据 console_enabled 决定是否创建控制台路由服务
        let console_router = if console_enabled {
            // 创建控制台服务器并转换为 Service
            Some(make_console_server().into_service::<Body>())
        } else {
            None
        };

        Self {
            router,
            console_enabled,
            console_router,
        }
    }

    // 插入一个路由规则，将指定的 HTTP 方法和路径映射到操作 T
    pub fn insert(&mut self, method: Method, path: &str, operation: T) -> std::io::Result<()> {
        // 构造路由字符串，格式为 "METHOD|PATH"
        let path = Self::make_route_str(method, path);

        // warn!("set uri {}", &path);

        // 插入到 matchit 路由中，并将 matchit::Error 转换为 std::io::Error
        self.router.insert(path, operation).map_err(std::io::Error::other)?;

        Ok(())
    }

    // 辅助函数：构造路由字符串，格式为 "METHOD|PATH"
    fn make_route_str(method: Method, path: &str) -> String {
        format!("{}|{}", method.as_str(), path)
    }
}

// S3Router 的 Default 实现
impl<T: Operation> Default for S3Router<T> {
    fn default() -> Self {
        // 默认情况下控制台未启用
        Self::new(false)
    }
}

// 为 S3Router 实现 s3s 库的 S3Route trait
#[async_trait::async_trait]
impl<T> S3Route for S3Router<T>
where
    T: Operation, // T 必须实现 Operation trait
{
    // 检查请求是否应由本路由器处理
    fn is_match(&self, method: &Method, uri: &Uri, headers: &HeaderMap, _: &mut Extensions) -> bool {
        let path = uri.path();
        // 性能分析端点 (GET /profile/cpu, /profile/memory)
        if method == Method::GET && (path == "/profile/cpu" || path == "/profile/memory") {
            return true;
        }

        // 健康检查端点 (HEAD/GET /health)
        if (method == Method::HEAD || method == Method::GET) && path == "/health" {
            return true;
        }

        // AssumeRole 接口 (POST /，且 Content-Type 为 x-www-form-urlencoded)
        if method == Method::POST && path == "/" {
            if let Some(val) = headers.get(header::CONTENT_TYPE) {
                if val.as_bytes() == b"application/x-www-form-urlencoded" {
                    return true;
                }
            }
        }

        // 如果路径以 ADMIN_PREFIX 或 RPC_PREFIX 开头，或者是一个控制台路径
        path.starts_with(ADMIN_PREFIX) || path.starts_with(RPC_PREFIX) || is_console_path(path)
    }

    // 在调用操作之前进行访问检查（鉴权）
    async fn check_access(&self, req: &mut S3Request<Body>) -> S3Result<()> {
        let path = req.uri.path();

        // 允许未认证访问性能分析端点
        if req.method == Method::GET && (path == "/profile/cpu" || path == "/profile/memory") {
            return Ok(());
        }

        // 允许未认证访问健康检查端点
        if (req.method == Method::HEAD || req.method == Method::GET) && path == "/health" {
            return Ok(());
        }

        // 如果控制台启用，允许未认证访问控制台静态文件
        if self.console_enabled && is_console_path(path) {
            return Ok(());
        }

        // 检查 RPC 签名验证
        if req.uri.path().starts_with(RPC_PREFIX) {
            // 跳过 HEAD 请求的签名验证 (HEAD 通常用于健康检查)
            if req.method != Method::HEAD {
                // 验证 RPC 签名
                verify_rpc_signature(&req.uri.to_string(), &req.method, &req.headers).map_err(|e| {
                    error!("RPC signature verification failed: {}", e);
                    // 签名验证失败，返回 AccessDenied S3 错误
                    s3_error!(AccessDenied, "{}", e)
                })?;
            }
            return Ok(());
        }

        // 对于非 RPC 的管理请求，检查凭证
        match req.credentials {
            // 如果存在凭证，则通过
            Some(_) => Ok(()),
            // 如果没有凭证，则返回 AccessDenied 错误
            None => Err(s3_error!(AccessDenied, "Signature is required")),
        }
    }

    // 处理请求并返回 S3 响应
    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        // 如果是控制台路径且控制台启用
        if self.console_enabled && is_console_path(req.uri.path()) {
            if let Some(console_router) = &self.console_router {
                // 克隆控制台路由服务
                let mut console_router = console_router.clone();
                // 将 S3Request 转换为 hyper/http::Request
                let req = convert_request(req);
                // 调用控制台路由服务
                let result = console_router.call(req).await;
                return match result {
                    // 成功：将 hyper/http::Response 转换为 S3Response
                    Ok(resp) => Ok(convert_response(resp)),
                    // 失败：返回 InternalError S3 错误
                    Err(e) => Err(s3_error!(InternalError, "{}", e)),
                };
            }
            // 控制台未启用（理论上不应该发生，因为前面的 is_match 已经处理了）
            return Err(s3_error!(InternalError, "console is not enabled"));
        }

        // 构造用于路由查找的字符串 "METHOD|PATH"
        let uri = format!("{}|{}", &req.method, req.uri.path());
        // 尝试匹配路由
        if let Ok(mat) = self.router.at(&uri) {
            // 获取匹配到的操作
            let op: &T = mat.value;
            // 调用操作，传递 S3 请求和路由参数
            let mut resp = op.call(req, mat.params).await?;
            // 设置响应状态码
            resp.status = Some(resp.output.0);
            // 映射响应体，去除状态码，只保留 Body
            return Ok(resp.map_output(|x| x.1));
        }

        // 如果没有找到匹配的路由，返回 NotImplemented S3 错误
        Err(s3_error!(NotImplemented))
    }
}

// Operation trait 定义了管理操作的接口
#[async_trait::async_trait]
pub trait Operation: Send + Sync + 'static {
    // async fn method() -> Method; // 路由方法 (注释掉)
    // async fn uri() -> &'static str; // 路由 URI (注释掉)
    // 异步调用方法，接收 S3 请求和路由参数，返回 S3 响应（包含 HTTP 状态码和 Body）
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>>;
}

// AdminOperation 结构体，是对 Operation trait 对象的简单包装
pub struct AdminOperation(pub &'static dyn Operation);

// 为 AdminOperation 实现 Operation trait
#[async_trait::async_trait]
impl Operation for AdminOperation {
    // 转发调用到内部的 Operation trait 对象
    async fn call(&self, req: S3Request<Body>, params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        self.0.call(req, params).await
    }
}

// 额外的请求信息结构体，用于在 S3Request 和 http::Request 之间转换时存储信息
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Extra {
    pub credentials: Option<s3s::auth::Credentials>,
    pub region: Option<String>,
    pub service: Option<String>,
}

// 将 s3s::S3Request<Body> 转换为 http::Request<Body> (用于控制台路由)
fn convert_request(req: S3Request<Body>) -> http::Request<Body> {
    // 创建一个空的 http::Request 并解构其 parts
    let (mut parts, _) = http::Request::new(Body::empty()).into_parts();
    // 复制 S3Request 的 method, uri, headers, extensions
    parts.method = req.method;
    parts.uri = req.uri;
    parts.headers = req.headers;
    parts.extensions = req.extensions;
    // 将 S3Request 中的额外信息 (credentials, region, service) 插入到 extensions 中
    parts.extensions.insert(Extra {
        credentials: req.credentials,
        region: req.region,
        service: req.service,
    });
    // 使用新的 parts 和原始请求体构造 http::Request
    http::Request::from_parts(parts, req.input)
}

// 将 http::Response<axum::body::Body> 转换为 s3s::S3Response<Body> (用于控制台路由)
fn convert_response(resp: http::Response<axum::body::Body>) -> S3Response<Body> {
    // 解构 http::Response
    let (parts, body) = resp.into_parts();
    // 创建一个新的 S3Response，将 axum::body::Body 转换为 s3s::Body
    let mut s3_resp = S3Response::new(Body::http_body_unsync(body));
    // 复制 status, headers, extensions
    s3_resp.status = Some(parts.status);
    s3_resp.headers = parts.headers;
    s3_resp.extensions = parts.extensions;
    s3_resp
}