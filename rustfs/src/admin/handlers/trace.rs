// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 版权所有 2024 RustFS 团队
//
// 遵循 Apache 许可证 2.0 版本 ("License") 许可；
// 除非遵守许可证，否则不得使用此文件。
// 您可以在以下地址获取许可证副本：
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，
// 根据“AS IS”基础分发的软件，不附带任何明示或暗示的保证或条件。
// 有关特定语言的管理权限和限制，请参阅许可证。

use http::StatusCode; // 引入 http 库的 StatusCode，用于 HTTP 状态码
use hyper::Uri; // 引入 hyper 库的 Uri，用于统一资源标识符
use matchit::Params; // 引入 matchit 库的 Params，用于路由匹配的参数
use rustfs_ecstore::{GLOBAL_Endpoints, rpc::PeerRestClient}; // 引入 rustfs_ecstore 库的相关项，包括全局端点和 RPC 客户端
use rustfs_madmin::service_commands::ServiceTraceOpts; // 引入 rustfs_madmin 库的服务追踪选项
use s3s::{Body, S3Request, S3Response, S3Result, s3_error}; // 引入 s3s 库的核心类型和错误宏
use tracing::warn; // 引入 tracing 库的 warn 宏，用于记录警告信息

use crate::admin::router::Operation; // 引入本地 admin 模块中 router 模块的 Operation trait

// 允许 dead_code (未使用的代码) 警告
#[allow(dead_code)]
// 函数：从 Uri 中提取追踪选项
fn extract_trace_options(uri: &Uri) -> S3Result<ServiceTraceOpts> {
    // 创建默认的服务追踪选项
  let mut st_opts = ServiceTraceOpts::default();
    // 解析 Uri 中的参数，如果失败则返回 InvalidRequest 错误
  st_opts
    .parse_params(uri)
    .map_err(|_| s3_error!(InvalidRequest, "invalid params"))?;

    // 返回解析后的追踪选项
  Ok(st_opts)
}

// 允许 dead_code (未使用的代码) 警告
#[allow(dead_code)]
// 结构体：Trace 操作
pub struct Trace {}

// 为 Trace 结构体实现 Operation trait，使用 async_trait 宏处理异步
#[async_trait::async_trait]
impl Operation for Trace {
    // 异步方法：处理 S3 请求
  async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 记录警告信息
    warn!("handle Trace");

        // 提取追踪选项（目前未使用 _trace_opts，但保留调用）
    let _trace_opts = extract_trace_options(&req.uri)?;

        // 注释掉的代码：// let (tx, rx) = mpsc::channel(10000);

        // 尝试从全局端点获取 PeerRestClient 客户端
    let _peers = match GLOBAL_Endpoints.get() {
            // 如果获取到端点，则创建新的客户端
      Some(ep) => PeerRestClient::new_clients(ep.clone()).await,
            // 否则返回空的 Vec
      None => (Vec::new(), Vec::new()),
    };
        // 当前实现返回 NotImplemented 错误，表示功能尚未实现
    Err(s3_error!(NotImplemented))
  }
}