// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 版权所有 2024 RustFS 团队
//
// 根据 Apache 许可证 2.0 版本（“许可证”）获得许可；
// 除非遵守许可证，否则您不得使用此文件。
// 您可以在以下网址获得许可证的副本：
//
//      http://www.apache.org/licenses-2.0
//
// 除非适用法律要求或书面同意，
// 根据“原样”基础分发的软件，
// 不附带任何明示或暗示的保证或条件。
// 有关特定语言的管理权限和
// 限制，请参阅许可证。

use super::router::AdminOperation; // 导入管理员操作类型
use super::router::Operation; // 导入操作特征
use super::router::S3Router; // 导入 S3 路由结构体
use futures::StreamExt; // 导入 StreamExt 特征，用于处理流
use http::StatusCode; // 导入 HTTP 状态码
use hyper::Method; // 导入 HTTP 方法 (GET, PUT, HEAD)
use matchit::Params; // 导入 matchit 库中的 Params，用于存储路由参数
use rustfs_config::MAX_ADMIN_REQUEST_BODY_SIZE; // 导入管理员请求的最大请求体大小配置
use rustfs_ecstore::disk::DiskAPI; // 导入 DiskAPI 特征，用于磁盘操作
use rustfs_ecstore::disk::WalkDirOptions; // 导入 WalkDirOptions 结构体，用于目录遍历选项
use rustfs_ecstore::set_disk::DEFAULT_READ_BUFFER_SIZE; // 导入默认读取缓冲区大小
use rustfs_ecstore::store::find_local_disk; // 导入查找本地磁盘的函数
use rustfs_utils::net::bytes_stream; // 导入用于将异步读取器转换为字节流的函数
use s3s::Body; // 导入 S3 服务的 Body 类型
use s3s::S3Request; // 导入 S3 请求类型
use s3s::S3Response; // 导入 S3 响应类型
use s3s::S3Result; // 导入 S3 结果类型
use s3s::dto::StreamingBlob; // 导入用于流式传输的 StreamingBlob
use s3s::s3_error; // 导入用于创建 S3 错误的宏
use serde_urlencoded::from_bytes; // 导入用于从字节反序列化 URL 编码查询参数的函数
use tokio::io::AsyncWriteExt; // 导入 Tokio 异步写入特性
use tokio_util::io::ReaderStream; // 导入用于将异步读取器转换为流的 ReaderStream
use tracing::warn; // 导入用于警告日志记录的 warn 宏

pub const RPC_PREFIX: &str = "/rustfs/rpc"; // 远程过程调用 (RPC) 路由前缀

// 注册 RPC 路由
pub fn register_rpc_route(r: &mut S3Router<AdminOperation>) -> std::io::Result<()> {
    // 注册 GET /rustfs/rpc/read_file_stream 路由
    r.insert(
        Method::GET,
        format!("{}{}", RPC_PREFIX, "/read_file_stream").as_str(),
        AdminOperation(&ReadFile {}),
    )?;

    // 注册 HEAD /rustfs/rpc/read_file_stream 路由 (用于检查文件是否存在/元数据)
    r.insert(
        Method::HEAD,
        format!("{}{}", RPC_PREFIX, "/read_file_stream").as_str(),
        AdminOperation(&ReadFile {}),
    )?;

    // 注册 PUT /rustfs/rpc/put_file_stream 路由
    r.insert(
        Method::PUT,
        format!("{}{}", RPC_PREFIX, "/put_file_stream").as_str(),
        AdminOperation(&PutFile {}),
    )?;

    // 注册 GET /rustfs/rpc/walk_dir 路由
    r.insert(
        Method::GET,
        format!("{}{}", RPC_PREFIX, "/walk_dir").as_str(),
        AdminOperation(&WalkDir {}),
    )?;

    // 注册 HEAD /rustfs/rpc/walk_dir 路由
    r.insert(
        Method::HEAD,
        format!("{}{}", RPC_PREFIX, "/walk_dir").as_str(),
        AdminOperation(&WalkDir {}),
    )?;

    Ok(())
}

// /rustfs/rpc/read_file_stream?disk={}&volume={}&path={}&offset={}&length={}"
// 读取文件请求的查询参数结构体
#[derive(Debug, Default, serde::Deserialize)]
pub struct ReadFileQuery {
    disk: String, // 磁盘名称
    volume: String, // 卷名称
    path: String, // 文件路径
    offset: usize, // 读取起始偏移量
    length: usize, // 读取长度
}

// ReadFile 操作结构体
pub struct ReadFile {}

#[async_trait::async_trait]
impl Operation for ReadFile {
    // 处理 ReadFile RPC 请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 如果是 HEAD 请求，只返回 200 OK 状态码，不返回内容
        if req.method == Method::HEAD {
            return Ok(S3Response::new((StatusCode::OK, Body::empty())));
        }
        
        // 解析 URL 查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                // 将 URL 编码的查询字符串反序列化为 ReadFileQuery
                let input: ReadFileQuery =
                    from_bytes(query.as_bytes()).map_err(|e| s3_error!(InvalidArgument, "get query failed1 {:?}", e))?;
                input
            } else {
                // 如果没有查询参数，则使用默认值
                ReadFileQuery::default()
            }
        };

        // 查找本地磁盘
        let Some(disk) = find_local_disk(&query.disk).await else {
            return Err(s3_error!(InvalidArgument, "disk not found")); // 如果未找到磁盘，返回 InvalidArgument 错误
        };

        // 从磁盘获取文件读取流
        let file = disk
            .read_file_stream(&query.volume, &query.path, query.offset, query.length)
            .await
            .map_err(|e| s3_error!(InternalError, "read file err {}", e))?; // 如果读取失败，返回 InternalError

        // 返回 S3 响应，包含文件内容的流
        Ok(S3Response::new((
            StatusCode::OK,
            Body::from(StreamingBlob::wrap(bytes_stream( // 将异步读取器转换为字节流
                ReaderStream::with_capacity(file, DEFAULT_READ_BUFFER_SIZE), // 使用指定容量的 ReaderStream
                query.length, // 指定流的长度
            ))),
        )))
    }
}

// WalkDir 请求的查询参数结构体
#[derive(Debug, Default, serde::Deserialize)]
pub struct WalkDirQuery {
    disk: String, // 磁盘名称
}

// WalkDir 操作结构体
pub struct WalkDir {}

#[async_trait::async_trait]
impl Operation for WalkDir {
    // 处理 WalkDir RPC 请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 如果是 HEAD 请求，只返回 200 OK 状态码
        if req.method == Method::HEAD {
            return Ok(S3Response::new((StatusCode::OK, Body::empty())));
        }

        // 解析 URL 查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: WalkDirQuery =
                    from_bytes(query.as_bytes()).map_err(|e| s3_error!(InvalidArgument, "get query failed1 {:?}", e))?;
                input
            } else {
                WalkDirQuery::default()
            }
        };

        let mut input = req.input;
        // 读取请求体，并限制大小
        let body = match input.store_all_limited(MAX_ADMIN_REQUEST_BODY_SIZE).await {
            Ok(b) => b,
            Err(e) => {
                warn!("get body failed, e: {:?}", e);
                return Err(s3_error!(InvalidRequest, "RPC request body too large or failed to read"));
            }
        };

        // 将请求体（包含 WalkDirOptions）从 JSON 反序列化
        let args: WalkDirOptions =
            serde_json::from_slice(&body).map_err(|e| s3_error!(InternalError, "unmarshal body err {}", e))?;
        
        // 查找本地磁盘
        let Some(disk) = find_local_disk(&query.disk).await else {
            return Err(s3_error!(InvalidArgument, "disk not found"));
        };

        // 创建一个异步双工通道 (Duplex pipe)，用于在两个异步任务间传输数据
        let (rd, mut wd) = tokio::io::duplex(DEFAULT_READ_BUFFER_SIZE);

        // 启动一个异步任务来执行目录遍历
        tokio::spawn(async move {
            // walk_dir 的输出会写入到 wd (写入端)
            if let Err(e) = disk.walk_dir(args, &mut wd).await {
                warn!("walk dir err {}", e);
            }
            // 当 walk_dir 完成或失败时，wd 将关闭，这会结束 rd 上的流
        });

        // 将读取端 (rd) 包装成流并作为响应体返回
        let body = Body::from(StreamingBlob::wrap(ReaderStream::with_capacity(rd, DEFAULT_READ_BUFFER_SIZE)));
        Ok(S3Response::new((StatusCode::OK, body)))
    }
}

// /rustfs/rpc/put_file_stream?disk={}&volume={}&path={}&append={}&size={}"
// 写入文件请求的查询参数结构体
#[derive(Debug, Default, serde::Deserialize)]
pub struct PutFileQuery {
    disk: String, // 磁盘名称
    volume: String, // 卷名称
    path: String, // 文件路径
    append: bool, // 是否以追加模式写入
    size: i64, // 文件大小
}

// PutFile 操作结构体
pub struct PutFile {}

#[async_trait::async_trait]
impl Operation for PutFile {
    // 处理 PutFile RPC 请求
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        // 解析 URL 查询参数
        let query = {
            if let Some(query) = req.uri.query() {
                let input: PutFileQuery =
                    from_bytes(query.as_bytes()).map_err(|e| s3_error!(InvalidArgument, "get query failed1 {:?}", e))?;
                input
            } else {
                PutFileQuery::default()
            }
        };

        // 查找本地磁盘
        let Some(disk) = find_local_disk(&query.disk).await else {
            return Err(s3_error!(InvalidArgument, "disk not found"));
        };

        // 根据 append 标志创建文件或获取文件追加句柄
        let mut file = if query.append {
            // 追加文件
            disk.append_file(&query.volume, &query.path)
                .await
                .map_err(|e| s3_error!(InternalError, "append file err {}", e))?
        } else {
            // 创建新文件
            disk.create_file("", &query.volume, &query.path, query.size)
                .await
                .map_err(|e| s3_error!(InternalError, "read file err {}", e))?
        };

        // 从请求体流中读取数据并写入文件
        let mut body = req.input;
        while let Some(item) = body.next().await {
            // 获取字节块
            let bytes = item.map_err(|e| s3_error!(InternalError, "body stream err {}", e))?;
            // 写入文件
            let result = file.write_all(&bytes).await;
            result.map_err(|e| s3_error!(InternalError, "write file err {}", e))?;
        }

        // 写入完成后，返回 200 OK
        Ok(S3Response::new((StatusCode::OK, Body::empty())))
    }
}