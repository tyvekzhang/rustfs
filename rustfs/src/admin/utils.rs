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

// 检查字符串 s 是否在其开头或结尾包含空格（' '）。
pub(crate) fn has_space_be(s: &str) -> bool {
    // s.trim() 返回一个删除了开头和结尾空白字符的字符串切片。
    // 如果修剪后的长度不等于原始长度，则表示存在前导或尾随空格。
    s.trim().len() != s.len()
}