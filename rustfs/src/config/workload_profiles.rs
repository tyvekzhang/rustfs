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

// 版权所有 2024 RustFS 团队
//
// 根据 Apache 许可证 2.0 版（“许可证”）获得许可；
// 除非遵守许可证，否则您不得使用此文件。
// 您可以在以下位置获取许可证的副本：
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，
// 根据“原样”基础分发的软件，
// 不附带任何明示或暗示的保证或条件。
// 请参阅许可证以了解特定语言的权限和限制。

#![allow(dead_code)] // 允许存在未使用的代码（例如私有函数或结构体字段，如果它们是通过公共 API 间接使用的）

//! Adaptive buffer sizing optimization for different workload types.
//!
//! This module provides intelligent buffer size selection based on file size and workload profile
//! to achieve optimal balance between performance, memory usage, and security.

// 针对不同工作负载类型的自适应缓冲区大小优化。
//
// 此模块根据文件大小和工作负载配置文件提供智能的缓冲区大小选择，
// 以实现在性能、内存使用和安全性之间的最佳平衡。

use rustfs_config::{KI_B, MI_B}; // 导入配置中的 KB 和 MB 常量
use std::sync::OnceLock; // 导入 OnceLock 用于全局单次初始化
use std::sync::atomic::{AtomicBool, Ordering}; // 导入原子布尔值和内存排序

/// Global buffer configuration that can be set at application startup
static GLOBAL_BUFFER_CONFIG: OnceLock<RustFSBufferConfig> = OnceLock::new();
// 全局缓冲区配置，可在应用启动时设置（OnceLock 确保只初始化一次）

/// Global flag indicating whether buffer profiles are enabled
static BUFFER_PROFILE_ENABLED: AtomicBool = AtomicBool::new(false);
// 全局标志，指示缓冲区配置文件是否启用（使用 AtomicBool 实现线程安全的布尔值）

/// Enable or disable buffer profiling globally
///
/// This controls whether the opt-in buffer profiling feature is active.
///
/// # Arguments
/// * `enabled` - Whether to enable buffer profiling
pub fn set_buffer_profile_enabled(enabled: bool) {
    // 全局启用或禁用缓冲区性能分析（Profiling）
    //
    // 这控制了可选的缓冲区性能分析功能是否激活。
    //
    // # 参数
    // * `enabled` - 是否启用缓冲区性能分析
    BUFFER_PROFILE_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if buffer profiling is enabled globally
pub fn is_buffer_profile_enabled() -> bool {
    // 检查缓冲区性能分析是否全局启用
    BUFFER_PROFILE_ENABLED.load(Ordering::Relaxed)
}

/// Initialize the global buffer configuration
///
/// This should be called once at application startup with the desired profile.
/// If not called, the default GeneralPurpose profile will be used.
///
/// # Arguments
/// * `config` - The buffer configuration to use globally
///
/// # Examples
/// ```ignore
/// use rustfs::config::workload_profiles::{RustFSBufferConfig, WorkloadProfile};
///
/// // Initialize with AiTraining profile
/// init_global_buffer_config(RustFSBufferConfig::new(WorkloadProfile::AiTraining));
/// ```
pub fn init_global_buffer_config(config: RustFSBufferConfig) {
    // 初始化全局缓冲区配置
    //
    // 这应该在应用启动时调用一次，传入所需的配置文件。
    // 如果不调用，将使用默认的 GeneralPurpose（通用目的）配置文件。
    //
    // # 参数
    // * `config` - 要全局使用的缓冲区配置
    let _ = GLOBAL_BUFFER_CONFIG.set(config); // 尝试设置配置，忽略设置结果（如果是第二次设置则失败）
}

/// Get the global buffer configuration
///
/// Returns the configured profile, or GeneralPurpose if not initialized.
pub fn get_global_buffer_config() -> &'static RustFSBufferConfig {
    // 获取全局缓冲区配置
    //
    // 返回已配置的配置文件，如果未初始化则返回 GeneralPurpose（通用目的）配置文件。
    GLOBAL_BUFFER_CONFIG.get_or_init(RustFSBufferConfig::default)
}

/// Workload profile types that define buffer sizing strategies
#[derive(Debug, Clone, PartialEq)]
pub enum WorkloadProfile {
    /// General purpose - default configuration with balanced performance and memory
    GeneralPurpose, // 通用目的 - 默认配置，性能和内存平衡
    /// AI/ML training: optimized for large sequential reads with maximum throughput
    AiTraining, // AI/ML 训练：针对大顺序读取优化，追求最大吞吐量
    /// Data analytics: mixed read-write patterns with moderate buffer sizes
    DataAnalytics, // 数据分析：混合读写模式，适度的缓冲区大小
    /// Web workloads: small file intensive with minimal memory overhead
    WebWorkload, // Web 工作负载：小文件密集型，最小化内存开销
    /// Industrial IoT: real-time streaming with low latency priority
    IndustrialIoT, // 工业物联网：实时流传输，低延迟优先
    /// Secure storage: security first, memory constrained for compliance
    SecureStorage, // 安全存储：安全优先，为合规性限制内存
    /// Custom configuration for specialized requirements
    Custom(BufferConfig), // 自定义配置，用于特殊需求
}

/// Buffer size configuration for adaptive buffering
#[derive(Debug, Clone, PartialEq)]
pub struct BufferConfig {
    /// Minimum buffer size in bytes (for very small files or memory-constrained environments)
    pub min_size: usize, // 最小缓冲区大小（字节），适用于非常小的文件或内存受限环境
    /// Maximum buffer size in bytes (cap for large files to prevent excessive memory usage)
    pub max_size: usize, // 最大缓冲区大小（字节），用于限制大文件以防止过度内存使用
    /// Default size for unknown file size scenarios (streaming/chunked uploads)
    pub default_unknown: usize, // 针对未知文件大小场景（流式传输/分块上传）的默认大小
    /// File size thresholds and corresponding buffer sizes: (file_size_threshold, buffer_size)
    /// Thresholds should be in ascending order
    pub thresholds: Vec<(i64, usize)>, // 文件大小阈值及其对应的缓冲区大小：(文件大小阈值, 缓冲区大小)
                                      // 阈值应按升序排列
}

/// Complete buffer configuration for RustFS
#[derive(Debug, Clone)]
pub struct RustFSBufferConfig {
    /// Selected workload profile
    pub workload: WorkloadProfile, // 选定的工作负载配置文件
    /// Computed buffer configuration (either from profile or custom)
    pub base_config: BufferConfig, // 计算出的基本缓冲区配置（来自配置文件或自定义）
}

impl WorkloadProfile {
    /// Parse a workload profile from a string name
    ///
    /// # Arguments
    /// * `name` - The name of the profile (case-insensitive)
    ///
    /// # Returns
    /// The corresponding WorkloadProfile, or GeneralPurpose if name is not recognized
    ///
    /// # Examples
    /// ```
    /// use rustfs::config::workload_profiles::WorkloadProfile;
    ///
    /// let profile = WorkloadProfile::from_name("AiTraining");
    /// let profile2 = WorkloadProfile::from_name("aitraining"); // case-insensitive
    /// let profile3 = WorkloadProfile::from_name("unknown"); // defaults to GeneralPurpose
    /// ```
    pub fn from_name(name: &str) -> Self {
        // 从字符串名称解析工作负载配置文件
        //
        // # 参数
        // * `name` - 配置文件的名称（不区分大小写）
        //
        // # 返回值
        // 对应的 WorkloadProfile，如果名称无法识别，则返回 GeneralPurpose
        match name.to_lowercase().as_str() {
            "generalpurpose" | "general" => WorkloadProfile::GeneralPurpose, // 通用目的
            "aitraining" | "ai" => WorkloadProfile::AiTraining, // AI/ML 训练
            "dataanalytics" | "analytics" => WorkloadProfile::DataAnalytics, // 数据分析
            "webworkload" | "web" => WorkloadProfile::WebWorkload, // Web 工作负载
            "industrialiot" | "iot" => WorkloadProfile::IndustrialIoT, // 工业物联网
            "securestorage" | "secure" => WorkloadProfile::SecureStorage, // 安全存储
            _ => {
                // Default to GeneralPurpose for unknown profiles
                // 对于未知配置文件，默认使用 GeneralPurpose
                WorkloadProfile::GeneralPurpose
            }
        }
    }

    /// Get the buffer configuration for this workload profile
    pub fn config(&self) -> BufferConfig {
        // 获取此工作负载配置文件的缓冲区配置
        match self {
            WorkloadProfile::GeneralPurpose => Self::general_purpose_config(),
            WorkloadProfile::AiTraining => Self::ai_training_config(),
            WorkloadProfile::DataAnalytics => Self::data_analytics_config(),
            WorkloadProfile::WebWorkload => Self::web_workload_config(),
            WorkloadProfile::IndustrialIoT => Self::industrial_iot_config(),
            WorkloadProfile::SecureStorage => Self::secure_storage_config(),
            WorkloadProfile::Custom(config) => config.clone(),
        }
    }

    /// General purpose configuration: balanced performance and memory usage
    /// - Small files (< 1MB): 64KB buffer
    /// - Medium files (1MB-100MB): 256KB buffer
    /// - Large files (>= 100MB): 1MB buffer
    fn general_purpose_config() -> BufferConfig {
        // 通用目的配置：平衡性能和内存使用
        // - 小文件 (< 1MB): 64KB 缓冲区
        // - 中等文件 (1MB-100MB): 256KB 缓冲区
        // - 大文件 (>= 100MB): 1MB 缓冲区
        BufferConfig {
            min_size: 64 * KI_B,
            max_size: MI_B,
            default_unknown: MI_B,
            thresholds: vec![
                (MI_B as i64, 64 * KI_B),        // < 1MB: 64KB
                (100 * MI_B as i64, 256 * KI_B), // 1MB-100MB: 256KB
                (i64::MAX, MI_B),                // >= 100MB: 1MB
            ],
        }
    }

    /// AI/ML training configuration: optimized for large sequential reads
    /// - Small files (< 10MB): 512KB buffer
    /// - Medium files (10MB-500MB): 2MB buffer
    /// - Large files (>= 500MB): 4MB buffer for maximum throughput
    fn ai_training_config() -> BufferConfig {
        // AI/ML 训练配置：针对大顺序读取优化
        // - 小文件 (< 10MB): 512KB 缓冲区
        // - 中等文件 (10MB-500MB): 2MB 缓冲区
        // - 大文件 (>= 500MB): 4MB 缓冲区以获得最大吞吐量
        BufferConfig {
            min_size: 512 * KI_B,
            max_size: 4 * MI_B,
            default_unknown: 2 * MI_B,
            thresholds: vec![
                (10 * MI_B as i64, 512 * KI_B), // < 10MB: 512KB
                (500 * MI_B as i64, 2 * MI_B),  // 10MB-500MB: 2MB
                (i64::MAX, 4 * MI_B),           // >= 500MB: 4MB
            ],
        }
    }

    /// Data analytics configuration: mixed read-write patterns
    /// - Small files (< 5MB): 128KB buffer
    /// - Medium files (5MB-200MB): 512KB buffer
    /// - Large files (>= 200MB): 2MB buffer
    fn data_analytics_config() -> BufferConfig {
        // 数据分析配置：混合读写模式
        // - 小文件 (< 5MB): 128KB 缓冲区
        // - 中等文件 (5MB-200MB): 512KB 缓冲区
        // - 大文件 (>= 200MB): 2MB 缓冲区
        BufferConfig {
            min_size: 128 * KI_B,
            max_size: 2 * MI_B,
            default_unknown: 512 * KI_B,
            thresholds: vec![
                (5 * MI_B as i64, 128 * KI_B),   // < 5MB: 128KB
                (200 * MI_B as i64, 512 * KI_B), // 5MB-200MB: 512KB
                (i64::MAX, 2 * MI_B),            // >= 200MB: 2MB
            ],
        }
    }

    /// Web workload configuration: small file intensive
    /// - Small files (< 512KB): 32KB buffer to minimize memory
    /// - Medium files (512KB-10MB): 128KB buffer
    /// - Large files (>= 10MB): 256KB buffer (rare for web assets)
    fn web_workload_config() -> BufferConfig {
        // Web 工作负载配置：小文件密集型
        // - 小文件 (< 512KB): 32KB 缓冲区以最小化内存
        // - 中等文件 (512KB-10MB): 128KB 缓冲区
        // - 大文件 (>= 10MB): 256KB 缓冲区（对于 Web 资产很少见）
        BufferConfig {
            min_size: 32 * KI_B,
            max_size: 256 * KI_B,
            default_unknown: 128 * KI_B,
            thresholds: vec![
                (512 * KI_B as i64, 32 * KI_B), // < 512KB: 32KB
                (10 * MI_B as i64, 128 * KI_B), // 512KB-10MB: 128KB
                (i64::MAX, 256 * KI_B),         // >= 10MB: 256KB
            ],
        }
    }

    /// Industrial IoT configuration: real-time streaming with low latency
    /// - Small files (< 1MB): 64KB buffer for quick processing
    /// - Medium files (1MB-50MB): 256KB buffer
    /// - Large files (>= 50MB): 512KB buffer (cap for memory constraints)
    fn industrial_iot_config() -> BufferConfig {
        // 工业物联网配置：实时流传输，低延迟优先
        // - 小文件 (< 1MB): 64KB 缓冲区以便快速处理
        // - 中等文件 (1MB-50MB): 256KB 缓冲区
        // - 大文件 (>= 50MB): 512KB 缓冲区（内存限制的上限）
        BufferConfig {
            min_size: 64 * KI_B,
            max_size: 512 * KI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![
                (MI_B as i64, 64 * KI_B),       // < 1MB: 64KB
                (50 * MI_B as i64, 256 * KI_B), // 1MB-50MB: 256KB
                (i64::MAX, 512 * KI_B),         // >= 50MB: 512KB
            ],
        }
    }

    /// Secure storage configuration: security first, memory constrained
    /// - Small files (< 1MB): 32KB buffer (minimal memory footprint)
    /// - Medium files (1MB-50MB): 128KB buffer
    /// - Large files (>= 50MB): 256KB buffer (strict memory limit for compliance)
    fn secure_storage_config() -> BufferConfig {
        // 安全存储配置：安全优先，内存受限
        // - 小文件 (< 1MB): 32KB 缓冲区（最小内存占用）
        // - 中等文件 (1MB-50MB): 128KB 缓冲区
        // - 大文件 (>= 50MB): 256KB 缓冲区（为合规性设置严格的内存限制）
        BufferConfig {
            min_size: 32 * KI_B,
            max_size: 256 * KI_B,
            default_unknown: 128 * KI_B,
            thresholds: vec![
                (MI_B as i64, 32 * KI_B),       // < 1MB: 32KB
                (50 * MI_B as i64, 128 * KI_B), // 1MB-50MB: 128KB
                (i64::MAX, 256 * KI_B),         // >= 50MB: 256KB
            ],
        }
    }

    /// Detect special OS environment and return appropriate workload profile
    /// Supports Chinese secure operating systems (Kylin, NeoKylin, Unity OS, etc.)
    pub fn detect_os_environment() -> Option<WorkloadProfile> {
        // 检测特殊的操作系统环境并返回合适的工作负载配置文件
        // 支持国产安全操作系统（麒麟、中标麒麟、统信 UOS 等）
        #[cfg(target_os = "linux")] // 仅在 Linux 目标系统上编译
        {
            // Read /etc/os-release to detect Chinese secure OS distributions
            // 读取 /etc/os-release 文件以检测国产安全操作系统发行版
            if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
                let content_lower = content.to_lowercase();
                // Check for Chinese secure OS distributions
                // 检查国产安全操作系统发行版
                if content_lower.contains("kylin") // 麒麟
                    || content_lower.contains("neokylin") // 中标麒麟
                    || content_lower.contains("uos") // 统信 UOS
                    || content_lower.contains("unity") // 麒麟系统中的 Unity 标识
                    || content_lower.contains("openkylin") // 开放麒麟
                {
                    // Use SecureStorage profile for Chinese secure OS environments
                    // 对国产安全操作系统环境使用 SecureStorage 配置文件
                    return Some(WorkloadProfile::SecureStorage);
                }
            }
        }
        None // 未检测到特殊环境
    }
}

impl BufferConfig {
    /// Calculate the optimal buffer size for a given file size
    ///
    /// # Arguments
    /// * `file_size` - The size of the file in bytes, or -1 if unknown
    ///
    /// # Returns
    /// Optimal buffer size in bytes based on the configuration
    pub fn calculate_buffer_size(&self, file_size: i64) -> usize {
        // 计算给定文件大小的最佳缓冲区大小
        //
        // # 参数
        // * `file_size` - 文件大小（字节），如果未知则为 -1
        //
        // # 返回值
        // 基于配置的最佳缓冲区大小（字节）

        // Handle unknown or negative file sizes
        // 处理未知或负数文件大小
        if file_size < 0 {
            // 使用默认未知大小，并限制在 [min_size, max_size] 范围内
            return self.default_unknown.clamp(self.min_size, self.max_size);
        }

        // Find the appropriate buffer size from thresholds
        // 从阈值中查找合适的缓冲区大小
        for (threshold, buffer_size) in &self.thresholds {
            if file_size < *threshold {
                // 文件大小小于当前阈值，返回对应的缓冲区大小，并限制在 [min_size, max_size] 范围内
                return (*buffer_size).clamp(self.min_size, self.max_size);
            }
        }

        // Fallback to max_size if no threshold matched (shouldn't happen with i64::MAX threshold)
        // 如果没有阈值匹配（理论上 i64::MAX 阈值应该能匹配），则回退到 max_size
        self.max_size
    }

    /// Validate the buffer configuration
    pub fn validate(&self) -> Result<(), String> {
        // 验证缓冲区配置
        if self.min_size == 0 {
            return Err("min_size must be greater than 0".to_string()); // min_size 必须大于 0
        }
        if self.max_size < self.min_size {
            return Err("max_size must be >= min_size".to_string()); // max_size 必须大于等于 min_size
        }
        if self.default_unknown < self.min_size || self.default_unknown > self.max_size {
            return Err("default_unknown must be between min_size and max_size".to_string()); // default_unknown 必须在 [min_size, max_size] 之间
        }
        if self.thresholds.is_empty() {
            return Err("thresholds cannot be empty".to_string()); // thresholds 不能为空
        }

        // Validate thresholds are in ascending order
        // 验证阈值是否按升序排列
        let mut prev_threshold = -1i64;
        for (threshold, buffer_size) in &self.thresholds {
            if *threshold <= prev_threshold {
                return Err("thresholds must be in ascending order".to_string()); // 阈值必须按升序排列
            }
            if *buffer_size < self.min_size || *buffer_size > self.max_size {
                return Err(format!(
                    "buffer_size {} must be between min_size {} and max_size {}",
                    buffer_size, self.min_size, self.max_size // 缓冲区大小必须在 [min_size, max_size] 之间
                ));
            }
            prev_threshold = *threshold;
        }

        Ok(()) // 验证通过
    }
}

impl RustFSBufferConfig {
    /// Create a new buffer configuration with the given workload profile
    pub fn new(workload: WorkloadProfile) -> Self {
        // 使用给定的工作负载配置文件创建一个新的缓冲区配置
        let base_config = workload.config();
        Self { workload, base_config }
    }

    /// Create a configuration with auto-detected OS environment
    /// Falls back to GeneralPurpose if no special environment detected
    pub fn with_auto_detect() -> Self {
        // 创建一个具有自动检测操作系统环境的配置
        // 如果未检测到特殊环境，则回退到 GeneralPurpose
        let workload = WorkloadProfile::detect_os_environment().unwrap_or(WorkloadProfile::GeneralPurpose);
        Self::new(workload)
    }

    /// Get the buffer size for a given file size
    pub fn get_buffer_size(&self, file_size: i64) -> usize {
        // 获取给定文件大小的缓冲区大小
        self.base_config.calculate_buffer_size(file_size)
    }
}

impl Default for RustFSBufferConfig {
    fn default() -> Self {
        // 默认实现：使用 GeneralPurpose 配置文件
        Self::new(WorkloadProfile::GeneralPurpose)
    }
}

#[cfg(test)] // 仅在运行测试时编译以下模块
mod tests {
    use super::*;

    #[test]
    fn test_general_purpose_config() {
        let config = WorkloadProfile::GeneralPurpose.config();

        // Test small files (< 1MB) - should use 64KB
        // 测试小文件 (< 1MB) - 应使用 64KB
        assert_eq!(config.calculate_buffer_size(0), 64 * KI_B);
        assert_eq!(config.calculate_buffer_size(512 * KI_B as i64), 64 * KI_B);
        assert_eq!(config.calculate_buffer_size((MI_B - 1) as i64), 64 * KI_B);

        // Test medium files (1MB - 100MB) - should use 256KB
        // 测试中等文件 (1MB - 100MB) - 应使用 256KB
        assert_eq!(config.calculate_buffer_size(MI_B as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size((50 * MI_B) as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size((100 * MI_B - 1) as i64), 256 * KI_B);

        // Test large files (>= 100MB) - should use 1MB
        // 测试大文件 (>= 100MB) - 应使用 1MB
        assert_eq!(config.calculate_buffer_size((100 * MI_B) as i64), MI_B);
        assert_eq!(config.calculate_buffer_size((500 * MI_B) as i64), MI_B);
        assert_eq!(config.calculate_buffer_size((10 * 1024 * MI_B) as i64), MI_B);

        // Test unknown size
        // 测试未知大小
        assert_eq!(config.calculate_buffer_size(-1), MI_B);
    }

    #[test]
    fn test_ai_training_config() {
        let config = WorkloadProfile::AiTraining.config();

        // Test small files
        // 测试小文件
        assert_eq!(config.calculate_buffer_size((5 * MI_B) as i64), 512 * KI_B);
        assert_eq!(config.calculate_buffer_size((10 * MI_B - 1) as i64), 512 * KI_B);

        // Test medium files
        // 测试中等文件
        assert_eq!(config.calculate_buffer_size((10 * MI_B) as i64), 2 * MI_B);
        assert_eq!(config.calculate_buffer_size((100 * MI_B) as i64), 2 * MI_B);
        assert_eq!(config.calculate_buffer_size((500 * MI_B - 1) as i64), 2 * MI_B);

        // Test large files
        // 测试大文件
        assert_eq!(config.calculate_buffer_size((500 * MI_B) as i64), 4 * MI_B);
        assert_eq!(config.calculate_buffer_size((1024 * MI_B) as i64), 4 * MI_B);

        // Test unknown size
        // 测试未知大小
        assert_eq!(config.calculate_buffer_size(-1), 2 * MI_B);
    }

    #[test]
    fn test_web_workload_config() {
        let config = WorkloadProfile::WebWorkload.config();

        // Test small files
        // 测试小文件
        assert_eq!(config.calculate_buffer_size((100 * KI_B) as i64), 32 * KI_B);
        assert_eq!(config.calculate_buffer_size((512 * KI_B - 1) as i64), 32 * KI_B);

        // Test medium files
        // 测试中等文件
        assert_eq!(config.calculate_buffer_size((512 * KI_B) as i64), 128 * KI_B);
        assert_eq!(config.calculate_buffer_size((5 * MI_B) as i64), 128 * KI_B);
        assert_eq!(config.calculate_buffer_size((10 * MI_B - 1) as i64), 128 * KI_B);

        // Test large files
        // 测试大文件
        assert_eq!(config.calculate_buffer_size((10 * MI_B) as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size((50 * MI_B) as i64), 256 * KI_B);

        // Test unknown size
        // 测试未知大小
        assert_eq!(config.calculate_buffer_size(-1), 128 * KI_B);
    }

    #[test]
    fn test_secure_storage_config() {
        let config = WorkloadProfile::SecureStorage.config();

        // Test small files
        // 测试小文件
        assert_eq!(config.calculate_buffer_size((500 * KI_B) as i64), 32 * KI_B);
        assert_eq!(config.calculate_buffer_size((MI_B - 1) as i64), 32 * KI_B);

        // Test medium files
        // 测试中等文件
        assert_eq!(config.calculate_buffer_size(MI_B as i64), 128 * KI_B);
        assert_eq!(config.calculate_buffer_size((25 * MI_B) as i64), 128 * KI_B);
        assert_eq!(config.calculate_buffer_size((50 * MI_B - 1) as i64), 128 * KI_B);

        // Test large files
        // 测试大文件
        assert_eq!(config.calculate_buffer_size((50 * MI_B) as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size((100 * MI_B) as i64), 256 * KI_B);

        // Test unknown size
        // 测试未知大小
        assert_eq!(config.calculate_buffer_size(-1), 128 * KI_B);
    }

    #[test]
    fn test_industrial_iot_config() {
        let config = WorkloadProfile::IndustrialIoT.config();

        // Test configuration
        // 测试配置
        assert_eq!(config.calculate_buffer_size((500 * KI_B) as i64), 64 * KI_B);
        assert_eq!(config.calculate_buffer_size((25 * MI_B) as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size((100 * MI_B) as i64), 512 * KI_B);
        assert_eq!(config.calculate_buffer_size(-1), 256 * KI_B);
    }

    #[test]
    fn test_data_analytics_config() {
        let config = WorkloadProfile::DataAnalytics.config();

        // Test configuration
        // 测试配置
        assert_eq!(config.calculate_buffer_size((2 * MI_B) as i64), 128 * KI_B);
        assert_eq!(config.calculate_buffer_size((100 * MI_B) as i64), 512 * KI_B);
        assert_eq!(config.calculate_buffer_size((500 * MI_B) as i64), 2 * MI_B);
        assert_eq!(config.calculate_buffer_size(-1), 512 * KI_B);
    }

    #[test]
    fn test_custom_config() {
        // 测试自定义配置
        let custom_config = BufferConfig {
            min_size: 16 * KI_B,
            max_size: 512 * KI_B,
            default_unknown: 128 * KI_B,
            thresholds: vec![(MI_B as i64, 64 * KI_B), (i64::MAX, 256 * KI_B)],
        };

        let profile = WorkloadProfile::Custom(custom_config.clone());
        let config = profile.config();

        assert_eq!(config.calculate_buffer_size(512 * KI_B as i64), 64 * KI_B);
        assert_eq!(config.calculate_buffer_size(2 * MI_B as i64), 256 * KI_B);
        assert_eq!(config.calculate_buffer_size(-1), 128 * KI_B);
    }

    #[test]
    fn test_buffer_config_validation() {
        // Valid configuration
        // 有效配置
        let valid_config = BufferConfig {
            min_size: 32 * KI_B,
            max_size: MI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![(MI_B as i64, 128 * KI_B), (i64::MAX, 512 * KI_B)],
        };
        assert!(valid_config.validate().is_ok());

        // Invalid: min_size is 0
        // 无效：min_size 为 0
        let invalid_config = BufferConfig {
            min_size: 0,
            max_size: MI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![(MI_B as i64, 128 * KI_B)],
        };
        assert!(invalid_config.validate().is_err());

        // Invalid: max_size < min_size
        // 无效：max_size < min_size
        let invalid_config = BufferConfig {
            min_size: MI_B,
            max_size: 32 * KI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![(MI_B as i64, 128 * KI_B)],
        };
        assert!(invalid_config.validate().is_err());

        // Invalid: default_unknown out of range
        // 无效：default_unknown 超出范围
        let invalid_config = BufferConfig {
            min_size: 32 * KI_B,
            max_size: 256 * KI_B,
            default_unknown: MI_B,
            thresholds: vec![(MI_B as i64, 128 * KI_B)],
        };
        assert!(invalid_config.validate().is_err());

        // Invalid: empty thresholds
        // 无效：thresholds 为空
        let invalid_config = BufferConfig {
            min_size: 32 * KI_B,
            max_size: MI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![],
        };
        assert!(invalid_config.validate().is_err());

        // Invalid: thresholds not in ascending order
        // 无效：thresholds 未按升序排列
        let invalid_config = BufferConfig {
            min_size: 32 * KI_B,
            max_size: MI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![(100 * MI_B as i64, 512 * KI_B), (MI_B as i64, 128 * KI_B)],
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_rustfs_buffer_config() {
        // 测试 RustFSBufferConfig
        let config = RustFSBufferConfig::new(WorkloadProfile::GeneralPurpose);
        assert_eq!(config.get_buffer_size(500 * KI_B as i64), 64 * KI_B);
        assert_eq!(config.get_buffer_size(50 * MI_B as i64), 256 * KI_B);
        assert_eq!(config.get_buffer_size(200 * MI_B as i64), MI_B);

        let default_config = RustFSBufferConfig::default();
        assert_eq!(default_config.get_buffer_size(500 * KI_B as i64), 64 * KI_B);
    }

    #[test]
    fn test_workload_profile_equality() {
        // 测试 WorkloadProfile 相等性
        assert_eq!(WorkloadProfile::GeneralPurpose, WorkloadProfile::GeneralPurpose);
        assert_ne!(WorkloadProfile::GeneralPurpose, WorkloadProfile::AiTraining);

        let custom1 = BufferConfig {
            min_size: 32 * KI_B,
            max_size: MI_B,
            default_unknown: 256 * KI_B,
            thresholds: vec![(MI_B as i64, 128 * KI_B)],
        };
        let custom2 = custom1.clone();

        assert_eq!(WorkloadProfile::Custom(custom1.clone()), WorkloadProfile::Custom(custom2));
    }

    #[test]
    fn test_workload_profile_from_name() {
        // Test exact matches (case-insensitive)
        // 测试精确匹配（不区分大小写）
        assert_eq!(WorkloadProfile::from_name("GeneralPurpose"), WorkloadProfile::GeneralPurpose);
        assert_eq!(WorkloadProfile::from_name("generalpurpose"), WorkloadProfile::GeneralPurpose);
        assert_eq!(WorkloadProfile::from_name("GENERALPURPOSE"), WorkloadProfile::GeneralPurpose);
        assert_eq!(WorkloadProfile::from_name("general"), WorkloadProfile::GeneralPurpose);

        assert_eq!(WorkloadProfile::from_name("AiTraining"), WorkloadProfile::AiTraining);
        assert_eq!(WorkloadProfile::from_name("aitraining"), WorkloadProfile::AiTraining);
        assert_eq!(WorkloadProfile::from_name("ai"), WorkloadProfile::AiTraining);

        assert_eq!(WorkloadProfile::from_name("DataAnalytics"), WorkloadProfile::DataAnalytics);
        assert_eq!(WorkloadProfile::from_name("dataanalytics"), WorkloadProfile::DataAnalytics);
        assert_eq!(WorkloadProfile::from_name("analytics"), WorkloadProfile::DataAnalytics);

        assert_eq!(WorkloadProfile::from_name("WebWorkload"), WorkloadProfile::WebWorkload);
        assert_eq!(WorkloadProfile::from_name("webworkload"), WorkloadProfile::WebWorkload);
        assert_eq!(WorkloadProfile::from_name("web"), WorkloadProfile::WebWorkload);

        assert_eq!(WorkloadProfile::from_name("IndustrialIoT"), WorkloadProfile::IndustrialIoT);
        assert_eq!(WorkloadProfile::from_name("industrialiot"), WorkloadProfile::IndustrialIoT);
        assert_eq!(WorkloadProfile::from_name("iot"), WorkloadProfile::IndustrialIoT);

        assert_eq!(WorkloadProfile::from_name("SecureStorage"), WorkloadProfile::SecureStorage);
        assert_eq!(WorkloadProfile::from_name("securestorage"), WorkloadProfile::SecureStorage);
        assert_eq!(WorkloadProfile::from_name("secure"), WorkloadProfile::SecureStorage);

        // Test unknown name defaults to GeneralPurpose
        // 测试未知名称默认回退到 GeneralPurpose
        assert_eq!(WorkloadProfile::from_name("unknown"), WorkloadProfile::GeneralPurpose);
        assert_eq!(WorkloadProfile::from_name("invalid"), WorkloadProfile::GeneralPurpose);
        assert_eq!(WorkloadProfile::from_name(""), WorkloadProfile::GeneralPurpose);
    }

    #[test]
    fn test_global_buffer_config() {
        use super::{is_buffer_profile_enabled, set_buffer_profile_enabled};

        // Test enable/disable
        // 测试启用/禁用
        set_buffer_profile_enabled(true);
        assert!(is_buffer_profile_enabled());

        set_buffer_profile_enabled(false);
        assert!(!is_buffer_profile_enabled());

        // Reset for other tests
        // 为其他测试重置
        set_buffer_profile_enabled(false);
    }
}