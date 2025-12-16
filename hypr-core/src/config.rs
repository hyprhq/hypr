//! Configuration management.

use crate::error::{HyprError, Result};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent configuration for HYPR.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub default_cpus: u32,
    pub default_memory_mb: u32,
    pub auto_start_daemon: bool,
    pub start_at_login: bool,
    pub log_level: String,
    pub max_concurrent_builds: u32,
    pub cache_size_limit_bytes: u64,
    pub log_retention_days: u64,
    pub telemetry_enabled: bool,
    pub data_dir: String,
    pub runtime_dir: String,
    pub socket_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_cpus: 2,
            default_memory_mb: 512,
            auto_start_daemon: true,
            start_at_login: false,
            log_level: "info".to_string(),
            max_concurrent_builds: 4,
            cache_size_limit_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            log_retention_days: 7,
            telemetry_enabled: false,
            data_dir: paths::data_dir().to_string_lossy().to_string(),
            runtime_dir: paths::runtime_dir().to_string_lossy().to_string(),
            socket_path: "/tmp/hypr.sock".to_string(),
        }
    }
}

impl Config {
    /// Get the path to the configuration file.
    pub fn config_path() -> PathBuf {
        paths::config_dir().join("config.json")
    }

    /// Load configuration from disk.
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to read config: {}", e),
        })?;
        serde_json::from_str(&content).map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to parse config: {}", e),
        })
    }

    /// Save configuration to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HyprError::IoError { path: parent.to_path_buf(), source: e })?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to serialize config: {}", e),
        })?;
        std::fs::write(&path, content).map_err(|e| HyprError::IoError { path, source: e })
    }
}
