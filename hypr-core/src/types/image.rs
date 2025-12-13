//! Image domain types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// Container image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    /// Image ID (SHA256 hash)
    pub id: String,

    /// Image name (e.g., "nginx")
    pub name: String,

    /// Image tag (e.g., "latest")
    pub tag: String,

    /// Image manifest
    pub manifest: ImageManifest,

    /// Path to rootfs (SquashFS file)
    pub rootfs_path: PathBuf,

    /// Size in bytes
    pub size_bytes: u64,

    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Image manifest (embedded in image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Manifest version
    pub version: String,

    /// Image name
    pub name: String,

    /// Image tag
    pub tag: String,

    /// Image architecture (x86_64, aarch64)
    pub architecture: String,

    /// Operating system (linux)
    pub os: String,

    /// Entrypoint command
    pub entrypoint: Vec<String>,

    /// Default command
    pub cmd: Vec<String>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Working directory
    pub workdir: String,

    /// User to run as (e.g., "nginx", "1000", "1000:1000")
    #[serde(default)]
    pub user: Option<String>,

    /// Exposed ports
    pub exposed_ports: Vec<u16>,

    /// Runtime configuration
    pub runtime: RuntimeConfig,

    /// Health check configuration
    pub health: Option<HealthCheckConfig>,

    /// Layer history (for image history command)
    #[serde(default)]
    pub history: Vec<LayerHistory>,
}

/// Layer history entry (similar to Docker history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerHistory {
    /// Layer ID (digest or short hash)
    pub id: String,

    /// Dockerfile instruction that created this layer
    pub created_by: String,

    /// Layer size in bytes (0 for empty layers)
    pub size_bytes: u64,

    /// Creation timestamp (Unix epoch seconds)
    pub created_at: i64,

    /// Comment (optional)
    #[serde(default)]
    pub comment: String,

    /// True if this layer adds no files (e.g., ENV, LABEL)
    #[serde(default)]
    pub empty_layer: bool,
}

/// Runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Default memory allocation (MB)
    pub default_memory_mb: u32,

    /// Default CPU count
    pub default_cpus: u32,

    /// Kernel channel (stable, latest)
    pub kernel_channel: String,

    /// Rootfs type (squashfs, ext4)
    pub rootfs_type: String,

    /// Restart policy
    pub restart_policy: RestartPolicy,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            default_memory_mb: 512,
            default_cpus: 2,
            kernel_channel: "stable".to_string(),
            rootfs_type: "squashfs".to_string(),
            restart_policy: RestartPolicy::No,
        }
    }
}

/// Restart policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RestartPolicy {
    No,
    Always,
    OnFailure,
    UnlessStopped,
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check type
    pub check_type: HealthCheckType,

    /// HTTP endpoint (for HTTP checks)
    pub endpoint: Option<String>,

    /// Port to check
    pub port: u16,

    /// Interval in seconds
    pub interval_sec: u32,

    /// Timeout in seconds
    pub timeout_sec: u32,

    /// Number of retries
    pub retries: u32,
}

/// Health check type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckType {
    Http,
    Tcp,
    Exec,
}
