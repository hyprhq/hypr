//! Stack domain types (Compose).

use crate::types::VmConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// Multi-service stack (from compose file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stack {
    /// Stack ID
    pub id: String,

    /// Stack name
    pub name: String,

    /// Services in stack
    pub services: Vec<Service>,

    /// Compose file path
    pub compose_path: Option<String>,

    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Service in a stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service name
    pub name: String,

    /// VM ID for this service instance
    pub vm_id: String,

    /// Service status
    pub status: String,
}

/// Stack configuration from compose file conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackConfig {
    /// Stack name
    pub name: String,

    /// Service configurations
    pub services: Vec<ServiceConfig>,

    /// Volume configurations
    pub volumes: Vec<VolumeConfig>,

    /// Network configuration
    pub network: NetworkStackConfig,
}

/// Service configuration within a stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service name
    pub name: String,

    /// VM configuration for this service
    pub vm_config: VmConfig,

    /// Services this depends on
    pub depends_on: Vec<String>,

    /// Health check configuration
    pub healthcheck: Option<HealthCheck>,
}

/// Volume configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeConfig {
    /// Volume name
    pub name: String,

    /// Mount path in VM
    pub mount_path: String,

    /// Volume source
    pub source: VolumeSource,
}

/// Volume source type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolumeSource {
    /// Named volume (stored in /var/lib/hypr/volumes/)
    Named(String),

    /// Host path bind mount
    HostPath(PathBuf),
}

/// Network configuration for a stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStackConfig {
    /// Network name
    pub name: String,

    /// Subnet CIDR
    pub subnet: String,
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Health check command
    pub test: Vec<String>,

    /// Interval between checks (seconds)
    pub interval: u64,

    /// Timeout for each check (seconds)
    pub timeout: u64,

    /// Number of retries before marking unhealthy
    pub retries: u32,
}
