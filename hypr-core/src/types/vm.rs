//! VM domain types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

/// Virtual machine instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vm {
    /// Unique VM identifier (UUID v4)
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Image ID this VM is based on
    pub image_id: String,

    /// Current VM status
    pub status: VmStatus,

    /// VM configuration
    pub config: VmConfig,

    /// Assigned IP address (e.g., 100.64.0.5)
    pub ip_address: Option<String>,

    /// Hypervisor process PID
    pub pid: Option<u32>,

    /// Path to vsock socket
    pub vsock_path: Option<PathBuf>,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Start timestamp
    pub started_at: Option<SystemTime>,

    /// Stop timestamp
    pub stopped_at: Option<SystemTime>,
}

/// VM status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmStatus {
    /// VM is being created
    Creating,

    /// VM is running
    Running,

    /// VM is stopped
    Stopped,

    /// VM encountered an error
    Failed,

    /// VM is being deleted
    Deleting,
}

impl std::fmt::Display for VmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "creating"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
            Self::Deleting => write!(f, "deleting"),
        }
    }
}

/// VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// VM identifier
    pub id: String,

    /// VM name
    pub name: String,

    /// Resource allocation
    pub resources: VmResources,

    /// Kernel path (optional, uses default if not specified)
    pub kernel_path: Option<PathBuf>,

    /// Kernel command-line arguments
    pub kernel_args: Vec<String>,

    /// Disk configurations
    pub disks: Vec<DiskConfig>,

    /// Network configuration
    pub network: NetworkConfig,

    /// Port mappings
    pub ports: Vec<PortMapping>,

    /// Environment variables
    pub env: HashMap<String, String>,

    /// Volume mounts
    pub volumes: Vec<VolumeMount>,

    /// GPU configuration (optional)
    pub gpu: Option<GpuConfig>,

    /// Path to vsock socket
    pub vsock_path: PathBuf,
}

/// VM resource allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmResources {
    /// Number of vCPUs
    pub cpus: u32,

    /// Memory in megabytes
    pub memory_mb: u32,
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mb: 512,
        }
    }
}

/// Disk configuration for VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConfig {
    /// Path to disk image
    pub path: PathBuf,

    /// Read-only disk
    pub readonly: bool,

    /// Disk format (squashfs, ext4, raw)
    pub format: DiskFormat,
}

/// Disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskFormat {
    Squashfs,
    Ext4,
    Raw,
}

/// GPU configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuConfig {
    /// GPU vendor
    pub vendor: GpuVendor,

    /// PCI address (Linux: e.g., "0000:01:00.0")
    pub pci_address: Option<String>,

    /// GPU model (e.g., "NVIDIA A100 80GB")
    pub model: String,

    /// Use SR-IOV virtual function
    pub use_sriov: bool,

    /// GPU memory in MB (detected from hardware)
    pub gpu_memory_mb: Option<u64>,
}

/// GPU vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Metal, // macOS Metal
}

/// VM handle returned by adapter after creation.
#[derive(Debug, Clone)]
pub struct VmHandle {
    /// VM identifier
    pub id: String,

    /// Hypervisor process PID (if external process)
    pub pid: Option<u32>,

    /// Path to adapter control socket (e.g., cloud-hypervisor API socket)
    pub socket_path: Option<PathBuf>,
}

// Re-exports needed by other modules
use crate::types::network::{NetworkConfig, PortMapping};
use crate::types::volume::VolumeMount;
