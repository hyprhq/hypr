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

    /// Assigned IP address (e.g., 10.88.0.5)
    pub ip_address: Option<String>,

    /// Hypervisor process PID
    pub pid: Option<u32>,

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
    /// Whether this VM needs network access (false for build VMs - security isolation)
    #[serde(default)]
    pub network_enabled: bool,
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

    /// Initramfs path (optional, for minimal boot environments)
    pub initramfs_path: Option<PathBuf>,

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

    /// virtio-fs shared directory mounts
    pub virtio_fs_mounts: Vec<VirtioFsMount>,
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
        Self { cpus: 2, memory_mb: 512 }
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

/// virtio-fs shared directory mount.
///
/// Allows sharing a host directory with the guest VM using virtio-fs.
/// The guest can mount it with: `mount -t virtiofs <tag> <mount_point>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioFsMount {
    /// Host directory path to share
    pub host_path: PathBuf,

    /// Mount tag (used by guest to identify the mount)
    /// Example: "shared" → guest runs `mount -t virtiofs shared /mnt/shared`
    pub tag: String,
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

/// Command specification for spawning a VM.
/// Adapters build this, vm_builder spawns it.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// Program to execute (e.g., "vfkit", "cloud-hypervisor")
    pub program: String,

    /// Command-line arguments
    pub args: Vec<String>,

    /// Environment variables
    pub env: Vec<(String, String)>,
}

/// VM handle returned by adapter after creation.
/// Represents "this VM exists in the world" but doesn't own the process.
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
