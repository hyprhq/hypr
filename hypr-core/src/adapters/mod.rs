//! VMM (Virtual Machine Monitor) adapter abstraction.
//!
//! HYPR supports multiple hypervisors via the `VmmAdapter` trait:
//! - Linux: cloud-hypervisor (primary)
//! - macOS: libkrun (native, with GPU support)
//! - Windows: WSL2 wrapper (future)

use crate::error::Result;
use crate::types::network::NetworkConfig;
use crate::types::vm::{CommandSpec, DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// VMM adapter trait.
///
/// All hypervisor integrations must implement this trait.
/// Methods are instrumented by implementations (not here) to maintain observability.
#[async_trait]
pub trait VmmAdapter: Send + Sync {
    /// Build command for spawning a VM (for builder VMs that need stdout capture).
    ///
    /// Returns a CommandSpec that the caller can spawn with piped stdout/stderr.
    /// Use this for build VMs where live output is needed.
    ///
    /// This method is async to allow adapters to start prerequisite processes
    /// (e.g., virtiofsd daemons for CloudHypervisor).
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec>;

    /// Create a new VM (allocate resources, configure, spawn).
    ///
    /// This prepares and starts the VM. For runtime VMs only.
    /// Builder VMs should use `build_command()` instead.
    async fn create(&self, config: &VmConfig) -> Result<VmHandle>;

    /// Start an existing VM.
    ///
    /// Boots the VM and waits for it to reach running state.
    async fn start(&self, handle: &VmHandle) -> Result<()>;

    /// Stop a running VM gracefully.
    ///
    /// Sends shutdown signal and waits up to `timeout` for clean shutdown.
    /// Falls back to `kill()` if timeout expires.
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()>;

    /// Force kill a VM immediately.
    ///
    /// Does not wait for clean shutdown. Use only when `stop()` fails.
    async fn kill(&self, handle: &VmHandle) -> Result<()>;

    /// Delete VM resources.
    ///
    /// VM must be stopped before calling this.
    async fn delete(&self, handle: &VmHandle) -> Result<()>;

    /// Attach a disk device (virtio-blk).
    async fn attach_disk(&self, handle: &VmHandle, disk: &DiskConfig) -> Result<()>;

    /// Attach a network device (virtio-net).
    async fn attach_network(&self, handle: &VmHandle, net: &NetworkConfig) -> Result<()>;

    /// Attach GPU (VFIO on Linux, Metal on macOS).
    async fn attach_gpu(&self, handle: &VmHandle, gpu: &GpuConfig) -> Result<()>;

    /// Get vsock path for guest communication.
    fn vsock_path(&self, handle: &VmHandle) -> PathBuf;

    /// Get adapter capabilities (for feature detection).
    fn capabilities(&self) -> AdapterCapabilities;

    /// Get adapter name (for logging/metrics).
    fn name(&self) -> &str;

    /// Downcast to concrete type (for adapter-specific methods).
    fn as_any(&self) -> &dyn Any;
}

/// Adapter capabilities.
#[derive(Debug, Clone, Default)]
pub struct AdapterCapabilities {
    /// Supports GPU passthrough
    pub gpu_passthrough: bool,

    /// Supports virtio-fs
    pub virtio_fs: bool,

    /// Supports hotplug devices
    pub hotplug_devices: bool,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

// Platform-specific adapters
#[cfg(target_os = "linux")]
pub mod cloudhypervisor;

#[cfg(target_os = "macos")]
mod libkrun_ffi;

#[cfg(target_os = "macos")]
pub mod krun;

// VFIO module (GPU passthrough)
// Available on all platforms, but VFIO operations only work on Linux
pub mod vfio;

// Re-export adapter types with proper cfg gates
#[cfg(target_os = "linux")]
pub use cloudhypervisor::CloudHypervisorAdapter;

#[cfg(target_os = "macos")]
pub use krun::LibkrunAdapter;

mod factory;
pub use factory::AdapterFactory;
