//! cloud-hypervisor adapter for Linux.
//!
//! Provides VM lifecycle management using cloud-hypervisor:
//! - Create: Spawn CH process with API socket
//! - Start: Send boot command via API
//! - Stop: Send shutdown command
//! - Kill: SIGKILL the CH process
//! - Delete: Clean up resources

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::vm::{DiskConfig, GpuConfig, VmConfig, VmHandle};
use crate::types::network::NetworkConfig;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error, info, instrument, span, Level};

/// cloud-hypervisor adapter.
pub struct CloudHypervisorAdapter {
    /// Path to cloud-hypervisor binary
    binary_path: PathBuf,
    /// Runtime directory for API sockets
    runtime_dir: PathBuf,
    /// Default kernel path
    kernel_path: PathBuf,
}

impl CloudHypervisorAdapter {
    /// Create a new CloudHypervisor adapter.
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_binary()?;
        let runtime_dir = PathBuf::from("/run/hypr/ch");
        let kernel_path = PathBuf::from("/usr/lib/hypr/vmlinux");

        Ok(Self {
            binary_path,
            runtime_dir,
            kernel_path,
        })
    }

    /// Find cloud-hypervisor binary in PATH.
    fn find_binary() -> Result<PathBuf> {
        // Check common locations
        let candidates = vec![
            PathBuf::from("/usr/local/bin/cloud-hypervisor"),
            PathBuf::from("/usr/bin/cloud-hypervisor"),
            PathBuf::from("./cloud-hypervisor"),
        ];

        for path in candidates {
            if path.exists() {
                return Ok(path);
            }
        }

        Err(HyprError::HypervisorNotFound {
            hypervisor: "cloud-hypervisor".to_string(),
        })
    }

    /// Build cloud-hypervisor command-line arguments.
    #[instrument(skip(self))]
    fn build_args(&self, config: &VmConfig) -> Result<Vec<String>> {
        let mut args = Vec::new();

        // API socket
        let api_socket = self.runtime_dir.join(format!("{}.sock", config.id));
        args.push("--api-socket".to_string());
        args.push(api_socket.to_string_lossy().to_string());

        // CPUs
        args.push("--cpus".to_string());
        args.push(format!("boot={}", config.resources.cpus));

        // Memory
        args.push("--memory".to_string());
        args.push(format!("size={}M", config.resources.memory_mb));

        // Kernel
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        args.push("--kernel".to_string());
        args.push(kernel.to_string_lossy().to_string());

        // Kernel cmdline
        if !config.kernel_args.is_empty() {
            args.push("--cmdline".to_string());
            args.push(config.kernel_args.join(" "));
        }

        // Disks
        for disk in &config.disks {
            args.push("--disk".to_string());
            let disk_arg = format!(
                "path={},readonly={}",
                disk.path.display(),
                if disk.readonly { "on" } else { "off" }
            );
            args.push(disk_arg);
        }

        // Network (simplified - will be enhanced in Phase 2)
        args.push("--net".to_string());
        args.push(format!(
            "tap=tap{},mac={}",
            config.id,
            config.network.mac_address.as_ref().unwrap_or(&"auto".to_string())
        ));

        // Vsock
        args.push("--vsock".to_string());
        args.push(format!("cid=3,socket={}", config.vsock_path.display()));

        debug!("Built CH args: {:?}", args);
        Ok(args)
    }

    /// Get API socket path for a VM.
    fn api_socket_path(&self, vm_id: &str) -> PathBuf {
        self.runtime_dir.join(format!("{}.sock", vm_id))
    }

    /// Wait for API socket to become available.
    #[instrument(skip(self))]
    async fn wait_for_api_socket(&self, socket_path: &Path, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        loop {
            if socket_path.exists() {
                debug!("API socket ready at {:?}", socket_path);
                return Ok(());
            }

            if start.elapsed() > timeout {
                metrics::counter!("hypr_vm_start_failures_total", "adapter" => "cloudhypervisor", "reason" => "socket_timeout").increment(1);
                return Err(HyprError::VmStartFailed {
                    vm_id: socket_path.to_string_lossy().to_string(),
                    reason: "API socket did not appear within timeout".to_string(),
                });
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Default for CloudHypervisorAdapter {
    fn default() -> Self {
        Self::new().expect("Failed to create CloudHypervisor adapter")
    }
}

#[async_trait]
impl VmmAdapter for CloudHypervisorAdapter {
    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with cloud-hypervisor");

        // Ensure runtime directory exists
        fs::create_dir_all(&self.runtime_dir)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to create runtime dir: {}", e)))?;

        // Build arguments
        let _span = span!(Level::DEBUG, "build_ch_args").entered();
        let args = self.build_args(config)?;

        // Spawn cloud-hypervisor process
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .spawn()
            .map_err(|e| {
                metrics::counter!("hypr_vm_start_failures_total", "adapter" => "cloudhypervisor", "reason" => "spawn_failed").increment(1);
                HyprError::VmStartFailed {
                    vm_id: config.id.clone(),
                    reason: format!("Failed to spawn cloud-hypervisor: {}", e),
                }
            })?;

        let pid = child.id().ok_or_else(|| HyprError::VmStartFailed {
            vm_id: config.id.clone(),
            reason: "Failed to get process ID".to_string(),
        })?;

        // Wait for API socket
        let api_socket = self.api_socket_path(&config.id);
        self.wait_for_api_socket(&api_socket, Duration::from_secs(5))
            .await?;

        // Record metrics
        let histogram = metrics::histogram!("hypr_vm_boot_duration_seconds", "adapter" => "cloudhypervisor");
        histogram.record(start.elapsed().as_secs_f64());

        let counter = metrics::counter!("hypr_vm_created_total", "adapter" => "cloudhypervisor");
        counter.increment(1);

        info!(
            pid = pid,
            duration_ms = start.elapsed().as_millis(),
            "VM created successfully"
        );

        Ok(VmHandle {
            id: config.id.clone(),
            pid: Some(pid),
            socket_path: Some(api_socket),
        })
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn start(&self, handle: &VmHandle) -> Result<()> {
        info!("Starting VM");

        // For now, cloud-hypervisor boots immediately when created
        // In production, we'd send "POST /api/v1/vm.boot" to API socket
        // Simplified for Phase 1

        info!("VM started (auto-boot mode)");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()> {
        info!("Stopping VM");

        // Send shutdown signal via API
        // For Phase 1: simplified to process kill after timeout
        tokio::time::sleep(timeout).await;

        // Fallback to kill if still running
        self.kill(handle).await?;

        info!("VM stopped");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn kill(&self, handle: &VmHandle) -> Result<()> {
        info!("Killing VM");

        if let Some(pid) = handle.pid {
            // Send SIGKILL
            let result = Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .output()
                .await;

            match result {
                Ok(output) if output.status.success() => {
                    info!("VM process killed");
                }
                Ok(_) => {
                    error!("Failed to kill VM process (may already be dead)");
                }
                Err(e) => {
                    error!("Error killing VM process: {}", e);
                    metrics::counter!("hypr_vm_stop_failures_total", "adapter" => "cloudhypervisor", "reason" => "kill_failed").increment(1);
                    return Err(HyprError::VmStopFailed {
                        vm_id: handle.id.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn delete(&self, handle: &VmHandle) -> Result<()> {
        info!("Deleting VM resources");

        // Clean up API socket
        if let Some(socket_path) = &handle.socket_path {
            if socket_path.exists() {
                fs::remove_file(socket_path).await.map_err(|e| {
                    HyprError::Internal(format!("Failed to remove API socket: {}", e))
                })?;
            }
        }

        info!("VM resources deleted");
        Ok(())
    }

    #[instrument(skip(self, _disk), fields(vm_id = %_handle.id))]
    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "cloudhypervisor", "operation" => "attach_disk").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "cloud-hypervisor (Phase 1)".to_string(),
        })
    }

    #[instrument(skip(self, _net), fields(vm_id = %_handle.id))]
    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "cloudhypervisor", "operation" => "attach_network").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "cloud-hypervisor (Phase 1)".to_string(),
        })
    }

    #[instrument(skip(self, _gpu), fields(vm_id = %_handle.id))]
    async fn attach_gpu(&self, _handle: &VmHandle, _gpu: &GpuConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "cloudhypervisor", "operation" => "attach_gpu").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "GPU passthrough".to_string(),
            platform: "cloud-hypervisor (Phase 1)".to_string(),
        })
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        PathBuf::from(format!("/run/hypr/vm-{}.vsock", handle.id))
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            gpu_passthrough: false, // Phase 4
            virtio_fs: true,
            hotplug_devices: false, // Phase 1
            metadata: HashMap::from([
                ("adapter".to_string(), "cloud-hypervisor".to_string()),
                ("version".to_string(), "38.0".to_string()),
            ]),
        }
    }

    fn name(&self) -> &str {
        "cloud-hypervisor"
    }
}
