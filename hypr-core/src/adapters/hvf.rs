//! HVF (Hypervisor.framework) adapter for macOS.
//!
//! Provides VM lifecycle management using vfkit on macOS.
//! This is a fallback adapter when libkrun-efi is not available.

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::vm::{DiskConfig, GpuConfig, VmConfig, VmHandle};
use crate::types::network::NetworkConfig;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, error, info, instrument, warn};

/// HVF adapter using vfkit.
pub struct HvfAdapter {
    /// Path to vfkit binary
    binary_path: PathBuf,
    /// Default kernel path
    kernel_path: PathBuf,
}

impl HvfAdapter {
    /// Create a new HVF adapter.
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_binary()?;
        let kernel_path = PathBuf::from("/usr/local/lib/hypr/vmlinux");

        Ok(Self {
            binary_path,
            kernel_path,
        })
    }

    /// Find vfkit binary in PATH.
    fn find_binary() -> Result<PathBuf> {
        let candidates = vec![
            PathBuf::from("/usr/local/bin/vfkit"),
            PathBuf::from("/opt/homebrew/bin/vfkit"),
            PathBuf::from("./vfkit"),
        ];

        for path in candidates {
            if path.exists() {
                return Ok(path);
            }
        }

        Err(HyprError::HypervisorNotFound {
            hypervisor: "vfkit".to_string(),
        })
    }

    /// Build vfkit command-line arguments.
    #[instrument(skip(self))]
    fn build_args(&self, config: &VmConfig) -> Result<Vec<String>> {
        let mut args = Vec::new();

        // CPUs
        args.push("--cpus".to_string());
        args.push(config.resources.cpus.to_string());

        // Memory
        args.push("--memory".to_string());
        args.push(format!("{}", config.resources.memory_mb));

        // Bootloader (kernel + cmdline)
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        args.push("--bootloader".to_string());
        let cmdline = if config.kernel_args.is_empty() {
            kernel.to_string_lossy().to_string()
        } else {
            format!("{},{}", kernel.display(), config.kernel_args.join(" "))
        };
        args.push(cmdline);

        // Disks
        for disk in &config.disks {
            args.push("--device".to_string());
            args.push(format!("virtio-blk,path={}", disk.path.display()));
        }

        // Network (NAT mode)
        args.push("--device".to_string());
        let mac = config
            .network
            .mac_address
            .as_ref()
            .map(|m| format!(",mac={}", m))
            .unwrap_or_default();
        args.push(format!("virtio-net,nat{}", mac));

        // Vsock
        args.push("--device".to_string());
        args.push(format!(
            "virtio-vsock,socketURL=unix://{}",
            config.vsock_path.display()
        ));

        debug!("Built vfkit args: {:?}", args);
        Ok(args)
    }

    /// Check if GPU is requested and warn user.
    fn check_gpu_support(&self, config: &VmConfig) -> Result<()> {
        if config.gpu.is_some() {
            warn!(
                "GPU requested but HVF does not support GPU passthrough.\n\
                \n\
                For GPU-accelerated VMs on macOS, install libkrun-efi:\n\
                \n\
                brew install hypr-libkrun\n\
                hypr config set vmm.macos libkrun\n\
                \n\
                Continuing with CPU-only VM..."
            );
        }
        Ok(())
    }
}

impl Default for HvfAdapter {
    fn default() -> Self {
        Self::new().expect("Failed to create HVF adapter")
    }
}

#[async_trait]
impl VmmAdapter for HvfAdapter {
    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with HVF/vfkit");

        // Check for GPU and warn
        self.check_gpu_support(config)?;

        // Build arguments
        let args = self.build_args(config)?;

        // Spawn vfkit process
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .spawn()
            .map_err(|e| HyprError::VmStartFailed {
                vm_id: config.id.clone(),
                reason: format!("Failed to spawn vfkit: {}", e),
            })?;

        let pid = child.id().ok_or_else(|| HyprError::VmStartFailed {
            vm_id: config.id.clone(),
            reason: "Failed to get process ID".to_string(),
        })?;

        // Record metrics
        let histogram = metrics::histogram!("hypr_vm_boot_duration_seconds", "adapter" => "hvf");
        histogram.record(start.elapsed().as_secs_f64());

        let counter = metrics::counter!("hypr_vm_created_total", "adapter" => "hvf");
        counter.increment(1);

        info!(
            pid = pid,
            duration_ms = start.elapsed().as_millis(),
            "VM created successfully"
        );

        Ok(VmHandle {
            id: config.id.clone(),
            pid: Some(pid),
            socket_path: None, // vfkit doesn't use control socket
        })
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn start(&self, handle: &VmHandle) -> Result<()> {
        info!("Starting VM");
        // vfkit boots immediately when spawned
        info!("VM started (auto-boot mode)");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()> {
        info!("Stopping VM");

        // Wait for timeout, then kill
        tokio::time::sleep(timeout).await;

        // Fallback to kill
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
        // vfkit doesn't create persistent resources
        info!("VM resources deleted");
        Ok(())
    }

    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "hvf (Phase 1)".to_string(),
        })
    }

    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "hvf (Phase 1)".to_string(),
        })
    }

    async fn attach_gpu(&self, _handle: &VmHandle, _gpu: &GpuConfig) -> Result<()> {
        Err(HyprError::GpuUnavailable {
            reason: "HVF does not support GPU passthrough. Use libkrun-efi for Metal support."
                .to_string(),
        })
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        PathBuf::from(format!("/tmp/hypr-vm-{}.vsock", handle.id))
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            gpu_passthrough: false,
            virtio_fs: false,
            hotplug_devices: false,
            metadata: HashMap::from([
                ("adapter".to_string(), "hvf".to_string()),
                ("backend".to_string(), "vfkit".to_string()),
            ]),
        }
    }

    fn name(&self) -> &str {
        "hvf"
    }
}
