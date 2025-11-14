//! cloud-hypervisor adapter for Linux.
//!
//! Provides VM lifecycle management using cloud-hypervisor:
//! - Create: Spawn CH process with API socket
//! - Start: Send boot command via API
//! - Stop: Send shutdown command
//! - Kill: SIGKILL the CH process
//! - Delete: Clean up resources

use crate::adapters::{AdapterCapabilities, CommandSpec, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::network::NetworkConfig;
use crate::types::vm::{DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error, info, instrument, span, warn, Level};

/// cloud-hypervisor adapter.
#[derive(Clone)]
pub struct CloudHypervisorAdapter {
    /// Path to cloud-hypervisor binary
    binary_path: PathBuf,
    /// Path to virtiofsd binary
    virtiofsd_binary: PathBuf,
    /// Runtime directory for API sockets
    runtime_dir: PathBuf,
    /// Default kernel path
    kernel_path: PathBuf,
    /// Track virtiofsd daemons by VM ID (for cleanup)
    virtiofsd_daemons: Arc<Mutex<HashMap<String, Vec<VirtiofsdDaemon>>>>,
}

/// Handle to a running virtiofsd daemon.
#[derive(Clone, Debug)]
struct VirtiofsdDaemon {
    tag: String,
    socket_path: PathBuf,
    pid: u32,
}

impl CloudHypervisorAdapter {
    /// Create a new CloudHypervisor adapter.
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_binary("cloud-hypervisor")?;
        let virtiofsd_binary = Self::find_binary("virtiofsd")?;
        let runtime_dir = PathBuf::from("/run/hypr/ch");
        let kernel_path = PathBuf::from("/usr/lib/hypr/vmlinux");

        Ok(Self {
            binary_path,
            virtiofsd_binary,
            runtime_dir,
            kernel_path,
            virtiofsd_daemons: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Find binary in PATH or common locations.
    fn find_binary(name: &str) -> Result<PathBuf> {
        // Check common locations
        let candidates = vec![
            PathBuf::from(format!("/usr/local/bin/{}", name)),
            PathBuf::from(format!("/usr/bin/{}", name)),
            PathBuf::from(format!("/usr/libexec/{}", name)),
            PathBuf::from(format!("./{}", name)),
        ];

        for path in candidates {
            if path.exists() {
                return Ok(path);
            }
        }

        Err(HyprError::HypervisorNotFound { hypervisor: name.to_string() })
    }

    /// Start virtiofsd daemons for virtio-fs mounts.
    ///
    /// Each mount gets its own virtiofsd daemon listening on a Unix socket.
    #[instrument(skip(self))]
    async fn start_virtiofsd_daemons(
        &self,
        vm_id: &str,
        mounts: &[crate::types::vm::VirtioFsMount],
    ) -> Result<Vec<VirtiofsdDaemon>> {
        let mut daemons = Vec::new();

        for mount in mounts {
            let socket_path = self.runtime_dir.join(format!("{}-{}.sock", vm_id, mount.tag));

            // Remove stale socket if it exists
            if socket_path.exists() {
                tokio::fs::remove_file(&socket_path).await.map_err(|e| {
                    HyprError::Internal(format!("Failed to remove stale virtiofsd socket: {}", e))
                })?;
            }

            info!(
                "Starting virtiofsd: tag={}, shared_dir={}, socket={}",
                mount.tag,
                mount.host_path.display(),
                socket_path.display()
            );

            // Spawn virtiofsd daemon
            // virtiofsd --socket-path=/path/to/socket --shared-dir=/path/to/share --cache=never
            let mut child = Command::new(&self.virtiofsd_binary)
                .arg("--socket-path")
                .arg(&socket_path)
                .arg("--shared-dir")
                .arg(&mount.host_path)
                .arg("--cache")
                .arg("never")
                .spawn()
                .map_err(|e| HyprError::Internal(format!("Failed to spawn virtiofsd: {}", e)))?;

            let pid = child.id().ok_or_else(|| {
                HyprError::Internal(format!("Failed to get virtiofsd PID for tag={}", mount.tag))
            })?;

            // Wait for socket to be created (virtiofsd creates it on startup)
            let start = Instant::now();
            while !socket_path.exists() {
                if start.elapsed() > Duration::from_secs(5) {
                    // Kill the daemon
                    let _ = child.kill().await;
                    return Err(HyprError::Internal(format!(
                        "virtiofsd socket did not appear within timeout: {}",
                        socket_path.display()
                    )));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            debug!("virtiofsd daemon started: tag={}, pid={}", mount.tag, pid);

            // Detach child process (it will continue running)
            std::mem::forget(child);

            daemons.push(VirtiofsdDaemon { tag: mount.tag.clone(), socket_path, pid });
        }

        Ok(daemons)
    }

    /// Stop virtiofsd daemons for a VM.
    #[instrument(skip(self))]
    async fn stop_virtiofsd_daemons(&self, vm_id: &str) -> Result<()> {
        let daemons = {
            let mut map = self.virtiofsd_daemons.lock().unwrap();
            map.remove(vm_id)
        };

        if let Some(daemons) = daemons {
            for daemon in daemons {
                debug!("Stopping virtiofsd: tag={}, pid={}", daemon.tag, daemon.pid);

                // Send SIGTERM to virtiofsd process
                let kill_result =
                    Command::new("kill").arg("-TERM").arg(daemon.pid.to_string()).status().await;

                if let Err(e) = kill_result {
                    warn!("Failed to kill virtiofsd daemon (pid={}): {}", daemon.pid, e);
                }

                // Remove socket file
                if daemon.socket_path.exists() {
                    let _ = tokio::fs::remove_file(&daemon.socket_path).await;
                }
            }
        }

        Ok(())
    }

    /// Build cloud-hypervisor command-line arguments.
    #[instrument(skip(self))]
    fn build_args(
        &self,
        config: &VmConfig,
        virtiofsd_daemons: &[VirtiofsdDaemon],
    ) -> Result<Vec<String>> {
        let mut args = Vec::new();

        // API socket
        let api_socket = self.runtime_dir.join(format!("{}.sock", config.id));
        args.push("--api-socket".to_string());
        args.push(api_socket.to_string_lossy().to_string());

        // CPUs
        args.push("--cpus".to_string());
        args.push(format!("boot={}", config.resources.cpus));

        // Memory (shared=on required for virtio-fs vhost-user)
        args.push("--memory".to_string());
        args.push(format!("size={}M,shared=on", config.resources.memory_mb));

        // Kernel
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        args.push("--kernel".to_string());
        args.push(kernel.to_string_lossy().to_string());

        // Kernel cmdline
        if !config.kernel_args.is_empty() {
            args.push("--cmdline".to_string());
            args.push(config.kernel_args.join(" "));
        }

        // Initramfs (for minimal boot environments like builder VMs)
        if let Some(initramfs) = &config.initramfs_path {
            args.push("--initramfs".to_string());
            args.push(initramfs.to_string_lossy().to_string());
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

        // virtio-fs mounts (using pre-started virtiofsd daemons)
        // Cloud-hypervisor requires a single --fs argument with multiple devices separated by space
        if !virtiofsd_daemons.is_empty() {
            args.push("--fs".to_string());
            let fs_configs: Vec<String> = virtiofsd_daemons
                .iter()
                .map(|daemon| {
                    format!(
                        "tag={},socket={},num_queues=1",
                        daemon.tag,
                        daemon.socket_path.display()
                    )
                })
                .collect();
            args.push(fs_configs.join(" "));
        }

        // Network (only if enabled - build VMs have this disabled for security)
        if config.network_enabled {
            args.push("--net".to_string());
            args.push(format!(
                "tap=tap{},mac={}",
                config.id,
                config.network.mac_address.as_deref().unwrap_or("auto")
            ));
        }

        // Serial console (build VM stdout/stderr visible on host)
        args.push("--serial".to_string());
        args.push("tty".to_string());

        // Console mode
        args.push("--console".to_string());
        args.push("off".to_string());

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
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec> {
        // Start virtiofsd daemons if virtio-fs mounts are present
        let virtiofsd_daemons = if !config.virtio_fs_mounts.is_empty() {
            info!("Starting {} virtiofsd daemons for build VM", config.virtio_fs_mounts.len());
            let daemons =
                self.start_virtiofsd_daemons(&config.id, &config.virtio_fs_mounts).await?;

            // Store daemons for cleanup (vm_builder will need to call delete() later)
            {
                let mut map = self.virtiofsd_daemons.lock().unwrap();
                map.insert(config.id.clone(), daemons.clone());
            }

            daemons
        } else {
            Vec::new()
        };

        // Build arguments with virtiofsd socket paths
        let args = self.build_args(config, &virtiofsd_daemons)?;

        Ok(CommandSpec {
            program: self.binary_path.to_string_lossy().to_string(),
            args,
            env: vec![],
        })
    }

    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with cloud-hypervisor");

        // Ensure runtime directory exists
        fs::create_dir_all(&self.runtime_dir)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to create runtime dir: {}", e)))?;

        // Start virtiofsd daemons BEFORE spawning cloud-hypervisor
        let virtiofsd_daemons = if !config.virtio_fs_mounts.is_empty() {
            info!("Starting {} virtiofsd daemons", config.virtio_fs_mounts.len());
            let daemons =
                self.start_virtiofsd_daemons(&config.id, &config.virtio_fs_mounts).await?;

            // Store daemons for cleanup
            {
                let mut map = self.virtiofsd_daemons.lock().unwrap();
                map.insert(config.id.clone(), daemons.clone());
            }

            daemons
        } else {
            Vec::new()
        };

        // Build arguments (using virtiofsd daemon socket paths)
        let args = {
            let _span = span!(Level::DEBUG, "build_ch_args").entered();
            self.build_args(config, &virtiofsd_daemons)?
        };

        // Spawn cloud-hypervisor process
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .spawn()
            .map_err(|e| {
                // Clean up virtiofsd daemons on failure
                let rt = tokio::runtime::Handle::current();
                let adapter = self.clone();
                let vm_id = config.id.clone();
                std::thread::spawn(move || {
                    rt.block_on(async {
                        let _ = adapter.stop_virtiofsd_daemons(&vm_id).await;
                    });
                });

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
        self.wait_for_api_socket(&api_socket, Duration::from_secs(5)).await?;

        // Record metrics
        let histogram =
            metrics::histogram!("hypr_vm_boot_duration_seconds", "adapter" => "cloudhypervisor");
        histogram.record(start.elapsed().as_secs_f64());

        let counter = metrics::counter!("hypr_vm_created_total", "adapter" => "cloudhypervisor");
        counter.increment(1);

        info!(pid = pid, duration_ms = start.elapsed().as_millis(), "VM created successfully");

        // Store the API socket path for VM control
        Ok(VmHandle { id: config.id.clone(), pid: Some(pid), socket_path: Some(api_socket) })
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
            let result = Command::new("kill").arg("-9").arg(pid.to_string()).output().await;

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

        // Stop virtiofsd daemons
        self.stop_virtiofsd_daemons(&handle.id).await?;

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

    fn vsock_path(&self, _handle: &VmHandle) -> PathBuf {
        // No longer used - communication via virtio-fs + stdout parsing
        PathBuf::from("/dev/null")
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
