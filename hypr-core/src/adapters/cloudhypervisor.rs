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
        // Use embedded cloud-hypervisor binary (extracted at runtime)
        let binary_path = crate::embedded::get_cloud_hypervisor_path()?;
        let virtiofsd_binary = Self::find_binary("virtiofsd")?;
        let runtime_dir = crate::paths::runtime_dir().join("ch");
        let kernel_path = crate::paths::kernel_path();

        // Ensure runtime directory exists
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;

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

    /// Get the log file path for a VM.
    ///
    /// Uses centralized paths module for consistency.
    fn get_vm_log_path(vm_id: &str) -> Result<PathBuf> {
        let log_dir = crate::paths::logs_dir();

        // Create log directory if it doesn't exist
        std::fs::create_dir_all(&log_dir)
            .map_err(|e| HyprError::IoError { path: log_dir.clone(), source: e })?;

        Ok(log_dir.join(format!("{}.log", vm_id)))
    }

    /// Generate a random locally-administered MAC address.
    ///
    /// Uses the 52:54:00 prefix (QEMU/KVM convention) with random suffix.
    fn generate_mac_address() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        format!("52:54:00:{:02x}:{:02x}:{:02x}", (seed >> 16) as u8, (seed >> 8) as u8, seed as u8)
    }

    /// Configure the host-side TAP device for VM networking.
    ///
    /// This sets up the TAP device with the gateway IP so the host can communicate with the VM.
    /// Uses the 10.88.0.0/16 subnet (private range, avoids Tailscale conflict).
    fn configure_tap_device(tap_name: &str) -> Result<()> {
        use std::process::Command as StdCommand;

        // Enable IP forwarding (required for routing between host and VM)
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

        // Configure TAP device with gateway IP
        // The VM uses 10.88.0.x, gateway is 10.88.0.1
        let output = StdCommand::new("ip")
            .args(["addr", "add", "10.88.0.1/16", "dev", tap_name])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                debug!("Configured TAP {} with IP 10.88.0.1/16", tap_name);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // Ignore "RTNETLINK answers: File exists" - IP already assigned
                if !stderr.contains("File exists") {
                    warn!("Failed to add IP to TAP {}: {}", tap_name, stderr);
                }
            }
            Err(e) => {
                warn!("Failed to run ip command: {}", e);
            }
        }

        // Bring TAP device up
        let _ = StdCommand::new("ip")
            .args(["link", "set", tap_name, "up"])
            .output();

        Ok(())
    }

    /// Clean up a TAP device when VM is deleted.
    fn cleanup_tap_device(tap_name: &str) {
        use std::process::Command as StdCommand;

        // Delete the TAP device
        let output = StdCommand::new("ip")
            .args(["link", "delete", tap_name])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                debug!("Deleted TAP device {}", tap_name);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // Ignore "Cannot find device" - already deleted
                if !stderr.contains("Cannot find device") {
                    debug!("TAP {} cleanup: {}", tap_name, stderr.trim());
                }
            }
            Err(e) => {
                debug!("Failed to delete TAP {}: {}", tap_name, e);
            }
        }
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
        log_path: Option<&std::path::Path>,
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

        // Kernel cmdline - build with network parameters if IP is assigned
        let mut kernel_cmdline_parts: Vec<String> = config.kernel_args.clone();

        // Enable serial console output (cloud-hypervisor uses legacy serial which maps to ttyS0)
        kernel_cmdline_parts.push("console=ttyS0".to_string());

        // Inject network configuration into kernel cmdline for runtime VMs
        if config.network_enabled {
            if let Some(ip) = &config.network.ip_address {
                // Use proper kernel IP-Config format: ip=<client>:<server>:<gw>:<netmask>:<host>:<dev>:<autoconf>
                // This ensures the kernel sets up networking correctly before init runs
                // Format: ip=10.88.0.2::10.88.0.1:255.255.0.0:::off
                kernel_cmdline_parts.push(format!("ip={}::10.88.0.1:255.255.0.0:::off", ip));
                // Also pass for kestrel's use (backwards compatibility)
                kernel_cmdline_parts.push("netmask=255.255.0.0".to_string());
                kernel_cmdline_parts.push("gateway=10.88.0.1".to_string());
                kernel_cmdline_parts.push("mode=runtime".to_string());
                debug!("Injected network config: ip={}::10.88.0.1:255.255.0.0:::off", ip);
            }
        }

        // Initramfs - always required for cloud-hypervisor (kestrel is our init)
        // Use provided path or fall back to embedded initramfs
        let initramfs_path = match &config.initramfs_path {
            Some(path) => path.clone(),
            None => {
                // Extract embedded initramfs for runtime VMs
                crate::builder::initramfs::create_builder_initramfs().map_err(|e| {
                    HyprError::BuildFailed {
                        reason: format!("Failed to extract embedded initramfs: {}", e),
                    }
                })?
            }
        };
        // Tell kernel to use init from initramfs instead of mounting root device
        kernel_cmdline_parts.push("rdinit=/init".to_string());
        args.push("--initramfs".to_string());
        args.push(initramfs_path.to_string_lossy().to_string());

        if !kernel_cmdline_parts.is_empty() {
            args.push("--cmdline".to_string());
            args.push(kernel_cmdline_parts.join(" "));
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
        // Cloud-hypervisor expects: --fs config1 config2 config3 (multiple values, single flag)
        if !virtiofsd_daemons.is_empty() {
            args.push("--fs".to_string());
            for daemon in virtiofsd_daemons {
                args.push(format!(
                    "tag={},socket={},num_queues=1",
                    daemon.tag,
                    daemon.socket_path.display()
                ));
            }
        }

        // Network (only if enabled - build VMs have this disabled for security)
        if config.network_enabled {
            let mac = config.network.mac_address.clone().unwrap_or_else(Self::generate_mac_address);
            // TAP device names are limited to 15 chars (IFNAMSIZ-1 on Linux)
            // Use "tap" prefix (3 chars) + truncated ID (12 chars max)
            let tap_name = format!("tap{}", &config.id[..config.id.len().min(12)]);
            args.push("--net".to_string());
            args.push(format!("tap={},mac={}", tap_name, mac));
        }

        // Serial console - redirect to log file if provided, otherwise tty
        args.push("--serial".to_string());
        if let Some(path) = log_path {
            args.push(format!("file={}", path.display()));
        } else {
            args.push("tty".to_string());
        }

        // Console mode
        args.push("--console".to_string());
        args.push("off".to_string());

        // RNG device (entropy source for VM)
        // Eliminates getrandom() blocking on fresh VM boot
        args.push("--rng".to_string());
        args.push("src=/dev/urandom".to_string());

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

        // Build arguments with virtiofsd socket paths (no log file for command spec)
        let args = self.build_args(config, &virtiofsd_daemons, None)?;

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

        // Create log file path for VM output
        let log_path = Self::get_vm_log_path(&config.id)?;

        // Build arguments (using virtiofsd daemon socket paths and log path for serial)
        let args = {
            let _span = span!(Level::DEBUG, "build_ch_args").entered();
            self.build_args(config, &virtiofsd_daemons, Some(&log_path))?
        };
        let log_file = std::fs::File::create(&log_path)
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;
        let log_file_err = log_file
            .try_clone()
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;

        info!("VM logs will be written to: {}", log_path.display());

        // Spawn cloud-hypervisor process with stdout/stderr redirected to log file
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(log_file_err))
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

        // Configure host-side TAP device for networking (after VM creates it)
        if config.network_enabled {
            let tap_name = format!("tap{}", &config.id[..config.id.len().min(12)]);
            Self::configure_tap_device(&tap_name)?;
        }

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

        // Clean up TAP device
        let tap_name = format!("tap{}", &handle.id[..handle.id.len().min(12)]);
        Self::cleanup_tap_device(&tap_name);

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
