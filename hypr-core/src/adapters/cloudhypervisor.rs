//! cloud-hypervisor adapter for Linux.
//!
//! Provides VM lifecycle management using cloud-hypervisor:
//! - Create: Spawn CH process with API socket (auto-boots immediately)
//! - Start: No-op (VM boots on create)
//! - Stop: Send graceful shutdown via API, wait for exit, fallback to SIGKILL
//! - Kill: SIGKILL the CH process immediately
//! - Delete: Clean up resources (virtiofsd, gvproxy, VFIO)

use crate::adapters::{AdapterCapabilities, CommandSpec, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::network::{gvproxy, GvproxyBackend, GvproxyPortForward};
use crate::types::network::NetworkConfig;
use crate::types::vm::{DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
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
    /// Track gvproxy backends by VM ID (for cleanup)
    gvproxy_backends: Arc<Mutex<HashMap<String, GvproxyBackend>>>,
    /// Track bound VFIO devices by VM ID (for cleanup/restore)
    bound_vfio_devices: Arc<Mutex<HashMap<String, Vec<String>>>>,
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
            gvproxy_backends: Arc::new(Mutex::new(HashMap::new())),
            bound_vfio_devices: Arc::new(Mutex::new(HashMap::new())),
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
                if start.elapsed() > Duration::from_secs(30) {
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
        gvproxy_socket: Option<&std::path::Path>,
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

        // Memory balloon (for dynamic memory management)
        // Allows the VM to return unused memory to the host.
        if config.resources.balloon_enabled {
            args.push("--balloon".to_string());
            args.push("size=0".to_string()); // Start with no balloon inflation
            debug!("Memory balloon enabled - VM can dynamically return unused memory");
        }

        // Kernel
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        args.push("--kernel".to_string());
        args.push(kernel.to_string_lossy().to_string());

        // Kernel cmdline - build with network parameters if IP is assigned
        let mut kernel_cmdline_parts: Vec<String> = config.kernel_args.clone();

        // Enable serial console output
        // x86_64: uses 8250 serial (ttyS0)
        // aarch64: uses PL011 UART (ttyAMA0)
        #[cfg(target_arch = "x86_64")]
        kernel_cmdline_parts.push("console=ttyS0".to_string());
        #[cfg(target_arch = "aarch64")]
        kernel_cmdline_parts.push("console=ttyAMA0".to_string());

        // Inject network configuration into kernel cmdline for runtime VMs
        // gvproxy uses 192.168.127.0/24 subnet with DHCP
        if config.network_enabled {
            if let Some(ip) = &config.network.ip_address {
                // Use proper kernel IP-Config format: ip=<client>:<server>:<gw>:<netmask>:<host>:<dev>:<autoconf>
                // This ensures the kernel sets up networking correctly before init runs
                kernel_cmdline_parts.push(format!(
                    "ip={}::{}:{}:::off",
                    ip,
                    gvproxy::defaults::GATEWAY,
                    gvproxy::defaults::NETMASK_STR
                ));
                // Also pass for kestrel's use (backwards compatibility)
                kernel_cmdline_parts.push(format!("netmask={}", gvproxy::defaults::NETMASK_STR));
                kernel_cmdline_parts.push(format!("gateway={}", gvproxy::defaults::GATEWAY));
                kernel_cmdline_parts.push("mode=runtime".to_string());
                debug!(
                    "Injected network config: ip={}::{}:{}:::off",
                    ip,
                    gvproxy::defaults::GATEWAY,
                    gvproxy::defaults::NETMASK_STR
                );
            } else {
                // Use DHCP (gvproxy default)
                kernel_cmdline_parts.push("mode=runtime".to_string());
                debug!("Network enabled with DHCP (gvproxy default)");
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

        // Network via gvproxy (only if enabled - build VMs have this disabled for security)
        if config.network_enabled {
            if let Some(socket_path) = gvproxy_socket {
                let mac =
                    config.network.mac_address.clone().unwrap_or_else(Self::generate_mac_address);
                // Use gvproxy's qemu socket for virtio-net
                args.push("--net".to_string());
                args.push(format!("socket={},mac={}", socket_path.display(), mac));
                debug!(socket = %socket_path.display(), mac = %mac, "Network via gvproxy");
            } else {
                warn!("Network enabled but no gvproxy socket provided");
            }
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

        // GPU passthrough via VFIO
        // cloud-hypervisor expects: --device path=/sys/bus/pci/devices/0000:01:00.0/
        if let Some(gpu) = &config.gpu {
            if let Some(pci_address) = &gpu.pci_address {
                let mut device_arg = format!("path=/sys/bus/pci/devices/{}/", pci_address);

                // NVIDIA GPUDirect P2P support (Turing, Ampere, Hopper, Lovelace)
                // Enables PCIe P2P for multi-GPU setups
                if gpu.vendor == crate::types::vm::GpuVendor::Nvidia {
                    if let Some(clique) = gpu.gpudirect_clique {
                        device_arg.push_str(&format!(",x_nv_gpudirect_clique={}", clique));
                        debug!(clique = clique, "NVIDIA GPUDirect P2P enabled");
                    }
                }

                args.push("--device".to_string());
                args.push(device_arg);

                info!(
                    pci_address = %pci_address,
                    vendor = ?gpu.vendor,
                    "GPU passthrough enabled via VFIO"
                );
            }
        }

        // vsock for guest-host communication (exec, etc.)
        // CID 3 is the standard guest CID
        let vsock_path = self.runtime_dir.join(format!("ch/{}.vsock", config.id));
        // Ensure parent directory exists
        if let Some(parent) = vsock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        args.push("--vsock".to_string());
        args.push(format!("cid=3,socket={}", vsock_path.display()));
        debug!("vsock enabled at {}", vsock_path.display());

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

    /// Send an HTTP request to the cloud-hypervisor API socket.
    ///
    /// cloud-hypervisor exposes a REST API over Unix socket for VM control.
    async fn send_api_request(
        socket_path: &Path,
        method: &str,
        endpoint: &str,
    ) -> Result<(u16, String)> {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to API socket: {}", e)))?;

        // Build HTTP request
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            method, endpoint
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write to API socket: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read from API socket: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response);

        // Parse HTTP status code
        let status_code = response_str
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);

        Ok((status_code, response_str.to_string()))
    }

    /// Check if a process is still running.
    fn is_process_running(pid: u32) -> bool {
        // Use kill with signal 0 to check if process exists
        unsafe { libc::kill(pid as i32, 0) == 0 }
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

        // Build arguments with virtiofsd socket paths (no gvproxy or log file for command spec)
        // Build VMs don't use networking for security
        let args = self.build_args(config, &virtiofsd_daemons, None, None)?;

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

        // Start gvproxy for networking if enabled
        let gvproxy_socket: Option<PathBuf> = if config.network_enabled {
            debug!("Starting gvproxy for networking");
            let mut backend = GvproxyBackend::new(&config.id);

            // Convert port mappings to gvproxy format
            let port_forwards: Vec<GvproxyPortForward> = config
                .ports
                .iter()
                .map(|pm| GvproxyPortForward {
                    host_port: pm.host_port,
                    guest_port: pm.vm_port,
                    protocol: format!("{:?}", pm.protocol).to_lowercase(),
                })
                .collect();

            backend.start(
                gvproxy::defaults::GATEWAY,
                gvproxy::defaults::CIDR,
                port_forwards,
                None, // Use gvproxy's built-in DNS
            )?;

            let socket_path = backend.qemu_socket_path().to_path_buf();

            // Store gvproxy for cleanup
            {
                let mut map = self.gvproxy_backends.lock().unwrap();
                map.insert(config.id.clone(), backend);
            }

            Some(socket_path)
        } else {
            None
        };

        // Build arguments (using virtiofsd daemon socket paths, gvproxy socket, and log path)
        let args = {
            let _span = span!(Level::DEBUG, "build_ch_args").entered();
            self.build_args(config, &virtiofsd_daemons, gvproxy_socket.as_deref(), Some(&log_path))?
        };
        let log_file = std::fs::File::create(&log_path)
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;
        let log_file_err = log_file
            .try_clone()
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;

        info!("VM logs will be written to: {}", log_path.display());

        // Bind GPU device to vfio-pci if GPU passthrough is requested
        if let Some(gpu) = &config.gpu {
            if let Some(pci_addr) = &gpu.pci_address {
                info!(pci_address = %pci_addr, "Binding GPU to vfio-pci for passthrough");

                let mut vfio_manager = crate::adapters::vfio::VfioManager::new();
                let bind_options = crate::adapters::vfio::BindOptions {
                    force_boot_vga: false,             // Never unbind boot VGA automatically
                    include_iommu_group_devices: true, // Include all devices in IOMMU group
                    ..Default::default()
                };

                // Validate and bind device to vfio-pci
                vfio_manager.validate_devices(std::slice::from_ref(pci_addr), &bind_options)?;
                vfio_manager.bind_devices(std::slice::from_ref(pci_addr))?;

                // Track for cleanup on delete
                {
                    let mut bound = self.bound_vfio_devices.lock().unwrap();
                    bound.insert(config.id.clone(), vec![pci_addr.clone()]);
                }

                info!(pci_address = %pci_addr, "GPU bound to vfio-pci successfully");
            }
        }

        // Spawn cloud-hypervisor process with stdout/stderr redirected to log file
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(log_file_err))
            .spawn()
            .map_err(|e| {
                // Clean up gvproxy on failure
                if config.network_enabled {
                    if let Ok(mut map) = self.gvproxy_backends.lock() {
                        if let Some(mut backend) = map.remove(&config.id) {
                            let _ = backend.stop();
                        }
                    }
                }

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

        // Wait for API socket (120s timeout - multiple VMs starting simultaneously can be slow)
        let api_socket = self.api_socket_path(&config.id);
        self.wait_for_api_socket(&api_socket, Duration::from_secs(120)).await?;

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
        // cloud-hypervisor is configured to auto-boot when created.
        // This is intentional - we want VMs to start immediately after create().
        // If we needed pause/resume, we'd use --api-socket without kernel args
        // and send "PUT /api/v1/vm.boot" here.
        info!("VM started (auto-boot mode)");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()> {
        info!("Stopping VM gracefully");

        let pid = match handle.pid {
            Some(pid) => pid,
            None => {
                warn!("No PID for VM, nothing to stop");
                return Ok(());
            }
        };

        // Send graceful shutdown via cloud-hypervisor API
        if let Some(socket_path) = &handle.socket_path {
            let socket = PathBuf::from(socket_path);
            if socket.exists() {
                match Self::send_api_request(&socket, "PUT", "/api/v1/vm.shutdown").await {
                    Ok((status, _)) if status == 200 || status == 204 => {
                        info!("Shutdown request sent successfully");
                    }
                    Ok((status, body)) => {
                        warn!(
                            "Shutdown request returned status {}: {}",
                            status,
                            body.lines().next().unwrap_or("")
                        );
                    }
                    Err(e) => {
                        warn!("Failed to send shutdown request: {}", e);
                    }
                }
            }
        }

        // Wait for process to exit gracefully
        let start = Instant::now();
        while start.elapsed() < timeout {
            if !Self::is_process_running(pid) {
                info!(duration_ms = start.elapsed().as_millis(), "VM stopped gracefully");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Timeout - fall back to SIGKILL
        warn!("Graceful shutdown timed out after {:?}, forcing kill", timeout);
        self.kill(handle).await?;

        info!("VM stopped (forced)");
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

        // Restore GPU to host driver (unbind from vfio-pci)
        let bound_devices = {
            let mut bound = self.bound_vfio_devices.lock().unwrap();
            bound.remove(&handle.id)
        };

        if let Some(devices) = bound_devices {
            if !devices.is_empty() {
                info!("Restoring {} GPU device(s) to host driver", devices.len());

                let mut vfio_manager = crate::adapters::vfio::VfioManager::new();
                match vfio_manager.unbind_devices(&devices) {
                    Ok(()) => {
                        info!("GPU device(s) restored to host driver");
                    }
                    Err(e) => {
                        // Don't fail delete on unbind error - VM is already stopped
                        warn!("Failed to restore GPU to host driver: {}. Device may need manual rebind.", e);
                    }
                }
            }
        }

        // Stop gvproxy
        {
            let mut map = self.gvproxy_backends.lock().unwrap();
            if let Some(mut backend) = map.remove(&handle.id) {
                if let Err(e) = backend.stop() {
                    warn!(error = %e, "Failed to stop gvproxy");
                }
            }
        }

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

    #[instrument(skip(self, gpu), fields(vm_id = %_handle.id))]
    async fn attach_gpu(&self, _handle: &VmHandle, gpu: &GpuConfig) -> Result<()> {
        // GPU passthrough is configured at VM creation time via build_args()
        // Hot-plug of GPUs is not currently supported by cloud-hypervisor
        //
        // For hot-plug in the future:
        // POST /api/v1/vm.add-device with {"path": "/sys/bus/pci/devices/..."}

        if gpu.pci_address.is_none() {
            return Err(HyprError::GpuNotBound {
                pci_address: "unspecified".to_string(),
                hint: "Linux GPU passthrough requires a PCI address (e.g., 0000:01:00.0)"
                    .to_string(),
            });
        }

        info!(
            pci_address = ?gpu.pci_address,
            vendor = ?gpu.vendor,
            model = %gpu.model,
            "GPU configured for VFIO passthrough"
        );

        // GPU is actually attached at VM creation time (in build_args)
        // This method just validates the configuration
        Ok(())
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        self.runtime_dir.join(format!("ch/{}.vsock", handle.id))
    }

    fn metrics_vsock_path(&self, handle: &VmHandle) -> PathBuf {
        // Cloud-hypervisor multiplexes all vsock ports through a single socket.
        // The vsock protocol handles port differentiation internally.
        // For metrics (guest pushes to host port 1025), we use the same socket
        // as exec (host connects to guest port 1024).
        self.vsock_path(handle)
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            gpu_passthrough: true, // VFIO passthrough supported
            virtio_fs: true,
            hotplug_devices: false, // Phase 1
            metadata: HashMap::from([
                ("adapter".to_string(), "cloud-hypervisor".to_string()),
                ("version".to_string(), "38.0".to_string()),
                ("gpu_backend".to_string(), "vfio".to_string()),
            ]),
        }
    }

    fn name(&self) -> &str {
        "cloud-hypervisor"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
