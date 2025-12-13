//! libkrun adapter for macOS.
//!
//! Provides VM lifecycle management using libkrun, which leverages
//! Apple's Hypervisor.framework with additional features:
//!
//! - **Direct kernel boot**: via `krun_set_kernel()` - same model as Linux
//! - **GPU passthrough**: via virtio-gpu + Venus → Metal
//! - **Rosetta support**: x86_64 emulation on Apple Silicon
//! - **Native performance**: Uses Virtualization.framework under the hood

use super::libkrun_ffi::{net_features, net_flags, GpuFlags, KernelFormat, Libkrun};
use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::network::NetworkConfig;
use crate::types::vm::{CommandSpec, DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

// Embed kestrel initramfs directly in the binary
#[cfg(target_arch = "x86_64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-amd64.cpio"));

#[cfg(target_arch = "aarch64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-arm64.cpio"));

use crate::network::{GvproxyBackend, GvproxyPortForward, gvproxy};

/// VM context state tracked by the adapter.
struct VmContext {
    ctx_id: u32,
    shutdown_eventfd: Option<i32>,
    /// Receiver to wait for VM exit (for builders)
    exit_receiver: Option<tokio::sync::oneshot::Receiver<()>>,
    /// gvproxy backend (if networking enabled)
    gvproxy: Option<GvproxyBackend>,
}

/// libkrun adapter for macOS.
///
/// Uses libkrun for native macOS virtualization with:
/// - Direct kernel boot (same as cloud-hypervisor on Linux)
/// - GPU passthrough via virtio-gpu + Venus (Metal backend)
/// - Full virtio device support
pub struct LibkrunAdapter {
    /// libkrun library handle
    libkrun: Arc<Libkrun>,
    /// Default kernel path
    kernel_path: PathBuf,
    /// Active VM contexts (vm_id -> context)
    contexts: Mutex<HashMap<String, VmContext>>,
    /// Exit notification senders (moved to start())
    exit_senders: Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>,
    /// Whether GPU is available (Apple Silicon)
    gpu_available: bool,
}

impl LibkrunAdapter {
    /// Create a new libkrun adapter.
    pub fn new() -> Result<Self> {
        let libkrun = Arc::new(Libkrun::load()?);

        // Set log level based on RUST_LOG
        let log_level = if tracing::enabled!(tracing::Level::TRACE) {
            5 // trace
        } else if tracing::enabled!(tracing::Level::DEBUG) {
            4 // debug
        } else if tracing::enabled!(tracing::Level::INFO) {
            3 // info
        } else if tracing::enabled!(tracing::Level::WARN) {
            2 // warn
        } else {
            1 // error
        };
        let _ = libkrun.set_log_level(log_level);

        let kernel_path = crate::paths::kernel_path();

        // GPU is available on Apple Silicon (aarch64)
        #[cfg(target_arch = "aarch64")]
        let gpu_available = true;

        #[cfg(not(target_arch = "aarch64"))]
        let gpu_available = false;

        info!(
            kernel = %kernel_path.display(),
            gpu_available,
            "libkrun adapter initialized"
        );

        Ok(Self {
            libkrun,
            kernel_path,
            contexts: Mutex::new(HashMap::new()),
            exit_senders: Mutex::new(HashMap::new()),
            gpu_available,
        })
    }

    /// Write embedded initramfs to a temporary file and return its path.
    fn get_initramfs_path() -> Result<PathBuf> {
        let runtime_dir = crate::paths::runtime_dir();
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;
        let temp_path = runtime_dir.join("kestrel-initramfs.cpio");

        // Only write if it doesn't exist or is outdated
        let should_write = if temp_path.exists() {
            let metadata = std::fs::metadata(&temp_path)
                .map_err(|e| HyprError::IoError { path: temp_path.clone(), source: e })?;
            metadata.len() != KESTREL_INITRAMFS.len() as u64
        } else {
            true
        };

        if should_write {
            let mut file = std::fs::File::create(&temp_path)
                .map_err(|e| HyprError::IoError { path: temp_path.clone(), source: e })?;
            file.write_all(KESTREL_INITRAMFS)
                .map_err(|e| HyprError::IoError { path: temp_path.clone(), source: e })?;
            debug!("Wrote embedded kestrel initramfs to {}", temp_path.display());
        }

        Ok(temp_path)
    }

    /// Get the log file path for a VM.
    fn get_vm_log_path(vm_id: &str) -> Result<PathBuf> {
        let log_dir = crate::paths::logs_dir();
        std::fs::create_dir_all(&log_dir)
            .map_err(|e| HyprError::IoError { path: log_dir.clone(), source: e })?;
        Ok(log_dir.join(format!("{}.log", vm_id)))
    }

    /// Build kernel command line.
    fn build_kernel_cmdline(&self, config: &VmConfig) -> String {
        let mut parts: Vec<String> = config.kernel_args.clone();

        // Console on hvc0 (virtio-console)
        parts.push("console=hvc0".to_string());

        // Inject network configuration for runtime VMs
        // gvproxy uses 192.168.127.0/24 subnet with DHCP
        if config.network_enabled {
            if let Some(ip) = &config.network.ip_address {
                // Use static IP if specified
                parts.push(format!("ip={}", ip));
                parts.push(format!("netmask={}", gvproxy::defaults::NETMASK_STR));
                parts.push(format!("gateway={}", gvproxy::defaults::GATEWAY));
                parts.push("mode=runtime".to_string());
                debug!(
                    "Injected network config: ip={} netmask={} gateway={}",
                    ip,
                    gvproxy::defaults::NETMASK_STR,
                    gvproxy::defaults::GATEWAY
                );
            } else {
                // Use DHCP (gvproxy default)
                parts.push("mode=runtime".to_string());
                debug!("Network enabled with DHCP (gvproxy default)");
            }
        }

        parts.join(" ")
    }

    /// Generate a random locally-administered MAC address.
    ///
    /// Uses the 52:54:00 prefix (QEMU/KVM convention) with random suffix.
    fn generate_mac_address_bytes() -> [u8; 6] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        [
            0x52, // Locally administered, unicast
            0x54,
            0x00,
            ((seed >> 16) & 0xff) as u8,
            ((seed >> 8) & 0xff) as u8,
            (seed & 0xff) as u8,
        ]
    }

    /// Wait for the VM to exit.
    /// This is useful for builders that need to wait for the VM to complete.
    pub async fn wait_for_exit(&self, handle: &VmHandle) -> Result<()> {
        let receiver = {
            let mut contexts = self.contexts.lock().await;
            contexts.get_mut(&handle.id).and_then(|ctx| ctx.exit_receiver.take())
        };

        if let Some(rx) = receiver {
            let _ = rx.await;
            info!(vm_id = %handle.id, "VM exit detected");
        } else {
            warn!(vm_id = %handle.id, "No exit receiver available, VM may have already exited");
        }
        Ok(())
    }

    /// Configure a libkrun context with VM settings.
    ///
    /// # Arguments
    /// * `ctx_id` - libkrun context ID
    /// * `config` - VM configuration
    /// * `gvproxy_socket` - Optional gvproxy socket path (for networking)
    fn configure_context(
        &self,
        ctx_id: u32,
        config: &VmConfig,
        gvproxy_socket: Option<&std::path::Path>,
    ) -> Result<()> {
        // Set VM resources
        let vcpus = config.resources.cpus.min(255) as u8;
        let ram_mib = config.resources.memory_mb;
        self.libkrun.set_vm_config(ctx_id, vcpus, ram_mib)?;

        // Set kernel for direct boot
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        let initramfs = match &config.initramfs_path {
            Some(p) => p.clone(),
            None => Self::get_initramfs_path()?,
        };
        let cmdline = self.build_kernel_cmdline(config);

        // Detect kernel format based on architecture
        // ARM64 uses Raw format (uncompressed Image), x86_64 uses ELF (vmlinux)
        #[cfg(target_arch = "aarch64")]
        let kernel_format = KernelFormat::Raw;

        #[cfg(target_arch = "x86_64")]
        let kernel_format = KernelFormat::Elf;

        self.libkrun.set_kernel(ctx_id, kernel, kernel_format, Some(&initramfs), &cmdline)?;

        // Add root disk (first disk is root)
        if let Some(disk) = config.disks.first() {
            self.libkrun.set_root_disk(ctx_id, &disk.path)?;
        }

        // Add additional disks
        for (i, disk) in config.disks.iter().skip(1).enumerate() {
            let block_id = format!("vdb{}", i);
            self.libkrun.add_disk(ctx_id, &block_id, &disk.path, disk.readonly)?;
        }

        // Add virtio-fs mounts
        for mount in &config.virtio_fs_mounts {
            self.libkrun.add_virtiofs(ctx_id, &mount.tag, &mount.host_path)?;
        }

        // Enable networking if requested
        // On macOS, we use gvproxy for userspace networking
        if config.network_enabled {
            if let Some(socket_path) = gvproxy_socket {
                let mac = Self::generate_mac_address_bytes();

                // Create our side of the unixgram socket pair
                // gvproxy listens on vfkit_socket_path, we connect from vm_socket_path
                let vm_socket_path = socket_path.with_extension("vm.sock");

                // Use add_net_unixgram for gvproxy/vfkit mode
                self.libkrun.add_net_unixgram(
                    ctx_id,
                    &vm_socket_path,  // Our socket
                    socket_path,      // gvproxy's socket
                    &mac,
                    net_features::COMPAT,
                    net_flags::VFKIT, // vfkit compatibility mode for gvproxy
                )?;

                debug!(
                    mac = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    ),
                    socket = %socket_path.display(),
                    "Network enabled via gvproxy"
                );
            } else {
                warn!("Network enabled but no gvproxy socket provided");
            }
        }

        // Add Rosetta support on ARM64
        #[cfg(target_arch = "aarch64")]
        {
            // Rosetta is exposed as a virtio-fs share with tag "rosetta"
            // The guest (kestrel) mounts this and registers with binfmt_misc
            let rosetta_path = PathBuf::from("/usr/libexec/rosetta/rosetta");
            if rosetta_path.exists() {
                // Note: libkrun handles Rosetta automatically when available
                debug!("Rosetta x86_64 emulation available");
            }
        }

        // Set up vsock for guest-host communication
        let vsock_path = self.vsock_path_for_id(&config.id);
        if let Some(parent) = vsock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Remove existing socket file if present
        let _ = std::fs::remove_file(&vsock_path);
        self.libkrun.add_vsock_port2(ctx_id, 1024, &vsock_path, true)?;
        debug!("vsock enabled at {}", vsock_path.display());

        // Set console output to log file
        let log_path = Self::get_vm_log_path(&config.id)?;
        self.libkrun.set_console_output(ctx_id, &log_path)?;
        info!("VM console log: {}", log_path.display());

        // Enable GPU if requested and available
        if config.gpu.is_some() && self.gpu_available {
            self.libkrun.set_gpu_options(ctx_id, GpuFlags::Virgl)?;
            info!("GPU enabled via virtio-gpu + Venus (Metal backend)");
        }

        Ok(())
    }

    fn vsock_path_for_id(&self, vm_id: &str) -> PathBuf {
        crate::paths::runtime_dir().join("krun").join(format!("{}.vsock", vm_id))
    }

    fn metrics_vsock_path_for_id(&self, vm_id: &str) -> PathBuf {
        crate::paths::runtime_dir().join("krun").join(format!("{}.metrics.vsock", vm_id))
    }
}

impl Default for LibkrunAdapter {
    fn default() -> Self {
        Self::new().expect("Failed to create libkrun adapter")
    }
}

#[async_trait]
impl VmmAdapter for LibkrunAdapter {
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec> {
        // libkrun doesn't work via CLI spawning - it runs in-process
        // For builder VMs, we return a special marker that the builder
        // will recognize and handle via create() instead
        //
        // Return a "pseudo command" that indicates libkrun should be used
        Ok(CommandSpec {
            program: "__libkrun__".to_string(),
            args: vec![config.id.clone()],
            env: vec![],
        })
    }

    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with libkrun");

        let start = Instant::now();

        // Start gvproxy for networking if enabled
        let mut gvproxy_backend: Option<GvproxyBackend> = None;
        let gvproxy_socket: Option<PathBuf>;

        if config.network_enabled {
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

            gvproxy_socket = Some(backend.vfkit_socket_path().to_path_buf());
            gvproxy_backend = Some(backend);
        } else {
            gvproxy_socket = None;
        }

        // Create libkrun context
        let ctx_id = self.libkrun.create_ctx()?;
        debug!(ctx_id, "Created libkrun context");

        // Configure the context (pass gvproxy socket path if available)
        if let Err(e) = self.configure_context(ctx_id, config, gvproxy_socket.as_deref()) {
            // Clean up on failure
            let _ = self.libkrun.free_ctx(ctx_id);
            if let Some(mut gv) = gvproxy_backend.take() {
                let _ = gv.stop();
            }
            metrics::counter!("hypr_vm_start_failures_total", "adapter" => "libkrun", "reason" => "config_failed").increment(1);
            return Err(e);
        }

        // Get shutdown eventfd for graceful shutdown
        let shutdown_eventfd = self.libkrun.get_shutdown_eventfd(ctx_id).ok();

        // Create exit notification channel
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();

        // Store context with exit receiver and gvproxy backend
        {
            let mut contexts = self.contexts.lock().await;
            contexts.insert(
                config.id.clone(),
                VmContext {
                    ctx_id,
                    shutdown_eventfd,
                    exit_receiver: Some(exit_rx),
                    gvproxy: gvproxy_backend,
                },
            );
        }

        // Store sender for later use in start()
        // We use a separate map because we need to move the sender
        self.exit_senders.lock().await.insert(config.id.clone(), exit_tx);

        // Record metrics
        let histogram =
            metrics::histogram!("hypr_vm_boot_duration_seconds", "adapter" => "libkrun");
        histogram.record(start.elapsed().as_secs_f64());

        let counter = metrics::counter!("hypr_vm_created_total", "adapter" => "libkrun");
        counter.increment(1);

        info!(ctx_id, duration_ms = start.elapsed().as_millis(), "VM created successfully");

        Ok(VmHandle {
            id: config.id.clone(),
            pid: None, // libkrun runs in-process, no separate PID
            socket_path: None,
        })
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn start(&self, handle: &VmHandle) -> Result<()> {
        let ctx_id = {
            let contexts = self.contexts.lock().await;
            contexts
                .get(&handle.id)
                .map(|c| c.ctx_id)
                .ok_or_else(|| HyprError::VmNotFound { vm_id: handle.id.clone() })?
        };

        info!(ctx_id, "Starting VM");

        // Get the exit sender to notify when VM exits
        let exit_sender = self.exit_senders.lock().await.remove(&handle.id);

        // krun_start_enter is blocking - spawn in a separate thread
        let libkrun = self.libkrun.clone();
        let vm_id = handle.id.clone();

        tokio::task::spawn_blocking(move || {
            // Fork before calling start_enter because libkrun calls exit() on VM shutdown
            // This ensures only the child process dies, not the parent
            unsafe {
                let pid = libc::fork();
                if pid == 0 {
                    // Child process - run the VM (will exit when VM shuts down)
                    let _ = libkrun.start_enter(ctx_id);
                    // If we get here, VM exited normally (shouldn't happen with libkrun)
                    std::process::exit(0);
                } else if pid > 0 {
                    // Parent process - wait for child
                    let mut status: libc::c_int = 0;
                    libc::waitpid(pid, &mut status, 0);

                    if libc::WIFEXITED(status) {
                        let exit_code = libc::WEXITSTATUS(status);
                        if exit_code == 0 {
                            info!(vm_id = %vm_id, "VM exited normally");
                        } else {
                            error!(vm_id = %vm_id, exit_code, "VM exited with error");
                        }
                    } else {
                        info!(vm_id = %vm_id, "VM terminated by signal");
                    }
                } else {
                    error!(vm_id = %vm_id, "Failed to fork for VM execution");
                }
            }

            // Signal that VM has exited
            if let Some(sender) = exit_sender {
                let _ = sender.send(());
            }
        });

        // Give the VM a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("VM started");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()> {
        info!("Stopping VM gracefully");

        let (ctx_id, eventfd) = {
            let contexts = self.contexts.lock().await;
            match contexts.get(&handle.id) {
                Some(ctx) => (ctx.ctx_id, ctx.shutdown_eventfd),
                None => {
                    warn!("VM context not found, may already be stopped");
                    return Ok(());
                }
            }
        };

        // Signal shutdown via eventfd if available
        if let Some(fd) = eventfd {
            debug!(ctx_id, fd, "Signaling shutdown via eventfd");
            // Write 1 to eventfd to signal shutdown
            let buf: [u8; 8] = 1u64.to_ne_bytes();
            unsafe {
                libc::write(fd, buf.as_ptr() as *const libc::c_void, 8);
            }
        }

        // Wait for graceful shutdown
        let start = Instant::now();
        while start.elapsed() < timeout {
            // Check if context is still active
            // For now, just wait - libkrun will clean up
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Clean up context
        self.delete(handle).await?;

        info!("VM stopped");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn kill(&self, handle: &VmHandle) -> Result<()> {
        info!("Killing VM");

        // Just delete the context - this will force stop
        self.delete(handle).await?;

        info!("VM killed");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn delete(&self, handle: &VmHandle) -> Result<()> {
        info!("Deleting VM resources");

        let (ctx_id, mut gvproxy) = {
            let mut contexts = self.contexts.lock().await;
            contexts
                .remove(&handle.id)
                .map(|c| (Some(c.ctx_id), c.gvproxy))
                .unwrap_or((None, None))
        };

        // Free libkrun context
        if let Some(ctx_id) = ctx_id {
            if let Err(e) = self.libkrun.free_ctx(ctx_id) {
                warn!(error = %e, "Failed to free libkrun context");
            }
        }

        // Stop gvproxy
        if let Some(ref mut gv) = gvproxy {
            if let Err(e) = gv.stop() {
                warn!(error = %e, "Failed to stop gvproxy");
            }
        }

        // Clean up vsock file
        let vsock_path = self.vsock_path_for_id(&handle.id);
        let _ = std::fs::remove_file(&vsock_path);

        info!("VM resources deleted");
        Ok(())
    }

    #[instrument(skip(self, _disk), fields(vm_id = %_handle.id))]
    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "libkrun", "operation" => "attach_disk").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "libkrun".to_string(),
        })
    }

    #[instrument(skip(self, _net), fields(vm_id = %_handle.id))]
    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "libkrun", "operation" => "attach_network").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "libkrun".to_string(),
        })
    }

    #[instrument(skip(self, gpu), fields(vm_id = %handle.id))]
    async fn attach_gpu(&self, handle: &VmHandle, gpu: &GpuConfig) -> Result<()> {
        if !self.gpu_available {
            metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "libkrun", "operation" => "attach_gpu").increment(1);
            return Err(HyprError::GpuUnavailable {
                reason: "GPU passthrough requires Apple Silicon (ARM64)".to_string(),
            });
        }

        let ctx_id = {
            let contexts = self.contexts.lock().await;
            contexts
                .get(&handle.id)
                .map(|c| c.ctx_id)
                .ok_or_else(|| HyprError::VmNotFound { vm_id: handle.id.clone() })?
        };

        // Enable GPU for the context
        self.libkrun.set_gpu_options(ctx_id, GpuFlags::Virgl)?;

        info!(
            vendor = ?gpu.vendor,
            model = %gpu.model,
            "GPU attached via virtio-gpu + Venus (Metal backend)"
        );

        Ok(())
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        self.vsock_path_for_id(&handle.id)
    }

    fn metrics_vsock_path(&self, handle: &VmHandle) -> PathBuf {
        self.metrics_vsock_path_for_id(&handle.id)
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            gpu_passthrough: self.gpu_available,
            virtio_fs: true,
            hotplug_devices: false,
            metadata: HashMap::from([
                ("adapter".to_string(), "libkrun".to_string()),
                ("backend".to_string(), "libkrun".to_string()),
                (
                    "gpu_backend".to_string(),
                    if self.gpu_available { "metal" } else { "none" }.to_string(),
                ),
            ]),
        }
    }

    fn name(&self) -> &str {
        "libkrun"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libkrun_adapter_creation() {
        match LibkrunAdapter::new() {
            Ok(adapter) => {
                println!("Adapter created: {}", adapter.name());
                let caps = adapter.capabilities();
                println!("GPU available: {}", caps.gpu_passthrough);
            }
            Err(e) => {
                println!("Adapter creation failed (expected if libkrun not installed): {}", e);
            }
        }
    }
}
