//! HVF (Hypervisor.framework) adapter for macOS.
//!
//! Provides VM lifecycle management using vfkit on macOS.
//! This is a fallback adapter when libkrun-efi is not available.

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::network::NetworkConfig;
use crate::types::vm::{CommandSpec, DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{debug, error, info, instrument, warn};

// Embed kestrel initramfs directly in the binary (1.9MB)
// This is built by hypr-core/build.rs during compilation
// Works for both development and distributed binaries!
#[cfg(target_arch = "x86_64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-amd64.cpio"));

#[cfg(target_arch = "aarch64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-arm64.cpio"));

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
        let kernel_path = crate::paths::kernel_path();

        Ok(Self { binary_path, kernel_path })
    }

    /// Write embedded initramfs to a temporary file and return its path.
    ///
    /// The initramfs is embedded in the binary at compile time, so this works
    /// for both development and distributed binaries.
    fn get_initramfs_path() -> Result<PathBuf> {
        // Use centralized runtime directory
        let runtime_dir = crate::paths::runtime_dir();
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;
        let temp_path = runtime_dir.join("kestrel-initramfs.cpio");

        // Only write if it doesn't exist or is outdated
        // (Check size to avoid rewriting on every VM)
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

        Err(HyprError::HypervisorNotFound { hypervisor: "vfkit".to_string() })
    }

    /// Prepare a disk image for macOS Virtualization.framework.
    ///
    /// # Optimization Strategy
    ///
    /// 1. **Fast Path (Upstream Alignment)**: If the image is already 4KB-aligned
    ///    (built by HYPR), use it directly without any conversion.
    ///
    /// 2. **Fast Path (Cache Hit)**: If we've already converted this image, use the cached copy.
    ///
    /// 3. **Fallback (APFS CoW)**: For unaligned external images, use `fs::copy()` which
    ///    leverages macOS APFS Copy-on-Write (via `fclonefileat` syscall). This creates
    ///    an instant clone that shares disk blocks with the original until modified.
    ///    We then append padding to align to 4KB sectors.
    fn convert_to_raw_disk(squashfs_path: &std::path::Path) -> Result<PathBuf> {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;

        // Get squashfs file metadata
        let metadata = fs::metadata(squashfs_path)
            .map_err(|e| HyprError::IoError { path: squashfs_path.to_path_buf(), source: e })?;
        let current_size = metadata.len();

        // Alignment for macOS Virtualization.framework (covers both 512 and 4K sectors)
        const SECTOR_ALIGN: u64 = 4096;

        // FAST PATH 1: Upstream Alignment
        // If the image was built by HYPR, it's already padded to 4KB. Use it directly.
        if current_size % SECTOR_ALIGN == 0 {
            debug!("Image is already 4KB-aligned ({} bytes), using directly", current_size);
            return Ok(squashfs_path.to_path_buf());
        }

        // Generate cache key using path + mtime + size (fast, avoids SHA256 of large files)
        let cache_dir = crate::paths::cache_dir();
        fs::create_dir_all(&cache_dir)
            .map_err(|e| HyprError::IoError { path: cache_dir.clone(), source: e })?;

        let hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            squashfs_path.hash(&mut hasher);
            metadata.mtime().hash(&mut hasher);
            current_size.hash(&mut hasher);
            hasher.finish()
        };
        let raw_path = cache_dir.join(format!("rootfs-{:x}.raw", hash));

        // Calculate aligned size
        let padded_size = current_size.div_ceil(SECTOR_ALIGN) * SECTOR_ALIGN;

        // FAST PATH 2: Cache Hit
        if raw_path.exists() {
            if let Ok(raw_meta) = fs::metadata(&raw_path) {
                if raw_meta.len() == padded_size {
                    debug!("Using cached aligned disk image: {}", raw_path.display());
                    return Ok(raw_path);
                }
            }
        }

        // FALLBACK: APFS Clone & Pad
        // On macOS, fs::copy() uses fclonefileat() which creates a CoW copy.
        // This is instant and takes ~0 additional disk space until modified.
        info!(
            "Aligning image for macOS Virtualization.framework (APFS CoW): {} -> {}",
            squashfs_path.display(),
            raw_path.display()
        );

        fs::copy(squashfs_path, &raw_path)
            .map_err(|e| HyprError::IoError { path: raw_path.clone(), source: e })?;

        // Append padding to reach alignment
        let padding_needed = (padded_size - current_size) as usize;
        if padding_needed > 0 {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(&raw_path)
                .map_err(|e| HyprError::IoError { path: raw_path.clone(), source: e })?;

            // Write zeros to pad (ensures the block is allocated, not sparse at the end)
            let zeros = vec![0u8; padding_needed];
            file.write_all(&zeros)
                .map_err(|e| HyprError::IoError { path: raw_path.clone(), source: e })?;

            file.sync_all()
                .map_err(|e| HyprError::IoError { path: raw_path.clone(), source: e })?;
        }

        debug!(
            "Created aligned disk image via APFS clone: {} ({} bytes, padded {} bytes)",
            raw_path.display(),
            padded_size,
            padding_needed
        );

        Ok(raw_path)
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

        // Kernel
        let kernel = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        args.push("--kernel".to_string());
        args.push(kernel.to_string_lossy().to_string());

        // Initrd (use config if provided, otherwise use embedded kestrel initramfs)
        args.push("--initrd".to_string());
        if let Some(custom_initrd) = &config.initramfs_path {
            args.push(custom_initrd.to_string_lossy().to_string());
        } else {
            let initrd_path = Self::get_initramfs_path()?;
            args.push(initrd_path.to_string_lossy().to_string());
        }

        // Kernel command line (REQUIRED by vfkit when using --kernel/--initrd, even if empty)
        args.push("--kernel-cmdline".to_string());

        // Build kernel command line with network parameters if IP is assigned
        let mut kernel_cmdline_parts: Vec<String> = config.kernel_args.clone();

        // Enable serial console output (vfkit uses virtio-serial which maps to hvc0)
        kernel_cmdline_parts.push("console=hvc0".to_string());

        // Inject network configuration into kernel cmdline for runtime VMs
        if config.network_enabled {
            if let Some(ip) = &config.network.ip_address {
                kernel_cmdline_parts.push(format!("ip={}", ip));
                // macOS vmnet uses 192.168.64.0/24 subnet
                kernel_cmdline_parts.push("netmask=255.255.255.0".to_string());
                kernel_cmdline_parts.push("gateway=192.168.64.1".to_string());
                kernel_cmdline_parts.push("mode=runtime".to_string());
                debug!(
                    "Injected network config: ip={} netmask=255.255.255.0 gateway=192.168.64.1",
                    ip
                );
            }
        }

        args.push(kernel_cmdline_parts.join(" "));

        // Disks - macOS Virtualization.framework requires raw disk images
        // For squashfs files, we need to convert them to a raw image format
        for disk in &config.disks {
            args.push("--device".to_string());

            // Check if this is a squashfs file that needs conversion
            let disk_path = if disk.path.extension().is_some_and(|ext| ext == "squashfs") {
                // Convert squashfs to raw disk image for macOS compatibility
                match Self::convert_to_raw_disk(&disk.path) {
                    Ok(raw_path) => raw_path,
                    Err(e) => {
                        warn!("Failed to convert squashfs to raw disk: {}, using original", e);
                        disk.path.clone()
                    }
                }
            } else {
                disk.path.clone()
            };

            args.push(format!("virtio-blk,path={}", disk_path.display()));
        }

        // virtio-fs mounts
        for mount in &config.virtio_fs_mounts {
            args.push("--device".to_string());
            args.push(format!(
                "virtio-fs,sharedDir={},mountTag={}",
                mount.host_path.display(),
                mount.tag
            ));
        }

        // Network (only if enabled - build VMs have this disabled for security)
        if config.network_enabled {
            args.push("--device".to_string());
            let mac = config
                .network
                .mac_address
                .as_ref()
                .map(|m| format!(",mac={}", m))
                .unwrap_or_default();
            args.push(format!("virtio-net,nat{}", mac));
        }

        // Serial console
        // For runtime VMs: use stdio (user needs to see output!)
        // Serial console output to log file (required for daemon mode - no stdio available)
        args.push("--device".to_string());
        let log_path = crate::paths::vm_log_path(&config.id);
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        args.push(format!("virtio-serial,logFilePath={}", log_path.display()));
        debug!("VM console log: {}", log_path.display());

        // RNG device (entropy source for VM)
        // Eliminates getrandom() blocking on fresh VM boot
        args.push("--device".to_string());
        args.push("virtio-rng".to_string());

        // Rosetta x86_64 emulation (macOS ARM64 only)
        // This enables running x86_64 container images on Apple Silicon via Rosetta 2.
        // vfkit will expose the Rosetta runtime as a virtio-fs share with tag "rosetta".
        // The guest (Kestrel) will mount this and register it with binfmt_misc.
        // Cost is negligible if unused - Rosetta share is only accessed when x86_64 binaries run.
        #[cfg(target_arch = "aarch64")]
        {
            args.push("--device".to_string());
            args.push("rosetta,mountTag=rosetta".to_string());
            debug!("Rosetta x86_64 emulation enabled for ARM64 host");
        }

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
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec> {
        // Check for GPU and warn
        self.check_gpu_support(config)?;

        // Build arguments
        let args = self.build_args(config)?;

        Ok(CommandSpec {
            program: self.binary_path.to_string_lossy().to_string(),
            args,
            env: vec![],
        })
    }

    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with HVF/vfkit");

        // Check for GPU and warn
        self.check_gpu_support(config)?;

        // Build arguments
        let args = self.build_args(config)?;

        // Create log file for VM output
        let log_path = Self::get_vm_log_path(&config.id)?;
        let log_file = std::fs::File::create(&log_path)
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;
        let log_file_err = log_file
            .try_clone()
            .map_err(|e| HyprError::IoError { path: log_path.clone(), source: e })?;

        info!("VM logs will be written to: {}", log_path.display());

        // Spawn vfkit process with stdout/stderr redirected to log file
        let start = Instant::now();
        let child = Command::new(&self.binary_path)
            .args(&args)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(log_file_err))
            .spawn()
            .map_err(|e| {
                metrics::counter!("hypr_vm_start_failures_total", "adapter" => "hvf", "reason" => "spawn_failed").increment(1);
                HyprError::VmStartFailed {
                    vm_id: config.id.clone(),
                    reason: format!("Failed to spawn vfkit: {}", e),
                }
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

        info!(pid = pid, duration_ms = start.elapsed().as_millis(), "VM created successfully");

        Ok(VmHandle {
            id: config.id.clone(),
            pid: Some(pid),
            socket_path: None, // No control socket for vfkit
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
                    metrics::counter!("hypr_vm_stop_failures_total", "adapter" => "hvf", "reason" => "kill_failed").increment(1);
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

    #[instrument(skip(self, _disk), fields(vm_id = %_handle.id))]
    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "hvf", "operation" => "attach_disk").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "hvf (Phase 1)".to_string(),
        })
    }

    #[instrument(skip(self, _net), fields(vm_id = %_handle.id))]
    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "hvf", "operation" => "attach_network").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "hvf (Phase 1)".to_string(),
        })
    }

    #[instrument(skip(self, _gpu), fields(vm_id = %_handle.id))]
    async fn attach_gpu(&self, _handle: &VmHandle, _gpu: &GpuConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "hvf", "operation" => "attach_gpu").increment(1);
        Err(HyprError::GpuUnavailable {
            reason: "HVF does not support GPU passthrough. Use libkrun-efi for Metal support."
                .to_string(),
        })
    }

    fn vsock_path(&self, _handle: &VmHandle) -> PathBuf {
        // No longer used - communication via virtio-fs + stdout parsing
        PathBuf::from("/dev/null")
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
