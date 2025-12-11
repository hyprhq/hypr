//! Native macOS Virtualization.framework adapter.
//!
//! Provides VM lifecycle management using Apple's Virtualization.framework directly
//! via objc2-virtualization bindings. This gives full control over VM configuration
//! without external library dependencies.
//!
//! Features:
//! - **Direct kernel boot**: via VZLinuxBootLoader
//! - **GPU passthrough**: via virtio-gpu (Apple Silicon only)
//! - **Rosetta support**: x86_64 emulation on Apple Silicon
//! - **Native performance**: Direct Virtualization.framework integration

use crate::adapters::{AdapterCapabilities, VmmAdapter};
use crate::error::{HyprError, Result};
use crate::types::network::NetworkConfig;
use crate::types::vm::{CommandSpec, DiskConfig, GpuConfig, VmConfig, VmHandle};
use async_trait::async_trait;
use objc2::rc::Retained;
use objc2::{msg_send, AllocAnyThread};
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
    VZSharedDirectory, VZSingleDirectoryShare, VZVirtioBlockDeviceConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioGraphicsDeviceConfiguration, VZVirtioGraphicsScanoutConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketDeviceConfiguration,
    VZVirtioTraditionalMemoryBalloonDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

// Embed kestrel initramfs directly in the binary
#[cfg(target_arch = "x86_64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-amd64.cpio"));

#[cfg(target_arch = "aarch64")]
static KESTREL_INITRAMFS: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/embedded/initramfs-linux-arm64.cpio"));

/// State for a running VM.
struct VmState {
    /// The VZVirtualMachine instance
    vm: Retained<VZVirtualMachine>,
    /// Path to vsock socket
    vsock_path: PathBuf,
    /// Path to console log file
    #[allow(dead_code)]
    log_path: PathBuf,
}

// VZVirtualMachine is thread-safe when used with proper dispatch queues
unsafe impl Send for VmState {}
unsafe impl Sync for VmState {}

/// Native Virtualization.framework adapter for macOS.
///
/// Uses Apple's Virtualization.framework directly for VM management:
/// - Direct kernel boot (same as cloud-hypervisor on Linux)
/// - GPU passthrough via virtio-gpu (Apple Silicon only)
/// - Full virtio device support
/// - No external library dependencies
pub struct VirtualizationAdapter {
    /// Default kernel path
    kernel_path: PathBuf,
    /// Active VMs (vm_id -> state)
    vms: Mutex<HashMap<String, VmState>>,
    /// Whether GPU is available (Apple Silicon)
    gpu_available: bool,
}

impl VirtualizationAdapter {
    /// Create a new Virtualization.framework adapter.
    pub fn new() -> Result<Self> {
        let kernel_path = crate::paths::kernel_path();

        // GPU is available on Apple Silicon (aarch64)
        #[cfg(target_arch = "aarch64")]
        let gpu_available = true;

        #[cfg(not(target_arch = "aarch64"))]
        let gpu_available = false;

        info!(
            kernel = %kernel_path.display(),
            gpu_available,
            "Virtualization.framework adapter initialized"
        );

        Ok(Self { kernel_path, vms: Mutex::new(HashMap::new()), gpu_available })
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
        if config.network_enabled {
            if let Some(ip) = &config.network.ip_address {
                parts.push(format!("ip={}", ip));
                // Virtualization.framework uses vmnet which defaults to 192.168.64.0/24
                parts.push("netmask=255.255.255.0".to_string());
                parts.push("gateway=192.168.64.1".to_string());
                parts.push("mode=runtime".to_string());
                debug!(
                    "Injected network config: ip={} netmask=255.255.255.0 gateway=192.168.64.1",
                    ip
                );
            }
        }

        parts.join(" ")
    }

    fn vsock_path_for_id(&self, vm_id: &str) -> PathBuf {
        crate::paths::runtime_dir().join("vz").join(format!("{}.vsock", vm_id))
    }

    /// Configure and create a VZVirtualMachineConfiguration.
    fn configure_vm(&self, config: &VmConfig) -> Result<Retained<VZVirtualMachineConfiguration>> {
        let kernel_path = config.kernel_path.as_ref().unwrap_or(&self.kernel_path);
        let initramfs_path = match &config.initramfs_path {
            Some(p) => p.clone(),
            None => Self::get_initramfs_path()?,
        };
        let cmdline = self.build_kernel_cmdline(config);

        debug!(
            kernel = %kernel_path.display(),
            initramfs = %initramfs_path.display(),
            cmdline = %cmdline,
            "Configuring VM"
        );

        unsafe {
            // Create boot loader
            let kernel_url = Self::path_to_nsurl(kernel_path)?;
            let initramfs_url = Self::path_to_nsurl(&initramfs_path)?;
            let cmdline_ns = NSString::from_str(&cmdline);

            let boot_loader =
                VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url);
            boot_loader.setInitialRamdiskURL(Some(&initramfs_url));
            boot_loader.setCommandLine(&cmdline_ns);

            // Create main configuration
            let vm_config = VZVirtualMachineConfiguration::new();

            // Set boot loader
            vm_config.setBootLoader(Some(&boot_loader));

            // CPU and memory
            let vcpus = config.resources.cpus.min(255) as usize;
            let ram_bytes = (config.resources.memory_mb as u64) * 1024 * 1024;
            vm_config.setCPUCount(vcpus);
            vm_config.setMemorySize(ram_bytes);

            debug!(vcpus, ram_mb = config.resources.memory_mb, "Set VM resources");

            // Storage devices - use raw msg_send to avoid type mismatch issues
            let mut storage_devices: Vec<Retained<VZVirtioBlockDeviceConfiguration>> = Vec::new();
            for disk in &config.disks {
                let disk_config = self.configure_disk(disk)?;
                storage_devices.push(disk_config);
            }
            if !storage_devices.is_empty() {
                let storage_array = NSArray::from_retained_slice(&storage_devices);
                // Cast through transmute since VZVirtioBlockDeviceConfiguration conforms to VZStorageDeviceConfiguration
                let storage_array_cast: &NSArray<
                    objc2_virtualization::VZStorageDeviceConfiguration,
                > = std::mem::transmute(&*storage_array);
                vm_config.setStorageDevices(storage_array_cast);
            }

            // Network device
            if config.network_enabled {
                let network_config = self.configure_network()?;
                let network_array = NSArray::from_retained_slice(&[network_config]);
                let network_array_cast: &NSArray<
                    objc2_virtualization::VZNetworkDeviceConfiguration,
                > = std::mem::transmute(&*network_array);
                vm_config.setNetworkDevices(network_array_cast);
            }

            // virtio-fs mounts
            let mut fs_devices: Vec<Retained<VZVirtioFileSystemDeviceConfiguration>> = Vec::new();
            for mount in &config.virtio_fs_mounts {
                let fs_config = self.configure_virtiofs(&mount.tag, &mount.host_path)?;
                fs_devices.push(fs_config);
            }

            // Add Rosetta if available on ARM64
            #[cfg(target_arch = "aarch64")]
            {
                use objc2_virtualization::VZLinuxRosettaDirectoryShare;
                if VZLinuxRosettaDirectoryShare::availability()
                    == objc2_virtualization::VZLinuxRosettaAvailability::Installed
                {
                    if let Ok(rosetta_share) = self.configure_rosetta() {
                        fs_devices.push(rosetta_share);
                        debug!("Rosetta x86_64 emulation enabled");
                    }
                }
            }

            if !fs_devices.is_empty() {
                let fs_array = NSArray::from_retained_slice(&fs_devices);
                let fs_array_cast: &NSArray<
                    objc2_virtualization::VZDirectorySharingDeviceConfiguration,
                > = std::mem::transmute(&*fs_array);
                vm_config.setDirectorySharingDevices(fs_array_cast);
            }

            // Vsock device for guest-host communication
            let vsock_config = VZVirtioSocketDeviceConfiguration::new();
            let vsock_array = NSArray::from_retained_slice(&[vsock_config]);
            let vsock_array_cast: &NSArray<objc2_virtualization::VZSocketDeviceConfiguration> =
                std::mem::transmute(&*vsock_array);
            vm_config.setSocketDevices(vsock_array_cast);

            // Entropy device (for /dev/random)
            let entropy_config = VZVirtioEntropyDeviceConfiguration::new();
            let entropy_array = NSArray::from_retained_slice(&[entropy_config]);
            let entropy_array_cast: &NSArray<objc2_virtualization::VZEntropyDeviceConfiguration> =
                std::mem::transmute(&*entropy_array);
            vm_config.setEntropyDevices(entropy_array_cast);

            // Memory balloon (for dynamic memory)
            if config.resources.balloon_enabled {
                let balloon_config = VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new();
                let balloon_array = NSArray::from_retained_slice(&[balloon_config]);
                let balloon_array_cast: &NSArray<
                    objc2_virtualization::VZMemoryBalloonDeviceConfiguration,
                > = std::mem::transmute(&*balloon_array);
                vm_config.setMemoryBalloonDevices(balloon_array_cast);
            }

            // GPU device (Apple Silicon only)
            if config.gpu.is_some() && self.gpu_available {
                let graphics_config = self.configure_graphics()?;
                let graphics_array = NSArray::from_retained_slice(&[graphics_config]);
                let graphics_array_cast: &NSArray<
                    objc2_virtualization::VZGraphicsDeviceConfiguration,
                > = std::mem::transmute(&*graphics_array);
                vm_config.setGraphicsDevices(graphics_array_cast);
                info!("GPU enabled via virtio-gpu");
            }

            // Validate configuration
            let mut error: *mut NSError = std::ptr::null_mut();
            let valid: bool = msg_send![&*vm_config, validateWithError: &mut error];
            if !valid && !error.is_null() {
                let err_desc = (*error).localizedDescription();
                return Err(HyprError::InvalidConfig {
                    reason: format!("VM configuration invalid: {}", err_desc),
                });
            }

            Ok(vm_config)
        }
    }

    /// Configure a disk device.
    fn configure_disk(
        &self,
        disk: &DiskConfig,
    ) -> Result<Retained<VZVirtioBlockDeviceConfiguration>> {
        unsafe {
            let disk_url = Self::path_to_nsurl(&disk.path)?;

            let attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &disk_url,
                disk.readonly,
            );

            let attachment = attachment.map_err(|e| HyprError::VmStartFailed {
                vm_id: "disk".to_string(),
                reason: format!("Failed to attach disk {}: {}", disk.path.display(), e),
            })?;

            let block_config = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &attachment,
            );

            debug!(disk = %disk.path.display(), readonly = disk.readonly, "Configured disk");

            Ok(block_config)
        }
    }

    /// Configure network device with NAT.
    fn configure_network(&self) -> Result<Retained<VZVirtioNetworkDeviceConfiguration>> {
        unsafe {
            let attachment = VZNATNetworkDeviceAttachment::new();
            let network_config = VZVirtioNetworkDeviceConfiguration::new();

            network_config.setAttachment(Some(&attachment));

            debug!("Configured NAT network");

            Ok(network_config)
        }
    }

    /// Configure virtio-fs mount.
    fn configure_virtiofs(
        &self,
        tag: &str,
        host_path: &PathBuf,
    ) -> Result<Retained<VZVirtioFileSystemDeviceConfiguration>> {
        unsafe {
            let tag_ns = NSString::from_str(tag);
            let path_url = Self::path_to_nsurl(host_path)?;

            // Create shared directory
            let shared_dir = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &path_url,
                false, // read-write
            );

            // Create single directory share
            let share = VZSingleDirectoryShare::initWithDirectory(
                VZSingleDirectoryShare::alloc(),
                &shared_dir,
            );

            // Create virtio-fs device config
            let fs_config = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &tag_ns,
            );

            fs_config.setShare(Some(&share));

            debug!(tag, path = %host_path.display(), "Configured virtio-fs mount");

            Ok(fs_config)
        }
    }

    /// Configure Rosetta directory share for x86_64 emulation.
    #[cfg(target_arch = "aarch64")]
    fn configure_rosetta(&self) -> Result<Retained<VZVirtioFileSystemDeviceConfiguration>> {
        use objc2_virtualization::VZLinuxRosettaDirectoryShare;

        unsafe {
            // Create Rosetta directory share
            let rosetta_share = VZLinuxRosettaDirectoryShare::new();

            let tag_ns = NSString::from_str("rosetta");
            let fs_config = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &tag_ns,
            );

            fs_config.setShare(Some(&rosetta_share));

            Ok(fs_config)
        }
    }

    /// Configure virtio-gpu for graphics.
    fn configure_graphics(&self) -> Result<Retained<VZVirtioGraphicsDeviceConfiguration>> {
        unsafe {
            let graphics_config = VZVirtioGraphicsDeviceConfiguration::new();

            // Create scanout configuration (display)
            let scanout =
                VZVirtioGraphicsScanoutConfiguration::initWithWidthInPixels_heightInPixels(
                    VZVirtioGraphicsScanoutConfiguration::alloc(),
                    1920,
                    1080,
                );

            let scanout_array = NSArray::from_retained_slice(&[scanout]);
            graphics_config.setScanouts(&scanout_array);

            Ok(graphics_config)
        }
    }

    /// Convert Path to NSURL.
    fn path_to_nsurl(path: &std::path::Path) -> Result<Retained<NSURL>> {
        let path_str = path.to_str().ok_or_else(|| HyprError::InvalidConfig {
            reason: format!("Path contains invalid UTF-8: {}", path.display()),
        })?;
        let ns_string = NSString::from_str(path_str);
        let url = NSURL::fileURLWithPath(&ns_string);
        Ok(url)
    }

    /// Start VM using direct API call.
    /// Note: VZVirtualMachine requires running on the main thread or a dedicated dispatch queue.
    /// For now, we start synchronously and poll for state changes.
    fn start_vm_sync(vm: &VZVirtualMachine, vm_id: &str) -> Result<()> {
        use objc2_virtualization::VZVirtualMachineState;

        // Check if we can start
        let can_start: bool = unsafe { msg_send![vm, canStart] };
        if !can_start {
            return Err(HyprError::VmStartFailed {
                vm_id: vm_id.to_string(),
                reason: "VM cannot be started (may already be running or in error state)"
                    .to_string(),
            });
        }

        // Start the VM using the synchronous method via Objective-C
        // VZVirtualMachine.start() is blocking when called without completion handler
        let _: () = unsafe { msg_send![vm, start] };

        // Poll for running state
        for _ in 0..50 {
            let state: VZVirtualMachineState = unsafe { vm.state() };
            match state {
                VZVirtualMachineState::Running => {
                    debug!(vm_id, "VM reached running state");
                    return Ok(());
                }
                VZVirtualMachineState::Error => {
                    return Err(HyprError::VmStartFailed {
                        vm_id: vm_id.to_string(),
                        reason: "VM entered error state".to_string(),
                    });
                }
                VZVirtualMachineState::Stopped => {
                    return Err(HyprError::VmStartFailed {
                        vm_id: vm_id.to_string(),
                        reason: "VM stopped unexpectedly".to_string(),
                    });
                }
                _ => {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        Err(HyprError::VmStartFailed {
            vm_id: vm_id.to_string(),
            reason: "Timed out waiting for VM to start".to_string(),
        })
    }

    /// Stop VM using direct API call.
    fn stop_vm_sync(vm: &VZVirtualMachine, vm_id: &str, _timeout: Duration) -> Result<()> {
        use objc2_virtualization::VZVirtualMachineState;

        unsafe {
            // Check if we can stop
            let can_stop: bool = msg_send![vm, canStop];
            if !can_stop {
                let state: VZVirtualMachineState = vm.state();
                if state == VZVirtualMachineState::Stopped {
                    return Ok(()); // Already stopped
                }
                return Err(HyprError::VmStopFailed {
                    vm_id: vm_id.to_string(),
                    reason: "VM cannot be stopped".to_string(),
                });
            }

            // Request stop
            let _: () = msg_send![vm, stop];

            // Poll for stopped state
            for _ in 0..50 {
                let state: VZVirtualMachineState = vm.state();
                if state == VZVirtualMachineState::Stopped {
                    debug!(vm_id, "VM stopped");
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            warn!(vm_id, "Stop timed out, VM may still be running");
            Ok(()) // Return ok anyway - cleanup will handle it
        }
    }
}

impl Default for VirtualizationAdapter {
    fn default() -> Self {
        Self::new().expect("Failed to create Virtualization.framework adapter")
    }
}

#[async_trait]
impl VmmAdapter for VirtualizationAdapter {
    async fn build_command(&self, config: &VmConfig) -> Result<CommandSpec> {
        // Virtualization.framework runs in-process like libkrun
        // Return a special marker that the builder will recognize
        Ok(CommandSpec {
            program: "__virtualization__".to_string(),
            args: vec![config.id.clone()],
            env: vec![],
        })
    }

    #[instrument(skip(self), fields(vm_id = %config.id))]
    async fn create(&self, config: &VmConfig) -> Result<VmHandle> {
        info!("Creating VM with Virtualization.framework");

        let start = Instant::now();
        let vm_id = config.id.clone();
        let vsock_path = self.vsock_path_for_id(&config.id);

        if let Some(parent) = vsock_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HyprError::IoError { path: parent.to_path_buf(), source: e })?;
        }

        let log_path = Self::get_vm_log_path(&config.id)?;

        // Acquire lock first, then configure and create VM while holding lock
        // This avoids holding VZ types across await points
        let mut vms = self.vms.lock().await;

        // Configure and create the VM
        let vm_config = self.configure_vm(config)?;
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &vm_config)
        };

        // Store VM state
        vms.insert(vm_id.clone(), VmState { vm, vsock_path: vsock_path.clone(), log_path });

        // Drop lock before any more awaits
        drop(vms);

        // Record metrics
        let histogram =
            metrics::histogram!("hypr_vm_boot_duration_seconds", "adapter" => "virtualization");
        histogram.record(start.elapsed().as_secs_f64());

        let counter = metrics::counter!("hypr_vm_created_total", "adapter" => "virtualization");
        counter.increment(1);

        info!(duration_ms = start.elapsed().as_millis(), "VM created successfully");

        Ok(VmHandle {
            id: vm_id,
            pid: None, // Virtualization.framework runs in-process
            socket_path: None,
        })
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn start(&self, handle: &VmHandle) -> Result<()> {
        info!("Starting VM");

        // Get VM and start it in a single sync block
        {
            let vms = self.vms.lock().await;
            let state = vms
                .get(&handle.id)
                .ok_or_else(|| HyprError::VmNotFound { vm_id: handle.id.clone() })?;

            // VZVirtualMachine is not thread-safe, so we must call start on the current thread.
            Self::start_vm_sync(&state.vm, &handle.id)?;
        }

        // Give the VM a moment to boot (no VZ types held here)
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("VM started");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn stop(&self, handle: &VmHandle, timeout: Duration) -> Result<()> {
        info!("Stopping VM gracefully");

        // Stop VM in a sync block
        let stop_result = {
            let vms = self.vms.lock().await;
            match vms.get(&handle.id) {
                Some(state) => Self::stop_vm_sync(&state.vm, &handle.id, timeout),
                None => {
                    warn!("VM not found, may already be stopped");
                    return Ok(());
                }
            }
        };

        match stop_result {
            Ok(()) => {
                info!("VM stopped gracefully");
            }
            Err(e) => {
                warn!(error = %e, "Graceful stop failed");
            }
        }

        // Clean up (no VZ types held here)
        self.delete(handle).await?;

        info!("VM stopped");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn kill(&self, handle: &VmHandle) -> Result<()> {
        info!("Killing VM");

        // Just delete - the VM will be terminated when dropped
        self.delete(handle).await?;

        info!("VM killed");
        Ok(())
    }

    #[instrument(skip(self), fields(vm_id = %handle.id))]
    async fn delete(&self, handle: &VmHandle) -> Result<()> {
        info!("Deleting VM resources");

        let vsock_path = {
            let mut vms = self.vms.lock().await;
            vms.remove(&handle.id).map(|s| s.vsock_path)
        };

        // Clean up vsock file
        if let Some(path) = vsock_path {
            let _ = std::fs::remove_file(&path);
        }

        info!("VM resources deleted");
        Ok(())
    }

    #[instrument(skip(self, _disk), fields(vm_id = %_handle.id))]
    async fn attach_disk(&self, _handle: &VmHandle, _disk: &DiskConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "virtualization", "operation" => "attach_disk").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "disk hotplug".to_string(),
            platform: "Virtualization.framework".to_string(),
        })
    }

    #[instrument(skip(self, _net), fields(vm_id = %_handle.id))]
    async fn attach_network(&self, _handle: &VmHandle, _net: &NetworkConfig) -> Result<()> {
        metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "virtualization", "operation" => "attach_network").increment(1);
        Err(HyprError::PlatformUnsupported {
            feature: "network hotplug".to_string(),
            platform: "Virtualization.framework".to_string(),
        })
    }

    #[instrument(skip(self, gpu), fields(vm_id = %handle.id))]
    async fn attach_gpu(&self, handle: &VmHandle, gpu: &GpuConfig) -> Result<()> {
        if !self.gpu_available {
            metrics::counter!("hypr_adapter_unsupported_total", "adapter" => "virtualization", "operation" => "attach_gpu").increment(1);
            return Err(HyprError::GpuUnavailable {
                reason: "GPU passthrough requires Apple Silicon (ARM64)".to_string(),
            });
        }

        // GPU must be configured at VM creation time, not attached later
        warn!(
            vm_id = %handle.id,
            vendor = ?gpu.vendor,
            "GPU hotplug not supported - GPU must be configured at VM creation"
        );

        Err(HyprError::PlatformUnsupported {
            feature: "GPU hotplug".to_string(),
            platform: "Virtualization.framework".to_string(),
        })
    }

    fn vsock_path(&self, handle: &VmHandle) -> PathBuf {
        self.vsock_path_for_id(&handle.id)
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            gpu_passthrough: self.gpu_available,
            virtio_fs: true,
            hotplug_devices: false,
            metadata: HashMap::from([
                ("adapter".to_string(), "virtualization".to_string()),
                ("backend".to_string(), "Virtualization.framework".to_string()),
                (
                    "gpu_backend".to_string(),
                    if self.gpu_available { "metal" } else { "none" }.to_string(),
                ),
            ]),
        }
    }

    fn name(&self) -> &str {
        "virtualization"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtualization_adapter_creation() {
        match VirtualizationAdapter::new() {
            Ok(adapter) => {
                println!("Adapter created: {}", adapter.name());
                let caps = adapter.capabilities();
                println!("GPU available: {}", caps.gpu_passthrough);
            }
            Err(e) => {
                println!("Adapter creation failed: {}", e);
            }
        }
    }
}
