//! FFI bindings for libkrun.
//!
//! This module provides safe Rust wrappers around the libkrun C API.
//! The library is loaded dynamically at runtime via dlopen.

use crate::error::{HyprError, Result};
use libloading::{Library, Symbol};
use std::ffi::{c_char, c_int, c_uint, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// Kernel format constants from libkrun.h
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Variants for future use
pub enum KernelFormat {
    /// Raw binary
    Raw = 0,
    /// ELF binary
    Elf = 1,
    /// PE compressed with gzip
    PeGz = 2,
    /// Linux Image compressed with bzip2
    ImageBz2 = 3,
    /// Linux Image compressed with gzip
    ImageGz = 4,
    /// Linux Image compressed with zstd
    ImageZstd = 5,
}

/// GPU/virgl flags for krun_set_gpu_options
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Variants for future use
pub enum GpuFlags {
    /// No GPU
    None = 0,
    /// Enable virgl (Venus/Metal)
    Virgl = 1,
}

/// Network feature flags from libkrun.h (virtio_net features)
#[allow(dead_code)]
pub mod net_features {
    pub const CSUM: u32 = 1 << 0;
    pub const GUEST_CSUM: u32 = 1 << 1;
    pub const GUEST_TSO4: u32 = 1 << 7;
    pub const GUEST_TSO6: u32 = 1 << 8;
    pub const GUEST_UFO: u32 = 1 << 10;
    pub const HOST_TSO4: u32 = 1 << 11;
    pub const HOST_TSO6: u32 = 1 << 12;
    pub const HOST_UFO: u32 = 1 << 14;

    /// Compatible features for TAP networking
    pub const COMPAT: u32 = CSUM | GUEST_CSUM | GUEST_TSO4 | GUEST_UFO | HOST_TSO4 | HOST_UFO;
}

/// libkrun function signatures
type KrunSetLogLevel = unsafe extern "C" fn(level: c_uint) -> c_int;
type KrunCreateCtx = unsafe extern "C" fn() -> c_int;
type KrunFreeCtx = unsafe extern "C" fn(ctx_id: c_uint) -> c_int;
type KrunSetVmConfig =
    unsafe extern "C" fn(ctx_id: c_uint, num_vcpus: u8, ram_mib: c_uint) -> c_int;
type KrunSetKernel = unsafe extern "C" fn(
    ctx_id: c_uint,
    kernel_path: *const c_char,
    kernel_format: c_uint,
    initramfs: *const c_char,
    cmdline: *const c_char,
) -> c_int;
type KrunSetRootDisk = unsafe extern "C" fn(ctx_id: c_uint, disk_path: *const c_char) -> c_int;
type KrunAddDisk = unsafe extern "C" fn(
    ctx_id: c_uint,
    block_id: *const c_char,
    disk_path: *const c_char,
    read_only: bool,
) -> c_int;
type KrunAddVirtiofs =
    unsafe extern "C" fn(ctx_id: c_uint, tag: *const c_char, path: *const c_char) -> c_int;
type KrunAddVsockPort =
    unsafe extern "C" fn(ctx_id: c_uint, port: c_uint, filepath: *const c_char) -> c_int;
type KrunAddVsockPort2 = unsafe extern "C" fn(
    ctx_id: c_uint,
    port: c_uint,
    filepath: *const c_char,
    listen: bool,
) -> c_int;
type KrunSetGpuOptions = unsafe extern "C" fn(ctx_id: c_uint, virgl_flags: c_uint) -> c_int;
type KrunSetConsoleOutput = unsafe extern "C" fn(ctx_id: c_uint, filepath: *const c_char) -> c_int;
type KrunGetShutdownEventfd = unsafe extern "C" fn(ctx_id: c_uint) -> c_int;
type KrunStartEnter = unsafe extern "C" fn(ctx_id: c_uint) -> c_int;
type KrunSetNestedVirt = unsafe extern "C" fn(ctx_id: c_uint, enabled: bool) -> c_int;
type KrunSetNetMac = unsafe extern "C" fn(ctx_id: c_uint, mac: *const u8) -> c_int;
type KrunSetPasstFd = unsafe extern "C" fn(ctx_id: c_uint, fd: c_int) -> c_int;
type KrunAddNetTap = unsafe extern "C" fn(
    ctx_id: c_uint,
    tap_name: *const c_char,
    mac: *const u8,
    features: c_uint,
    flags: c_uint,
) -> c_int;
type KrunAddNetUnixstream = unsafe extern "C" fn(
    ctx_id: c_uint,
    path: *const c_char,
    fd: c_int,
    mac: *const u8,
    features: c_uint,
    flags: c_uint,
) -> c_int;
type KrunSetSmbiosOemStrings =
    unsafe extern "C" fn(ctx_id: c_uint, oem_strings: *const *const c_char) -> c_int;

// Console multiplexing types (for PTY/exec support)
type KrunAddVirtioConsoleMultiport = unsafe extern "C" fn(ctx_id: c_uint) -> c_int;
type KrunAddConsolePortTty = unsafe extern "C" fn(
    ctx_id: c_uint,
    port_name: *const c_char,
    tty_path: *const c_char,
) -> c_int;
type KrunAddConsolePortInout = unsafe extern "C" fn(
    ctx_id: c_uint,
    port_name: *const c_char,
    in_fd: c_int,
    out_fd: c_int,
) -> c_int;

/// Safe wrapper around libkrun.
///
/// Handles dynamic loading of the library and provides safe Rust methods
/// for all libkrun operations.
#[allow(dead_code)] // Some fields/methods for future use
pub struct Libkrun {
    _library: Arc<Library>,
    // Function pointers
    set_log_level: KrunSetLogLevel,
    create_ctx: KrunCreateCtx,
    free_ctx: KrunFreeCtx,
    set_vm_config: KrunSetVmConfig,
    set_kernel: KrunSetKernel,
    set_root_disk: KrunSetRootDisk,
    add_disk: KrunAddDisk,
    add_virtiofs: KrunAddVirtiofs,
    add_vsock_port: KrunAddVsockPort,
    add_vsock_port2: KrunAddVsockPort2,
    set_gpu_options: KrunSetGpuOptions,
    set_console_output: KrunSetConsoleOutput,
    get_shutdown_eventfd: KrunGetShutdownEventfd,
    start_enter: KrunStartEnter,
    set_nested_virt: KrunSetNestedVirt,
    set_net_mac: KrunSetNetMac,
    set_passt_fd: KrunSetPasstFd,
    add_net_tap: KrunAddNetTap,
    add_net_unixstream: KrunAddNetUnixstream,
    set_smbios_oem_strings: KrunSetSmbiosOemStrings,
    // Console multiplexing (for PTY/exec support)
    add_virtio_console_multiport: Option<KrunAddVirtioConsoleMultiport>,
    add_console_port_tty: Option<KrunAddConsolePortTty>,
    add_console_port_inout: Option<KrunAddConsolePortInout>,
}

#[allow(dead_code)] // Some methods for future use
impl Libkrun {
    /// Load libkrun dynamically.
    ///
    /// Searches standard Homebrew paths for the library.
    pub fn load() -> Result<Self> {
        let library_path = Self::find_library()?;
        info!(path = %library_path.display(), "Loading libkrun");

        // Safety: We're loading a known library with a stable C ABI
        let library = unsafe {
            Library::new(&library_path).map_err(|e| HyprError::HypervisorNotFound {
                hypervisor: format!(
                    "libkrun: failed to load {}: {}",
                    library_path.display(),
                    e
                ),
            })?
        };

        let library = Arc::new(library);
        let lib_clone = library.clone();

        // Load all function pointers
        // Safety: These are documented C functions with stable ABI
        unsafe {
            let set_log_level: Symbol<KrunSetLogLevel> = lib_clone
                .get(b"krun_set_log_level\0")
                .map_err(|e| Self::symbol_error("krun_set_log_level", e))?;
            let create_ctx: Symbol<KrunCreateCtx> = lib_clone
                .get(b"krun_create_ctx\0")
                .map_err(|e| Self::symbol_error("krun_create_ctx", e))?;
            let free_ctx: Symbol<KrunFreeCtx> = lib_clone
                .get(b"krun_free_ctx\0")
                .map_err(|e| Self::symbol_error("krun_free_ctx", e))?;
            let set_vm_config: Symbol<KrunSetVmConfig> = lib_clone
                .get(b"krun_set_vm_config\0")
                .map_err(|e| Self::symbol_error("krun_set_vm_config", e))?;
            let set_kernel: Symbol<KrunSetKernel> = lib_clone
                .get(b"krun_set_kernel\0")
                .map_err(|e| Self::symbol_error("krun_set_kernel", e))?;
            let set_root_disk: Symbol<KrunSetRootDisk> = lib_clone
                .get(b"krun_set_root_disk\0")
                .map_err(|e| Self::symbol_error("krun_set_root_disk", e))?;
            let add_disk: Symbol<KrunAddDisk> = lib_clone
                .get(b"krun_add_disk\0")
                .map_err(|e| Self::symbol_error("krun_add_disk", e))?;
            let add_virtiofs: Symbol<KrunAddVirtiofs> = lib_clone
                .get(b"krun_add_virtiofs\0")
                .map_err(|e| Self::symbol_error("krun_add_virtiofs", e))?;
            let add_vsock_port: Symbol<KrunAddVsockPort> = lib_clone
                .get(b"krun_add_vsock_port\0")
                .map_err(|e| Self::symbol_error("krun_add_vsock_port", e))?;
            let add_vsock_port2: Symbol<KrunAddVsockPort2> = lib_clone
                .get(b"krun_add_vsock_port2\0")
                .map_err(|e| Self::symbol_error("krun_add_vsock_port2", e))?;
            let set_gpu_options: Symbol<KrunSetGpuOptions> = lib_clone
                .get(b"krun_set_gpu_options\0")
                .map_err(|e| Self::symbol_error("krun_set_gpu_options", e))?;
            let set_console_output: Symbol<KrunSetConsoleOutput> = lib_clone
                .get(b"krun_set_console_output\0")
                .map_err(|e| Self::symbol_error("krun_set_console_output", e))?;
            let get_shutdown_eventfd: Symbol<KrunGetShutdownEventfd> = lib_clone
                .get(b"krun_get_shutdown_eventfd\0")
                .map_err(|e| Self::symbol_error("krun_get_shutdown_eventfd", e))?;
            let start_enter: Symbol<KrunStartEnter> = lib_clone
                .get(b"krun_start_enter\0")
                .map_err(|e| Self::symbol_error("krun_start_enter", e))?;
            let set_nested_virt: Symbol<KrunSetNestedVirt> = lib_clone
                .get(b"krun_set_nested_virt\0")
                .map_err(|e| Self::symbol_error("krun_set_nested_virt", e))?;
            let set_net_mac: Symbol<KrunSetNetMac> = lib_clone
                .get(b"krun_set_net_mac\0")
                .map_err(|e| Self::symbol_error("krun_set_net_mac", e))?;
            let set_passt_fd: Symbol<KrunSetPasstFd> = lib_clone
                .get(b"krun_set_passt_fd\0")
                .map_err(|e| Self::symbol_error("krun_set_passt_fd", e))?;
            let add_net_tap: Symbol<KrunAddNetTap> = lib_clone
                .get(b"krun_add_net_tap\0")
                .map_err(|e| Self::symbol_error("krun_add_net_tap", e))?;
            let add_net_unixstream: Symbol<KrunAddNetUnixstream> = lib_clone
                .get(b"krun_add_net_unixstream\0")
                .map_err(|e| Self::symbol_error("krun_add_net_unixstream", e))?;
            let set_smbios_oem_strings: Symbol<KrunSetSmbiosOemStrings> = lib_clone
                .get(b"krun_set_smbios_oem_strings\0")
                .map_err(|e| Self::symbol_error("krun_set_smbios_oem_strings", e))?;

            // Console multiplexing symbols (optional - may not be present in older libkrun)
            let add_virtio_console_multiport: Option<Symbol<KrunAddVirtioConsoleMultiport>> =
                lib_clone.get(b"krun_add_virtio_console_multiport\0").ok();
            let add_console_port_tty: Option<Symbol<KrunAddConsolePortTty>> =
                lib_clone.get(b"krun_add_console_port_tty\0").ok();
            let add_console_port_inout: Option<Symbol<KrunAddConsolePortInout>> =
                lib_clone.get(b"krun_add_console_port_inout\0").ok();

            // Store original library to keep it alive, use cloned refs for symbols
            Ok(Self {
                _library: library,
                set_log_level: *set_log_level,
                create_ctx: *create_ctx,
                free_ctx: *free_ctx,
                set_vm_config: *set_vm_config,
                set_kernel: *set_kernel,
                set_root_disk: *set_root_disk,
                add_disk: *add_disk,
                add_virtiofs: *add_virtiofs,
                add_vsock_port: *add_vsock_port,
                add_vsock_port2: *add_vsock_port2,
                set_gpu_options: *set_gpu_options,
                set_console_output: *set_console_output,
                get_shutdown_eventfd: *get_shutdown_eventfd,
                start_enter: *start_enter,
                set_nested_virt: *set_nested_virt,
                set_net_mac: *set_net_mac,
                set_passt_fd: *set_passt_fd,
                add_net_tap: *add_net_tap,
                add_net_unixstream: *add_net_unixstream,
                set_smbios_oem_strings: *set_smbios_oem_strings,
                // Console multiplexing (optional)
                add_virtio_console_multiport: add_virtio_console_multiport.map(|s| *s),
                add_console_port_tty: add_console_port_tty.map(|s| *s),
                add_console_port_inout: add_console_port_inout.map(|s| *s),
            })
        }
    }

    /// Find libkrun.dylib - first try embedded, then system paths.
    fn find_library() -> Result<PathBuf> {
        // First, try to get embedded libkrun (preferred - no external dependencies)
        if let Ok(path) = crate::embedded::get_libkrun_path() {
            debug!(path = %path.display(), "Using embedded libkrun");
            return Ok(path);
        }

        // Fallback to system-installed libkrun
        let candidates = [
            // Homebrew Apple Silicon
            "/opt/homebrew/opt/libkrun/lib/libkrun.dylib",
            "/opt/homebrew/lib/libkrun.dylib",
            // Homebrew Intel
            "/usr/local/opt/libkrun/lib/libkrun.dylib",
            "/usr/local/lib/libkrun.dylib",
        ];

        for path in candidates {
            let path = PathBuf::from(path);
            if path.exists() {
                debug!(path = %path.display(), "Found system libkrun");
                return Ok(path);
            }
        }

        Err(HyprError::HypervisorNotFound {
            hypervisor: "libkrun (embedded extraction failed and not found in system paths)"
                .to_string(),
        })
    }

    fn symbol_error(name: &str, e: libloading::Error) -> HyprError {
        HyprError::HypervisorNotFound {
            hypervisor: format!("libkrun: missing symbol {}: {}", name, e),
        }
    }

    fn check_result(ret: c_int, operation: &str) -> Result<()> {
        if ret < 0 {
            Err(HyprError::VmStartFailed {
                vm_id: "libkrun".to_string(),
                reason: format!("{} failed with error code {}", operation, ret),
            })
        } else {
            Ok(())
        }
    }

    /// Set libkrun log level (0=off, 1=error, 2=warn, 3=info, 4=debug, 5=trace).
    pub fn set_log_level(&self, level: u32) -> Result<()> {
        let ret = unsafe { (self.set_log_level)(level) };
        Self::check_result(ret, "krun_set_log_level")
    }

    /// Create a new VM context. Returns context ID.
    pub fn create_ctx(&self) -> Result<u32> {
        let ret = unsafe { (self.create_ctx)() };
        if ret < 0 {
            Err(HyprError::VmStartFailed {
                vm_id: "libkrun".to_string(),
                reason: format!("krun_create_ctx failed with error code {}", ret),
            })
        } else {
            Ok(ret as u32)
        }
    }

    /// Free a VM context.
    pub fn free_ctx(&self, ctx_id: u32) -> Result<()> {
        let ret = unsafe { (self.free_ctx)(ctx_id) };
        Self::check_result(ret, "krun_free_ctx")
    }

    /// Configure VM resources (vCPUs and RAM).
    pub fn set_vm_config(&self, ctx_id: u32, vcpus: u8, ram_mib: u32) -> Result<()> {
        debug!(ctx_id, vcpus, ram_mib, "Setting VM config");
        let ret = unsafe { (self.set_vm_config)(ctx_id, vcpus, ram_mib) };
        Self::check_result(ret, "krun_set_vm_config")
    }

    /// Set kernel for direct boot.
    pub fn set_kernel(
        &self,
        ctx_id: u32,
        kernel_path: &Path,
        format: KernelFormat,
        initramfs_path: Option<&Path>,
        cmdline: &str,
    ) -> Result<()> {
        let kernel_cstr = Self::path_to_cstring(kernel_path)?;
        let initramfs_cstr = match initramfs_path {
            Some(p) => Some(Self::path_to_cstring(p)?),
            None => None,
        };
        let cmdline_cstr = CString::new(cmdline).map_err(|_| HyprError::InvalidConfig {
            reason: "Kernel cmdline contains null byte".to_string(),
        })?;

        debug!(
            ctx_id,
            kernel = %kernel_path.display(),
            initramfs = ?initramfs_path.map(|p| p.display().to_string()),
            cmdline,
            "Setting kernel"
        );

        let initramfs_ptr = initramfs_cstr.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null());

        let ret = unsafe {
            (self.set_kernel)(
                ctx_id,
                kernel_cstr.as_ptr(),
                format as u32,
                initramfs_ptr,
                cmdline_cstr.as_ptr(),
            )
        };
        Self::check_result(ret, "krun_set_kernel")
    }

    /// Set root disk.
    pub fn set_root_disk(&self, ctx_id: u32, disk_path: &Path) -> Result<()> {
        let disk_cstr = Self::path_to_cstring(disk_path)?;
        debug!(ctx_id, disk = %disk_path.display(), "Setting root disk");
        let ret = unsafe { (self.set_root_disk)(ctx_id, disk_cstr.as_ptr()) };
        Self::check_result(ret, "krun_set_root_disk")
    }

    /// Add additional disk.
    pub fn add_disk(
        &self,
        ctx_id: u32,
        block_id: &str,
        disk_path: &Path,
        read_only: bool,
    ) -> Result<()> {
        let block_id_cstr = CString::new(block_id).map_err(|_| HyprError::InvalidConfig {
            reason: "Block ID contains null byte".to_string(),
        })?;
        let disk_cstr = Self::path_to_cstring(disk_path)?;

        debug!(ctx_id, block_id, disk = %disk_path.display(), read_only, "Adding disk");

        let ret = unsafe {
            (self.add_disk)(ctx_id, block_id_cstr.as_ptr(), disk_cstr.as_ptr(), read_only)
        };
        Self::check_result(ret, "krun_add_disk")
    }

    /// Add virtio-fs mount.
    pub fn add_virtiofs(&self, ctx_id: u32, tag: &str, path: &Path) -> Result<()> {
        let tag_cstr = CString::new(tag).map_err(|_| HyprError::InvalidConfig {
            reason: "virtio-fs tag contains null byte".to_string(),
        })?;
        let path_cstr = Self::path_to_cstring(path)?;

        debug!(ctx_id, tag, path = %path.display(), "Adding virtio-fs");

        let ret = unsafe { (self.add_virtiofs)(ctx_id, tag_cstr.as_ptr(), path_cstr.as_ptr()) };
        Self::check_result(ret, "krun_add_virtiofs")
    }

    /// Add vsock port.
    pub fn add_vsock_port(&self, ctx_id: u32, port: u32, socket_path: &Path) -> Result<()> {
        let path_cstr = Self::path_to_cstring(socket_path)?;
        debug!(ctx_id, port, path = %socket_path.display(), "Adding vsock port");
        let ret = unsafe { (self.add_vsock_port)(ctx_id, port, path_cstr.as_ptr()) };
        Self::check_result(ret, "krun_add_vsock_port")
    }

    /// Add vsock port with listen option.
    pub fn add_vsock_port2(
        &self,
        ctx_id: u32,
        port: u32,
        socket_path: &Path,
        listen: bool,
    ) -> Result<()> {
        let path_cstr = Self::path_to_cstring(socket_path)?;
        debug!(ctx_id, port, path = %socket_path.display(), listen, "Adding vsock port");
        let ret = unsafe { (self.add_vsock_port2)(ctx_id, port, path_cstr.as_ptr(), listen) };
        Self::check_result(ret, "krun_add_vsock_port2")
    }

    /// Set GPU options (enable virgl for Metal passthrough).
    pub fn set_gpu_options(&self, ctx_id: u32, flags: GpuFlags) -> Result<()> {
        debug!(ctx_id, flags = ?flags, "Setting GPU options");
        let ret = unsafe { (self.set_gpu_options)(ctx_id, flags as u32) };
        Self::check_result(ret, "krun_set_gpu_options")
    }

    /// Set console output file.
    pub fn set_console_output(&self, ctx_id: u32, path: &Path) -> Result<()> {
        let path_cstr = Self::path_to_cstring(path)?;
        debug!(ctx_id, path = %path.display(), "Setting console output");
        let ret = unsafe { (self.set_console_output)(ctx_id, path_cstr.as_ptr()) };
        Self::check_result(ret, "krun_set_console_output")
    }

    /// Get shutdown event fd for graceful shutdown signaling.
    pub fn get_shutdown_eventfd(&self, ctx_id: u32) -> Result<i32> {
        let ret = unsafe { (self.get_shutdown_eventfd)(ctx_id) };
        if ret < 0 {
            Err(HyprError::VmStartFailed {
                vm_id: "libkrun".to_string(),
                reason: format!("krun_get_shutdown_eventfd failed with error code {}", ret),
            })
        } else {
            Ok(ret)
        }
    }

    /// Start VM and enter (blocking). Returns when VM exits.
    pub fn start_enter(&self, ctx_id: u32) -> Result<()> {
        info!(ctx_id, "Starting VM");
        let ret = unsafe { (self.start_enter)(ctx_id) };
        Self::check_result(ret, "krun_start_enter")
    }

    /// Enable/disable nested virtualization.
    pub fn set_nested_virt(&self, ctx_id: u32, enabled: bool) -> Result<()> {
        debug!(ctx_id, enabled, "Setting nested virt");
        let ret = unsafe { (self.set_nested_virt)(ctx_id, enabled) };
        Self::check_result(ret, "krun_set_nested_virt")
    }

    /// Set network MAC address.
    pub fn set_net_mac(&self, ctx_id: u32, mac: &[u8; 6]) -> Result<()> {
        debug!(ctx_id, mac = ?mac, "Setting network MAC");
        let ret = unsafe { (self.set_net_mac)(ctx_id, mac.as_ptr()) };
        Self::check_result(ret, "krun_set_net_mac")
    }

    /// Set passt fd for networking.
    pub fn set_passt_fd(&self, ctx_id: u32, fd: i32) -> Result<()> {
        debug!(ctx_id, fd, "Setting passt fd");
        let ret = unsafe { (self.set_passt_fd)(ctx_id, fd) };
        Self::check_result(ret, "krun_set_passt_fd")
    }

    /// Add a TAP network device (same as cloud-hypervisor).
    ///
    /// Creates a virtio-net device connected to the specified TAP interface.
    /// The TAP device must already exist on the host.
    pub fn add_net_tap(
        &self,
        ctx_id: u32,
        tap_name: &str,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        let tap_cstr = CString::new(tap_name).map_err(|_| HyprError::InvalidConfig {
            reason: "TAP name contains null byte".to_string(),
        })?;
        debug!(
            ctx_id,
            tap_name,
            mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            features,
            flags,
            "Adding TAP network device"
        );
        let ret =
            unsafe { (self.add_net_tap)(ctx_id, tap_cstr.as_ptr(), mac.as_ptr(), features, flags) };
        Self::check_result(ret, "krun_add_net_tap")
    }

    /// Add a network device via unix stream socket (for passt/socket_vmnet on macOS).
    ///
    /// Creates a virtio-net device connected to a userspace network proxy.
    /// Either `path` (socket path) or `fd` (open socket fd) must be provided, not both.
    pub fn add_net_unixstream(
        &self,
        ctx_id: u32,
        path: Option<&Path>,
        fd: Option<i32>,
        mac: &[u8; 6],
        features: u32,
        flags: u32,
    ) -> Result<()> {
        let path_cstr = match path {
            Some(p) => Some(Self::path_to_cstring(p)?),
            None => None,
        };
        let path_ptr = path_cstr.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null());
        let fd_val = fd.unwrap_or(-1);

        debug!(
            ctx_id,
            path = ?path,
            fd = fd_val,
            mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            features,
            flags,
            "Adding network device via unix stream"
        );
        let ret = unsafe {
            (self.add_net_unixstream)(ctx_id, path_ptr, fd_val, mac.as_ptr(), features, flags)
        };
        Self::check_result(ret, "krun_add_net_unixstream")
    }

    /// Set SMBIOS OEM strings (for passing data to guest).
    pub fn set_smbios_oem_strings(&self, ctx_id: u32, strings: &[&str]) -> Result<()> {
        let cstrings: Vec<CString> = strings
            .iter()
            .map(|s| {
                CString::new(*s).map_err(|_| HyprError::InvalidConfig {
                    reason: "OEM string contains null byte".to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let ptrs: Vec<*const c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
        let mut ptrs_with_null = ptrs.clone();
        ptrs_with_null.push(std::ptr::null());

        debug!(ctx_id, strings = ?strings, "Setting SMBIOS OEM strings");
        let ret = unsafe { (self.set_smbios_oem_strings)(ctx_id, ptrs_with_null.as_ptr()) };
        Self::check_result(ret, "krun_set_smbios_oem_strings")
    }

    fn path_to_cstring(path: &Path) -> Result<CString> {
        let path_str = path.to_str().ok_or_else(|| HyprError::InvalidConfig {
            reason: format!("Path contains invalid UTF-8: {}", path.display()),
        })?;
        CString::new(path_str).map_err(|_| HyprError::InvalidConfig {
            reason: format!("Path contains null byte: {}", path.display()),
        })
    }

    // =========================================================================
    // Console Multiplexing (for PTY/exec support)
    // =========================================================================

    /// Check if console multiplexing is available.
    ///
    /// Returns true if the libkrun version supports virtio console multiport.
    pub fn has_console_multiplexing(&self) -> bool {
        self.add_virtio_console_multiport.is_some()
            && self.add_console_port_tty.is_some()
            && self.add_console_port_inout.is_some()
    }

    /// Add a virtio console multiport device.
    ///
    /// This enables multiple console connections to a single VM, which is
    /// essential for PTY support (exec, terminal sessions).
    pub fn add_virtio_console_multiport(&self, ctx_id: u32) -> Result<()> {
        let func = self.add_virtio_console_multiport.ok_or_else(|| HyprError::NotImplemented {
            feature: "console multiplexing (requires libkrun 1.9+)".to_string(),
        })?;

        debug!(ctx_id, "Adding virtio console multiport device");
        let ret = unsafe { func(ctx_id) };
        Self::check_result(ret, "krun_add_virtio_console_multiport")
    }

    /// Add a TTY console port.
    ///
    /// Creates a console port connected to a host TTY device (e.g., tmux session).
    pub fn add_console_port_tty(
        &self,
        ctx_id: u32,
        port_name: &str,
        tty_path: &Path,
    ) -> Result<()> {
        let func = self.add_console_port_tty.ok_or_else(|| HyprError::NotImplemented {
            feature: "console port TTY (requires libkrun 1.9+)".to_string(),
        })?;

        let port_name_cstr = CString::new(port_name).map_err(|_| HyprError::InvalidConfig {
            reason: "Port name contains null byte".to_string(),
        })?;
        let tty_path_cstr = Self::path_to_cstring(tty_path)?;

        debug!(ctx_id, port_name, tty = %tty_path.display(), "Adding TTY console port");
        let ret = unsafe { func(ctx_id, port_name_cstr.as_ptr(), tty_path_cstr.as_ptr()) };
        Self::check_result(ret, "krun_add_console_port_tty")
    }

    /// Add a console port with input/output file descriptors.
    ///
    /// Creates a console port connected to separate input and output FDs,
    /// typically FIFOs for bidirectional communication.
    ///
    /// # Arguments
    /// * `ctx_id` - VM context ID
    /// * `port_name` - Name for the console port (e.g., "exec0", "shell")
    /// * `in_fd` - File descriptor for input to the guest
    /// * `out_fd` - File descriptor for output from the guest
    pub fn add_console_port_inout(
        &self,
        ctx_id: u32,
        port_name: &str,
        in_fd: i32,
        out_fd: i32,
    ) -> Result<()> {
        let func = self.add_console_port_inout.ok_or_else(|| HyprError::NotImplemented {
            feature: "console port inout (requires libkrun 1.9+)".to_string(),
        })?;

        let port_name_cstr = CString::new(port_name).map_err(|_| HyprError::InvalidConfig {
            reason: "Port name contains null byte".to_string(),
        })?;

        debug!(ctx_id, port_name, in_fd, out_fd, "Adding inout console port");
        let ret = unsafe { func(ctx_id, port_name_cstr.as_ptr(), in_fd, out_fd) };
        Self::check_result(ret, "krun_add_console_port_inout")
    }
}

// Libkrun is thread-safe (each context is independent)
unsafe impl Send for Libkrun {}
unsafe impl Sync for Libkrun {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libkrun_load() {
        // This will fail if libkrun is not installed, which is expected
        match Libkrun::load() {
            Ok(lib) => {
                println!("libkrun loaded successfully");
                // Try creating and freeing a context
                if let Ok(ctx) = lib.create_ctx() {
                    println!("Created context: {}", ctx);
                    let _ = lib.free_ctx(ctx);
                }
            }
            Err(e) => {
                println!("libkrun not available: {} (expected if not installed)", e);
            }
        }
    }
}
