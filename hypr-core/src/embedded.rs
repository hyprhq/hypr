//! Embedded hypervisor binaries and resources.
//!
//! This module contains cloud-hypervisor binaries and eBPF programs embedded at compile time.
//! These are extracted to a runtime directory when needed, eliminating the need
//! for users to install dependencies separately.

use crate::error::{HyprError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Embedded cloud-hypervisor binary (architecture-specific at compile time)
#[cfg(target_arch = "x86_64")]
const CLOUD_HYPERVISOR_BINARY: &[u8] = include_bytes!("../embedded/cloud-hypervisor-static");

#[cfg(target_arch = "aarch64")]
const CLOUD_HYPERVISOR_BINARY: &[u8] =
    include_bytes!("../embedded/cloud-hypervisor-static-aarch64");

/// Embedded eBPF programs (Linux only, compiled during cargo build on Linux)
#[cfg(target_os = "linux")]
const EBPF_INGRESS: &[u8] = include_bytes!("../embedded/drift_l4_ingress.o");

#[cfg(target_os = "linux")]
const EBPF_EGRESS: &[u8] = include_bytes!("../embedded/drift_l4_egress.o");

/// Get the cloud-hypervisor binary path, extracting if needed.
///
/// This function:
/// 1. Determines the host architecture
/// 2. Checks if cloud-hypervisor is already extracted
/// 3. Extracts the embedded binary if missing
/// 4. Returns the path to the binary
///
/// Note: Uses data_dir (not runtime_dir) because /run is often mounted noexec.
pub fn get_cloud_hypervisor_path() -> Result<PathBuf> {
    // Use data_dir for executables (runtime_dir may be noexec)
    let bin_dir = crate::paths::data_dir().join("bin");
    fs::create_dir_all(&bin_dir)
        .map_err(|e| HyprError::IoError { path: bin_dir.clone(), source: e })?;

    let binary_name = if cfg!(target_arch = "x86_64") {
        "cloud-hypervisor-static"
    } else if cfg!(target_arch = "aarch64") {
        "cloud-hypervisor-static-aarch64"
    } else {
        return Err(HyprError::UnsupportedArchitecture {
            arch: std::env::consts::ARCH.to_string(),
        });
    };

    let binary_path = bin_dir.join(binary_name);

    // Extract if not exists
    if !binary_path.exists() {
        info!("Extracting embedded cloud-hypervisor to {}", binary_path.display());
        extract_cloud_hypervisor(&binary_path)?;
    } else {
        debug!("Using existing cloud-hypervisor at {}", binary_path.display());
    }

    Ok(binary_path)
}

/// Extract the appropriate cloud-hypervisor binary to disk.
fn extract_cloud_hypervisor(dest: &Path) -> Result<()> {
    let bytes = CLOUD_HYPERVISOR_BINARY;

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| HyprError::IoError { path: parent.to_path_buf(), source: e })?;
    }

    // Write binary
    fs::write(dest, bytes)
        .map_err(|e| HyprError::IoError { path: dest.to_path_buf(), source: e })?;

    // Make executable (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(dest)
            .map_err(|e| HyprError::IoError { path: dest.to_path_buf(), source: e })?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(dest, permissions)
            .map_err(|e| HyprError::IoError { path: dest.to_path_buf(), source: e })?;
    }

    info!(
        "Extracted cloud-hypervisor ({:.2} MB) to {}",
        bytes.len() as f64 / 1024.0 / 1024.0,
        dest.display()
    );

    Ok(())
}

/// Get eBPF program paths, extracting if needed (Linux only).
///
/// Returns (ingress_path, egress_path) for the eBPF programs.
/// These are extracted from the embedded binary to the data directory.
#[cfg(target_os = "linux")]
pub fn get_ebpf_paths() -> Result<(PathBuf, PathBuf)> {
    let ebpf_dir = crate::paths::data_dir().join("ebpf");
    fs::create_dir_all(&ebpf_dir)
        .map_err(|e| HyprError::IoError { path: ebpf_dir.clone(), source: e })?;

    let ingress_path = ebpf_dir.join("drift_l4_ingress.o");
    let egress_path = ebpf_dir.join("drift_l4_egress.o");

    // Extract if not exists
    if !ingress_path.exists() {
        info!("Extracting embedded eBPF ingress program");
        fs::write(&ingress_path, EBPF_INGRESS)
            .map_err(|e| HyprError::IoError { path: ingress_path.clone(), source: e })?;
    }

    if !egress_path.exists() {
        info!("Extracting embedded eBPF egress program");
        fs::write(&egress_path, EBPF_EGRESS)
            .map_err(|e| HyprError::IoError { path: egress_path.clone(), source: e })?;
    }

    debug!("eBPF programs ready at {}", ebpf_dir.display());
    Ok((ingress_path, egress_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_hypervisor_embedded() {
        // Verify binary is embedded and is a multi-megabyte binary
        assert!(CLOUD_HYPERVISOR_BINARY.len() > 1_000_000);
    }

    #[test]
    fn test_runtime_dir() {
        let runtime_dir = crate::paths::runtime_dir();
        // Just verify the path is reasonable
        assert!(!runtime_dir.as_os_str().is_empty());
    }
}
