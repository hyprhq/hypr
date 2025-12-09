//! Embedded hypervisor binaries and resources.
//!
//! This module contains cloud-hypervisor binaries embedded at compile time.
//! These are extracted to a runtime directory when needed, eliminating the need
//! for users to install cloud-hypervisor separately.

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

/// Get the cloud-hypervisor binary path, extracting if needed.
///
/// This function:
/// 1. Determines the host architecture
/// 2. Checks if cloud-hypervisor is already extracted
/// 3. Extracts the embedded binary if missing
/// 4. Returns the path to the binary
pub fn get_cloud_hypervisor_path() -> Result<PathBuf> {
    // Use centralized paths module for consistency
    let runtime_dir = crate::paths::runtime_dir();
    fs::create_dir_all(&runtime_dir)
        .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;

    let binary_name = if cfg!(target_arch = "x86_64") {
        "cloud-hypervisor-static"
    } else if cfg!(target_arch = "aarch64") {
        "cloud-hypervisor-static-aarch64"
    } else {
        return Err(HyprError::UnsupportedArchitecture {
            arch: std::env::consts::ARCH.to_string(),
        });
    };

    let binary_path = runtime_dir.join(binary_name);

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
