//! Embedded hypervisor binaries and resources.
//!
//! This module contains cloud-hypervisor binaries, libkrun, and eBPF programs embedded at compile time.
//! These are extracted to a runtime directory when needed, eliminating the need
//! for users to install dependencies separately.

use crate::error::{HyprError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Embedded libkrun dynamic library (macOS only)
#[cfg(target_os = "macos")]
const LIBKRUN_BINARY: &[u8] = include_bytes!("../embedded/libkrun.dylib");

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

/// Get the libkrun library path, extracting if needed (macOS only).
///
/// This function:
/// 1. Checks if libkrun.dylib is already extracted
/// 2. Extracts the embedded library if missing
/// 3. Returns the path to the library
#[cfg(target_os = "macos")]
pub fn get_libkrun_path() -> Result<PathBuf> {
    let lib_dir = crate::paths::data_dir().join("lib");
    fs::create_dir_all(&lib_dir)
        .map_err(|e| HyprError::IoError { path: lib_dir.clone(), source: e })?;

    let library_path = lib_dir.join("libkrun.dylib");

    // Extract if not exists or size mismatch (updated binary)
    let should_extract = if library_path.exists() {
        match fs::metadata(&library_path) {
            Ok(meta) => meta.len() != LIBKRUN_BINARY.len() as u64,
            Err(_) => true,
        }
    } else {
        true
    };

    if should_extract {
        info!("Extracting embedded libkrun to {}", library_path.display());
        extract_libkrun(&library_path)?;
    } else {
        debug!("Using existing libkrun at {}", library_path.display());
    }

    // Always ensure the library is signed with proper entitlements
    // This is fast and ensures it works even if the file existed but signature was invalid
    sign_libkrun(&library_path)?;

    Ok(library_path)
}

/// Sign libkrun.dylib with hypervisor entitlement.
#[cfg(target_os = "macos")]
fn sign_libkrun(path: &Path) -> Result<()> {
    // Create entitlements in temp file
    let entitlements_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>"#;

    let entitlements_path = path.with_extension("entitlements");
    fs::write(&entitlements_path, entitlements_content)
        .map_err(|e| HyprError::IoError { path: entitlements_path.clone(), source: e })?;

    // Sign the library
    let status = std::process::Command::new("codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--entitlements",
            entitlements_path.to_str().unwrap_or(""),
            path.to_str().unwrap_or(""),
        ])
        .output(); // Use output to capture stderr if needed

    // Clean up entitlements file
    let _ = fs::remove_file(&entitlements_path);

    match status {
        Ok(out) if out.status.success() => {
            debug!("Signed libkrun with hypervisor entitlement");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::warn!("codesign exited with status: {} (stderr: {})", out.status, stderr);
        }
        Err(e) => {
            tracing::warn!("Failed to run codesign: {} (VMs may not start)", e);
        }
    }

    Ok(())
}

/// Extract libkrun.dylib to disk.
#[cfg(target_os = "macos")]
fn extract_libkrun(dest: &Path) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| HyprError::IoError { path: parent.to_path_buf(), source: e })?;
    }

    // Write library
    fs::write(dest, LIBKRUN_BINARY)
        .map_err(|e| HyprError::IoError { path: dest.to_path_buf(), source: e })?;

    info!(
        "Extracted libkrun ({:.2} MB) to {}",
        LIBKRUN_BINARY.len() as f64 / 1024.0 / 1024.0,
        dest.display()
    );

    Ok(())
}

/// Placeholder marker for eBPF files that couldn't be compiled at build time.
#[cfg(target_os = "linux")]
const EBPF_PLACEHOLDER_MARKER: &[u8] = b"HYPR_EBPF_PLACEHOLDER";

/// Get eBPF program paths, extracting if needed (Linux only).
///
/// Returns (ingress_path, egress_path) for the eBPF programs.
/// These are extracted from the embedded binary to the data directory.
///
/// Returns an error if the embedded eBPF programs are placeholders
/// (i.e., they couldn't be compiled at build time due to missing tools).
#[cfg(target_os = "linux")]
pub fn get_ebpf_paths() -> Result<(PathBuf, PathBuf)> {
    // Check if we have real eBPF programs or just placeholders
    if EBPF_INGRESS.starts_with(EBPF_PLACEHOLDER_MARKER)
        || EBPF_EGRESS.starts_with(EBPF_PLACEHOLDER_MARKER)
    {
        info!("eBPF programs are placeholders (not compiled at build time)");
        return Err(HyprError::EbpfNotAvailable {
            reason: "eBPF programs not compiled at build time (missing bpftool/clang)".to_string(),
        });
    }

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
