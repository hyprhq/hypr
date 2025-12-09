//! Initramfs generation for builder VMs with embedded assets.
//!
//! Instead of generating initramfs at runtime (slow, network-dependent),
//! we embed pre-built initramfs.cpio archives at compile-time.
//!
//! Format: uncompressed cpio archive (newc format)

use crate::builder::embedded::{self, InitramfsSource};
use crate::builder::executor::{BuildError, BuildResult};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, info, instrument};

/// Creates an initramfs for builder VMs.
///
/// The initramfs is either:
/// - Extracted from embedded initramfs.cpio (default)
/// - Copied from INITRAMFS_PATH override (dev/testing)
///
/// Returns path to the initramfs.cpio file in a temporary location.
#[instrument]
pub fn create_builder_initramfs() -> BuildResult<PathBuf> {
    info!("Creating builder initramfs");

    // Determine target architecture (Linux VMs always run Linux initramfs)
    let host_arch = std::env::consts::ARCH;
    let linux_arch = match host_arch {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        other => {
            return Err(BuildError::ContextError(format!(
                "Unsupported host architecture: {}. Only x86_64 and aarch64/arm64 are supported.",
                other
            )))
        }
    };

    debug!("Target architecture: linux-{}", linux_arch);

    // Resolve initramfs source (embedded or override)
    match embedded::resolve_initramfs_source() {
        InitramfsSource::Embedded => {
            info!("Using embedded initramfs (linux-{})", linux_arch);
            extract_embedded_initramfs(linux_arch)
        }
        InitramfsSource::Override(override_path) => {
            info!("Using INITRAMFS_PATH override: {}", override_path.display());
            validate_and_copy_override(&override_path)
        }
    }
}

/// Extract embedded initramfs.cpio atomically.
fn extract_embedded_initramfs(arch: &str) -> BuildResult<PathBuf> {
    let initramfs_bytes = embedded::get_embedded_initramfs(arch).ok_or_else(|| {
        BuildError::ContextError(format!("No embedded initramfs for architecture: {}", arch))
    })?;

    debug!("Extracting embedded initramfs ({} bytes)", initramfs_bytes.len());

    // Use centralized runtime directory for consistency
    let runtime_dir = crate::paths::runtime_dir();
    fs::create_dir_all(&runtime_dir)
        .map_err(|e| BuildError::IoError { path: runtime_dir.clone(), source: e })?;

    let initramfs_path = runtime_dir.join(format!("initramfs-{}.cpio", uuid::Uuid::new_v4()));

    {
        let mut f = File::create(&initramfs_path)
            .map_err(|e| BuildError::IoError { path: initramfs_path.clone(), source: e })?;
        f.write_all(initramfs_bytes)
            .map_err(|e| BuildError::IoError { path: initramfs_path.clone(), source: e })?;
        f.flush().map_err(|e| BuildError::IoError { path: initramfs_path.clone(), source: e })?;
    }

    debug!("Embedded initramfs extracted successfully: {}", initramfs_path.display());

    Ok(initramfs_path)
}

/// Validate and copy override initramfs.
///
/// Fails fast if override path is invalid (no silent fallback).
fn validate_and_copy_override(src: &std::path::Path) -> BuildResult<PathBuf> {
    // Verify source exists
    if !src.exists() {
        return Err(BuildError::ContextError(format!(
            "INITRAMFS_PATH set but file not found: {}\n\
             \n\
             To use embedded initramfs, unset INITRAMFS_PATH:\n\
             unset INITRAMFS_PATH",
            src.display()
        )));
    }

    // Verify it's a file
    if !src.is_file() {
        return Err(BuildError::ContextError(format!(
            "INITRAMFS_PATH is not a file: {}",
            src.display()
        )));
    }

    // Verify it's a cpio archive (basic sanity check)
    let mut f =
        File::open(src).map_err(|e| BuildError::IoError { path: src.to_path_buf(), source: e })?;
    let mut magic = [0u8; 6];
    use std::io::Read;
    f.read_exact(&mut magic)
        .map_err(|e| BuildError::ContextError(format!("Failed to read cpio header: {}", e)))?;

    if magic != *b"070701" {
        return Err(BuildError::ContextError(format!(
            "INITRAMFS_PATH is not a valid cpio newc archive: {} (magic: {:?})",
            src.display(),
            std::str::from_utf8(&magic)
        )));
    }

    // Copy to runtime directory (to match embedded behavior)
    let runtime_dir = crate::paths::runtime_dir();
    fs::create_dir_all(&runtime_dir)
        .map_err(|e| BuildError::IoError { path: runtime_dir.clone(), source: e })?;

    let initramfs_path =
        runtime_dir.join(format!("initramfs-override-{}.cpio", uuid::Uuid::new_v4()));

    fs::copy(src, &initramfs_path)
        .map_err(|e| BuildError::IoError { path: initramfs_path.clone(), source: e })?;

    debug!("Override initramfs copied successfully");

    Ok(initramfs_path)
}
