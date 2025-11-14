//! Initramfs generation for builder VMs with embedded kestrel.
//!
//! Creates minimal initramfs containing:
//! - kestrel binary (PID 1 init, embedded at compile-time)
//! - busybox (static, downloaded from Debian)
//! - Basic directory structure
//!
//! Format: uncompressed cpio archive (newc format)

use crate::builder::embedded::{self, KestrelSource};
use crate::builder::executor::{BuildError, BuildResult};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, instrument, warn};

/// Creates an initramfs for builder VMs.
///
/// The initramfs contains:
/// - `/init` - kestrel binary (embedded or override)
/// - `/bin/busybox` - static busybox (downloaded from Debian)
/// - Basic directory structure (/dev, /proc, /sys, /tmp, /workspace, /shared)
///
/// Returns path to the generated initramfs.cpio file.
#[instrument]
pub fn create_builder_initramfs() -> BuildResult<PathBuf> {
    info!("Creating builder initramfs");

    // Create temporary directory for initramfs contents
    let temp_dir = std::env::temp_dir().join(format!("hypr-initramfs-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir)
        .map_err(|e| BuildError::IoError { path: temp_dir.clone(), source: e })?;

    debug!("Initramfs staging directory: {}", temp_dir.display());

    // Create directory structure
    create_directory_structure(&temp_dir)?;

    // Extract kestrel binary (embedded or override)
    extract_kestrel_binary(&temp_dir)?;

    // Copy or download busybox
    copy_busybox_binary(&temp_dir)?;

    // Create cpio archive
    let initramfs_path = create_cpio_archive(&temp_dir)?;

    // Cleanup staging directory
    let _ = fs::remove_dir_all(&temp_dir);

    info!("Initramfs created: {}", initramfs_path.display());

    Ok(initramfs_path)
}

/// Create basic directory structure in initramfs.
fn create_directory_structure(root: &Path) -> BuildResult<()> {
    let dirs = vec!["bin", "dev", "proc", "sys", "tmp", "workspace", "shared", "etc"];

    for dir in dirs {
        let path = root.join(dir);
        fs::create_dir_all(&path)
            .map_err(|e| BuildError::IoError { path: path.clone(), source: e })?;
    }

    Ok(())
}

/// Extract kestrel binary to initramfs /init.
///
/// Uses embedded binary by default, or KESTREL_BIN_PATH override if set.
fn extract_kestrel_binary(root: &Path) -> BuildResult<()> {
    let kestrel_dst = root.join("init");

    // Determine target architecture (Linux VMs always run Linux kestrel)
    let host_arch = std::env::consts::ARCH;
    let linux_arch = match host_arch {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        other => {
            return Err(BuildError::ContextError(format!(
                "Unsupported host architecture: {}. Only x86_64 and aarch64/arm64 are supported.",
                other
            )));
        }
    };

    debug!("Target architecture: linux-{}", linux_arch);

    // Resolve kestrel source (embedded or override)
    match embedded::resolve_kestrel_source() {
        KestrelSource::Embedded => {
            info!("Using embedded kestrel binary (linux-{})", linux_arch);
            extract_embedded_kestrel(linux_arch, &kestrel_dst)?;
        }
        KestrelSource::Override(override_path) => {
            info!("Using KESTREL_BIN_PATH override: {}", override_path.display());
            validate_and_copy_override(&override_path, &kestrel_dst)?;
        }
    }

    set_executable(&kestrel_dst)?;

    Ok(())
}

/// Extract embedded kestrel binary atomically.
fn extract_embedded_kestrel(arch: &str, dest: &Path) -> BuildResult<()> {
    let kestrel_bytes = embedded::get_embedded_kestrel(arch).ok_or_else(|| {
        BuildError::ContextError(format!("No embedded kestrel binary for architecture: {}", arch))
    })?;

    debug!("Extracting embedded kestrel ({} bytes)", kestrel_bytes.len());

    // Atomic write: temp file → rename
    let temp_path = dest.with_extension("tmp");

    {
        let mut f = File::create(&temp_path)
            .map_err(|e| BuildError::IoError { path: temp_path.clone(), source: e })?;
        f.write_all(kestrel_bytes)
            .map_err(|e| BuildError::IoError { path: temp_path.clone(), source: e })?;
        f.flush()
            .map_err(|e| BuildError::IoError { path: temp_path.clone(), source: e })?;
    }

    // Atomic rename
    fs::rename(&temp_path, dest)
        .map_err(|e| BuildError::IoError { path: dest.to_path_buf(), source: e })?;

    debug!("Embedded kestrel extracted successfully");

    Ok(())
}

/// Validate and copy override kestrel binary.
///
/// Fails fast if override path is invalid (no silent fallback).
fn validate_and_copy_override(src: &Path, dest: &Path) -> BuildResult<()> {
    // Verify source exists
    if !src.exists() {
        return Err(BuildError::ContextError(format!(
            "KESTREL_BIN_PATH set but file not found: {}\n\
             \n\
             To use embedded kestrel, unset KESTREL_BIN_PATH:\n\
             unset KESTREL_BIN_PATH",
            src.display()
        )));
    }

    // Verify it's a file
    if !src.is_file() {
        return Err(BuildError::ContextError(format!(
            "KESTREL_BIN_PATH is not a file: {}",
            src.display()
        )));
    }

    // Verify it's executable
    let metadata = fs::metadata(src)
        .map_err(|e| BuildError::IoError { path: src.to_path_buf(), source: e })?;

    #[cfg(unix)]
    {
        if metadata.permissions().mode() & 0o111 == 0 {
            warn!("KESTREL_BIN_PATH file is not executable: {}", src.display());
        }
    }

    // Verify it's an ELF binary (basic sanity check)
    let mut f = File::open(src)
        .map_err(|e| BuildError::IoError { path: src.to_path_buf(), source: e })?;
    let mut magic = [0u8; 4];
    use std::io::Read;
    f.read_exact(&mut magic)
        .map_err(|e| BuildError::ContextError(format!("Failed to read binary header: {}", e)))?;

    if magic != [0x7F, 0x45, 0x4C, 0x46] {
        return Err(BuildError::ContextError(format!(
            "KESTREL_BIN_PATH is not a valid ELF binary: {} (magic: {:02X?})",
            src.display(),
            magic
        )));
    }

    // Copy to destination
    fs::copy(src, dest)
        .map_err(|e| BuildError::IoError { path: dest.to_path_buf(), source: e })?;

    debug!("Override kestrel copied successfully");

    Ok(())
}

/// Set file as executable (Unix only).
fn set_executable(path: &Path) -> BuildResult<()> {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .map_err(|e| BuildError::IoError { path: path.to_path_buf(), source: e })?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .map_err(|e| BuildError::IoError { path: path.to_path_buf(), source: e })?;
    }
    Ok(())
}

/// Download and extract busybox from Debian packages.
fn copy_busybox_binary(root: &Path) -> BuildResult<()> {
    let busybox_dst = root.join("bin/busybox");

    // Determine target architecture
    let host_arch = std::env::consts::ARCH;
    let (deb_arch, deb_url) = match host_arch {
        "x86_64" => (
            "amd64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_amd64.deb",
        ),
        "aarch64" | "arm64" => (
            "arm64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_arm64.deb",
        ),
        other => {
            return Err(BuildError::ContextError(format!(
                "Unsupported host architecture: {}. Only x86_64 and aarch64/arm64 are supported.",
                other
            )));
        }
    };

    debug!("Downloading busybox-static ({})", deb_arch);

    // Create temp directory for extraction
    let temp_dir = std::env::temp_dir().join(format!("hypr-busybox-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir)
        .map_err(|e| BuildError::IoError { path: temp_dir.clone(), source: e })?;

    let deb_file = temp_dir.join(format!("busybox-static_{}.deb", deb_arch));

    // Download .deb file
    let download_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -fsSL {} -o {} || wget -q -O {} {}",
            deb_url,
            deb_file.display(),
            deb_file.display(),
            deb_url
        ))
        .status()
        .map_err(|e| BuildError::ContextError(format!("Failed to download busybox: {}", e)))?;

    if !download_status.success() {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(BuildError::ContextError(format!(
            "Failed to download busybox from Debian: {}",
            deb_url
        )));
    }

    // Extract .deb
    let extract_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && (ar x {} data.tar.xz 2>/dev/null || bsdtar -xf {} data.tar.xz) && \
             tar -xf data.tar.xz ./usr/bin/busybox && mv usr/bin/busybox {}",
            temp_dir.display(),
            deb_file.display(),
            deb_file.display(),
            busybox_dst.display()
        ))
        .status()
        .map_err(|e| BuildError::ContextError(format!("Failed to extract busybox: {}", e)))?;

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);

    if !extract_status.success() {
        return Err(BuildError::ContextError(
            "Failed to extract busybox from .deb package. \
             Requires 'ar' (binutils) or 'bsdtar' (libarchive) and 'tar'."
                .into(),
        ));
    }

    if !busybox_dst.exists() {
        return Err(BuildError::ContextError(format!(
            "Busybox binary not found after extraction: {}",
            busybox_dst.display()
        )));
    }

    set_executable(&busybox_dst)?;

    debug!("Busybox extracted successfully");

    Ok(())
}

/// Create cpio archive from directory contents.
fn create_cpio_archive(source_dir: &Path) -> BuildResult<PathBuf> {
    let output_path =
        std::env::temp_dir().join(format!("hypr-initramfs-{}.cpio", uuid::Uuid::new_v4()));

    debug!("Creating cpio archive: {} → {}", source_dir.display(), output_path.display());

    // Create cpio archive using find + cpio
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -print0 | cpio -0 -o -H newc > {}",
            source_dir.display(),
            output_path.display()
        ))
        .output()
        .map_err(|e| BuildError::ContextError(format!("Failed to run cpio command: {}", e)))?;

    if !output.status.success() {
        return Err(BuildError::ContextError(format!(
            "cpio failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    if !output_path.exists() {
        return Err(BuildError::ContextError(format!(
            "cpio archive not created at: {}",
            output_path.display()
        )));
    }

    let size = fs::metadata(&output_path)
        .map_err(|e| BuildError::IoError { path: output_path.clone(), source: e })?
        .len();

    info!("Initramfs cpio created: {} KB", size / 1024);

    Ok(output_path)
}
