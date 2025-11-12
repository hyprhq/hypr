// src/builder/initramfs.rs - On-the-fly initramfs generation for builder VMs
//
// Creates minimal initramfs containing:
// - kestrel binary (PID 1 init)
// - busybox (static)
// - Basic directory structure
//
// Format: uncompressed cpio archive (newc format)

use crate::builder::executor::{BuildError, BuildResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, instrument};

/// Creates an initramfs for builder VMs.
///
/// The initramfs contains:
/// - `/init` - kestrel binary (from build.rs compilation)
/// - `/bin/busybox` - static busybox (downloaded or bundled)
/// - Basic directory structure (/dev, /proc, /sys, /tmp, /workspace, /shared)
///
/// Returns path to the generated initramfs.cpio file.
#[instrument]
pub fn create_builder_initramfs() -> BuildResult<PathBuf> {
    info!("Creating builder initramfs");

    // Create temporary directory for initramfs contents
    let temp_dir = std::env::temp_dir().join(format!("hypr-initramfs-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).map_err(|e| BuildError::IoError {
        path: temp_dir.clone(),
        source: e,
    })?;

    debug!("Initramfs staging directory: {}", temp_dir.display());

    // Create directory structure
    create_directory_structure(&temp_dir)?;

    // Copy kestrel binary
    copy_kestrel_binary(&temp_dir)?;

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
    let dirs = vec![
        "bin",
        "dev",
        "proc",
        "sys",
        "tmp",
        "workspace",
        "shared",
        "etc",
    ];

    for dir in dirs {
        let path = root.join(dir);
        fs::create_dir_all(&path).map_err(|e| BuildError::IoError {
            path: path.clone(),
            source: e,
        })?;
    }

    Ok(())
}

/// Copy kestrel binary from build output to initramfs /init.
fn copy_kestrel_binary(root: &Path) -> BuildResult<()> {
    let kestrel_dst = root.join("init");

    // Determine architecture of the HOST (where hypr is running)
    // We need to download a LINUX binary for this architecture because
    // kestrel runs inside Linux VMs regardless of host OS
    let host_arch = std::env::consts::ARCH;
    let linux_arch = match host_arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm64" => "aarch64", // macOS reports arm64 instead of aarch64
        other => {
            return Err(BuildError::ContextError(format!(
                "Unsupported host architecture: {}. Only x86_64 and aarch64/arm64 are supported.",
                other
            )));
        }
    };

    debug!(
        "Host: {} {} → downloading kestrel-linux-{}",
        std::env::consts::OS,
        host_arch,
        linux_arch
    );

    // Fallback chain:
    // 1. Check KESTREL_BIN_PATH env var (build.rs compiled version, Linux only)
    // 2. Check ~/.hypr/bin/kestrel-linux-{arch} (locally built/manually placed)
    // 3. Download from GitHub releases (future CI/CD, proper distribution)

    #[cfg(target_os = "linux")]
    {
        // On Linux, prefer build.rs compiled version if architecture matches
        if let Ok(kestrel_src) = std::env::var("KESTREL_BIN_PATH") {
            if PathBuf::from(&kestrel_src).exists() {
                debug!("Using build.rs compiled kestrel: {}", kestrel_src);
                fs::copy(&kestrel_src, &kestrel_dst).map_err(|e| BuildError::IoError {
                    path: kestrel_dst.clone(),
                    source: e,
                })?;

                set_executable(&kestrel_dst)?;
                return Ok(());
            }
        }
    }

    // Check for locally built binary in ~/.hypr/bin/
    if let Ok(home) = std::env::var("HOME") {
        let local_kestrel = PathBuf::from(home)
            .join(".hypr")
            .join("bin")
            .join(format!("kestrel-linux-{}", linux_arch));

        if local_kestrel.exists() {
            debug!("Using locally built kestrel: {}", local_kestrel.display());
            fs::copy(&local_kestrel, &kestrel_dst).map_err(|e| BuildError::IoError {
                path: kestrel_dst.clone(),
                source: e,
            })?;

            set_executable(&kestrel_dst)?;
            return Ok(());
        } else {
            debug!("Local kestrel not found at: {}", local_kestrel.display());
        }
    }

    // Download Linux binary from GitHub releases
    // (works on both darwin and linux hosts)
    // Note: Requires GitHub Actions CI/CD to build and release kestrel binaries
    debug!("Attempting to download kestrel from GitHub releases");
    download_kestrel(linux_arch, &kestrel_dst)?;
    set_executable(&kestrel_dst)?;

    Ok(())
}

/// Download kestrel from GitHub releases.
fn download_kestrel(arch: &str, dest: &Path) -> BuildResult<()> {
    let url = format!("https://github.com/hyprhq/hypr/releases/download/latest/kestrel-linux-{}", arch);

    debug!("Downloading kestrel from: {}", url);

    // Use curl or wget (portable across Unix systems)
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("curl -fsSL {} -o {} || wget -q -O {} {}", url, dest.display(), dest.display(), url))
        .status()
        .map_err(|e| BuildError::ContextError(format!("Failed to download kestrel: {}", e)))?;

    if !status.success() {
        return Err(BuildError::ContextError(format!(
            "Failed to download kestrel from {}.\n\
             Please check internet connection or manually place kestrel binary at ~/.hypr/bin/kestrel-linux-{}",
            url, arch
        )));
    }

    // Verify downloaded
    if !dest.exists() {
        return Err(BuildError::ContextError(format!(
            "Kestrel binary not found after download: {}",
            dest.display()
        )));
    }

    debug!("Kestrel downloaded successfully");
    Ok(())
}

/// Set file as executable (Unix only).
fn set_executable(path: &Path) -> BuildResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| BuildError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(|e| BuildError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
    }
    Ok(())
}

/// Download and extract busybox from Debian packages.
fn copy_busybox_binary(root: &Path) -> BuildResult<()> {
    let busybox_dst = root.join("bin/busybox");

    // Determine architecture of the HOST (where hypr is running)
    // We need to download a LINUX binary for this architecture because
    // busybox runs inside Linux VMs regardless of host OS
    let host_arch = std::env::consts::ARCH;
    let (deb_arch, deb_url) = match host_arch {
        "x86_64" => (
            "amd64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_amd64.deb"
        ),
        "aarch64" | "arm64" => (
            "arm64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_arm64.deb"
        ),
        other => {
            return Err(BuildError::ContextError(format!(
                "Unsupported host architecture: {}. Only x86_64 and aarch64/arm64 are supported.",
                other
            )));
        }
    };

    debug!(
        "Host: {} {} → downloading busybox-static ({})",
        std::env::consts::OS,
        host_arch,
        deb_arch
    );

    // Create temp directory for extraction
    let temp_dir = std::env::temp_dir().join(format!("hypr-busybox-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).map_err(|e| BuildError::IoError {
        path: temp_dir.clone(),
        source: e,
    })?;

    let deb_file = temp_dir.join(format!("busybox-static_{}.deb", deb_arch));

    debug!("Downloading busybox-static from Debian: {}", deb_url);

    // Download .deb file
    let download_status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -fsSL {} -o {} || wget -q -O {} {}",
            deb_url, deb_file.display(), deb_file.display(), deb_url
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

    debug!("Extracting busybox from .deb package");

    // Extract .deb: ar x file.deb data.tar.xz, then tar -xf data.tar.xz ./usr/bin/busybox
    let extract_status = std::process::Command::new("sh")
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

    // Cleanup temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    if !extract_status.success() {
        return Err(BuildError::ContextError(
            "Failed to extract busybox from .deb package. \
             Requires 'ar' (binutils) or 'bsdtar' (libarchive) and 'tar'."
                .into(),
        ));
    }

    // Verify extracted
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
///
/// Uses `cpio` command to create newc format archive.
fn create_cpio_archive(source_dir: &Path) -> BuildResult<PathBuf> {
    let output_path = std::env::temp_dir().join(format!("hypr-initramfs-{}.cpio", uuid::Uuid::new_v4()));

    debug!(
        "Creating cpio archive: {} → {}",
        source_dir.display(),
        output_path.display()
    );

    // Create cpio archive using find + cpio
    // Command: cd <source_dir> && find . | cpio -o -H newc > <output>
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

    // Verify cpio was created
    if !output_path.exists() {
        return Err(BuildError::ContextError(format!(
            "cpio archive not created at: {}",
            output_path.display()
        )));
    }

    let size = fs::metadata(&output_path)
        .map_err(|e| BuildError::IoError {
            path: output_path.clone(),
            source: e,
        })?
        .len();

    info!("Initramfs cpio created: {} KB", size / 1024);

    Ok(output_path)
}
