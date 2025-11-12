// src/builder/initramfs.rs - On-the-fly initramfs generation for builder VMs
//
// Creates minimal initramfs containing:
// - kestrel binary (PID 1 init)
// - busybox (static)
// - Basic directory structure
//
// Format: uncompressed cpio archive (newc format)

use crate::builder::executor::{BuildError, BuildResult};
use std::fs::{self, File};
use std::io::Write;
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
    // On Linux, build.rs compiles kestrel.c and sets KESTREL_BIN_PATH
    // On macOS, we need a pre-built kestrel binary (or cross-compile)

    #[cfg(target_os = "linux")]
    {
        // Get kestrel binary path from build.rs
        let kestrel_src = env!("KESTREL_BIN_PATH");
        let kestrel_dst = root.join("init");

        debug!("Copying kestrel: {} → {}", kestrel_src, kestrel_dst.display());

        fs::copy(kestrel_src, &kestrel_dst).map_err(|e| BuildError::IoError {
            path: kestrel_dst.clone(),
            source: e,
        })?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&kestrel_dst)
                .map_err(|e| BuildError::IoError {
                    path: kestrel_dst.clone(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&kestrel_dst, perms).map_err(|e| BuildError::IoError {
                path: kestrel_dst.clone(),
                source: e,
            })?;
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On macOS, we need a pre-built Linux kestrel binary
        // Check for bundled kestrel or fail gracefully
        let bundled_kestrel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../guest/kestrel-linux-x86_64");

        if bundled_kestrel.exists() {
            let kestrel_dst = root.join("init");
            debug!(
                "Copying bundled kestrel: {} → {}",
                bundled_kestrel.display(),
                kestrel_dst.display()
            );
            fs::copy(&bundled_kestrel, &kestrel_dst).map_err(|e| BuildError::IoError {
                path: kestrel_dst.clone(),
                source: e,
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&kestrel_dst)
                    .map_err(|e| BuildError::IoError {
                        path: kestrel_dst.clone(),
                        source: e,
                    })?
                    .permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&kestrel_dst, perms).map_err(|e| BuildError::IoError {
                    path: kestrel_dst.clone(),
                    source: e,
                })?;
            }

            Ok(())
        } else {
            Err(BuildError::ContextError(format!(
                "Kestrel binary not found. On macOS, you need a pre-built Linux binary.\n\
                 Expected at: {}\n\
                 Please cross-compile kestrel.c for Linux or use a Linux build machine.",
                bundled_kestrel.display()
            )))
        }
    }
}

/// Copy or download busybox binary to initramfs /bin/busybox.
fn copy_busybox_binary(root: &Path) -> BuildResult<()> {
    let busybox_dst = root.join("bin/busybox");

    // Check for bundled busybox
    let bundled_busybox = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../guest/busybox-x86_64");

    if bundled_busybox.exists() {
        debug!(
            "Copying bundled busybox: {} → {}",
            bundled_busybox.display(),
            busybox_dst.display()
        );
        fs::copy(&bundled_busybox, &busybox_dst).map_err(|e| BuildError::IoError {
            path: busybox_dst.clone(),
            source: e,
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&busybox_dst)
                .map_err(|e| BuildError::IoError {
                    path: busybox_dst.clone(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&busybox_dst, perms).map_err(|e| BuildError::IoError {
                path: busybox_dst.clone(),
                source: e,
            })?;
        }

        Ok(())
    } else {
        // TODO: Download busybox from canonical source
        // For now, create a placeholder and warn
        let mut file = File::create(&busybox_dst).map_err(|e| BuildError::IoError {
            path: busybox_dst.clone(),
            source: e,
        })?;
        file.write_all(b"#!/bin/sh\necho 'busybox placeholder'\n")
            .map_err(|e| BuildError::IoError {
                path: busybox_dst.clone(),
                source: e,
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&busybox_dst)
                .map_err(|e| BuildError::IoError {
                    path: busybox_dst.clone(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&busybox_dst, perms).map_err(|e| BuildError::IoError {
                path: busybox_dst.clone(),
                source: e,
            })?;
        }

        eprintln!(
            "Warning: busybox not found, using placeholder. \
             Download busybox from https://busybox.net/downloads/binaries/ \
             and place at: {}",
            bundled_busybox.display()
        );

        Ok(())
    }
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
