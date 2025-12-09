//! Centralized path configuration for HYPR.
//!
//! All paths should go through this module to ensure consistency.
//! HYPR requires root privileges for VM operations, so paths are system-level.

use std::path::PathBuf;

/// Get the HYPR data directory.
///
/// Resolution order:
/// 1. `HYPR_DATA_DIR` environment variable (for testing/custom installs)
/// 2. `/var/lib/hypr` (standard system location)
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HYPR_DATA_DIR") {
        return PathBuf::from(dir);
    }

    PathBuf::from("/var/lib/hypr")
}

/// Get the database path.
pub fn db_path() -> PathBuf {
    data_dir().join("hypr.db")
}

/// Get the images directory.
pub fn images_dir() -> PathBuf {
    data_dir().join("images")
}

/// Get the logs directory.
pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

/// Get the cache directory.
pub fn cache_dir() -> PathBuf {
    data_dir().join("cache")
}

/// Get the VM log path for a specific VM.
pub fn vm_log_path(vm_id: &str) -> PathBuf {
    logs_dir().join(format!("{}.log", vm_id))
}

/// Get the kernel path.
pub fn kernel_path() -> PathBuf {
    data_dir().join("vmlinux")
}

/// Default kernel version to download.
pub const DEFAULT_KERNEL_VERSION: &str = "6.12";

/// Get the kernel download URL for the current architecture.
///
/// Uses HYPR's custom kernel builds which include squashfs,
/// overlayfs, virtio-fs, and container features.
pub fn kernel_url() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some(concat!(
            "https://github.com/hyprhq/hypr/releases/download/",
            "kernel-6.12-hypr/vmlinux-x86_64"
        )),
        "aarch64" => Some(concat!(
            "https://github.com/hyprhq/hypr/releases/download/",
            "kernel-6.12-hypr/Image-aarch64"
        )),
        _ => None,
    }
}

/// Ensure the kernel exists, downloading if necessary.
///
/// Returns the path to the kernel, downloading from HYPR releases if not present.
pub fn ensure_kernel() -> std::io::Result<PathBuf> {
    let path = kernel_path();

    if path.exists() {
        return Ok(path);
    }

    // Create data directory
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;

    // Get download URL
    let url = kernel_url().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("Unsupported architecture: {}", std::env::consts::ARCH),
        )
    })?;

    tracing::info!("Downloading HYPR kernel from: {}", url);

    // Create client with generous timeout for large kernel download (~20MB)
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| std::io::Error::other(format!("Failed to create HTTP client: {}", e)))?;

    // Download kernel with retries
    let mut last_error = None;
    for attempt in 1..=3 {
        tracing::info!("Download attempt {}/3...", attempt);

        match client.get(url).send() {
            Ok(response) => {
                if !response.status().is_success() {
                    last_error = Some(format!("Download failed: HTTP {}", response.status()));
                    continue;
                }

                match response.bytes() {
                    Ok(kernel_bytes) => {
                        std::fs::write(&path, &kernel_bytes)?;
                        tracing::info!(
                            "Kernel downloaded to: {} ({:.2} MB)",
                            path.display(),
                            kernel_bytes.len() as f64 / 1024.0 / 1024.0
                        );
                        return Ok(path);
                    }
                    Err(e) => {
                        last_error = Some(format!("Failed to read response: {}", e));
                    }
                }
            }
            Err(e) => {
                last_error = Some(format!("Request failed: {}", e));
            }
        }

        // Wait before retry
        if attempt < 3 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    Err(std::io::Error::other(
        last_error.unwrap_or_else(|| "Download failed after 3 attempts".to_string()),
    ))
}

/// Get the eBPF programs directory.
/// These are installed to a system location since they're loaded into the kernel.
pub fn ebpf_dir() -> PathBuf {
    data_dir()
}

/// Get the runtime directory for sockets, PIDs, etc.
///
/// This directory is used for ephemeral runtime files like:
/// - API sockets
/// - PID files
/// - virtiofsd sockets
/// - Extracted binaries (cloud-hypervisor)
/// - Initramfs files
///
/// Resolution order:
/// 1. `HYPR_RUNTIME_DIR` environment variable (for testing/custom installs)
/// 2. `/run/hypr` (Linux standard)
/// 3. `/tmp/hypr` (macOS fallback, no /run)
pub fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HYPR_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }

    // Linux uses /run, macOS uses /tmp
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/hypr")
    }

    #[cfg(not(target_os = "linux"))]
    {
        PathBuf::from("/tmp/hypr")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dir_from_env() {
        std::env::set_var("HYPR_DATA_DIR", "/tmp/hypr-test");
        assert_eq!(data_dir(), PathBuf::from("/tmp/hypr-test"));
        std::env::remove_var("HYPR_DATA_DIR");
    }

    #[test]
    fn test_paths_consistency() {
        let base = data_dir();
        assert!(db_path().starts_with(&base));
        assert!(images_dir().starts_with(&base));
        assert!(logs_dir().starts_with(&base));
        assert!(cache_dir().starts_with(&base));
    }
}
