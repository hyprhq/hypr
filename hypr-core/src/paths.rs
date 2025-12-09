//! Centralized path configuration for HYPR.
//!
//! All data paths should go through this module to ensure consistency
//! between daemon and CLI, whether running as user or system service.

use std::path::PathBuf;

/// Get the HYPR data directory.
///
/// Resolution order:
/// 1. `HYPR_DATA_DIR` environment variable
/// 2. `/var/lib/hypr` if it exists (system install - LaunchDaemon)
/// 3. `~/.hypr` for user-only installs
pub fn data_dir() -> PathBuf {
    // Check environment variable first
    if let Ok(dir) = std::env::var("HYPR_DATA_DIR") {
        return PathBuf::from(dir);
    }

    // Check if system install exists (LaunchDaemon mode)
    let system_dir = PathBuf::from("/var/lib/hypr");
    if system_dir.exists() {
        return system_dir;
    }

    // Fall back to user home directory
    dirs::home_dir().map(|h| h.join(".hypr")).unwrap_or(system_dir)
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
///
/// Resolution order:
/// 1. `HYPR_RUNTIME_DIR` environment variable
/// 2. `$XDG_RUNTIME_DIR/hypr` if XDG_RUNTIME_DIR is set
/// 3. `/run/hypr` if running as root
/// 4. `/tmp/hypr-runtime` as fallback
pub fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HYPR_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }

    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg).join("hypr");
    }

    // Check if running as root
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return PathBuf::from("/run/hypr");
        }
    }

    PathBuf::from("/tmp/hypr-runtime")
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
