//! Embedded initramfs for hermetic builds.
//!
//! Complete initramfs.cpio archives are embedded at compile-time using include_bytes!
//! and extracted atomically at runtime when spawning builder VMs.
//!
//! Each initramfs contains:
//! - kestrel binary (PID 1 init)
//! - busybox-static (utilities)
//! - Basic directory structure
//!
//! This ensures:
//! - Zero network dependencies at runtime
//! - Deterministic builds (locked versions)
//! - Version lockstep with HYPR binary
//! - Offline capability
//! - Fast initramfs creation (~1ms to write bytes to disk)

/// Embedded initramfs (architecture-specific at compile time)
///
/// Only the initramfs matching the host architecture is embedded.
/// Host can only virtualize VMs of its own architecture.
#[cfg(target_arch = "x86_64")]
pub const INITRAMFS_LINUX: &[u8] = include_bytes!("../../embedded/initramfs-linux-amd64.cpio");

#[cfg(target_arch = "aarch64")]
pub const INITRAMFS_LINUX: &[u8] = include_bytes!("../../embedded/initramfs-linux-arm64.cpio");

/// Source of initramfs (embedded or override)
#[derive(Debug, Clone)]
pub enum InitramfsSource {
    /// Use embedded initramfs.cpio (default, deterministic)
    Embedded,
    /// Use override path (developer/integrator intent)
    Override(std::path::PathBuf),
}

/// Resolve which initramfs source to use.
///
/// Priority:
/// 1. INITRAMFS_PATH environment variable (explicit override)
/// 2. Embedded initramfs.cpio (default, always present)
///
/// Note: This is NOT a fallback chain. If override is set but invalid,
/// we fail fast rather than silently falling back.
pub fn resolve_initramfs_source() -> InitramfsSource {
    if let Ok(path) = std::env::var("INITRAMFS_PATH") {
        return InitramfsSource::Override(std::path::PathBuf::from(path));
    }

    InitramfsSource::Embedded
}

/// Get the embedded initramfs.
///
/// Returns the embedded initramfs for the current architecture.
/// The architecture check is done at compile time via #[cfg].
pub fn get_embedded_initramfs(_arch: &str) -> Option<&'static [u8]> {
    // Only one initramfs is embedded (matching host architecture)
    Some(INITRAMFS_LINUX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_initramfs_exists() {
        assert!(!INITRAMFS_LINUX.is_empty());
        // Verify cpio magic number (070701 = newc format ASCII)
        // First 6 bytes should be "070701"
        assert_eq!(&INITRAMFS_LINUX[0..6], b"070701");
    }

    #[test]
    fn test_get_embedded_initramfs() {
        // Only one initramfs is embedded (matching host architecture)
        assert!(get_embedded_initramfs("any").is_some());
    }

    #[test]
    fn test_resolve_initramfs_source_default() {
        // Save current value
        let original = std::env::var("INITRAMFS_PATH").ok();

        // Without INITRAMFS_PATH, should use embedded
        std::env::remove_var("INITRAMFS_PATH");
        match resolve_initramfs_source() {
            InitramfsSource::Embedded => {}
            _ => panic!("Expected Embedded source"),
        }

        // Restore original value
        if let Some(val) = original {
            std::env::set_var("INITRAMFS_PATH", val);
        }
    }

    #[test]
    fn test_resolve_initramfs_source_override() {
        // With INITRAMFS_PATH, should use override
        std::env::set_var("INITRAMFS_PATH", "/custom/path/initramfs.cpio");
        match resolve_initramfs_source() {
            InitramfsSource::Override(path) => {
                assert_eq!(path.to_str().unwrap(), "/custom/path/initramfs.cpio");
            }
            _ => panic!("Expected Override source"),
        }
        std::env::remove_var("INITRAMFS_PATH");
    }
}
