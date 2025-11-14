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

/// Embedded initramfs for Linux amd64 (x86_64)
pub const INITRAMFS_LINUX_AMD64: &[u8] =
    include_bytes!("../../embedded/initramfs-linux-amd64.cpio");

/// Embedded initramfs for Linux arm64 (aarch64)
pub const INITRAMFS_LINUX_ARM64: &[u8] =
    include_bytes!("../../embedded/initramfs-linux-arm64.cpio");

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

/// Get the embedded initramfs for the specified architecture.
///
/// # Arguments
/// * `arch` - "amd64" or "arm64"
///
/// # Returns
/// Byte slice of the embedded initramfs.cpio
pub fn get_embedded_initramfs(arch: &str) -> Option<&'static [u8]> {
    match arch {
        "amd64" => Some(INITRAMFS_LINUX_AMD64),
        "arm64" => Some(INITRAMFS_LINUX_ARM64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_initramfs_amd64_exists() {
        assert!(!INITRAMFS_LINUX_AMD64.is_empty());
        // Verify cpio magic number (070701 = newc format ASCII)
        // First 6 bytes should be "070701"
        assert_eq!(&INITRAMFS_LINUX_AMD64[0..6], b"070701");
    }

    #[test]
    fn test_embedded_initramfs_arm64_exists() {
        assert!(!INITRAMFS_LINUX_ARM64.is_empty());
        // Verify cpio magic number
        assert_eq!(&INITRAMFS_LINUX_ARM64[0..6], b"070701");
    }

    #[test]
    fn test_get_embedded_initramfs() {
        assert!(get_embedded_initramfs("amd64").is_some());
        assert!(get_embedded_initramfs("arm64").is_some());
        assert!(get_embedded_initramfs("invalid").is_none());
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
