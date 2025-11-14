//! Embedded kestrel binaries for hermetic builds.
//!
//! These binaries are embedded at compile-time using include_bytes! and are
//! extracted atomically at runtime when building initramfs.
//!
//! This ensures:
//! - Zero network dependencies
//! - Deterministic builds
//! - Version lockstep with HYPR binary
//! - Offline capability

/// Embedded kestrel binary for Linux amd64 (x86_64)
pub const KESTREL_LINUX_AMD64: &[u8] = include_bytes!("../../embedded/kestrel-linux-amd64");

/// Embedded kestrel binary for Linux arm64 (aarch64)
pub const KESTREL_LINUX_ARM64: &[u8] = include_bytes!("../../embedded/kestrel-linux-arm64");

/// Source of kestrel binary (embedded or override)
#[derive(Debug, Clone)]
pub enum KestrelSource {
    /// Use embedded binary (default, deterministic)
    Embedded,
    /// Use override path (developer/integrator intent)
    Override(std::path::PathBuf),
}

/// Resolve which kestrel source to use.
///
/// Priority:
/// 1. KESTREL_BIN_PATH environment variable (explicit override)
/// 2. Embedded binary (default, always present)
///
/// Note: This is NOT a fallback chain. If override is set but invalid,
/// we fail fast rather than silently falling back.
pub fn resolve_kestrel_source() -> KestrelSource {
    if let Ok(path) = std::env::var("KESTREL_BIN_PATH") {
        return KestrelSource::Override(std::path::PathBuf::from(path));
    }

    KestrelSource::Embedded
}

/// Get the embedded kestrel binary for the specified architecture.
///
/// # Arguments
/// * `arch` - "amd64" or "arm64"
///
/// # Returns
/// Byte slice of the embedded kestrel binary
pub fn get_embedded_kestrel(arch: &str) -> Option<&'static [u8]> {
    match arch {
        "amd64" => Some(KESTREL_LINUX_AMD64),
        "arm64" => Some(KESTREL_LINUX_ARM64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_kestrel_amd64_exists() {
        assert!(!KESTREL_LINUX_AMD64.is_empty());
        // Verify ELF magic number (7F 45 4C 46)
        assert_eq!(&KESTREL_LINUX_AMD64[0..4], &[0x7F, 0x45, 0x4C, 0x46]);
    }

    #[test]
    fn test_embedded_kestrel_arm64_exists() {
        assert!(!KESTREL_LINUX_ARM64.is_empty());
        // Verify ELF magic number
        assert_eq!(&KESTREL_LINUX_ARM64[0..4], &[0x7F, 0x45, 0x4C, 0x46]);
    }

    #[test]
    fn test_get_embedded_kestrel() {
        assert!(get_embedded_kestrel("amd64").is_some());
        assert!(get_embedded_kestrel("arm64").is_some());
        assert!(get_embedded_kestrel("invalid").is_none());
    }

    #[test]
    fn test_resolve_kestrel_source_default() {
        // Save current value
        let original = std::env::var("KESTREL_BIN_PATH").ok();

        // Without KESTREL_BIN_PATH, should use embedded
        std::env::remove_var("KESTREL_BIN_PATH");
        match resolve_kestrel_source() {
            KestrelSource::Embedded => {},
            _ => panic!("Expected Embedded source"),
        }

        // Restore original value
        if let Some(val) = original {
            std::env::set_var("KESTREL_BIN_PATH", val);
        }
    }

    #[test]
    fn test_resolve_kestrel_source_override() {
        // With KESTREL_BIN_PATH, should use override
        std::env::set_var("KESTREL_BIN_PATH", "/custom/path/kestrel");
        match resolve_kestrel_source() {
            KestrelSource::Override(path) => {
                assert_eq!(path.to_str().unwrap(), "/custom/path/kestrel");
            },
            _ => panic!("Expected Override source"),
        }
        std::env::remove_var("KESTREL_BIN_PATH");
    }
}
