//! TAP device management for VM networking.
//!
//! This module provides platform-specific TAP device management:
//! - Linux: Uses ip tuntap for creating TAP devices
//! - macOS: Uses vmnet interfaces managed by hypervisor

use crate::error::{HyprError, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, instrument};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::LinuxTapManager;
#[cfg(target_os = "macos")]
pub use macos::MacOSTapManager;

/// Configuration for creating a TAP device.
#[derive(Debug, Clone)]
pub struct TapConfig {
    /// Name of the TAP device (e.g., "tap0")
    pub name: String,
    /// Name of the bridge to attach to
    pub bridge: String,
    /// UID for tap device ownership (Linux only)
    pub owner: Option<String>,
}

/// A TAP device handle.
#[derive(Debug, Clone)]
pub struct TapDevice {
    /// Name of the TAP device
    pub name: String,
    /// Path to the device file
    pub path: PathBuf,
}

/// Platform-agnostic TAP device management interface.
#[async_trait::async_trait]
pub trait TapManager: Send + Sync {
    /// Create a new TAP device.
    ///
    /// # Arguments
    /// * `config` - Configuration for the TAP device
    ///
    /// # Returns
    /// A handle to the created TAP device
    ///
    /// # Errors
    /// Returns `HyprError::NetworkSetupFailed` if device creation fails
    async fn create_tap(&self, config: &TapConfig) -> Result<TapDevice>;

    /// Delete a TAP device.
    ///
    /// # Arguments
    /// * `name` - Name of the TAP device to delete
    ///
    /// # Errors
    /// Returns `HyprError::NetworkSetupFailed` if deletion fails
    async fn delete_tap(&self, name: &str) -> Result<()>;

    /// Attach a TAP device to a bridge.
    ///
    /// # Arguments
    /// * `tap_name` - Name of the TAP device
    /// * `bridge_name` - Name of the bridge
    ///
    /// # Errors
    /// Returns `HyprError::NetworkSetupFailed` if attachment fails
    async fn attach_to_bridge(&self, tap_name: &str, bridge_name: &str) -> Result<()>;

    /// List all TAP devices.
    ///
    /// # Returns
    /// A vector of TAP device names
    async fn list_taps(&self) -> Result<Vec<String>>;
}

/// Create a platform-specific TAP manager.
///
/// # Returns
/// A TAP manager implementation for the current platform
///
/// # Errors
/// Returns `HyprError::PlatformUnsupported` if the platform is not supported
#[instrument]
pub fn create_tap_manager() -> Result<Arc<dyn TapManager>> {
    #[cfg(target_os = "linux")]
    {
        info!("Creating Linux TAP manager");
        Ok(Arc::new(LinuxTapManager))
    }

    #[cfg(target_os = "macos")]
    {
        info!("Creating macOS TAP manager");
        Ok(Arc::new(MacOSTapManager))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(HyprError::PlatformUnsupported {
            feature: "tap management".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_config_creation() {
        let config = TapConfig {
            name: "tap0".to_string(),
            bridge: "vbr0".to_string(),
            owner: None,
        };

        assert_eq!(config.name, "tap0");
        assert_eq!(config.bridge, "vbr0");
        assert!(config.owner.is_none());
    }

    #[test]
    fn test_tap_device_creation() {
        let device = TapDevice {
            name: "tap0".to_string(),
            path: PathBuf::from("/dev/net/tun"),
        };

        assert_eq!(device.name, "tap0");
        assert_eq!(device.path, PathBuf::from("/dev/net/tun"));
    }

    #[test]
    fn test_create_tap_manager() {
        let result = create_tap_manager();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(result.is_ok());

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(result.is_err());
    }
}
