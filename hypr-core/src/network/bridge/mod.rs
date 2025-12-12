//! Platform-specific bridge implementations.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[allow(unused_imports)]
use crate::error::{HyprError, Result};
use crate::network::defaults;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{info, instrument};

#[cfg(target_os = "linux")]
pub use linux::LinuxBridgeManager;

#[cfg(target_os = "macos")]
pub use macos::MacOSBridgeManager;

/// Bridge configuration.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge interface name
    pub name: String,

    /// Bridge IP address
    pub ip: Ipv4Addr,

    /// Network mask
    pub netmask: Ipv4Addr,

    /// MTU size
    pub mtu: u16,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let net = defaults::defaults();
        Self {
            name: "vbr0".to_string(),
            ip: net.gateway,
            netmask: net.netmask,
            mtu: 1500,
        }
    }
}

/// Bridge manager trait.
///
/// Provides platform-specific network bridge management for VM networking.
#[async_trait::async_trait]
pub trait BridgeManager: Send + Sync {
    /// Create a network bridge.
    ///
    /// # Arguments
    /// * `config` - Bridge configuration
    ///
    /// # Returns
    /// * `Ok(())` if bridge was created or already exists
    /// * `Err` if bridge creation failed
    async fn create_bridge(&self, config: &BridgeConfig) -> Result<()>;

    /// Delete a network bridge.
    ///
    /// # Arguments
    /// * `name` - Bridge interface name
    ///
    /// # Returns
    /// * `Ok(())` if bridge was deleted or doesn't exist
    /// * `Err` if bridge deletion failed
    async fn delete_bridge(&self, name: &str) -> Result<()>;

    /// Check if a bridge exists.
    ///
    /// # Arguments
    /// * `name` - Bridge interface name
    ///
    /// # Returns
    /// * `Ok(true)` if bridge exists
    /// * `Ok(false)` if bridge doesn't exist
    /// * `Err` if check failed
    async fn bridge_exists(&self, name: &str) -> Result<bool>;

    /// Enable IP forwarding.
    ///
    /// Required for VMs to communicate through the bridge.
    ///
    /// # Returns
    /// * `Ok(())` if IP forwarding was enabled or already enabled
    /// * `Err` if enabling failed
    async fn enable_ip_forward(&self) -> Result<()>;

    /// Setup NAT for the bridge.
    ///
    /// Configures iptables/pf rules for outbound NAT.
    ///
    /// # Arguments
    /// * `bridge_name` - Bridge interface name
    ///
    /// # Returns
    /// * `Ok(())` if NAT was configured or already configured
    /// * `Err` if NAT setup failed
    async fn setup_nat(&self, bridge_name: &str) -> Result<()>;
}

/// Create a platform-specific bridge manager.
///
/// # Returns
/// * `Ok(Arc<dyn BridgeManager>)` - Bridge manager for the current platform
/// * `Err(HyprError::PlatformUnsupported)` - If platform is not supported
///
/// # Supported Platforms
/// * Linux: Uses `ip` command and iptables
/// * macOS: Uses vmnet framework via libkrun
#[instrument]
pub fn create_bridge_manager() -> Result<Arc<dyn BridgeManager>> {
    #[cfg(target_os = "linux")]
    {
        info!("Creating Linux bridge manager");
        Ok(Arc::new(LinuxBridgeManager))
    }

    #[cfg(target_os = "macos")]
    {
        info!("Creating macOS bridge manager");
        Ok(Arc::new(MacOSBridgeManager))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(HyprError::PlatformUnsupported {
            feature: "bridge management".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BridgeConfig::default();
        let net = defaults::defaults();

        assert_eq!(config.name, "vbr0");
        assert_eq!(config.ip, net.gateway);
        assert_eq!(config.netmask, net.netmask);
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn test_bridge_config_clone() {
        let config = BridgeConfig::default();
        let cloned = config.clone();
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.ip, cloned.ip);
    }

    #[test]
    fn test_create_bridge_manager() {
        let result = create_bridge_manager();

        // Should succeed on Linux and macOS
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(result.is_ok());

        // Should fail on other platforms
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_manager_is_send_sync() {
        let mgr = create_bridge_manager();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let mgr = mgr.unwrap();
            // Test that we can clone the Arc
            let _cloned = Arc::clone(&mgr);
        }
    }
}
