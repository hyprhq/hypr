//! macOS bridge implementation.
//!
//! Delegates to vmnet framework via vfkit.

#[cfg(target_os = "macos")]
use super::*;

#[cfg(target_os = "macos")]
use tracing::{info, instrument, warn};

/// macOS bridge manager.
///
/// On macOS, network bridging is handled by the vmnet framework through vfkit.
/// This manager provides a compatibility layer that acknowledges the framework's
/// automatic handling of bridge creation and NAT.
#[cfg(target_os = "macos")]
pub struct MacOSBridgeManager;

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl BridgeManager for MacOSBridgeManager {
    #[instrument(skip(self), fields(bridge = %config.name))]
    async fn create_bridge(&self, config: &BridgeConfig) -> Result<()> {
        info!("Creating macOS bridge using vmnet framework");
        info!("Bridge configuration: name={}, ip={}, mtu={}", config.name, config.ip, config.mtu);

        // On macOS, we use vmnet framework instead of manual bridge
        // The actual bridge is created by vfkit/hypervisor framework
        warn!("macOS bridge creation delegated to vmnet framework");
        warn!("Ensure vfkit is configured with --net-mode vmnet");

        metrics::counter!("hypr_bridge_created_total").increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %name))]
    async fn delete_bridge(&self, name: &str) -> Result<()> {
        info!("Deleting macOS bridge: {}", name);

        // vmnet cleanup is automatic
        warn!("macOS bridge deletion handled automatically by vmnet");

        metrics::counter!("hypr_bridge_deleted_total").increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %name))]
    async fn bridge_exists(&self, name: &str) -> Result<bool> {
        info!("Checking if macOS bridge exists: {}", name);

        // vmnet is always available if vfkit is installed
        // We assume the bridge is always available in vmnet mode
        Ok(true)
    }

    #[instrument(skip(self))]
    async fn enable_ip_forward(&self) -> Result<()> {
        info!("IP forwarding on macOS");

        // Not needed on macOS with vmnet
        // vmnet handles packet forwarding automatically
        warn!("IP forwarding handled automatically by vmnet framework");

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %bridge_name))]
    async fn setup_nat(&self, bridge_name: &str) -> Result<()> {
        info!("Setting up NAT for macOS bridge: {}", bridge_name);

        // vmnet handles NAT automatically
        warn!("NAT configuration handled automatically by vmnet framework");

        metrics::counter!("hypr_nat_configured_total").increment(1);

        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_macos_bridge_exists() {
        let mgr = MacOSBridgeManager;
        let result = mgr.bridge_exists("vbr0").await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_macos_bridge_lifecycle() {
        let mgr = MacOSBridgeManager;
        let config = BridgeConfig::default();

        // Create bridge (should always succeed)
        let result = mgr.create_bridge(&config).await;
        assert!(result.is_ok());

        // Check existence
        let exists = mgr.bridge_exists(&config.name).await;
        assert!(exists.is_ok());
        assert!(exists.unwrap());

        // Enable IP forward
        let result = mgr.enable_ip_forward().await;
        assert!(result.is_ok());

        // Setup NAT
        let result = mgr.setup_nat(&config.name).await;
        assert!(result.is_ok());

        // Delete bridge
        let result = mgr.delete_bridge(&config.name).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_macos_bridge_manager_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<MacOSBridgeManager>();
        assert_sync::<MacOSBridgeManager>();
    }
}
