//! macOS vmnet interface management.
//!
//! On macOS, network interfaces are managed through vmnet framework.
//! The actual vmnet interface creation is handled by the hypervisor (vfkit),
//! so this implementation is primarily a pass-through.

#![cfg(target_os = "macos")]

use super::{TapConfig, TapDevice, TapManager};
use crate::error::Result;
use std::path::PathBuf;
use tracing::{info, instrument};

/// macOS TAP device manager using vmnet framework.
///
/// Note: On macOS, vmnet interfaces are created and managed by the hypervisor.
/// This manager provides a compatible interface but doesn't directly create
/// kernel interfaces.
#[derive(Debug, Clone, Copy)]
pub struct MacOSTapManager;

#[async_trait::async_trait]
impl TapManager for MacOSTapManager {
    #[instrument(skip(self), fields(tap = %config.name))]
    async fn create_tap(&self, config: &TapConfig) -> Result<TapDevice> {
        info!("Creating macOS vmnet interface: {}", config.name);

        // On macOS, vmnet interfaces are created by vfkit when the VM starts.
        // We don't manage them directly through system calls.
        // This is a placeholder that returns a valid TapDevice handle.

        info!("vmnet interface {} registered", config.name);
        metrics::counter!("hypr.tap.created", "device" => config.name.clone(), "platform" => "macos")
            .increment(1);

        Ok(TapDevice {
            name: config.name.clone(),
            path: PathBuf::from("/dev/vmnet0"), // Virtual path for compatibility
        })
    }

    #[instrument(skip(self), fields(tap = %name))]
    async fn delete_tap(&self, name: &str) -> Result<()> {
        info!("Deleting macOS vmnet interface: {}", name);

        // On macOS, vmnet cleanup is automatic when the VM terminates.
        // No explicit cleanup needed.

        info!("vmnet interface {} cleanup complete", name);
        metrics::counter!("hypr.tap.deleted", "device" => name.to_string(), "platform" => "macos")
            .increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(tap = %tap_name, bridge = %bridge_name))]
    async fn attach_to_bridge(&self, tap_name: &str, bridge_name: &str) -> Result<()> {
        info!(
            "Attaching vmnet interface {} to bridge {}",
            tap_name, bridge_name
        );

        // On macOS, vmnet handles bridge attachment automatically
        // through the shared or bridged mode configuration.

        info!(
            "vmnet interface {} bridge attachment configured",
            tap_name
        );
        metrics::counter!(
            "hypr.tap.attached",
            "device" => tap_name.to_string(),
            "bridge" => bridge_name.to_string(),
            "platform" => "macos"
        )
        .increment(1);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_taps(&self) -> Result<Vec<String>> {
        info!("Listing macOS vmnet interfaces");

        // On macOS, vmnet interfaces are ephemeral and managed by the hypervisor.
        // We don't maintain a persistent list of interfaces.

        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_tap_manager_creation() {
        let _manager = MacOSTapManager;
    }

    #[tokio::test]
    async fn test_tap_creation() {
        let mgr = MacOSTapManager;
        let config = TapConfig {
            name: "vmnet0".to_string(),
            bridge: "bridge0".to_string(),
            owner: None,
        };

        let result = mgr.create_tap(&config).await;
        assert!(result.is_ok());

        let tap_device = result.unwrap();
        assert_eq!(tap_device.name, "vmnet0");
        assert_eq!(tap_device.path, PathBuf::from("/dev/vmnet0"));
    }

    #[tokio::test]
    async fn test_tap_deletion() {
        let mgr = MacOSTapManager;

        let result = mgr.delete_tap("vmnet0").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_attach_to_bridge() {
        let mgr = MacOSTapManager;

        let result = mgr.attach_to_bridge("vmnet0", "bridge0").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_taps() {
        let mgr = MacOSTapManager;

        let result = mgr.list_taps().await;
        assert!(result.is_ok());

        let taps = result.unwrap();
        assert_eq!(taps.len(), 0); // macOS doesn't list vmnet interfaces
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let mgr = MacOSTapManager;

        // Create
        let config = TapConfig {
            name: "vmnet1".to_string(),
            bridge: "bridge0".to_string(),
            owner: None,
        };

        let create_result = mgr.create_tap(&config).await;
        assert!(create_result.is_ok());

        let tap_device = create_result.unwrap();
        assert_eq!(tap_device.name, "vmnet1");

        // Attach to bridge
        let attach_result = mgr.attach_to_bridge(&tap_device.name, "bridge0").await;
        assert!(attach_result.is_ok());

        // Delete
        let delete_result = mgr.delete_tap(&tap_device.name).await;
        assert!(delete_result.is_ok());
    }
}
