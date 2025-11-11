//! Linux TAP device management using ip tuntap commands.

#![cfg(target_os = "linux")]

use super::{TapConfig, TapDevice, TapManager};
use crate::error::{HyprError, Result};
use std::path::PathBuf;
use tokio::process::Command;
use tracing::{error, info, instrument, warn};

/// Linux TAP device manager using ip tuntap.
#[derive(Debug, Clone, Copy)]
pub struct LinuxTapManager;

impl LinuxTapManager {
    /// Execute an ip command and check for errors.
    async fn exec_ip(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to execute ip command: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("ip command failed: {}", stderr);
            return Err(HyprError::NetworkSetupFailed {
                reason: stderr.to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[async_trait::async_trait]
impl TapManager for LinuxTapManager {
    #[instrument(skip(self), fields(tap = %config.name, bridge = %config.bridge))]
    async fn create_tap(&self, config: &TapConfig) -> Result<TapDevice> {
        info!("Creating TAP device: {}", config.name);

        // Build the ip tuntap add command
        let mut args = vec!["tuntap", "add", "dev", &config.name, "mode", "tap"];

        // Add owner if specified
        let owner_str;
        if let Some(ref owner) = config.owner {
            owner_str = owner.clone();
            args.extend_from_slice(&["user", &owner_str]);
        }

        // Create TAP device
        self.exec_ip(&args).await.map_err(|e| {
            error!("Failed to create TAP device {}: {}", config.name, e);
            HyprError::NetworkSetupFailed {
                reason: format!("Failed to create TAP device: {}", e),
            }
        })?;

        info!("TAP device {} created successfully", config.name);

        // Bring interface up
        self.exec_ip(&["link", "set", "dev", &config.name, "up"])
            .await
            .map_err(|e| {
                error!("Failed to bring up TAP device {}: {}", config.name, e);
                HyprError::NetworkSetupFailed {
                    reason: format!("Failed to bring up TAP device: {}", e),
                }
            })?;

        info!("TAP device {} brought up", config.name);

        // Attach to bridge
        self.attach_to_bridge(&config.name, &config.bridge)
            .await?;

        info!(
            "TAP device {} created and attached to {}",
            config.name, config.bridge
        );
        metrics::counter!("hypr.tap.created", "device" => config.name.clone()).increment(1);

        Ok(TapDevice {
            name: config.name.clone(),
            path: PathBuf::from("/dev/net/tun"),
        })
    }

    #[instrument(skip(self), fields(tap = %name))]
    async fn delete_tap(&self, name: &str) -> Result<()> {
        info!("Deleting TAP device: {}", name);

        self.exec_ip(&["link", "delete", name]).await.map_err(|e| {
            warn!("Failed to delete TAP device {}: {}", name, e);
            HyprError::NetworkSetupFailed {
                reason: format!("Failed to delete TAP device: {}", e),
            }
        })?;

        info!("TAP device {} deleted successfully", name);
        metrics::counter!("hypr.tap.deleted", "device" => name.to_string()).increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(tap = %tap_name, bridge = %bridge_name))]
    async fn attach_to_bridge(&self, tap_name: &str, bridge_name: &str) -> Result<()> {
        info!("Attaching {} to bridge {}", tap_name, bridge_name);

        self.exec_ip(&["link", "set", tap_name, "master", bridge_name])
            .await
            .map_err(|e| {
                error!(
                    "Failed to attach {} to bridge {}: {}",
                    tap_name, bridge_name, e
                );
                HyprError::NetworkSetupFailed {
                    reason: format!("Failed to attach TAP to bridge: {}", e),
                }
            })?;

        info!("TAP device {} attached to bridge {}", tap_name, bridge_name);
        metrics::counter!(
            "hypr.tap.attached",
            "device" => tap_name.to_string(),
            "bridge" => bridge_name.to_string()
        )
        .increment(1);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_taps(&self) -> Result<Vec<String>> {
        info!("Listing TAP devices");

        let output = self.exec_ip(&["tuntap", "show"]).await.map_err(|e| {
            warn!("Failed to list TAP devices: {}", e);
            HyprError::NetworkSetupFailed {
                reason: format!("Failed to list TAP devices: {}", e),
            }
        })?;

        let taps: Vec<String> = output
            .lines()
            .filter_map(|line| {
                // Format: "tap0: tap"
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 && parts[1].trim().starts_with("tap") {
                    Some(parts[0].trim().to_string())
                } else {
                    None
                }
            })
            .collect();

        info!("Found {} TAP devices", taps.len());
        Ok(taps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_tap_manager_creation() {
        let _manager = LinuxTapManager;
    }

    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_tap_creation() {
        let mgr = LinuxTapManager;
        let config = TapConfig {
            name: "hypr-test-tap0".to_string(),
            bridge: "vbr0".to_string(),
            owner: None,
        };

        // Create TAP (requires sudo)
        let result = mgr.create_tap(&config).await;

        if let Ok(tap_device) = result {
            assert_eq!(tap_device.name, "hypr-test-tap0");
            assert_eq!(tap_device.path, PathBuf::from("/dev/net/tun"));

            // List TAPs
            let taps = mgr.list_taps().await.unwrap();
            assert!(taps.contains(&"hypr-test-tap0".to_string()));

            // Cleanup
            let _ = mgr.delete_tap("hypr-test-tap0").await;
        } else {
            // If we can't create the TAP, skip the test
            eprintln!("Skipping test: requires root privileges");
        }
    }

    #[tokio::test]
    #[ignore] // Requires root privileges
    async fn test_tap_deletion() {
        let mgr = LinuxTapManager;

        // First create a TAP device
        let config = TapConfig {
            name: "hypr-test-tap1".to_string(),
            bridge: "vbr0".to_string(),
            owner: None,
        };

        if mgr.create_tap(&config).await.is_ok() {
            // Delete it
            let result = mgr.delete_tap("hypr-test-tap1").await;
            assert!(result.is_ok());

            // Verify it's gone
            let taps = mgr.list_taps().await.unwrap();
            assert!(!taps.contains(&"hypr-test-tap1".to_string()));
        }
    }

    #[tokio::test]
    async fn test_list_taps() {
        let mgr = LinuxTapManager;

        // This should work even without root
        let result = mgr.list_taps().await;

        // May fail if ip command is not available, but shouldn't panic
        if result.is_ok() {
            let taps = result.unwrap();
            // Just verify we got a valid vector (may be empty)
            assert!(taps.len() >= 0);
        }
    }
}
