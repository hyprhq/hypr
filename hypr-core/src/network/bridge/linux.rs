//! Linux bridge implementation.
//!
//! Uses `ip` command for bridge management and iptables for NAT.

#[cfg(target_os = "linux")]
use super::*;
#[cfg(target_os = "linux")]
use tokio::process::Command;
#[cfg(target_os = "linux")]
use tracing::{info, instrument, warn};

/// Linux bridge manager.
///
/// Manages network bridges using Linux `ip` command and iptables.
#[cfg(target_os = "linux")]
pub struct LinuxBridgeManager;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl BridgeManager for LinuxBridgeManager {
    #[instrument(skip(self), fields(bridge = %config.name))]
    async fn create_bridge(&self, config: &BridgeConfig) -> Result<()> {
        info!("Creating Linux bridge: {}", config.name);

        // Check if bridge already exists
        if self.bridge_exists(&config.name).await? {
            info!("Bridge {} already exists, skipping creation", config.name);
            return Ok(());
        }

        // Create bridge using ip command
        let output = Command::new("ip")
            .args(["link", "add", "name", &config.name, "type", "bridge"])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to create bridge: {}", e),
            })?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        // Set bridge IP
        let ip_with_prefix = format!("{}/10", config.ip);
        let output = Command::new("ip")
            .args(["addr", "add", &ip_with_prefix, "dev", &config.name])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to set bridge IP: {}", e),
            })?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        // Set MTU
        let output = Command::new("ip")
            .args(["link", "set", "dev", &config.name, "mtu", &config.mtu.to_string()])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to set MTU: {}", e),
            })?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        // Bring bridge up
        let output =
            Command::new("ip").args(["link", "set", &config.name, "up"]).output().await.map_err(
                |e| HyprError::NetworkSetupFailed {
                    reason: format!("Failed to bring bridge up: {}", e),
                },
            )?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        info!("Bridge {} created successfully", config.name);
        metrics::counter!("hypr_bridge_created_total").increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %name))]
    async fn delete_bridge(&self, name: &str) -> Result<()> {
        info!("Deleting bridge: {}", name);

        // Check if bridge exists first
        if !self.bridge_exists(name).await? {
            info!("Bridge {} does not exist, skipping deletion", name);
            return Ok(());
        }

        let output =
            Command::new("ip").args(["link", "delete", name]).output().await.map_err(|e| {
                HyprError::NetworkSetupFailed { reason: format!("Failed to delete bridge: {}", e) }
            })?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        info!("Bridge {} deleted successfully", name);
        metrics::counter!("hypr_bridge_deleted_total").increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %name))]
    async fn bridge_exists(&self, name: &str) -> Result<bool> {
        let output =
            Command::new("ip").args(["link", "show", name]).output().await.map_err(|e| {
                HyprError::NetworkSetupFailed {
                    reason: format!("Failed to check bridge existence: {}", e),
                }
            })?;

        Ok(output.status.success())
    }

    #[instrument(skip(self))]
    async fn enable_ip_forward(&self) -> Result<()> {
        info!("Enabling IP forwarding");

        // Check current setting
        let output =
            Command::new("sysctl").args(["net.ipv4.ip_forward"]).output().await.map_err(|e| {
                HyprError::NetworkSetupFailed {
                    reason: format!("Failed to check IP forwarding: {}", e),
                }
            })?;

        let current_value = String::from_utf8_lossy(&output.stdout);
        if current_value.contains("= 1") {
            info!("IP forwarding already enabled");
            return Ok(());
        }

        // Enable IP forwarding
        let output =
            Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output().await.map_err(
                |e| HyprError::NetworkSetupFailed {
                    reason: format!("Failed to enable IP forwarding: {}", e),
                },
            )?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        info!("IP forwarding enabled");
        metrics::counter!("hypr_ip_forward_enabled_total").increment(1);

        Ok(())
    }

    #[instrument(skip(self), fields(bridge = %bridge_name))]
    async fn setup_nat(&self, bridge_name: &str) -> Result<()> {
        info!("Setting up NAT for bridge");

        // Detect default network interface
        let default_iface = self.detect_default_interface().await?;
        info!("Using default interface: {}", default_iface);

        // Check if MASQUERADE rule exists
        let output = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "-o",
                &default_iface,
                "-j",
                "MASQUERADE",
            ])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to check NAT rule: {}", e),
            })?;

        // Rule exists if command succeeds
        if !output.status.success() {
            // Add the MASQUERADE rule
            let output = Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    "100.64.0.0/10",
                    "-o",
                    &default_iface,
                    "-j",
                    "MASQUERADE",
                ])
                .output()
                .await
                .map_err(|e| HyprError::NetworkSetupFailed {
                    reason: format!("Failed to add NAT rule: {}", e),
                })?;

            if !output.status.success() {
                return Err(HyprError::NetworkSetupFailed {
                    reason: String::from_utf8_lossy(&output.stderr).to_string(),
                });
            }

            info!("NAT MASQUERADE rule added");
        } else {
            info!("NAT MASQUERADE rule already exists");
        }

        // Allow forwarding from bridge
        let output = Command::new("iptables")
            .args(["-C", "FORWARD", "-i", bridge_name, "-j", "ACCEPT"])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to check FORWARD rule: {}", e),
            })?;

        if !output.status.success() {
            Command::new("iptables")
                .args(["-A", "FORWARD", "-i", bridge_name, "-j", "ACCEPT"])
                .output()
                .await
                .map_err(|e| HyprError::NetworkSetupFailed {
                    reason: format!("Failed to add FORWARD rule: {}", e),
                })?;

            info!("Added FORWARD rule for incoming traffic");
        }

        // Allow forwarding to bridge
        let output = Command::new("iptables")
            .args(["-C", "FORWARD", "-o", bridge_name, "-j", "ACCEPT"])
            .output()
            .await
            .map_err(|e| HyprError::NetworkSetupFailed {
                reason: format!("Failed to check FORWARD rule: {}", e),
            })?;

        if !output.status.success() {
            Command::new("iptables")
                .args(["-A", "FORWARD", "-o", bridge_name, "-j", "ACCEPT"])
                .output()
                .await
                .map_err(|e| HyprError::NetworkSetupFailed {
                    reason: format!("Failed to add FORWARD rule: {}", e),
                })?;

            info!("Added FORWARD rule for outgoing traffic");
        }

        info!("NAT setup completed for bridge {}", bridge_name);
        metrics::counter!("hypr_nat_configured_total").increment(1);

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl LinuxBridgeManager {
    /// Detect the default network interface.
    ///
    /// Uses `ip route` to find the interface used for default route.
    #[instrument(skip(self))]
    async fn detect_default_interface(&self) -> Result<String> {
        let output =
            Command::new("ip").args(["route", "show", "default"]).output().await.map_err(|e| {
                HyprError::NetworkSetupFailed {
                    reason: format!("Failed to detect default interface: {}", e),
                }
            })?;

        if !output.status.success() {
            return Err(HyprError::NetworkSetupFailed {
                reason: "Failed to get default route".to_string(),
            });
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse output: "default via 192.168.1.1 dev eth0 ..."
        for line in output_str.lines() {
            if line.starts_with("default") {
                if let Some(dev_pos) = line.find(" dev ") {
                    let after_dev = &line[dev_pos + 5..];
                    if let Some(iface) = after_dev.split_whitespace().next() {
                        return Ok(iface.to_string());
                    }
                }
            }
        }

        // Fallback to eth0
        warn!("Could not detect default interface, falling back to eth0");
        Ok("eth0".to_string())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_exists_check() {
        let mgr = LinuxBridgeManager;

        // Check a non-existent bridge
        let result = mgr.bridge_exists("nonexistent_bridge_xyz").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_detect_default_interface() {
        let mgr = LinuxBridgeManager;
        let result = mgr.detect_default_interface().await;

        // Should succeed and return a non-empty interface name
        assert!(result.is_ok());
        let iface = result.unwrap();
        assert!(!iface.is_empty());
    }

    #[test]
    fn test_linux_bridge_manager_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<LinuxBridgeManager>();
        assert_sync::<LinuxBridgeManager>();
    }
}
