//! Graceful shutdown handling for hyprd.
//!
//! Provides coordinated shutdown of all running VMs and cleanup of resources
//! when the daemon receives SIGTERM or SIGINT.

use hypr_core::adapters::VmmAdapter;
use hypr_core::{StateManager, VmStatus};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::network_manager::NetworkManager;

/// Manages graceful shutdown of the daemon.
pub struct ShutdownManager {
    state: Arc<StateManager>,
    adapter: Arc<dyn VmmAdapter>,
    network_mgr: Arc<NetworkManager>,
    /// Timeout for graceful VM shutdown before force kill
    graceful_timeout: Duration,
}

impl ShutdownManager {
    /// Create a new shutdown manager.
    pub fn new(
        state: Arc<StateManager>,
        adapter: Arc<dyn VmmAdapter>,
        network_mgr: Arc<NetworkManager>,
    ) -> Self {
        Self { state, adapter, network_mgr, graceful_timeout: Duration::from_secs(30) }
    }

    /// Perform graceful shutdown of all VMs and cleanup resources.
    ///
    /// This method:
    /// 1. Lists all running VMs
    /// 2. Attempts graceful stop with timeout
    /// 3. Force kills VMs that don't stop gracefully
    /// 4. Cleans up network resources (port forwards, DNS)
    /// 5. Updates VM state in database
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting graceful shutdown...");

        // Get all VMs
        let vms = match self.state.list_vms().await {
            Ok(vms) => vms,
            Err(e) => {
                error!("Failed to list VMs for shutdown: {}", e);
                return Err(e.into());
            }
        };

        let running_vms: Vec<_> = vms
            .into_iter()
            .filter(|vm| vm.status == VmStatus::Running || vm.status == VmStatus::Creating)
            .collect();

        if running_vms.is_empty() {
            info!("No running VMs to stop");
        } else {
            info!("Stopping {} running VM(s)...", running_vms.len());
        }

        // Stop each VM
        for vm in running_vms {
            info!("Stopping VM {} ({})...", vm.name, vm.id);

            let handle = hypr_core::VmHandle { id: vm.id.clone(), pid: vm.pid, socket_path: None };

            // Try graceful stop first
            match tokio::time::timeout(
                self.graceful_timeout,
                self.adapter.stop(&handle, self.graceful_timeout),
            )
            .await
            {
                Ok(Ok(())) => {
                    info!("VM {} stopped gracefully", vm.name);
                }
                Ok(Err(e)) => {
                    warn!("Graceful stop failed for VM {}: {}, force killing...", vm.name, e);
                    if let Err(e) = self.adapter.kill(&handle).await {
                        error!("Failed to kill VM {}: {}", vm.name, e);
                    }
                }
                Err(_) => {
                    warn!("Graceful stop timed out for VM {}, force killing...", vm.name);
                    if let Err(e) = self.adapter.kill(&handle).await {
                        error!("Failed to kill VM {}: {}", vm.name, e);
                    }
                }
            }

            // Clean up network resources
            if let Err(e) = self.network_mgr.remove_vm_port_forwards(&vm.id).await {
                warn!("Failed to remove port forwards for VM {}: {}", vm.name, e);
            }

            let service_name = if !vm.name.is_empty() { &vm.name } else { &vm.id };
            if let Err(e) = self.network_mgr.unregister_service(service_name).await {
                warn!("Failed to unregister DNS for VM {}: {}", vm.name, e);
            }

            if let Err(e) = self.network_mgr.release_ip(&vm.id).await {
                warn!("Failed to release IP for VM {}: {}", vm.name, e);
            }

            // Update VM status in database
            if let Err(e) = self.state.update_vm_status(&vm.id, VmStatus::Stopped).await {
                warn!("Failed to update VM {} status: {}", vm.name, e);
            }

            // Clean up VM via adapter (removes VFIO bindings, etc.)
            if let Err(e) = self.adapter.delete(&handle).await {
                warn!("Failed to cleanup VM {}: {}", vm.name, e);
            }
        }

        // Clean up host DNS resolver configuration
        if let Err(e) = cleanup_host_dns_resolver().await {
            warn!("Failed to cleanup host DNS resolver: {}", e);
        }

        info!("Graceful shutdown complete");
        Ok(())
    }
}

/// Clean up host DNS resolver configuration.
///
/// On macOS: Removes /etc/resolver/hypr
/// On Linux: Removes systemd-resolved configuration
async fn cleanup_host_dns_resolver() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "macos")]
    {
        let resolver_path = std::path::Path::new("/etc/resolver/hypr");
        if resolver_path.exists() {
            info!("Removing /etc/resolver/hypr...");
            if let Err(e) = std::fs::remove_file(resolver_path) {
                // May fail if not root - that's ok, it will be cleaned up next run
                warn!("Could not remove /etc/resolver/hypr: {} (may require sudo)", e);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Try to remove systemd-resolved configuration
        let resolved_conf = std::path::Path::new("/etc/systemd/resolved.conf.d/hypr.conf");
        if resolved_conf.exists() {
            info!("Removing systemd-resolved configuration...");
            if let Err(e) = std::fs::remove_file(resolved_conf) {
                warn!("Could not remove systemd-resolved config: {} (may require sudo)", e);
            } else {
                // Restart systemd-resolved to pick up the change
                let _ = std::process::Command::new("systemctl")
                    .args(["restart", "systemd-resolved"])
                    .status();
            }
        }
    }

    Ok(())
}

/// Create a shutdown signal receiver.
///
/// Returns a broadcast receiver that will receive a signal when
/// SIGTERM, SIGINT, or SIGHUP is received.
pub fn shutdown_signal() -> broadcast::Receiver<()> {
    let (tx, rx) = broadcast::channel(1);

    tokio::spawn(async move {
        let ctrl_c = async {
            tokio::signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received SIGINT (Ctrl+C)");
            }
            _ = terminate => {
                info!("Received SIGTERM");
            }
        }

        let _ = tx.send(());
    });

    rx
}
