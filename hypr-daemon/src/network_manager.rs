//! Network subsystem coordinator for HYPR daemon.
//!
//! With gvproxy handling port forwarding at the adapter level, this module
//! focuses on IP allocation tracking and service discovery (DNS).

use hypr_core::network::{
    gvproxy, DnsServer, GvproxyPortForward as PortForward, IpAllocator, ServiceRegistry,
    SharedGvproxy,
};
use hypr_core::types::network::Protocol;
use hypr_core::{Result, StateManager};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, instrument};

/// Network manager coordinates networking subsystems.
///
/// With gvproxy, the manager's responsibilities are simplified:
/// - IP allocation tracking (gvproxy uses DHCP but we track for service registry)
/// - Service discovery (DNS for *.hypr domains)
/// - Managing the shared gvproxy instance
///
/// Port forwarding is handled by gvproxy (via shared instance).
pub struct NetworkManager {
    /// IP allocation (uses state manager for persistence)
    ip_allocator: Arc<Mutex<IpAllocator>>,

    /// Service registry (DNS name → IP mapping)
    service_registry: Arc<ServiceRegistry>,

    /// Shared gvproxy instance
    gvproxy: Arc<Mutex<SharedGvproxy>>,

    /// DNS server bind address
    dns_bind_addr: Option<IpAddr>,

    /// State manager for VM lookups
    state: Arc<StateManager>,
}

impl NetworkManager {
    /// Create a new network manager.
    ///
    /// # Network Configuration
    ///
    /// gvproxy provides unified networking for both macOS and Linux:
    /// - Subnet: 192.168.127.0/24
    /// - Gateway: 192.168.127.1
    /// - DHCP: Automatic IP assignment
    /// - Port forwarding: Handled by gvproxy
    #[instrument(skip(state))]
    pub async fn new(state: Arc<StateManager>) -> Result<Self> {
        info!("Initializing network manager (gvproxy mode)");

        // Create IP allocator with state manager
        let ip_allocator = Arc::new(Mutex::new(IpAllocator::new(state.clone())));

        // Create service registry with database pool
        let service_registry = Arc::new(ServiceRegistry::new(state.pool().clone()).await?);

        // Create shared gvproxy instance
        let gvproxy = Arc::new(Mutex::new(SharedGvproxy::new()));

        // DNS binds to localhost on all platforms
        // VMs access DNS through gvproxy's DNS forwarding
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        info!(
            gateway = %gvproxy::defaults::GATEWAY,
            subnet = gvproxy::defaults::CIDR,
            "Network manager initialized (gvproxy unified networking)"
        );

        Ok(Self { ip_allocator, service_registry, gvproxy, dns_bind_addr, state })
    }

    /// Allocates an IP for a VM.
    #[instrument(skip(self))]
    pub async fn allocate_ip(&self, vm_id: &str) -> Result<Ipv4Addr> {
        let allocator = self.ip_allocator.lock().await;
        allocator.allocate(vm_id).await
    }

    /// Releases an IP address.
    #[instrument(skip(self))]
    pub async fn release_ip(&self, vm_id: &str) -> Result<()> {
        let allocator = self.ip_allocator.lock().await;
        allocator.release(vm_id).await
    }

    /// Registers a service in the DNS registry.
    #[instrument(skip(self))]
    pub async fn register_service(
        &self,
        name: &str,
        ip: Ipv4Addr,
        ports: Vec<(u16, Protocol)>,
    ) -> Result<()> {
        let port_numbers: Vec<u16> = ports.iter().map(|(port, _)| *port).collect();
        self.service_registry
            .register(name.to_string(), IpAddr::V4(ip), port_numbers, HashMap::new())
            .await
    }

    /// Unregisters a service.
    #[instrument(skip(self))]
    pub async fn unregister_service(&self, name: &str) -> Result<()> {
        self.service_registry.unregister(name).await
    }

    /// Add a port forwarding rule.
    #[instrument(skip(self))]
    pub async fn add_port_forward(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
        protocol: Protocol,
        vm_id: String,
    ) -> Result<()> {
        info!(
            host_port,
            vm_ip = %vm_ip,
            vm_port,
            protocol = ?protocol,
            vm_id = %vm_id,
            "Adding port forward via gvproxy"
        );

        let forward = PortForward {
            host_port,
            guest_port: vm_port,
            protocol: protocol.to_string().to_lowercase(),
            guest_ip: vm_ip,
        };

        let gv = self.gvproxy.lock().await;
        gv.add_port_forward(forward).await?;

        Ok(())
    }

    /// Remove all port forwarding rules for a VM.
    #[instrument(skip(self))]
    pub async fn remove_vm_port_forwards(&self, vm_id: &str) -> Result<()> {
        info!(vm_id = %vm_id, "Removing port forwarding rules");

        // Get VM config to find ports
        // Note: This relies on VM still being in the database or at least accessible.
        match self.state.get_vm(vm_id).await {
            Ok(vm) => {
                let gv = self.gvproxy.lock().await;

                for port in vm.config.ports {
                    if let Err(e) = gv.remove_port_forward(port.host_port).await {
                        // Log but continue (best effort)
                        error!(
                            vm_id = %vm_id,
                            host_port = port.host_port,
                            error = %e,
                            "Failed to remove port forward"
                        );
                    } else {
                        info!(
                            vm_id = %vm_id,
                            host_port = port.host_port,
                            "Removed port forward"
                        );
                    }
                }
            }
            Err(e) => {
                // If VM is already deleted (e.g. force delete), we can't look up ports to unexpose.
                // In gvproxy, ports persist until process restart or explicit unexpose.
                // Without knowing the ports, we can't unexpose them here.
                tracing::warn!(vm_id = %vm_id, error = %e, "Could not fetch VM to clean up ports (may already be deleted)");
            }
        }
        Ok(())
    }

    /// Start network services (gvproxy and DNS).
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<()> {
        // Start shared gvproxy
        {
            let mut gv = self.gvproxy.lock().await;
            gv.start()?;
        }

        // Start DNS server
        if let Some(bind_ip) = self.dns_bind_addr {
            let registry = self.service_registry.clone();
            // Upstream DNS servers
            let upstream =
                vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];

            tokio::spawn(async move {
                let dns_server = DnsServer::new(bind_ip, 53, registry, upstream);
                info!("Starting DNS server on {}:53", bind_ip);
                if let Err(e) = dns_server.start().await {
                    error!("DNS server failed: {} (service discovery may not work)", e);
                }
            });
        }

        Ok(())
    }

    /// Get the service registry for direct lookups.
    #[allow(dead_code)]
    pub fn service_registry(&self) -> &Arc<ServiceRegistry> {
        &self.service_registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_network_manager() -> (NetworkManager, String) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("hypr-test-{}", id));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("test.db");
        let state = Arc::new(StateManager::new(db_path.to_str().unwrap()).await.unwrap());
        let mgr = NetworkManager::new(state).await.unwrap();
        (mgr, id.to_string())
    }

    #[tokio::test]
    async fn test_network_manager_creation() {
        let (mgr, id) = create_test_network_manager().await;
        // Check ip allocation works
        let vm_name = format!("test-vm-{}", id);
        let ip = mgr.allocate_ip(&vm_name).await.unwrap();
        assert!(!ip.is_unspecified());
    }
}
