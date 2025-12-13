//! Network subsystem coordinator for HYPR daemon.
//!
//! With gvproxy handling port forwarding at the adapter level, this module
//! focuses on IP allocation tracking and service discovery (DNS).

use hypr_core::network::{gvproxy, DnsServer, IpAllocator, ServiceRegistry};
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
///
/// Port forwarding is handled by gvproxy at the adapter level.
pub struct NetworkManager {
    /// IP allocation (uses state manager for persistence)
    ip_allocator: Arc<Mutex<IpAllocator>>,

    /// Service registry (DNS name → IP mapping)
    service_registry: Arc<ServiceRegistry>,

    /// DNS server bind address
    dns_bind_addr: Option<IpAddr>,
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
    /// - Port forwarding: Handled by gvproxy (no eBPF needed)
    #[instrument(skip(state))]
    pub async fn new(state: Arc<StateManager>) -> Result<Self> {
        info!("Initializing network manager (gvproxy mode)");

        // Create IP allocator with state manager
        let ip_allocator = Arc::new(Mutex::new(IpAllocator::new(state.clone())));

        // Create service registry with database pool
        let service_registry = Arc::new(ServiceRegistry::new(state.pool().clone()).await?);

        // DNS binds to localhost on all platforms
        // VMs access DNS through gvproxy's DNS forwarding
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        info!(
            gateway = %gvproxy::defaults::GATEWAY,
            subnet = gvproxy::defaults::CIDR,
            "Network manager initialized (gvproxy unified networking)"
        );

        Ok(Self { ip_allocator, service_registry, dns_bind_addr })
    }

    /// Allocate an IP address for a VM.
    ///
    /// Note: gvproxy assigns IPs via DHCP, but we track allocations
    /// for service registry purposes.
    #[instrument(skip(self))]
    pub async fn allocate_ip(&self, vm_id: &str) -> Result<Ipv4Addr> {
        let allocator = self.ip_allocator.lock().await;
        allocator.allocate(vm_id).await
    }

    /// Release an IP address when a VM is deleted.
    #[instrument(skip(self))]
    pub async fn release_ip(&self, vm_id: &str) -> Result<()> {
        let allocator = self.ip_allocator.lock().await;
        allocator.release(vm_id).await
    }

    /// Register a service in the DNS registry.
    ///
    /// Makes the service discoverable via `{name}.hypr` DNS queries.
    #[instrument(skip(self))]
    pub async fn register_service(
        &self,
        name: &str,
        ip: Ipv4Addr,
        ports: Vec<(u16, Protocol)>,
    ) -> Result<()> {
        // Extract just the port numbers
        let port_numbers: Vec<u16> = ports.iter().map(|(port, _)| *port).collect();

        self.service_registry
            .register(name.to_string(), IpAddr::V4(ip), port_numbers, HashMap::new())
            .await
    }

    /// Unregister a service from the DNS registry.
    #[instrument(skip(self))]
    pub async fn unregister_service(&self, name: &str) -> Result<()> {
        self.service_registry.unregister(name).await
    }

    /// Add a port forwarding rule.
    ///
    /// Note: With gvproxy, port forwarding is handled at the adapter level during VM creation.
    /// This method is kept for API compatibility but the actual port forwards are configured
    /// when the VM starts via gvproxy's initial configuration.
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
            "Port forward tracked (actual forwarding handled by gvproxy)"
        );
        // gvproxy handles port forwarding at VM creation time
        // Dynamic port forwards would require gvproxy HTTP API integration
        Ok(())
    }

    /// Remove all port forwarding rules for a VM.
    ///
    /// Note: With gvproxy, port forwards are automatically cleaned up when gvproxy stops.
    #[instrument(skip(self))]
    pub async fn remove_vm_port_forwards(&self, vm_id: &str) -> Result<()> {
        info!(vm_id = %vm_id, "Port forwards removed (gvproxy cleanup)");
        // gvproxy automatically cleans up when it stops
        Ok(())
    }

    /// Start the DNS server for service discovery.
    ///
    /// The DNS server resolves `*.hypr` domains to VM IPs.
    /// Non-.hypr queries are forwarded to upstream DNS servers.
    #[instrument(skip(self))]
    pub fn start_dns_server(&self) {
        if let Some(bind_ip) = self.dns_bind_addr {
            let registry = self.service_registry.clone();

            // Upstream DNS servers for non-.hypr queries
            let upstream =
                vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];

            tokio::spawn(async move {
                let dns_server = DnsServer::new(bind_ip, 53, registry, upstream);

                info!("Starting DNS server on {}:53", bind_ip);
                if let Err(e) = dns_server.start().await {
                    error!("DNS server failed: {} (service discovery may not work)", e);
                }
            });
        } else {
            info!("DNS server disabled (no bind address configured)");
        }
    }

    /// Get the service registry for direct lookups.
    #[allow(dead_code)] // May be used in future for direct registry access
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
        let vm_name = format!("test-vm-{}", id);
        let ip = mgr.allocate_ip(&vm_name).await.unwrap();
        assert!(!ip.is_unspecified());
        mgr.release_ip(&vm_name).await.unwrap();
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let (mgr, id) = create_test_network_manager().await;

        let ip1 = mgr.allocate_ip(&format!("vm-1-{}", id)).await.unwrap();
        let ip2 = mgr.allocate_ip(&format!("vm-2-{}", id)).await.unwrap();

        // IPs should be different
        assert_ne!(ip1, ip2);

        // Release
        mgr.release_ip(&format!("vm-1-{}", id)).await.unwrap();
        mgr.release_ip(&format!("vm-2-{}", id)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_service_registration() {
        let (mgr, id) = create_test_network_manager().await;
        let vm_name = format!("web-vm-{}", id);

        let vm_ip = mgr.allocate_ip(&vm_name).await.unwrap();

        // Register service
        let svc_name = format!("web-{}", id);
        let result = mgr
            .register_service(&svc_name, vm_ip, vec![(80, Protocol::Tcp), (443, Protocol::Tcp)])
            .await;
        assert!(result.is_ok());

        // Lookup service
        let service = mgr.service_registry.lookup(&svc_name).await.unwrap();
        assert_eq!(service.ip, vm_ip);
        assert_eq!(service.ports.len(), 2);

        // Unregister
        mgr.unregister_service(&svc_name).await.unwrap();

        // Should be gone
        assert!(mgr.service_registry.lookup(&svc_name).await.is_none());

        // Cleanup
        mgr.release_ip(&vm_name).await.unwrap();
    }
}
