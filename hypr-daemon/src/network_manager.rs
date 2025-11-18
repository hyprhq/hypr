//! Network subsystem coordinator for HYPR daemon.
//!
//! Manages all networking concerns: IP allocation, port forwarding, DNS, and service registry.

use hypr_core::network::{IpAllocator, PortForwarder, PortMapping, ProxyForwarder, ServiceRegistry};
use hypr_core::types::network::Protocol;
use hypr_core::{Result, StateManager};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, instrument};

#[cfg(target_os = "linux")]
use hypr_core::network::EbpfForwarder;

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use tracing::warn;

/// Network manager coordinates all networking subsystems.
pub struct NetworkManager {
    /// IP allocation (uses state manager for persistence)
    ip_allocator: Arc<Mutex<IpAllocator>>,

    /// Port forwarding (platform-specific)
    port_forwarder: Arc<PortForwarder>,

    /// Service registry (DNS name → IP mapping)
    service_registry: Arc<ServiceRegistry>,

    /// DNS server bind address (optional - not started yet)
    #[allow(dead_code)]
    dns_bind_addr: Option<IpAddr>,
}

impl NetworkManager {
    /// Create a new network manager.
    ///
    /// # Platform-specific behavior
    ///
    /// ## IP Allocation
    /// - **Linux**: Uses 100.64.0.0/10 IP pool (gateway: 100.64.0.1)
    /// - **macOS**: Uses 192.168.64.0/24 IP pool (gateway: 192.168.64.1, vmnet default)
    ///
    /// ## Port Forwarding
    /// - **Linux**: Attempts eBPF (10+ Gbps), falls back to userspace proxy (1 Gbps) if:
    ///   - eBPF programs not found at /usr/local/lib/hypr/
    ///   - Missing CAP_BPF capability or root privileges
    ///   - Network bridge interface (vbr0) not found
    /// - **macOS/Other**: Uses userspace proxy (1 Gbps, no special permissions)
    #[instrument(skip(state))]
    pub async fn new(state: Arc<StateManager>) -> Result<Self> {
        info!("Initializing network manager");

        // Create IP allocator with state manager
        let ip_allocator = Arc::new(Mutex::new(IpAllocator::new(state.clone())));

        // Platform-specific port forwarding initialization
        // Linux: Try eBPF (10+ Gbps), fallback to proxy (1 Gbps)
        // macOS: Use proxy (1 Gbps, no eBPF support)
        #[cfg(target_os = "linux")]
        let port_forwarder = {
            match try_ebpf_forwarder() {
                Ok(ebpf) => {
                    info!("Using eBPF port forwarding (10+ Gbps)");
                    Arc::new(PortForwarder::new(Arc::new(ebpf)))
                }
                Err(e) => {
                    warn!("eBPF unavailable ({}), falling back to userspace proxy", e);
                    let proxy = ProxyForwarder::new();
                    Arc::new(PortForwarder::new(Arc::new(proxy)))
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let port_forwarder = {
            info!("Using userspace proxy for port forwarding");
            let proxy = ProxyForwarder::new();
            Arc::new(PortForwarder::new(Arc::new(proxy)))
        };

        // Create service registry with database pool
        let service_registry = Arc::new(ServiceRegistry::new(state.pool().clone()).await?);

        // DNS bind address (not started yet, will be started in Phase 2A.2)
        #[cfg(target_os = "macos")]
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 64, 1)));

        #[cfg(target_os = "linux")]
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let dns_bind_addr = None;

        info!("Network manager initialized successfully");

        Ok(Self { ip_allocator, port_forwarder, service_registry, dns_bind_addr })
    }

    /// Allocate an IP address for a VM.
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

    /// Add a port forwarding rule.
    ///
    /// Maps host:host_port -> vm_ip:vm_port using the platform-specific forwarder.
    #[instrument(skip(self))]
    pub async fn add_port_forward(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
        protocol: Protocol,
        vm_id: String,
    ) -> Result<()> {
        self.port_forwarder.add_mapping_with_vm(host_port, vm_ip, vm_port, protocol, vm_id)
    }

    /// Remove a port forwarding rule.
    #[allow(dead_code)] // Will be used when we add explicit port management
    #[instrument(skip(self))]
    pub async fn remove_port_forward(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        self.port_forwarder.remove_mapping(host_port, protocol)
    }

    /// Remove all port forwarding rules for a specific VM.
    #[instrument(skip(self))]
    pub async fn remove_vm_port_forwards(&self, vm_id: &str) -> Result<()> {
        self.port_forwarder.remove_vm_mappings(vm_id)
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
        // Extract just the port numbers (ServiceRegistry only needs port numbers, not protocols)
        let port_numbers: Vec<u16> = ports.iter().map(|(port, _)| *port).collect();

        // ServiceRegistry.register takes individual params, not a ServiceInfo struct
        self.service_registry
            .register(name.to_string(), IpAddr::V4(ip), port_numbers, HashMap::new())
            .await
    }

    /// Unregister a service from the DNS registry.
    #[instrument(skip(self))]
    pub async fn unregister_service(&self, name: &str) -> Result<()> {
        self.service_registry.unregister(name).await
    }

    /// Get all active port mappings (for debugging/status).
    #[allow(dead_code)]
    pub fn list_port_mappings(&self) -> Vec<PortMapping> {
        self.port_forwarder.list_mappings()
    }
}

/// Try to initialize eBPF forwarder (Linux only).
///
/// This requires:
/// 1. Compiled eBPF programs (drift_l4_ingress.o, drift_l4_egress.o)
/// 2. CAP_BPF capability or root privileges
/// 3. Network bridge interface (vbr0, br0, etc.)
///
/// If any requirement is missing, returns error and caller should fallback to proxy.
#[cfg(target_os = "linux")]
fn try_ebpf_forwarder() -> Result<EbpfForwarder> {
    // Paths to compiled eBPF programs
    // TODO: Make these configurable or embed in binary
    let ingress = PathBuf::from("/usr/local/lib/hypr/drift_l4_ingress.o");
    let egress = PathBuf::from("/usr/local/lib/hypr/drift_l4_egress.o");

    // Check if eBPF programs exist
    if !ingress.exists() {
        return Err(hypr_core::error::HyprError::InvalidConfig {
            reason: format!(
                "eBPF ingress program not found at {}. Run 'make' in hypr-core/ebpf/ and install to /usr/local/lib/hypr/",
                ingress.display()
            ),
        });
    }

    if !egress.exists() {
        return Err(hypr_core::error::HyprError::InvalidConfig {
            reason: format!(
                "eBPF egress program not found at {}. Run 'make' in hypr-core/ebpf/ and install to /usr/local/lib/hypr/",
                egress.display()
            ),
        });
    }

    // TODO: Auto-detect bridge interface
    // For now, assume vbr0 (standard HYPR bridge)
    // Future: Check if vbr0 exists, fallback to br0, etc.
    let interface = "vbr0";

    // Create eBPF forwarder
    let forwarder = EbpfForwarder::new(ingress, egress, interface)?;

    // Attach to TC hooks (requires CAP_BPF or root)
    // Note: This is a sync function called from async context, but attach() is async
    // We use block_in_place to safely run async code in sync context
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(forwarder.attach())
    })?;

    Ok(forwarder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_manager_creation() {
        let mgr = NetworkManager::new().unwrap();
        assert!(mgr.ip_allocator.lock().await.available_count() > 0);
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let mgr = NetworkManager::new().unwrap();

        let ip1 = mgr.allocate_ip("vm-1").await.unwrap();
        let ip2 = mgr.allocate_ip("vm-2").await.unwrap();

        // IPs should be different
        assert_ne!(ip1, ip2);

        // Release
        mgr.release_ip(&ip1).await.unwrap();
        mgr.release_ip(&ip2).await.unwrap();
    }

    #[tokio::test]
    async fn test_port_forwarding() {
        let mgr = NetworkManager::new().unwrap();

        let vm_ip = mgr.allocate_ip("test-vm").await.unwrap();

        // Add port forward
        let result = mgr
            .add_port_forward(18082, vm_ip, 80, Protocol::Tcp, "test-vm".to_string())
            .await;
        assert!(result.is_ok());

        // Remove port forward
        let result = mgr.remove_port_forward(18082, Protocol::Tcp).await;
        assert!(result.is_ok());

        // Cleanup
        mgr.release_ip(&vm_ip).await.unwrap();
    }

    #[tokio::test]
    async fn test_service_registration() {
        let mgr = NetworkManager::new().unwrap();

        let vm_ip = mgr.allocate_ip("web-vm").await.unwrap();

        // Register service
        let result = mgr
            .register_service("web", vm_ip, vec![(80, Protocol::Tcp), (443, Protocol::Tcp)])
            .await;
        assert!(result.is_ok());

        // Lookup service
        let service = mgr.service_registry.lookup("web").await.unwrap();
        assert_eq!(service.ip_address, vm_ip);
        assert_eq!(service.ports.len(), 2);

        // Unregister
        mgr.unregister_service("web").await.unwrap();

        // Should be gone
        assert!(mgr.service_registry.lookup("web").await.is_none());

        // Cleanup
        mgr.release_ip(&vm_ip).await.unwrap();
    }

    #[tokio::test]
    async fn test_remove_vm_port_forwards() {
        let mgr = NetworkManager::new().unwrap();

        let vm_ip = mgr.allocate_ip("multi-port-vm").await.unwrap();

        // Add multiple port forwards
        mgr.add_port_forward(18083, vm_ip, 80, Protocol::Tcp, "multi-port-vm".to_string())
            .await
            .unwrap();

        mgr.add_port_forward(18084, vm_ip, 443, Protocol::Tcp, "multi-port-vm".to_string())
            .await
            .unwrap();

        // Remove all for VM
        mgr.remove_vm_port_forwards("multi-port-vm").await.unwrap();

        // Cleanup
        mgr.release_ip(&vm_ip).await.unwrap();
    }
}
