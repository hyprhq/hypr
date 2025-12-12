//! Network subsystem coordinator for HYPR daemon.
//!
//! Manages all networking concerns: IP allocation, port forwarding, DNS, and service registry.

use hypr_core::network::{
    DnsServer, IpAllocator, PortForwarder, PortMapping, ProxyForwarder, ServiceRegistry,
};
use hypr_core::types::network::Protocol;
use hypr_core::{Result, StateManager};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, instrument};

#[cfg(target_os = "linux")]
use hypr_core::network::{EbpfForwarder, HybridForwarder};

#[cfg(target_os = "linux")]
use hypr_core::network::bridge::{create_bridge_manager, BridgeConfig};

#[cfg(target_os = "linux")]
use tracing::{debug, warn};

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
    /// - **Linux**: Uses 10.88.0.0/16 IP pool (gateway: 10.88.0.1)
    /// - **macOS**: Uses 192.168.64.0/24 IP pool (gateway: 192.168.64.1, vmnet default)
    ///
    /// ## Port Forwarding
    /// - **Linux**: Attempts eBPF (10+ Gbps), falls back to userspace proxy (1 Gbps) if:
    ///   - eBPF programs not found at <data_dir>/ (see hypr_core::paths)
    ///   - Missing CAP_BPF capability or root privileges
    ///   - Network bridge interface (vbr0) not found
    /// - **macOS/Other**: Uses userspace proxy (1 Gbps, no special permissions)
    #[instrument(skip(state))]
    pub async fn new(state: Arc<StateManager>) -> Result<Self> {
        info!("Initializing network manager");

        // Create IP allocator with state manager
        let ip_allocator = Arc::new(Mutex::new(IpAllocator::new(state.clone())));

        // Platform-specific port forwarding initialization
        // Linux: eBPF by default (10+ Gbps), embedded in binary
        // macOS: userspace proxy (1 Gbps)
        #[cfg(target_os = "linux")]
        let port_forwarder = {
            // First, ensure the bridge exists before trying to attach eBPF
            if let Err(e) = setup_linux_bridge().await {
                warn!("Failed to setup bridge: {}", e);
            }

            match try_ebpf_forwarder() {
                Ok(ebpf) => {
                    // Use hybrid forwarder: eBPF for bridge traffic + proxy for localhost
                    info!("Using hybrid port forwarding (eBPF + proxy for localhost)");
                    let hybrid = HybridForwarder::new(Arc::new(ebpf));
                    Arc::new(PortForwarder::new(Arc::new(hybrid)))
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

        // DNS bind address
        // - Linux: bind to bridge IP (10.88.0.1) since the bridge always exists
        // - macOS: bind to localhost since vmnet IP (192.168.64.1) only exists when VMs are running
        #[cfg(target_os = "macos")]
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        #[cfg(target_os = "linux")]
        let dns_bind_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 88, 0, 1)));

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

    /// Start the DNS server for service discovery.
    ///
    /// The DNS server listens on the gateway IP (e.g., 10.88.0.1:53 on Linux,
    /// 192.168.64.1:53 on macOS) and resolves `*.hypr` domains to VM IPs.
    ///
    /// # Note
    ///
    /// This spawns a background task that runs until the daemon shuts down.
    /// The server will return errors if it cannot bind to port 53 (requires root).
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
}

/// Setup the Linux bridge (vbr0) for VM networking.
///
/// Creates the bridge if it doesn't exist, enables IP forwarding, and sets up NAT.
/// This must be called before trying to attach eBPF programs.
#[cfg(target_os = "linux")]
async fn setup_linux_bridge() -> Result<()> {
    let bridge_mgr = create_bridge_manager()?;
    let config = BridgeConfig::default();

    // Create bridge (idempotent - skips if already exists)
    debug!("Ensuring bridge {} exists", config.name);
    bridge_mgr.create_bridge(&config).await?;

    // Enable IP forwarding for routing between VMs and host
    debug!("Enabling IP forwarding");
    bridge_mgr.enable_ip_forward().await?;

    // Setup NAT for outbound connectivity
    debug!("Setting up NAT for bridge {}", config.name);
    bridge_mgr.setup_nat(&config.name).await?;

    info!("Linux bridge {} configured successfully", config.name);
    Ok(())
}

/// Try to initialize eBPF forwarder (Linux only).
///
/// Uses embedded eBPF programs (compiled during cargo build).
/// Requires CAP_BPF capability or root privileges.
#[cfg(target_os = "linux")]
fn try_ebpf_forwarder() -> Result<EbpfForwarder> {
    // Extract embedded eBPF programs
    let (ingress, egress) = hypr_core::embedded::get_ebpf_paths()?;

    // Auto-detect bridge interface (vbr0 is standard HYPR bridge)
    let interface = "vbr0";

    // Create eBPF forwarder
    let forwarder = EbpfForwarder::new(ingress, egress, interface)?;

    // Attach to TC hooks (requires CAP_BPF or root)
    forwarder.attach()?;

    Ok(forwarder)
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
        // NetworkManager created successfully - that's the test
        // Just verify we can allocate an IP
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
    async fn test_port_forwarding() {
        let (mgr, id) = create_test_network_manager().await;
        let vm_name = format!("test-vm-{}", id);

        let vm_ip = mgr.allocate_ip(&vm_name).await.unwrap();

        // Add port forward
        let result = mgr.add_port_forward(18082, vm_ip, 80, Protocol::Tcp, vm_name.clone()).await;
        assert!(result.is_ok());

        // Remove port forward
        let result = mgr.remove_port_forward(18082, Protocol::Tcp).await;
        assert!(result.is_ok());

        // Cleanup
        mgr.release_ip(&vm_name).await.unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remove_vm_port_forwards() {
        let (mgr, id) = create_test_network_manager().await;
        let vm_name = format!("multi-port-vm-{}", id);

        let vm_ip = mgr.allocate_ip(&vm_name).await.unwrap();

        // Add multiple port forwards
        mgr.add_port_forward(18083, vm_ip, 80, Protocol::Tcp, vm_name.clone()).await.unwrap();

        mgr.add_port_forward(18084, vm_ip, 443, Protocol::Tcp, vm_name.clone()).await.unwrap();

        // Remove all for VM
        mgr.remove_vm_port_forwards(&vm_name).await.unwrap();

        // Cleanup
        mgr.release_ip(&vm_name).await.unwrap();
    }
}
