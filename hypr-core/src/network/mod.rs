//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and service discovery.
//!
//! ## Network Backend
//!
//! HYPR uses gvproxy (gvisor-tap-vsock) as the unified networking backend
//! for both macOS and Linux. This provides:
//! - Userspace networking (no root required after initial setup)
//! - Built-in DHCP and DNS
//! - Port forwarding without eBPF
//! - Cross-platform consistency
//!
//! ## Legacy Code (to be removed)
//!
//! The following modules are deprecated and will be removed:
//! - bridge/ - No longer needed with gvproxy
//! - tap/ - No longer needed with gvproxy
//! - ebpf*.rs - No longer needed with gvproxy
//! - hybrid_forwarder.rs - No longer needed with gvproxy

// Legacy modules (deprecated - kept for reference, to be removed)
#[cfg(target_os = "linux")]
pub mod bridge;
pub mod ebpf;
pub mod ebpf_forwarder;
pub mod hybrid_forwarder;
pub mod port;
pub mod proxy_forwarder;

// Active modules
pub mod defaults;
pub mod dns;
pub mod gvproxy;
pub mod ipam;
pub mod registry;

// Re-exports for commonly used types
pub use defaults::{
    cidr as network_cidr, defaults as network_defaults, gateway, netmask, netmask_str,
    NetworkDefaults,
};
pub use dns::DnsServer;
pub use gvproxy::{
    defaults as gvproxy_defaults, GvproxyBackend, PortForward as GvproxyPortForward,
};
pub use ipam::IpAllocator;
pub use port::{BpfPortMap, MockBpfPortMap, PortForwarder, PortMapping};
pub use proxy_forwarder::ProxyForwarder;
pub use registry::{ServiceInfo, ServiceRegistry};

// Legacy re-exports (deprecated)
#[cfg(target_os = "linux")]
pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use ebpf::{DriftManager, DriftStats, Protocol};
pub use ebpf_forwarder::EbpfForwarder;
pub use hybrid_forwarder::HybridForwarder;
