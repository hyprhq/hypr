//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and connectivity.

pub mod bridge;
pub mod defaults;
pub mod dns;
pub mod ebpf;
pub mod ebpf_forwarder;
pub mod hybrid_forwarder;
pub mod ipam;
pub mod port;
pub mod proxy_forwarder;
pub mod registry;

pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use defaults::{
    cidr as network_cidr, defaults as network_defaults, gateway, netmask, netmask_str,
    NetworkDefaults,
};
pub use dns::DnsServer;
pub use ebpf::{DriftManager, DriftStats, Protocol};
pub use ebpf_forwarder::EbpfForwarder;
pub use hybrid_forwarder::HybridForwarder;
pub use ipam::IpAllocator;
pub use port::{BpfPortMap, MockBpfPortMap, PortForwarder, PortMapping};
pub use proxy_forwarder::ProxyForwarder;
pub use registry::{ServiceInfo, ServiceRegistry};
