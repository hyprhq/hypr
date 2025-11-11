//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and connectivity.

pub mod bridge;
pub mod dns;
pub mod ebpf;
pub mod port;
pub mod registry;

pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use dns::{DnsServer, DnsServerConfig};
pub use ebpf::{DriftManager, DriftStats, Protocol};
pub use port::{BpfPortMap, MockBpfPortMap, PortForwarder, PortMapping};
pub use registry::{ServiceInfo, ServiceRegistry};
