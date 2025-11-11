//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and connectivity.

pub mod bridge;
pub mod ebpf;
pub mod ipam;
pub mod port;
pub mod registry;

pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use ebpf::{DriftManager, DriftStats, Protocol};
pub use ipam::IpAllocator;
pub use port::{BpfPortMap, MockBpfPortMap, PortForwarder, PortMapping};
pub use registry::{ServiceInfo, ServiceRegistry};
