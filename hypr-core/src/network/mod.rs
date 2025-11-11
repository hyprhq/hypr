//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and connectivity.

pub mod bridge;
pub mod ebpf;

pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use ebpf::{DriftManager, DriftStats, Protocol};
