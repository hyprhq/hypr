//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and connectivity.

pub mod bridge;
pub mod ipam;

pub use bridge::{create_bridge_manager, BridgeConfig, BridgeManager};
pub use ipam::IpAllocator;
