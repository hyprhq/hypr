//! HYPR Core Library
//!
//! Shared types, traits, and utilities for the HYPR microVM orchestration engine.

pub mod adapters;
pub mod builder;
pub mod compose;
pub mod embedded;
pub mod error;
pub mod exec;
pub mod manifest;
pub mod network;
pub mod observability;
pub mod paths;
pub mod ports;
pub mod proto_convert;
pub mod registry;
pub mod state;
pub mod types;

// Re-export commonly used items
pub use compose::{ComposeFile, ComposeParser};
pub use error::{HyprError, Result};
pub use network::{create_bridge_manager, BridgeConfig, BridgeManager, IpAllocator};
pub use observability::{
    health::HealthChecker, init as init_observability, shutdown as shutdown_observability,
};
pub use state::StateManager;
pub use types::{
    HealthCheck, Image, ImageManifest, Network, NetworkConfig, NetworkStackConfig, PortMapping,
    Service, ServiceConfig, Stack, StackConfig, Vm, VmConfig, VmHandle, VmResources, VmStatus,
    Volume, VolumeConfig, VolumeMount, VolumeSource,
};
