//! HYPR Core Library
//!
//! Shared types, traits, and utilities for the HYPR microVM orchestration engine.

pub mod adapters;
pub mod error;
pub mod observability;
pub mod state;
pub mod types;

// Re-export commonly used items
pub use error::{HyprError, Result};
pub use observability::{
    health::HealthChecker, init as init_observability, shutdown as shutdown_observability,
};
pub use state::StateManager;
pub use types::{
    Image, ImageManifest, Network, NetworkConfig, PortMapping, Service, Stack, Vm, VmConfig,
    VmHandle, VmResources, VmStatus, Volume, VolumeMount,
};
