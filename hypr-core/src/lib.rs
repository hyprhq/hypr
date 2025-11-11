//! HYPR Core Library
//!
//! Shared types, traits, and utilities for the HYPR microVM orchestration engine.

pub mod adapters;
pub mod compose;
pub mod error;
pub mod observability;
pub mod proto_convert;
pub mod state;
pub mod types;

// Re-export commonly used items
pub use compose::{ComposeFile, ComposeParser};
pub use error::{HyprError, Result};
pub use observability::{
    health::HealthChecker, init as init_observability, shutdown as shutdown_observability,
};
pub use state::StateManager;
pub use types::{
    HealthCheck, Image, ImageManifest, Network, NetworkConfig, NetworkStackConfig, PortMapping,
    Service, ServiceConfig, Stack, StackConfig, Vm, VmConfig, VmHandle, VmResources, VmStatus,
    Volume, VolumeConfig, VolumeMount, VolumeSource,
};
