//! HYPR Core Library
//!
//! Shared types, traits, and utilities for the HYPR microVM orchestration engine.

pub mod adapters;
pub mod builder;
pub mod compose;
pub mod embedded;
pub mod error;
pub mod events;
pub mod exec;
pub mod manifest;
pub mod metrics;
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
pub use events::{Event, EventBus, EventSubscriber, EventType};
pub use metrics::{MetricsCollector, VmMetrics};
pub use network::{
    gateway, gvproxy, netmask, netmask_str, network_cidr, network_defaults, GvproxyBackend,
    GvproxyPortForward, IpAllocator, NetworkDefaults,
};
pub use observability::{
    health::HealthChecker, init as init_observability, shutdown as shutdown_observability,
};
pub use state::StateManager;
pub use types::{
    HealthCheck, Image, ImageManifest, Network, NetworkConfig, NetworkStackConfig, PortMapping,
    Service, ServiceConfig, Stack, StackConfig, Vm, VmConfig, VmHandle, VmResources, VmStatus,
    Volume, VolumeConfig, VolumeMount, VolumeSource,
};
