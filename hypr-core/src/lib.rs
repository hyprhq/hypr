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
pub mod process;
pub mod proto_convert;
pub mod registry;
pub mod security;
pub mod snapshots;
pub mod state;
pub mod templates;
pub mod types;

// Re-export commonly used items
pub use compose::{ComposeFile, ComposeParser};
pub use error::{HyprError, Result};
pub use events::{Event, EventBus, EventSubscriber, EventType};
pub use metrics::{
    MetricsCollector, MetricsDataPoint, MetricsHistory, MetricsResolution, VmMetrics,
};
pub use network::{
    gateway, gvproxy, netmask, netmask_str, network_cidr, network_defaults, GvproxyBackend,
    GvproxyPortForward, IpAllocator, NetworkDefaults,
};
pub use observability::{
    health::HealthChecker, init as init_observability, shutdown as shutdown_observability,
};
pub use process::{ProcessExplorer, ProcessSortBy, VMProcess};
pub use security::{
    RiskLevel, ScanOptions, ScanProgress, ScanStage, SecurityReport, SecurityScanner,
    TrivyScanner, Vulnerability, VulnerabilitySeverity, VulnerabilitySummary,
};
pub use snapshots::{Snapshot, SnapshotManager, SnapshotState, SnapshotType};
pub use state::StateManager;
pub use templates::{Template, TemplateCategory, TemplateRegistry};
pub use types::{
    HealthCheck, Image, ImageManifest, Network, NetworkConfig, NetworkStackConfig, PortMapping,
    Service, ServiceConfig, Stack, StackConfig, Vm, VmConfig, VmHandle, VmResources, VmStatus,
    Volume, VolumeConfig, VolumeMount, VolumeSource,
};
