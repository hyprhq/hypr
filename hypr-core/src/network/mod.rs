//! Network management for HYPR.
//!
//! Handles IP allocation, network configuration, and service discovery.
//!
//! ## Network Backend
//!
//! HYPR uses gvproxy (gvisor-tap-vsock) as the unified networking backend
//! for both macOS and Linux. This provides:
//! - Userspace networking (no root required after initial setup)
//! - Built-in DHCP and DNS
//! - Port forwarding without eBPF
//! - Cross-platform consistency
//!
// Active modules
pub mod defaults;
pub mod dns;
pub mod gvproxy;
pub mod ipam;
pub mod registry;

// Re-exports for commonly used types
pub use defaults::{
    cidr as network_cidr, defaults as network_defaults, gateway, netmask, netmask_str,
    NetworkDefaults,
};
pub use dns::DnsServer;
pub use gvproxy::{
    defaults as gvproxy_defaults, PortForward as GvproxyPortForward, SharedGvproxy,
};
pub use ipam::IpAllocator;
pub use registry::{ServiceInfo, ServiceRegistry};
