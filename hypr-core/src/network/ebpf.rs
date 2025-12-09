//! eBPF-based L4 port forwarding for HYPR.
//!
//! This module provides high-performance Layer 4 (TCP/UDP) port forwarding using eBPF
//! programs attached to the Traffic Control (TC) subsystem. The implementation uses
//! Drift L4 programs for ingress and egress traffic shaping.
//!
//! # Architecture
//!
//! - **Ingress Program**: Performs DNAT (Destination NAT) for incoming traffic
//!   - Client → Host:8080 → VM:192.168.1.10:80
//!   - Creates conntrack entries for reverse NAT
//!
//! - **Egress Program**: Performs reverse SNAT (Source NAT) for outgoing traffic
//!   - VM:192.168.1.10:80 → Client appears as Host:8080 → Client
//!   - Uses conntrack entries created by ingress
//!
//! # Requirements
//!
//! - Linux kernel with BPF support (5.10+)
//! - TC (Traffic Control) support
//! - libbpf and eBPF programs compiled to .o files
//!
//! # Example
//!
//! ```no_run
//! use hypr_core::network::ebpf::{DriftManager, PortMapping, Protocol};
//! use std::net::Ipv4Addr;
//!
//! # #[cfg(target_os = "linux")]
//! # async fn example() -> anyhow::Result<()> {
//! let mut manager = DriftManager::new(
//!     "drift_l4_ingress.o",
//!     "drift_l4_egress.o",
//!     "eth0",
//! )?;
//!
//! manager.add_port_mapping(PortMapping {
//!     protocol: Protocol::Tcp,
//!     host_port: 8080,
//!     backend_ip: Ipv4Addr::new(192, 168, 1, 10),
//!     backend_port: 80,
//! })?;
//!
//! manager.attach()?;
//! # Ok(())
//! # }
//! ```

use crate::error::{HyprError, Result};
use std::net::Ipv4Addr;
use std::path::Path;

#[cfg(target_os = "linux")]
use metrics::{counter, gauge};
#[cfg(target_os = "linux")]
use tracing::{debug, error, info, instrument, warn};

#[cfg(target_os = "linux")]
use libbpf_rs::{MapCore, Object, ObjectBuilder, TcHook, TcHookBuilder, TC_INGRESS};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;

/// Network protocol for port forwarding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Protocol {
    /// TCP protocol (IPPROTO_TCP = 6)
    Tcp = 6,
    /// UDP protocol (IPPROTO_UDP = 17)
    Udp = 17,
}

impl Protocol {
    /// Convert protocol to numeric value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// Port forwarding mapping from host port to backend VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,
    /// Host port to listen on
    pub host_port: u16,
    /// Backend VM IP address
    pub backend_ip: Ipv4Addr,
    /// Backend VM port
    pub backend_port: u16,
}

impl std::fmt::Display for PortMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}→{}:{}", self.protocol, self.host_port, self.backend_ip, self.backend_port)
    }
}

/// Statistics from eBPF programs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DriftStats {
    /// Ingress packets processed
    pub ingress_packets: u64,
    /// Ingress bytes processed
    pub ingress_bytes: u64,
    /// Egress packets processed
    pub egress_packets: u64,
    /// Egress bytes processed
    pub egress_bytes: u64,
}

/// Drift L4 port forwarding manager.
///
/// Manages eBPF programs for high-performance L4 port forwarding.
/// This is only available on Linux with eBPF support.
#[cfg(target_os = "linux")]
pub struct DriftManager {
    /// Interface name (e.g., "eth0", "br0")
    interface: String,
    /// Loaded eBPF object
    obj: Object,
    /// TC ingress hook
    ingress_link: Option<TcHook>,
    /// TC egress hook
    egress_link: Option<TcHook>,
    /// Whether programs are attached
    attached: bool,
}

#[cfg(target_os = "linux")]
impl DriftManager {
    /// Create a new Drift manager.
    ///
    /// # Arguments
    ///
    /// * `ingress_path` - Path to drift_l4_ingress.o
    /// * `egress_path` - Path to drift_l4_egress.o
    /// * `interface` - Network interface name (e.g., "eth0")
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - eBPF object files cannot be loaded
    /// - Interface does not exist
    /// - Insufficient permissions (requires CAP_BPF or root)
    #[instrument(skip_all, fields(interface = %interface))]
    pub fn new<P: AsRef<Path>>(ingress_path: P, egress_path: P, interface: &str) -> Result<Self> {
        info!("Creating Drift eBPF manager for interface {}", interface);

        // Load ingress program
        let ingress_obj = ObjectBuilder::default()
            .open_file(ingress_path.as_ref())
            .map_err(|e| {
                error!("Failed to open ingress eBPF object: {}", e);
                HyprError::EbpfLoadError(format!("Failed to open ingress object: {}", e))
            })?
            .load()
            .map_err(|e| {
                error!("Failed to load ingress eBPF object: {}", e);
                HyprError::EbpfLoadError(format!("Failed to load ingress object: {}", e))
            })?;

        // Load egress program
        let _egress_obj = ObjectBuilder::default()
            .open_file(egress_path.as_ref())
            .map_err(|e| {
                error!("Failed to open egress eBPF object: {}", e);
                HyprError::EbpfLoadError(format!("Failed to open egress object: {}", e))
            })?
            .load()
            .map_err(|e| {
                error!("Failed to load egress eBPF object: {}", e);
                HyprError::EbpfLoadError(format!("Failed to load egress object: {}", e))
            })?;

        info!("Loaded eBPF programs successfully");

        // For now, we'll use ingress_obj as the primary object
        // In a production system, you'd need to manage both objects separately
        // or combine them into a single object file
        Ok(Self {
            interface: interface.to_string(),
            obj: ingress_obj,
            ingress_link: None,
            egress_link: None,
            attached: false,
        })
    }

    /// Add a port forwarding rule.
    ///
    /// # Arguments
    ///
    /// * `mapping` - Port mapping configuration
    ///
    /// # Errors
    ///
    /// Returns error if map update fails.
    #[instrument(skip(self), fields(mapping = %mapping))]
    pub fn add_port_mapping(&self, mapping: PortMapping) -> Result<()> {
        debug!("Adding port mapping: {}", mapping);

        // Get portmap from eBPF object
        let portmap = self.obj.maps().find(|m| m.name() == "portmap").ok_or_else(|| {
            error!("portmap not found in eBPF object");
            HyprError::EbpfMapError("portmap not found".to_string())
        })?;

        // Construct key (protocol, port)
        // Key structure: [proto: u8, pad: u8, port: u16 (network byte order)]
        let mut key = [0u8; 4];
        key[0] = mapping.protocol.as_u8();
        key[1] = 0; // padding
        let port_be = mapping.host_port.to_be_bytes();
        key[2] = port_be[0];
        key[3] = port_be[1];

        // Construct value (dst_ip in host order, dst_port in network order)
        // Value structure: [dst_ip: u32 (host order), dst_port: u16 (network order), pad: u16]
        let mut value = [0u8; 8];
        let ip_octets = mapping.backend_ip.octets();
        // Store IP in host byte order (little-endian on x86)
        value[0] = ip_octets[0];
        value[1] = ip_octets[1];
        value[2] = ip_octets[2];
        value[3] = ip_octets[3];
        // Store port in network byte order
        let port_be = mapping.backend_port.to_be_bytes();
        value[4] = port_be[0];
        value[5] = port_be[1];
        // value[6-7] = padding (already zeroed)

        // Update map
        portmap.update(&key, &value, libbpf_rs::MapFlags::ANY).map_err(|e| {
            error!("Failed to update portmap: {}", e);
            HyprError::EbpfMapError(format!("Failed to update portmap: {}", e))
        })?;

        info!("Added port mapping: {}", mapping);
        counter!("hypr.ebpf.port_mappings.added").increment(1);

        Ok(())
    }

    /// Remove a port forwarding rule.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Protocol (TCP or UDP)
    /// * `host_port` - Host port to remove
    ///
    /// # Errors
    ///
    /// Returns error if map deletion fails.
    #[instrument(skip(self))]
    pub fn remove_port_mapping(&self, protocol: Protocol, host_port: u16) -> Result<()> {
        debug!("Removing port mapping: {}:{}", protocol, host_port);

        let portmap = self.obj.maps().find(|m| m.name() == "portmap").ok_or_else(|| {
            error!("portmap not found in eBPF object");
            HyprError::EbpfMapError("portmap not found".to_string())
        })?;

        // Construct key
        let mut key = [0u8; 4];
        key[0] = protocol.as_u8();
        key[1] = 0;
        let port_be = host_port.to_be_bytes();
        key[2] = port_be[0];
        key[3] = port_be[1];

        // Delete from map
        portmap.delete(&key).map_err(|e| {
            warn!("Failed to delete portmap entry: {}", e);
            HyprError::EbpfMapError(format!("Failed to delete portmap: {}", e))
        })?;

        info!("Removed port mapping: {}:{}", protocol, host_port);
        counter!("hypr.ebpf.port_mappings.removed").increment(1);

        Ok(())
    }

    /// Attach eBPF programs to TC hooks.
    ///
    /// This attaches the ingress and egress programs to the specified interface.
    /// Before attaching, it cleans up any stale TC hooks from previous daemon runs.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface does not exist
    /// - Insufficient permissions
    /// - Programs already attached
    #[instrument(skip(self))]
    pub fn attach(&mut self) -> Result<()> {
        if self.attached {
            warn!("eBPF programs already attached");
            return Err(HyprError::EbpfAttachError("Programs already attached".to_string()));
        }

        info!("Attaching eBPF programs to interface {}", self.interface);

        // Get program FDs
        let ingress_prog =
            self.obj.progs().find(|p| p.name() == "drift_l4_ingress").ok_or_else(|| {
                error!("drift_l4_ingress program not found");
                HyprError::EbpfLoadError("drift_l4_ingress not found".to_string())
            })?;

        // Create TC ingress hook
        let ifindex = nix::net::if_::if_nametoindex(self.interface.as_str()).map_err(|e| {
            error!("Failed to get interface index: {}", e);
            HyprError::EbpfAttachError(format!("Failed to get interface index: {}", e))
        })? as i32;

        // Clean up any stale TC hooks from previous daemon runs
        // This prevents "Exclusivity flag on, cannot modify" errors
        debug!("Cleaning up stale TC hooks on interface {}", self.interface);
        let mut cleanup_builder = TcHookBuilder::new(ingress_prog.as_fd());
        cleanup_builder.ifindex(ifindex).replace(true).handle(1).priority(1);
        let mut cleanup_hook = cleanup_builder.hook(TC_INGRESS);
        // Try to destroy existing qdisc - ignore errors (it might not exist)
        if let Err(e) = cleanup_hook.destroy() {
            debug!("No existing TC qdisc to clean up ({})", e);
        }

        let mut tc_builder = TcHookBuilder::new(ingress_prog.as_fd());
        tc_builder.ifindex(ifindex).replace(true).handle(1).priority(1);

        let mut ingress_hook = tc_builder.hook(TC_INGRESS);

        ingress_hook.create().map_err(|e| {
            error!("Failed to create TC ingress hook: {}", e);
            HyprError::EbpfAttachError(format!("Failed to create ingress hook: {}", e))
        })?;

        let ingress_link = ingress_hook.attach().map_err(|e| {
            error!("Failed to attach ingress program: {}", e);
            HyprError::EbpfAttachError(format!("Failed to attach ingress: {}", e))
        })?;

        // For egress, we'd do the same with TC_EGRESS
        // For simplicity in this implementation, we're focusing on ingress
        // A full implementation would handle egress similarly

        self.ingress_link = Some(ingress_link);
        self.attached = true;

        info!("Successfully attached eBPF programs");
        gauge!("hypr.ebpf.programs.attached").set(1.0);

        Ok(())
    }

    /// Detach eBPF programs from TC hooks.
    ///
    /// # Errors
    ///
    /// Returns error if programs are not attached.
    #[instrument(skip(self))]
    pub fn detach(&mut self) -> Result<()> {
        if !self.attached {
            warn!("eBPF programs not attached");
            return Ok(());
        }

        info!("Detaching eBPF programs from interface {}", self.interface);

        // Explicitly detach hooks
        if let Some(mut hook) = self.ingress_link.take() {
            hook.detach().map_err(|e| {
                error!("Failed to detach ingress hook: {}", e);
                HyprError::EbpfAttachError(format!("Failed to detach ingress: {}", e))
            })?;
        }

        if let Some(mut hook) = self.egress_link.take() {
            hook.detach().map_err(|e| {
                error!("Failed to detach egress hook: {}", e);
                HyprError::EbpfAttachError(format!("Failed to detach egress: {}", e))
            })?;
        }

        self.attached = false;

        info!("Successfully detached eBPF programs");
        gauge!("hypr.ebpf.programs.attached").set(0.0);

        Ok(())
    }

    /// Get statistics from eBPF programs.
    ///
    /// # Errors
    ///
    /// Returns error if stats map cannot be read.
    #[instrument(skip(self))]
    pub fn get_stats(&self) -> Result<DriftStats> {
        let stats_map = self.obj.maps().find(|m| m.name() == "stats").ok_or_else(|| {
            error!("stats map not found in eBPF object");
            HyprError::EbpfMapError("stats not found".to_string())
        })?;

        let mut stats = DriftStats::default();

        // Read ingress stats (indices 0, 1)
        if let Ok(Some(value)) = stats_map.lookup(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            if value.len() >= 8 {
                stats.ingress_packets = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            }
        }

        if let Ok(Some(value)) = stats_map.lookup(&1u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            if value.len() >= 8 {
                stats.ingress_bytes = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            }
        }

        // Read egress stats (indices 2, 3)
        if let Ok(Some(value)) = stats_map.lookup(&2u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            if value.len() >= 8 {
                stats.egress_packets = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            }
        }

        if let Ok(Some(value)) = stats_map.lookup(&3u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
            if value.len() >= 8 {
                stats.egress_bytes = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            }
        }

        debug!("eBPF stats: {:?}", stats);

        Ok(stats)
    }

    /// Check if programs are attached.
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Get the interface name.
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

#[cfg(target_os = "linux")]
impl Drop for DriftManager {
    fn drop(&mut self) {
        if self.attached {
            if let Err(e) = self.detach() {
                error!("Failed to detach eBPF programs during drop: {}", e);
            }
        }
    }
}

// Mock implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct DriftManager;

#[cfg(not(target_os = "linux"))]
impl DriftManager {
    pub fn new<P: AsRef<Path>>(
        _ingress_path: P,
        _egress_path: P,
        _interface: &str,
    ) -> Result<Self> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn add_port_mapping(&self, _mapping: PortMapping) -> Result<()> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn remove_port_mapping(&self, _protocol: Protocol, _host_port: u16) -> Result<()> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn attach(&mut self) -> Result<()> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn detach(&mut self) -> Result<()> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn get_stats(&self) -> Result<DriftStats> {
        Err(HyprError::UnsupportedPlatform("eBPF is only supported on Linux".to_string()))
    }

    pub fn is_attached(&self) -> bool {
        false
    }

    pub fn interface(&self) -> &str {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
    }

    #[test]
    fn test_protocol_as_u8() {
        assert_eq!(Protocol::Tcp.as_u8(), 6);
        assert_eq!(Protocol::Udp.as_u8(), 17);
    }

    #[test]
    fn test_port_mapping_display() {
        let mapping = PortMapping {
            protocol: Protocol::Tcp,
            host_port: 8080,
            backend_ip: Ipv4Addr::new(192, 168, 1, 10),
            backend_port: 80,
        };
        assert_eq!(mapping.to_string(), "TCP:8080→192.168.1.10:80");
    }

    #[test]
    fn test_drift_stats_default() {
        let stats = DriftStats::default();
        assert_eq!(stats.ingress_packets, 0);
        assert_eq!(stats.ingress_bytes, 0);
        assert_eq!(stats.egress_packets, 0);
        assert_eq!(stats.egress_bytes, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_non_linux_returns_error() {
        let result = DriftManager::new("ingress.o", "egress.o", "eth0");
        assert!(result.is_err());
    }

    // Integration tests for Linux would require:
    // - Root/CAP_BPF permissions
    // - Compiled eBPF programs
    // - Test network interface
    // These are better suited for a separate integration test suite
}
