//! eBPF-based port forwarding adapter for Linux.
//!
//! Wraps DriftManager to implement the BpfPortMap trait for platform abstraction.

use crate::error::Result;
use crate::network::port::{BpfPortMap, PortMapping};
use crate::types::network::Protocol;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::network::ebpf::{DriftManager, Protocol as EbpfProtocol};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use tracing::{info, instrument};

#[cfg(not(target_os = "linux"))]
use crate::error::HyprError;

/// Wrapper to make DriftManager Send+Sync safe.
/// Safety: Access is protected by a Mutex, so only one thread can access at a time.
#[cfg(target_os = "linux")]
struct SendSyncDrift(DriftManager);

#[cfg(target_os = "linux")]
unsafe impl Send for SendSyncDrift {}
#[cfg(target_os = "linux")]
unsafe impl Sync for SendSyncDrift {}

/// eBPF-based port forwarder using Drift L4 programs.
///
/// Only available on Linux. Provides 10+ Gbps throughput via kernel datapath.
#[cfg(target_os = "linux")]
pub struct EbpfForwarder {
    drift: Mutex<SendSyncDrift>,
}

#[cfg(target_os = "linux")]
impl EbpfForwarder {
    /// Create a new eBPF forwarder.
    ///
    /// # Arguments
    ///
    /// * `ingress_path` - Path to drift_l4_ingress.o
    /// * `egress_path` - Path to drift_l4_egress.o
    /// * `interface` - Network interface (e.g., "eth0", "br0")
    ///
    /// # Errors
    ///
    /// Returns error if eBPF programs cannot be loaded or interface doesn't exist.
    #[instrument(skip_all, fields(interface = %interface))]
    pub fn new(ingress_path: PathBuf, egress_path: PathBuf, interface: &str) -> Result<Self> {
        info!("Creating eBPF port forwarder on interface {}", interface);

        let drift = DriftManager::new(ingress_path, egress_path, interface)?;

        Ok(Self { drift: Mutex::new(SendSyncDrift(drift)) })
    }

    /// Attach eBPF programs to the network interface.
    ///
    /// This must be called after creating the forwarder and before adding mappings.
    #[instrument(skip(self))]
    pub fn attach(&self) -> Result<()> {
        let mut drift = self.drift.lock().unwrap();
        drift.0.attach()
    }

    /// Detach eBPF programs from the network interface.
    #[instrument(skip(self))]
    pub fn detach(&self) -> Result<()> {
        let mut drift = self.drift.lock().unwrap();
        drift.0.detach()
    }
}

#[cfg(target_os = "linux")]
impl BpfPortMap for EbpfForwarder {
    fn add_mapping(&self, mapping: &PortMapping) -> Result<()> {
        // Convert Protocol to EbpfProtocol
        let ebpf_proto = match mapping.protocol {
            Protocol::Tcp => EbpfProtocol::Tcp,
            Protocol::Udp => EbpfProtocol::Udp,
        };

        // Convert to eBPF PortMapping format
        let ebpf_mapping = crate::network::ebpf::PortMapping {
            protocol: ebpf_proto,
            host_port: mapping.host_port,
            backend_ip: mapping.vm_ip,
            backend_port: mapping.vm_port,
        };

        // Add mapping (blocking call is OK here since eBPF map updates are fast)
        let drift = self.drift.lock().unwrap();
        drift.0.add_port_mapping(ebpf_mapping)
    }

    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        // Convert protocol
        let ebpf_proto = match protocol {
            Protocol::Tcp => EbpfProtocol::Tcp,
            Protocol::Udp => EbpfProtocol::Udp,
        };

        // Remove mapping (note: DriftManager::remove_port_mapping takes (protocol, port))
        let drift = self.drift.lock().unwrap();
        drift.0.remove_port_mapping(ebpf_proto, host_port)
    }

    fn is_available(&self) -> bool {
        // eBPF is available if we successfully created the forwarder
        true
    }
}

#[cfg(not(target_os = "linux"))]
pub struct EbpfForwarder;

#[cfg(not(target_os = "linux"))]
impl EbpfForwarder {
    pub fn new(_ingress_path: PathBuf, _egress_path: PathBuf, _interface: &str) -> Result<Self> {
        Err(HyprError::PlatformUnsupported {
            feature: "eBPF port forwarding".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl BpfPortMap for EbpfForwarder {
    fn add_mapping(&self, _mapping: &PortMapping) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "eBPF port forwarding".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    fn remove_mapping(&self, _host_port: u16, _protocol: Protocol) -> Result<()> {
        Err(HyprError::PlatformUnsupported {
            feature: "eBPF port forwarding".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    fn is_available(&self) -> bool {
        false
    }
}
