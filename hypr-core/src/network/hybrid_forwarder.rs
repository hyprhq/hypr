//! Hybrid port forwarder combining eBPF and userspace proxy.
//!
//! Uses eBPF for high-performance bridge traffic (external access) and
//! userspace proxy for localhost traffic (which eBPF TC hooks can't intercept).

use crate::error::Result;
use crate::network::port::{BpfPortMap, PortMapping};
use crate::types::network::Protocol;

#[cfg(target_os = "linux")]
use crate::network::ebpf_forwarder::EbpfForwarder;
#[cfg(target_os = "linux")]
use crate::network::proxy_forwarder::ProxyForwarder;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tracing::{debug, info};

/// Hybrid forwarder that uses both eBPF and userspace proxy.
///
/// - eBPF: Handles bridge/external traffic at 10+ Gbps
/// - Proxy: Handles localhost traffic reliably
#[cfg(target_os = "linux")]
pub struct HybridForwarder {
    /// eBPF forwarder for bridge traffic
    ebpf: Arc<EbpfForwarder>,
    /// Proxy forwarder for localhost traffic
    proxy: ProxyForwarder,
}

#[cfg(target_os = "linux")]
impl HybridForwarder {
    /// Create a new hybrid forwarder.
    pub fn new(ebpf: Arc<EbpfForwarder>) -> Self {
        info!("Creating hybrid forwarder (eBPF + proxy)");
        Self { ebpf, proxy: ProxyForwarder::new() }
    }
}

#[cfg(target_os = "linux")]
impl BpfPortMap for HybridForwarder {
    fn add_mapping(&self, mapping: &PortMapping) -> Result<()> {
        // Add to eBPF for bridge traffic (external access via host IP)
        debug!("Hybrid: adding eBPF mapping for bridge traffic");
        self.ebpf.add_mapping(mapping)?;

        // Add to proxy for localhost traffic
        debug!("Hybrid: adding proxy mapping for localhost traffic");
        self.proxy.add_mapping(mapping)?;

        info!(
            "Hybrid forwarder: {}:{} -> {}:{} (eBPF + proxy)",
            mapping.host_port, mapping.protocol, mapping.vm_ip, mapping.vm_port
        );

        Ok(())
    }

    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        // Remove from both
        let _ = self.ebpf.remove_mapping(host_port, protocol);
        let _ = self.proxy.remove_mapping(host_port, protocol);
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.ebpf.is_available()
    }
}

// Non-Linux stub
#[cfg(not(target_os = "linux"))]
pub struct HybridForwarder;

#[cfg(not(target_os = "linux"))]
impl HybridForwarder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
impl BpfPortMap for HybridForwarder {
    fn add_mapping(&self, _mapping: &PortMapping) -> Result<()> {
        Err(crate::error::HyprError::PlatformUnsupported {
            feature: "hybrid forwarder".to_string(),
            platform: std::env::consts::OS.to_string(),
        })
    }

    fn remove_mapping(&self, _host_port: u16, _protocol: Protocol) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        false
    }
}
