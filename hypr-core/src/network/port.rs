//! Port forwarding management for HYPR.
//!
//! Manages port forwarding rules between the host and VMs using eBPF maps.
//! Supports both TCP and UDP protocols with conflict detection and SQLite persistence.

use crate::error::{HyprError, Result};
use crate::types::network::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, instrument, warn};

/// Port mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMapping {
    /// Host port
    pub host_port: u16,

    /// VM IP address
    pub vm_ip: Ipv4Addr,

    /// VM port
    pub vm_port: u16,

    /// Protocol (TCP or UDP)
    pub protocol: Protocol,

    /// Associated VM ID (optional, for tracking)
    pub vm_id: Option<String>,
}

impl PortMapping {
    /// Create a new port mapping.
    pub fn new(host_port: u16, vm_ip: Ipv4Addr, vm_port: u16, protocol: Protocol) -> Self {
        Self { host_port, vm_ip, vm_port, protocol, vm_id: None }
    }

    /// Create a new port mapping with VM ID.
    pub fn with_vm_id(
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
        protocol: Protocol,
        vm_id: String,
    ) -> Self {
        Self { host_port, vm_ip, vm_port, protocol, vm_id: Some(vm_id) }
    }
}

/// eBPF port map interface trait (for testing and platform abstraction).
pub trait BpfPortMap: Send + Sync {
    /// Add a port mapping to the eBPF map.
    fn add_mapping(&self, mapping: &PortMapping) -> Result<()>;

    /// Remove a port mapping from the eBPF map.
    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()>;

    /// Check if eBPF is available.
    fn is_available(&self) -> bool;
}

/// Mock eBPF port map for testing and non-Linux platforms.
#[derive(Debug, Clone)]
pub struct MockBpfPortMap {
    available: bool,
}

impl MockBpfPortMap {
    /// Create a new mock BPF port map.
    pub fn new(available: bool) -> Self {
        Self { available }
    }
}

impl BpfPortMap for MockBpfPortMap {
    fn add_mapping(&self, mapping: &PortMapping) -> Result<()> {
        if !self.available {
            return Err(HyprError::PlatformUnsupported {
                feature: "eBPF port forwarding".to_string(),
                platform: std::env::consts::OS.to_string(),
            });
        }
        debug!(
            "Mock: Adding port mapping {}:{} -> {}:{}",
            mapping.host_port, mapping.protocol, mapping.vm_ip, mapping.vm_port
        );
        Ok(())
    }

    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        if !self.available {
            return Err(HyprError::PlatformUnsupported {
                feature: "eBPF port forwarding".to_string(),
                platform: std::env::consts::OS.to_string(),
            });
        }
        debug!("Mock: Removing port mapping {}:{}", host_port, protocol);
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

/// Port forwarder manages port forwarding rules.
pub struct PortForwarder {
    /// In-memory map of port mappings (key: "port:protocol")
    mappings: Arc<Mutex<HashMap<String, PortMapping>>>,

    /// eBPF port map backend
    bpf_map: Arc<dyn BpfPortMap>,
}

impl PortForwarder {
    /// Create a new port forwarder.
    #[instrument(skip(bpf_map))]
    pub fn new(bpf_map: Arc<dyn BpfPortMap>) -> Self {
        info!("Creating port forwarder");
        Self { mappings: Arc::new(Mutex::new(HashMap::new())), bpf_map }
    }

    /// Create a new port forwarder with mock backend (for testing).
    #[cfg(test)]
    pub fn new_mock() -> Self {
        Self::new(Arc::new(MockBpfPortMap::new(true)))
    }

    /// Add a port mapping.
    ///
    /// # Arguments
    /// * `host_port` - Port on the host to forward from
    /// * `vm_ip` - IP address of the target VM
    /// * `vm_port` - Port on the VM to forward to
    /// * `protocol` - Protocol (TCP or UDP)
    ///
    /// # Errors
    /// * `PortConflict` - If the host port is already mapped
    /// * `InvalidConfig` - If port validation fails
    /// * Platform errors if eBPF operations fail
    #[instrument(skip(self))]
    pub fn add_mapping(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
        protocol: Protocol,
    ) -> Result<()> {
        // Validate port numbers
        Self::validate_port(host_port)?;
        Self::validate_port(vm_port)?;

        let key = Self::make_key(host_port, protocol);
        let mapping = PortMapping::new(host_port, vm_ip, vm_port, protocol);

        // Check for conflicts
        {
            let mappings = self.mappings.lock().unwrap();
            if mappings.contains_key(&key) {
                return Err(HyprError::PortConflict { port: host_port });
            }
        }

        // Add to eBPF map first (fail fast)
        self.bpf_map.add_mapping(&mapping)?;

        // Add to in-memory map
        {
            let mut mappings = self.mappings.lock().unwrap();
            mappings.insert(key.clone(), mapping.clone());
        }

        info!("Added port mapping: {}:{} -> {}:{}", host_port, protocol, vm_ip, vm_port);

        Ok(())
    }

    /// Add a port mapping with VM ID.
    #[instrument(skip(self))]
    pub fn add_mapping_with_vm(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
        protocol: Protocol,
        vm_id: String,
    ) -> Result<()> {
        // Validate port numbers
        Self::validate_port(host_port)?;
        Self::validate_port(vm_port)?;

        let key = Self::make_key(host_port, protocol);
        let mapping = PortMapping::with_vm_id(host_port, vm_ip, vm_port, protocol, vm_id);

        // Check for conflicts
        {
            let mappings = self.mappings.lock().unwrap();
            if mappings.contains_key(&key) {
                return Err(HyprError::PortConflict { port: host_port });
            }
        }

        // Add to eBPF map first (fail fast)
        self.bpf_map.add_mapping(&mapping)?;

        // Add to in-memory map
        {
            let mut mappings = self.mappings.lock().unwrap();
            mappings.insert(key.clone(), mapping.clone());
        }

        info!(
            "Added port mapping: {}:{} -> {}:{} (VM: {:?})",
            host_port, protocol, vm_ip, vm_port, mapping.vm_id
        );

        Ok(())
    }

    /// Remove a port mapping.
    ///
    /// # Arguments
    /// * `host_port` - Port on the host
    /// * `protocol` - Protocol (TCP or UDP)
    ///
    /// # Errors
    /// * Returns error if the mapping doesn't exist or eBPF operations fail
    #[instrument(skip(self))]
    pub fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        let key = Self::make_key(host_port, protocol);

        // Check if mapping exists
        {
            let mappings = self.mappings.lock().unwrap();
            if !mappings.contains_key(&key) {
                return Err(HyprError::InvalidConfig {
                    reason: format!("Port mapping not found: {}:{}", host_port, protocol),
                });
            }
        }

        // Remove from eBPF map first
        self.bpf_map.remove_mapping(host_port, protocol)?;

        // Remove from in-memory map
        {
            let mut mappings = self.mappings.lock().unwrap();
            mappings.remove(&key);
        }

        info!("Removed port mapping: {}:{}", host_port, protocol);

        Ok(())
    }

    /// Remove all port mappings for a specific VM.
    #[instrument(skip(self))]
    pub fn remove_vm_mappings(&self, vm_id: &str) -> Result<()> {
        let mut to_remove = Vec::new();

        // Find all mappings for this VM
        {
            let mappings = self.mappings.lock().unwrap();
            for (_key, mapping) in mappings.iter() {
                if let Some(ref id) = mapping.vm_id {
                    if id == vm_id {
                        to_remove.push((mapping.host_port, mapping.protocol));
                    }
                }
            }
        }

        // Remove each mapping
        for (host_port, protocol) in to_remove {
            if let Err(e) = self.remove_mapping(host_port, protocol) {
                warn!(
                    "Failed to remove port mapping {}:{} for VM {}: {}",
                    host_port, protocol, vm_id, e
                );
            }
        }

        info!("Removed all port mappings for VM: {}", vm_id);

        Ok(())
    }

    /// List all port mappings.
    #[instrument(skip(self))]
    pub fn list_mappings(&self) -> Vec<PortMapping> {
        let mappings = self.mappings.lock().unwrap();
        mappings.values().cloned().collect()
    }

    /// Get a specific port mapping.
    #[instrument(skip(self))]
    pub fn get_mapping(&self, host_port: u16, protocol: Protocol) -> Option<PortMapping> {
        let key = Self::make_key(host_port, protocol);
        let mappings = self.mappings.lock().unwrap();
        mappings.get(&key).cloned()
    }

    /// Restore mappings from a list (used during daemon restart).
    #[instrument(skip(self, mappings))]
    pub fn restore_mappings(&self, mappings: Vec<PortMapping>) -> Result<()> {
        info!("Restoring {} port mappings", mappings.len());

        for mapping in mappings {
            // Add to eBPF map
            if let Err(e) = self.bpf_map.add_mapping(&mapping) {
                warn!(
                    "Failed to restore port mapping {}:{}: {}",
                    mapping.host_port, mapping.protocol, e
                );
                continue;
            }

            // Add to in-memory map
            let key = Self::make_key(mapping.host_port, mapping.protocol);
            let mut map = self.mappings.lock().unwrap();
            map.insert(key, mapping);
        }

        Ok(())
    }

    /// Clear all port mappings.
    #[instrument(skip(self))]
    pub fn clear_all(&self) -> Result<()> {
        let mappings: Vec<_> = {
            let map = self.mappings.lock().unwrap();
            map.values().map(|m| (m.host_port, m.protocol)).collect()
        };

        for (host_port, protocol) in mappings {
            if let Err(e) = self.remove_mapping(host_port, protocol) {
                warn!("Failed to remove port mapping {}:{}: {}", host_port, protocol, e);
            }
        }

        Ok(())
    }

    /// Check if eBPF is available.
    pub fn is_ebpf_available(&self) -> bool {
        self.bpf_map.is_available()
    }

    // Private helpers

    fn make_key(port: u16, protocol: Protocol) -> String {
        format!("{}:{}", port, protocol)
    }

    fn validate_port(port: u16) -> Result<()> {
        if port == 0 {
            return Err(HyprError::InvalidConfig { reason: "Port cannot be 0".to_string() });
        }

        // Warn about privileged ports but don't fail
        if port < 1024 {
            warn!("Port {} is in privileged range (<1024), may require root", port);
        }

        Ok(())
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ip() -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, 10)
    }

    #[test]
    fn test_add_mapping() {
        let forwarder = PortForwarder::new_mock();

        let result = forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp);
        assert!(result.is_ok());

        // Verify mapping exists
        let mapping = forwarder.get_mapping(8080, Protocol::Tcp);
        assert!(mapping.is_some());

        let mapping = mapping.unwrap();
        assert_eq!(mapping.host_port, 8080);
        assert_eq!(mapping.vm_ip, test_ip());
        assert_eq!(mapping.vm_port, 80);
        assert_eq!(mapping.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_add_mapping_conflict() {
        let forwarder = PortForwarder::new_mock();

        // Add first mapping
        forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp).unwrap();

        // Try to add conflicting mapping
        let result = forwarder.add_mapping(8080, test_ip(), 8080, Protocol::Tcp);
        assert!(matches!(result, Err(HyprError::PortConflict { port: 8080 })));
    }

    #[test]
    fn test_add_mapping_different_protocols() {
        let forwarder = PortForwarder::new_mock();

        // Add TCP mapping
        forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp).unwrap();

        // Add UDP mapping on same port (should succeed)
        let result = forwarder.add_mapping(8080, test_ip(), 80, Protocol::Udp);
        assert!(result.is_ok());

        // Verify both exist
        assert!(forwarder.get_mapping(8080, Protocol::Tcp).is_some());
        assert!(forwarder.get_mapping(8080, Protocol::Udp).is_some());
    }

    #[test]
    fn test_remove_mapping() {
        let forwarder = PortForwarder::new_mock();

        forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp).unwrap();

        let result = forwarder.remove_mapping(8080, Protocol::Tcp);
        assert!(result.is_ok());

        // Verify mapping is gone
        assert!(forwarder.get_mapping(8080, Protocol::Tcp).is_none());
    }

    #[test]
    fn test_remove_nonexistent_mapping() {
        let forwarder = PortForwarder::new_mock();

        let result = forwarder.remove_mapping(8080, Protocol::Tcp);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_mappings() {
        let forwarder = PortForwarder::new_mock();

        forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp).unwrap();
        forwarder.add_mapping(8443, test_ip(), 443, Protocol::Tcp).unwrap();
        forwarder.add_mapping(5353, test_ip(), 53, Protocol::Udp).unwrap();

        let mappings = forwarder.list_mappings();
        assert_eq!(mappings.len(), 3);
    }

    #[test]
    fn test_add_mapping_with_vm_id() {
        let forwarder = PortForwarder::new_mock();

        let result =
            forwarder.add_mapping_with_vm(8080, test_ip(), 80, Protocol::Tcp, "vm-123".to_string());
        assert!(result.is_ok());

        let mapping = forwarder.get_mapping(8080, Protocol::Tcp).unwrap();
        assert_eq!(mapping.vm_id, Some("vm-123".to_string()));
    }

    #[test]
    fn test_remove_vm_mappings() {
        let forwarder = PortForwarder::new_mock();

        forwarder
            .add_mapping_with_vm(8080, test_ip(), 80, Protocol::Tcp, "vm-123".to_string())
            .unwrap();

        forwarder
            .add_mapping_with_vm(8443, test_ip(), 443, Protocol::Tcp, "vm-123".to_string())
            .unwrap();

        forwarder
            .add_mapping_with_vm(9090, test_ip(), 90, Protocol::Tcp, "vm-456".to_string())
            .unwrap();

        // Remove all mappings for vm-123
        forwarder.remove_vm_mappings("vm-123").unwrap();

        // Verify vm-123 mappings are gone
        assert!(forwarder.get_mapping(8080, Protocol::Tcp).is_none());
        assert!(forwarder.get_mapping(8443, Protocol::Tcp).is_none());

        // Verify vm-456 mapping still exists
        assert!(forwarder.get_mapping(9090, Protocol::Tcp).is_some());
    }

    #[test]
    fn test_validate_port_zero() {
        let forwarder = PortForwarder::new_mock();

        let result = forwarder.add_mapping(0, test_ip(), 80, Protocol::Tcp);
        assert!(matches!(result, Err(HyprError::InvalidConfig { .. })));
    }

    #[test]
    fn test_clear_all() {
        let forwarder = PortForwarder::new_mock();

        forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp).unwrap();
        forwarder.add_mapping(8443, test_ip(), 443, Protocol::Tcp).unwrap();

        forwarder.clear_all().unwrap();

        assert_eq!(forwarder.list_mappings().len(), 0);
    }

    #[test]
    fn test_restore_mappings() {
        let forwarder = PortForwarder::new_mock();

        let mappings = vec![
            PortMapping::new(8080, test_ip(), 80, Protocol::Tcp),
            PortMapping::new(8443, test_ip(), 443, Protocol::Tcp),
        ];

        forwarder.restore_mappings(mappings).unwrap();

        assert_eq!(forwarder.list_mappings().len(), 2);
        assert!(forwarder.get_mapping(8080, Protocol::Tcp).is_some());
        assert!(forwarder.get_mapping(8443, Protocol::Tcp).is_some());
    }

    #[test]
    fn test_mock_ebpf_unavailable() {
        let bpf_map = Arc::new(MockBpfPortMap::new(false));
        let forwarder = PortForwarder::new(bpf_map);

        let result = forwarder.add_mapping(8080, test_ip(), 80, Protocol::Tcp);
        assert!(matches!(result, Err(HyprError::PlatformUnsupported { .. })));

        assert!(!forwarder.is_ebpf_available());
    }
}
