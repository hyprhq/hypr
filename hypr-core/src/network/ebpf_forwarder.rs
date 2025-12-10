//! eBPF-based port forwarding adapter for Linux.
//!
//! Wraps DriftManager to implement the BpfPortMap trait for platform abstraction.
//! Also adds iptables DNAT rules for localhost traffic (eBPF TC hooks don't
//! intercept loopback traffic).

use crate::error::Result;
use crate::network::port::{BpfPortMap, PortMapping};
use crate::types::network::Protocol;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::network::ebpf::{DriftManager, Protocol as EbpfProtocol};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use tracing::{debug, info, instrument, warn};

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
/// Also adds iptables DNAT rules for localhost traffic since eBPF TC hooks
/// don't intercept loopback interface traffic.
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

    /// Add iptables DNAT rule for localhost traffic.
    /// eBPF TC hooks don't intercept loopback traffic, so we need iptables for localhost.
    fn add_iptables_dnat(&self, mapping: &PortMapping) {
        let proto = match mapping.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let dest = format!("{}:{}", mapping.vm_ip, mapping.vm_port);

        // Add DNAT rule to OUTPUT chain (for localhost traffic)
        // iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 10.88.0.2:80
        let result = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                &mapping.host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &dest,
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    debug!("Added iptables DNAT for localhost: {} -> {}", mapping.host_port, dest);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to add iptables DNAT: {}", stderr);
                }
            }
            Err(e) => {
                warn!("Failed to execute iptables: {}", e);
            }
        }

        // Also add to PREROUTING for external access via host IP
        let result = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                proto,
                "--dport",
                &mapping.host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &dest,
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    debug!("Added iptables PREROUTING DNAT: {} -> {}", mapping.host_port, dest);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // PREROUTING may fail if chain doesn't exist, that's OK
                    debug!("iptables PREROUTING DNAT: {}", stderr);
                }
            }
            Err(e) => {
                debug!("iptables PREROUTING: {}", e);
            }
        }

        // Add MASQUERADE for localhost traffic going to VM network
        // Without this, the VM sees source=127.0.0.1 and responds to its own loopback
        // MASQUERADE changes source to 10.88.0.1 (bridge gateway) so responses route back
        let result = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "127.0.0.1",
                "-d",
                &mapping.vm_ip.to_string(),
                "-p",
                proto,
                "--dport",
                &mapping.vm_port.to_string(),
                "-j",
                "MASQUERADE",
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    debug!("Added iptables MASQUERADE for localhost -> {}", mapping.vm_ip);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    debug!("iptables MASQUERADE: {}", stderr);
                }
            }
            Err(e) => {
                debug!("iptables MASQUERADE: {}", e);
            }
        }
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

        // Add eBPF mapping (for bridge/external traffic)
        let drift = self.drift.lock().unwrap();
        drift.0.add_port_mapping(ebpf_mapping)?;

        // Also add iptables DNAT for localhost traffic
        // (eBPF TC hooks don't intercept loopback interface)
        drop(drift); // Release lock before calling iptables
        self.add_iptables_dnat(mapping);

        Ok(())
    }

    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        // Convert protocol
        let ebpf_proto = match protocol {
            Protocol::Tcp => EbpfProtocol::Tcp,
            Protocol::Udp => EbpfProtocol::Udp,
        };

        // Remove eBPF mapping
        let drift = self.drift.lock().unwrap();
        let result = drift.0.remove_port_mapping(ebpf_proto, host_port);
        drop(drift);

        // Remove iptables DNAT rules
        self.remove_iptables_dnat_by_port(host_port, protocol);

        result
    }

    fn is_available(&self) -> bool {
        // eBPF is available if we successfully created the forwarder
        true
    }
}

#[cfg(target_os = "linux")]
impl EbpfForwarder {
    /// Remove iptables DNAT rules by port (without knowing VM IP).
    /// Uses iptables -S to find matching rules and delete them.
    fn remove_iptables_dnat_by_port(&self, host_port: u16, protocol: Protocol) {
        let proto = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };

        // List rules in OUTPUT chain and find ones matching our port
        if let Ok(output) = Command::new("iptables").args(["-t", "nat", "-S", "OUTPUT"]).output() {
            let rules = String::from_utf8_lossy(&output.stdout);
            for line in rules.lines() {
                // Look for rules like: -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 10.88.0.2:80
                if line.contains(&format!("--dport {}", host_port))
                    && line.contains(&format!("-p {}", proto))
                    && line.contains("DNAT")
                {
                    // Convert -A to -D for deletion
                    let delete_rule = line.replace("-A OUTPUT", "-D OUTPUT");
                    let args: Vec<&str> = delete_rule.split_whitespace().collect();
                    if !args.is_empty() {
                        let mut cmd_args = vec!["-t", "nat"];
                        cmd_args.extend(args);
                        let _ = Command::new("iptables").args(&cmd_args).output();
                    }
                }
            }
        }

        // Same for PREROUTING
        if let Ok(output) =
            Command::new("iptables").args(["-t", "nat", "-S", "PREROUTING"]).output()
        {
            let rules = String::from_utf8_lossy(&output.stdout);
            for line in rules.lines() {
                if line.contains(&format!("--dport {}", host_port))
                    && line.contains(&format!("-p {}", proto))
                    && line.contains("DNAT")
                {
                    let delete_rule = line.replace("-A PREROUTING", "-D PREROUTING");
                    let args: Vec<&str> = delete_rule.split_whitespace().collect();
                    if !args.is_empty() {
                        let mut cmd_args = vec!["-t", "nat"];
                        cmd_args.extend(args);
                        let _ = Command::new("iptables").args(&cmd_args).output();
                    }
                }
            }
        }

        // Clean up POSTROUTING MASQUERADE rules for localhost traffic
        if let Ok(output) =
            Command::new("iptables").args(["-t", "nat", "-S", "POSTROUTING"]).output()
        {
            let rules = String::from_utf8_lossy(&output.stdout);
            for line in rules.lines() {
                // Match rules like: -A POSTROUTING -s 127.0.0.1 -d 10.88.0.2 -p tcp --dport 80 -j MASQUERADE
                if line.contains("-s 127.0.0.1")
                    && line.contains(&format!("--dport {}", host_port))
                    && line.contains(&format!("-p {}", proto))
                    && line.contains("MASQUERADE")
                {
                    let delete_rule = line.replace("-A POSTROUTING", "-D POSTROUTING");
                    let args: Vec<&str> = delete_rule.split_whitespace().collect();
                    if !args.is_empty() {
                        let mut cmd_args = vec!["-t", "nat"];
                        cmd_args.extend(args);
                        let _ = Command::new("iptables").args(&cmd_args).output();
                    }
                }
            }
        }

        debug!("Cleaned up iptables rules for port {}", host_port);
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
