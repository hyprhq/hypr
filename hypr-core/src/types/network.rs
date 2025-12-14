//! Network domain types.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::SystemTime;

/// Network driver type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDriver {
    #[default]
    Bridge,
}

impl std::fmt::Display for NetworkDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkDriver::Bridge => write!(f, "bridge"),
        }
    }
}

impl std::str::FromStr for NetworkDriver {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bridge" => Ok(NetworkDriver::Bridge),
            _ => Err(format!("Unknown network driver: {}", s)),
        }
    }
}

/// Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// Network ID
    pub id: String,

    /// Network name
    pub name: String,

    /// Network driver
    pub driver: NetworkDriver,

    /// CIDR (e.g., "10.88.0.0/16")
    pub cidr: String,

    /// Gateway IP address (e.g., "10.88.0.1")
    pub gateway: Ipv4Addr,

    /// Bridge interface name (e.g., "vbr0")
    pub bridge_name: String,

    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Network configuration for VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network name
    pub network: String,

    /// MAC address (auto-generated if not specified)
    pub mac_address: Option<String>,

    /// Static IP (allocated from pool if not specified)
    pub ip_address: Option<Ipv4Addr>,

    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: "default".to_string(),
            mac_address: None,
            ip_address: None,
            dns_servers: vec![Ipv4Addr::new(192, 168, 127, 1)],
        }
    }
}

/// Port mapping (host:vm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Host port
    pub host_port: u16,

    /// VM port
    pub vm_port: u16,

    /// Protocol (tcp, udp)
    pub protocol: Protocol,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}
