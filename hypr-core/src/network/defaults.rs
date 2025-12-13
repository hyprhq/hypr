//! Unified network defaults for gvproxy.
//!
//! gvproxy provides consistent networking across macOS and Linux:
//! - Subnet: 192.168.127.0/24
//! - Gateway: 192.168.127.1
//! - Pool: 192.168.127.2 - 192.168.127.254
//!
//! This replaces the old platform-specific configurations:
//! - Linux (old): 10.88.0.0/16 with bridge/TAP/eBPF
//! - macOS (old): 192.168.64.0/24 with socket_vmnet

use std::net::Ipv4Addr;

/// Default network configuration (unified via gvproxy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDefaults {
    /// Gateway IP address
    pub gateway: Ipv4Addr,
    /// Netmask
    pub netmask: Ipv4Addr,
    /// Netmask as string (e.g., "255.255.255.0")
    pub netmask_str: &'static str,
    /// CIDR notation (e.g., "/24")
    pub cidr_suffix: &'static str,
    /// First allocatable IP (after gateway)
    pub pool_start: Ipv4Addr,
    /// Last allocatable IP
    pub pool_end: Ipv4Addr,
    /// DNS servers to use
    pub dns_servers: &'static [&'static str],
}

/// Get the default network configuration.
///
/// Uses unified gvproxy defaults for all platforms:
/// - Gateway: 192.168.127.1
/// - Subnet: 192.168.127.0/24
/// - Pool: 192.168.127.2 - 192.168.127.254
#[must_use]
pub const fn defaults() -> NetworkDefaults {
    NetworkDefaults {
        gateway: Ipv4Addr::new(192, 168, 127, 1),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        netmask_str: "255.255.255.0",
        cidr_suffix: "/24",
        pool_start: Ipv4Addr::new(192, 168, 127, 2),
        pool_end: Ipv4Addr::new(192, 168, 127, 254),
        dns_servers: &["8.8.8.8", "1.1.1.1"],
    }
}

/// Get the gateway IP address.
#[must_use]
pub const fn gateway() -> Ipv4Addr {
    defaults().gateway
}

/// Get the netmask.
#[must_use]
pub const fn netmask() -> Ipv4Addr {
    defaults().netmask
}

/// Get the netmask as a string.
#[must_use]
pub const fn netmask_str() -> &'static str {
    defaults().netmask_str
}

/// Get the CIDR suffix (e.g., "/24").
#[must_use]
pub const fn cidr_suffix() -> &'static str {
    defaults().cidr_suffix
}

/// Get the DNS servers to use.
#[must_use]
pub const fn dns_servers() -> &'static [&'static str] {
    defaults().dns_servers
}

/// Get the full CIDR notation (e.g., "192.168.127.0/24").
#[must_use]
pub const fn cidr() -> &'static str {
    "192.168.127.0/24"
}

/// Calculate the pool size.
#[must_use]
pub const fn pool_size() -> usize {
    // 192.168.127.0/24 = 256 addresses
    // Pool is .2 to .254 = 253 available
    253
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_are_consistent() {
        let d = defaults();

        // Gateway should be .1
        assert_eq!(d.gateway.octets()[3], 1);

        // Pool start should be .2
        assert_eq!(d.pool_start.octets()[3], 2);

        // Pool start should be after gateway
        assert!(d.pool_start > d.gateway);

        // Pool end should be after pool start
        assert!(d.pool_end > d.pool_start);
    }

    #[test]
    fn test_gvproxy_config() {
        let d = defaults();
        assert_eq!(d.gateway, Ipv4Addr::new(192, 168, 127, 1));
        assert_eq!(d.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(d.netmask_str, "255.255.255.0");
        assert_eq!(d.cidr_suffix, "/24");
        assert_eq!(d.pool_start, Ipv4Addr::new(192, 168, 127, 2));
        assert_eq!(d.pool_end, Ipv4Addr::new(192, 168, 127, 254));
    }

    #[test]
    fn test_pool_size() {
        let size = pool_size();
        assert_eq!(size, 253);
    }
}
