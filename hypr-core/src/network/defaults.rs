//! Platform-aware network defaults.
//!
//! This module provides the single source of truth for network configuration
//! across both Linux and macOS platforms. All network configuration should
//! reference these functions rather than hardcoding values.
//!
//! ## Platform-specific configurations:
//!
//! | Platform | Subnet          | Gateway        | Netmask        |
//! |----------|-----------------|----------------|----------------|
//! | Linux    | 10.88.0.0/16    | 10.88.0.1      | 255.255.0.0    |
//! | macOS    | 192.168.64.0/24 | 192.168.64.1   | 255.255.255.0  |

use std::net::Ipv4Addr;

/// Default network configuration for the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDefaults {
    /// Gateway IP address
    pub gateway: Ipv4Addr,
    /// Netmask
    pub netmask: Ipv4Addr,
    /// Netmask as string (e.g., "255.255.0.0")
    pub netmask_str: &'static str,
    /// CIDR notation (e.g., "/16")
    pub cidr_suffix: &'static str,
    /// First allocatable IP (after gateway)
    pub pool_start: Ipv4Addr,
    /// Last allocatable IP
    pub pool_end: Ipv4Addr,
    /// DNS servers to use
    pub dns_servers: &'static [&'static str],
}

/// Get the default network configuration for the current platform.
///
/// # Platform-specific behavior
///
/// - **Linux**: Uses 10.88.0.0/16 (private range, avoids Tailscale conflict)
/// - **macOS**: Uses 192.168.64.0/24 (vmnet default range)
#[must_use]
pub const fn defaults() -> NetworkDefaults {
    #[cfg(target_os = "linux")]
    {
        NetworkDefaults {
            gateway: Ipv4Addr::new(10, 88, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
            netmask_str: "255.255.0.0",
            cidr_suffix: "/16",
            pool_start: Ipv4Addr::new(10, 88, 0, 2),
            pool_end: Ipv4Addr::new(10, 88, 255, 254),
            dns_servers: &["8.8.8.8", "1.1.1.1"],
        }
    }

    #[cfg(target_os = "macos")]
    {
        // DHCP is limited to .2 only (effectively disabled)
        // Static IPs start from .10 to leave a buffer
        NetworkDefaults {
            gateway: Ipv4Addr::new(192, 168, 64, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            netmask_str: "255.255.255.0",
            cidr_suffix: "/24",
            pool_start: Ipv4Addr::new(192, 168, 64, 10),
            pool_end: Ipv4Addr::new(192, 168, 64, 254),
            dns_servers: &["8.8.8.8", "1.1.1.1"],
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback to Linux defaults for other platforms
        NetworkDefaults {
            gateway: Ipv4Addr::new(10, 88, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
            netmask_str: "255.255.0.0",
            cidr_suffix: "/16",
            pool_start: Ipv4Addr::new(10, 88, 0, 2),
            pool_end: Ipv4Addr::new(10, 88, 255, 254),
            dns_servers: &["8.8.8.8", "1.1.1.1"],
        }
    }
}

/// Get the gateway IP address for the current platform.
#[must_use]
pub const fn gateway() -> Ipv4Addr {
    defaults().gateway
}

/// Get the netmask for the current platform.
#[must_use]
pub const fn netmask() -> Ipv4Addr {
    defaults().netmask
}

/// Get the netmask as a string for the current platform.
#[must_use]
pub const fn netmask_str() -> &'static str {
    defaults().netmask_str
}

/// Get the CIDR suffix for the current platform (e.g., "/16" or "/24").
#[must_use]
pub const fn cidr_suffix() -> &'static str {
    defaults().cidr_suffix
}

/// Get the DNS servers to use.
#[must_use]
pub const fn dns_servers() -> &'static [&'static str] {
    defaults().dns_servers
}

/// Get the full CIDR notation (e.g., "10.88.0.0/16" or "192.168.64.0/24").
#[must_use]
pub const fn cidr() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "10.88.0.0/16"
    }

    #[cfg(target_os = "macos")]
    {
        "192.168.64.0/24"
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "10.88.0.0/16"
    }
}

/// Calculate the pool size based on platform defaults.
#[must_use]
pub const fn pool_size() -> usize {
    #[cfg(target_os = "linux")]
    {
        // 10.88.0.0/16 = 65,536 addresses
        // Minus network (.0) and gateway (.1) and broadcast = 65,533 available
        65_533
    }

    #[cfg(target_os = "macos")]
    {
        // 192.168.64.0/24 = 256 addresses
        // Pool is .10 to .254 = 245 available (leaving .2-.9 as buffer)
        245
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        65_533
    }
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
    fn test_linux_config() {
        #[cfg(target_os = "linux")]
        {
            let d = defaults();
            assert_eq!(d.gateway, Ipv4Addr::new(10, 88, 0, 1));
            assert_eq!(d.netmask, Ipv4Addr::new(255, 255, 0, 0));
            assert_eq!(d.netmask_str, "255.255.0.0");
            assert_eq!(d.cidr_suffix, "/16");
        }
    }

    #[test]
    fn test_macos_config() {
        #[cfg(target_os = "macos")]
        {
            let d = defaults();
            assert_eq!(d.gateway, Ipv4Addr::new(192, 168, 64, 1));
            assert_eq!(d.netmask, Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(d.netmask_str, "255.255.255.0");
            assert_eq!(d.cidr_suffix, "/24");
            // Pool starts at .10 to avoid DHCP conflict
            assert_eq!(d.pool_start, Ipv4Addr::new(192, 168, 64, 10));
        }
    }

    #[test]
    fn test_pool_size() {
        let size = pool_size();
        assert!(size > 0);

        #[cfg(target_os = "linux")]
        assert_eq!(size, 65_533);

        #[cfg(target_os = "macos")]
        assert_eq!(size, 245);
    }
}
