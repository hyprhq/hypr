//! gvproxy networking backend for HYPR.
//!
//! gvproxy (gvisor-tap-vsock) provides userspace networking for VMs without
//! requiring root privileges, kernel modules, or platform-specific APIs.
//!
//! This module is the unified networking backend for both macOS and Linux,
//! replacing:
//! - macOS: socket_vmnet (which required root and was fragile)
//! - Linux: bridge + TAP + eBPF (which required root and eBPF)
//!
//! ## How it works
//!
//! 1. gvproxy runs as a userspace process per VM
//! 2. It creates a virtual network with DHCP, DNS, and NAT
//! 3. VMM connects via Unix socket (datagram for libkrun, stream for CH)
//! 4. Port forwarding is handled by gvproxy (no eBPF needed)
//!
//! ## Socket paths
//!
//! For each VM, gvproxy creates:
//! - `/var/run/hypr/{vm_id}.gvproxy.sock` - Control/API socket
//! - `/var/run/hypr/{vm_id}.vfkit.sock` - VMM connection socket (vfkit mode)
//! - `/var/run/hypr/{vm_id}.qemu.sock` - VMM connection socket (qemu mode)

use crate::error::{HyprError, Result};
use crate::paths;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Port mapping for gvproxy.
#[derive(Debug, Clone)]
pub struct PortForward {
    /// Host port to listen on
    pub host_port: u16,
    /// Guest port to forward to
    pub guest_port: u16,
    /// Protocol (tcp or udp)
    pub protocol: String,
}

/// gvproxy networking backend.
///
/// Manages a gvproxy process for a single VM, providing:
/// - NAT networking to the host
/// - DHCP for automatic IP assignment
/// - DNS forwarding (with optional *.hypr resolution)
/// - Port forwarding without eBPF
pub struct GvproxyBackend {
    /// VM ID this backend serves
    vm_id: String,
    /// gvproxy process handle
    process: Option<Child>,
    /// Socket path for vfkit/libkrun connection (unixgram)
    vfkit_socket_path: PathBuf,
    /// Socket path for qemu/cloud-hypervisor connection (unix stream)
    qemu_socket_path: PathBuf,
    /// Gateway IP address
    gateway: Ipv4Addr,
    /// Subnet in CIDR notation
    subnet: String,
    /// Port forwards configured
    port_forwards: Vec<PortForward>,
    /// Assigned IP (tracked after VM gets DHCP lease)
    assigned_ip: Option<Ipv4Addr>,
}

impl GvproxyBackend {
    /// Create a new gvproxy backend for a VM.
    ///
    /// This does NOT start gvproxy - call `start()` after creation.
    pub fn new(vm_id: &str) -> Self {
        let runtime_dir = paths::runtime_dir();
        Self {
            vm_id: vm_id.to_string(),
            process: None,
            vfkit_socket_path: runtime_dir.join(format!("{}.vfkit.sock", vm_id)),
            qemu_socket_path: runtime_dir.join(format!("{}.qemu.sock", vm_id)),
            gateway: Ipv4Addr::new(192, 168, 127, 1),
            subnet: "192.168.127.0/24".to_string(),
            port_forwards: Vec::new(),
            assigned_ip: None,
        }
    }

    /// Start gvproxy for this VM.
    ///
    /// # Arguments
    /// * `gateway` - Gateway IP address (e.g., 192.168.127.1)
    /// * `subnet` - Subnet in CIDR notation (e.g., 192.168.127.0/24)
    /// * `port_forwards` - Initial port forwards to configure
    /// * `dns_server` - Optional DNS server IP (defaults to gvproxy's built-in)
    pub fn start(
        &mut self,
        gateway: Ipv4Addr,
        subnet: &str,
        port_forwards: Vec<PortForward>,
        dns_server: Option<Ipv4Addr>,
    ) -> Result<()> {
        self.gateway = gateway;
        self.subnet = subnet.to_string();
        self.port_forwards = port_forwards;

        // Ensure runtime directory exists
        let runtime_dir = paths::runtime_dir();
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;

        // Clean up stale sockets
        let _ = std::fs::remove_file(&self.vfkit_socket_path);
        let _ = std::fs::remove_file(&self.qemu_socket_path);

        // Find gvproxy binary
        let gvproxy_path = Self::find_gvproxy()?;

        // Build command line
        let mut cmd = Command::new(&gvproxy_path);

        // Listen sockets for VMM connection
        // vfkit mode: for libkrun (macOS) - uses unixgram
        cmd.arg("--listen-vfkit")
            .arg(format!("unixgram://{}", self.vfkit_socket_path.display()));

        // qemu mode: for cloud-hypervisor (Linux) - uses unix stream
        cmd.arg("--listen-qemu")
            .arg(format!("unix://{}", self.qemu_socket_path.display()));

        // Network configuration
        cmd.arg("--gateway").arg(gateway.to_string());
        cmd.arg("--netmask").arg("255.255.255.0");

        // DNS configuration
        if let Some(dns) = dns_server {
            cmd.arg("--dns").arg(dns.to_string());
        }

        // Port forwards
        for pf in &self.port_forwards {
            // Format: -p <host_port>:<guest_ip>:<guest_port>/<protocol>
            // Guest IP is dynamic (DHCP), so we use the gateway subnet base + 2
            // gvproxy assigns IPs starting from .2
            cmd.arg("-p").arg(format!(
                "{}:192.168.127.2:{}/{}",
                pf.host_port, pf.guest_port, pf.protocol
            ));
        }

        // Don't forward SSH by default
        cmd.arg("--ssh-port").arg("0");

        // Suppress stdout, capture stderr
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        info!(
            vm_id = %self.vm_id,
            binary = %gvproxy_path.display(),
            vfkit_socket = %self.vfkit_socket_path.display(),
            qemu_socket = %self.qemu_socket_path.display(),
            gateway = %gateway,
            subnet = %subnet,
            "Starting gvproxy"
        );

        let child = cmd.spawn().map_err(|e| HyprError::NetworkSetupFailed {
            reason: format!("Failed to spawn gvproxy: {}", e),
        })?;

        info!(vm_id = %self.vm_id, pid = ?child.id(), "gvproxy started");
        self.process = Some(child);

        // Wait for socket to become available
        self.wait_for_socket(Duration::from_secs(5))?;

        Ok(())
    }

    /// Wait for the vfkit socket to become available.
    fn wait_for_socket(&mut self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        while start.elapsed() < timeout {
            if self.vfkit_socket_path.exists() {
                debug!(
                    vm_id = %self.vm_id,
                    socket = %self.vfkit_socket_path.display(),
                    elapsed_ms = start.elapsed().as_millis(),
                    "gvproxy socket ready"
                );
                return Ok(());
            }
            std::thread::sleep(check_interval);
        }

        // Check if process exited with error
        if let Some(ref mut proc) = self.process.as_mut() {
            if let Ok(Some(status)) = proc.try_wait() {
                let mut stderr = String::new();
                if let Some(ref mut err) = proc.stderr {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut stderr);
                }
                return Err(HyprError::NetworkSetupFailed {
                    reason: format!(
                        "gvproxy exited with {}: {}",
                        status,
                        stderr.trim()
                    ),
                });
            }
        }

        Err(HyprError::NetworkSetupFailed {
            reason: format!(
                "gvproxy socket {} not available after {:?}",
                self.vfkit_socket_path.display(),
                timeout
            ),
        })
    }

    /// Find the gvproxy binary.
    fn find_gvproxy() -> Result<PathBuf> {
        // Check common installation paths
        let paths = [
            // macOS Homebrew
            "/opt/homebrew/bin/gvproxy",
            "/usr/local/bin/gvproxy",
            // Linux package managers
            "/usr/bin/gvproxy",
            "/usr/local/bin/gvproxy",
            // Podman installation
            "/opt/homebrew/Cellar/podman/*/libexec/podman/gvproxy",
            "/usr/libexec/podman/gvproxy",
        ];

        for path in paths {
            // Handle glob patterns
            if path.contains('*') {
                if let Ok(matches) = glob::glob(path) {
                    for entry in matches.flatten() {
                        if entry.exists() && entry.is_file() {
                            return Ok(entry);
                        }
                    }
                }
            } else {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Ok(p);
                }
            }
        }

        // Try PATH
        if let Ok(output) = Command::new("which").arg("gvproxy").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout);
                let path = path.trim();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }

        Err(HyprError::NetworkSetupFailed {
            reason: "gvproxy not found. Install with: brew install podman (macOS) or dnf install podman (Linux)".to_string(),
        })
    }

    /// Get the vfkit socket path for libkrun connection (macOS).
    ///
    /// This socket uses the unixgram protocol for vfkit compatibility.
    pub fn vfkit_socket_path(&self) -> &Path {
        &self.vfkit_socket_path
    }

    /// Get the qemu socket path for cloud-hypervisor connection (Linux).
    ///
    /// This socket uses standard unix stream protocol.
    pub fn qemu_socket_path(&self) -> &Path {
        &self.qemu_socket_path
    }

    /// Get the gateway IP address.
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Get the subnet in CIDR notation.
    pub fn subnet(&self) -> &str {
        &self.subnet
    }

    /// Get the assigned IP address (if known).
    ///
    /// The IP is assigned via DHCP, so this may be None initially.
    /// gvproxy typically assigns the first available IP (.2) to the first VM.
    pub fn assigned_ip(&self) -> Option<Ipv4Addr> {
        self.assigned_ip
    }

    /// Set the assigned IP address (called after DHCP lease is observed).
    pub fn set_assigned_ip(&mut self, ip: Ipv4Addr) {
        self.assigned_ip = Some(ip);
    }

    /// Add a port forward dynamically.
    ///
    /// Note: This currently requires restarting gvproxy. In the future,
    /// we could use gvproxy's HTTP API for dynamic updates.
    pub fn add_port_forward(&mut self, forward: PortForward) -> Result<()> {
        // For now, we track it but don't apply dynamically
        // TODO: Use gvproxy HTTP API for dynamic port forwards
        warn!(
            vm_id = %self.vm_id,
            host_port = forward.host_port,
            guest_port = forward.guest_port,
            "Dynamic port forward added (will apply on next restart)"
        );
        self.port_forwards.push(forward);
        Ok(())
    }

    /// Stop gvproxy.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut proc) = self.process.take() {
            info!(vm_id = %self.vm_id, pid = ?proc.id(), "Stopping gvproxy");

            // Try graceful shutdown first (SIGTERM)
            #[cfg(unix)]
            unsafe {
                libc::kill(proc.id() as i32, libc::SIGTERM);
            }

            // Wait briefly for graceful exit
            std::thread::sleep(Duration::from_millis(500));

            // Force kill if still running
            if proc.try_wait().map(|s| s.is_none()).unwrap_or(false) {
                let _ = proc.kill();
            }

            // Wait for process to fully exit
            let _ = proc.wait();
        }

        // Clean up sockets
        let _ = std::fs::remove_file(&self.vfkit_socket_path);
        let _ = std::fs::remove_file(&self.qemu_socket_path);

        Ok(())
    }

    /// Check if gvproxy is running.
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut proc) = self.process {
            matches!(proc.try_wait(), Ok(None))
        } else {
            false
        }
    }
}

impl Drop for GvproxyBackend {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            error!(vm_id = %self.vm_id, error = %e, "Failed to stop gvproxy on drop");
        }
    }
}

/// Unified network defaults for gvproxy (same for macOS and Linux).
pub mod defaults {
    use std::net::Ipv4Addr;

    /// Default gateway IP for gvproxy networks
    pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);

    /// Default netmask
    pub const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

    /// Default netmask as string
    pub const NETMASK_STR: &str = "255.255.255.0";

    /// Default CIDR suffix
    pub const CIDR_SUFFIX: &str = "/24";

    /// Default subnet in CIDR notation
    pub const CIDR: &str = "192.168.127.0/24";

    /// First IP in the pool (gvproxy assigns from .2)
    pub const POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

    /// Last IP in the pool
    pub const POOL_END: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 254);

    /// Pool size (253 addresses: .2 to .254)
    pub const POOL_SIZE: usize = 253;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gvproxy_backend_new() {
        let backend = GvproxyBackend::new("test-vm");
        assert_eq!(backend.vm_id, "test-vm");
        assert!(backend.vfkit_socket_path.to_string_lossy().contains("test-vm.vfkit.sock"));
        assert!(backend.qemu_socket_path.to_string_lossy().contains("test-vm.qemu.sock"));
    }

    #[test]
    fn test_defaults() {
        assert_eq!(defaults::GATEWAY, Ipv4Addr::new(192, 168, 127, 1));
        assert_eq!(defaults::POOL_SIZE, 253);
    }
}
