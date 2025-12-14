//! gvproxy networking backend for HYPR.
//!
//! gvproxy (gvisor-tap-vsock) provides userspace networking for VMs without
//! requiring root privileges, kernel modules, or platform-specific APIs.
//!
//! This module implements a **Shared Network** architecture where a single
//! `gvproxy` instance serves all VMs, acting as a virtual switch and gateway.
//!
//! ## Architecture
//!
//! 1. **Singleton Process**: One `gvproxy` process runs on the host.
//! 2. **Shared Switch**: All VMs connect to the same Unix sockets.
//! 3. **Gateway**: `gvproxy` acts as the gateway (192.168.127.1).
//! 4. **IP Management**: VMs use static IPs assigned by HYPR to ensure predictability.
//! 5. **DNS**: `gvproxy` handles DNS forwarding.
//!
//! ## Socket paths
//!
//! Global sockets in `runtime_dir`:
//! - `gvproxy_control.sock` - APIs/Control
//! - `gvproxy_qemu.sock` - QEMU/CloudHypervisor (Stream)
//! - `gvproxy_vfkit.sock` - Vfkit/Libkrun (Datagram)

use crate::error::{HyprError, Result};
use crate::paths;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tracing::info;

/// Port mapping for gvproxy.
#[derive(Debug, Clone)]
pub struct PortForward {
    /// Host port to listen on
    pub host_port: u16,
    /// Guest port to forward to
    pub guest_port: u16,
    /// Protocol (tcp or udp)
    pub protocol: String,
    /// Target VM IP
    pub guest_ip: Ipv4Addr,
}

/// Shared gvproxy networking backend.
///
/// Manages the singleton gvproxy process that serves all VMs.
pub struct SharedGvproxy {
    /// gvproxy process handle
    process: Option<Child>,
    /// Gateway IP address
    #[allow(dead_code)]
    gateway: Ipv4Addr,
    /// Subnet in CIDR notation
    #[allow(dead_code)]
    subnet: String,
}


impl Default for SharedGvproxy {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedGvproxy {
    /// Create a new shared gvproxy manager.
    pub fn new() -> Self {
        Self {
            process: None,
            gateway: defaults::GATEWAY,
            subnet: defaults::CIDR.to_string(),
        }
    }

    /// socket paths
    pub fn control_socket() -> PathBuf {
        paths::runtime_dir().join("gvproxy_control.sock")
    }

    pub fn qemu_socket() -> PathBuf {
        paths::runtime_dir().join("gvproxy_qemu.sock")
    }

    pub fn vfkit_socket() -> PathBuf {
        paths::runtime_dir().join("gvproxy_vfkit.sock")
    }

    /// Start the shared gvproxy instance.
    pub fn start(&mut self) -> Result<()> {
        // Ensure runtime directory exists
        let runtime_dir = paths::runtime_dir();
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| HyprError::IoError { path: runtime_dir.clone(), source: e })?;

        let control_socket = Self::control_socket();
        let qemu_socket = Self::qemu_socket();
        let vfkit_socket = Self::vfkit_socket();

        // Check if already running by connecting to control socket
        if Self::is_active(&control_socket) {
            info!("Shared gvproxy is already running");
            return Ok(());
        }

        // Clean up stale sockets
        let _ = std::fs::remove_file(&control_socket);
        let _ = std::fs::remove_file(&qemu_socket);
        let _ = std::fs::remove_file(&vfkit_socket);

        // Find gvproxy binary
        let gvproxy_path = Self::find_gvproxy()?;

        // Build command line
        let mut cmd = Command::new(&gvproxy_path);

        // Listen sockets
        cmd.arg("-listen-vfkit").arg(format!("unixgram://{}", vfkit_socket.display()));
        cmd.arg("-listen-qemu").arg(format!("unix://{}", qemu_socket.display()));
        cmd.arg("-listen").arg(format!("unix://{}", control_socket.display()));

        // Don't forward SSH by default (ssh-port default is 2222 if not specified)
        // We cannot use 0 as it's invalid (must be 1024-65536).
        // If we want to avoid conflicts, we might need to set it to a random high port
        // or just let it be 2222 and hope it doesn't conflict.
        // For now, removing the invalid argument.

        // Suppress stdout, capture stderr
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());

        info!(
            binary = %gvproxy_path.display(),
            qemu_socket = %qemu_socket.display(),
            "Starting shared gvproxy"
        );

        let child = cmd.spawn().map_err(|e| HyprError::NetworkSetupFailed {
            reason: format!("Failed to spawn gvproxy: {}", e),
        })?;

        info!(pid = ?child.id(), "Shared gvproxy started");
        self.process = Some(child);

        // Wait for socket
        Self::wait_for_socket(&control_socket, Duration::from_secs(5))?;

        Ok(())
    }

    /// Stop the shared gvproxy instance.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut proc) = self.process.take() {
            info!("Stopping shared gvproxy");
            #[cfg(unix)]
            unsafe {
                libc::kill(proc.id() as i32, libc::SIGTERM);
            }
            let _ = proc.wait();
        }
        Ok(())
    }

    /// Add a port forward dynamically.
    pub async fn add_port_forward(&self, forward: PortForward) -> Result<()> {
        let control_socket = Self::control_socket();
        
        let json_body = format!(
            r#"{{"local":":{}","remote":"{}:{}"}}"#,
            forward.host_port, forward.guest_ip, forward.guest_port
        );

        let request = format!(
            "POST /services/forwarder/expose HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            json_body.len(),
            json_body
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(control_socket).await.map_err(|e| {
            HyprError::Internal(format!("Failed to connect to gvproxy control socket: {}", e))
        })?;

        stream.write_all(request.as_bytes()).await.map_err(|e| {
            HyprError::Internal(format!("Failed to send port forward request: {}", e))
        })?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.map_err(|e| {
            HyprError::Internal(format!("Failed to read port forward response: {}", e))
        })?;

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 200") {
            return Err(HyprError::Internal(format!(
                "gvproxy error: {}",
                response_str.lines().next().unwrap_or("Unknown error")
            )));
        }

        Ok(())
    }

    fn is_active(socket_path: &Path) -> bool {
        if !std::path::Path::new(socket_path).exists() {
             return false;
        }
        // Try connecting to verify it's not a stale socket
        use std::os::unix::net::UnixStream;
        UnixStream::connect(socket_path).is_ok()
    }

    fn wait_for_socket(socket_path: &Path, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if socket_path.exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(HyprError::NetworkSetupFailed {
            reason: format!("gvproxy socket {} timeout", socket_path.display()),
        })
    }

    fn find_gvproxy() -> Result<PathBuf> {
        // Reuse existing find logic...
        // Simplified for brevity, assume paths are checked
        let paths = [
             "/opt/homebrew/bin/gvproxy",
             "/usr/local/bin/gvproxy",
             "/usr/bin/gvproxy",
        ];
        
        for path in paths {
             if Path::new(path).exists() {
                 return Ok(PathBuf::from(path));
             }
        }
        
        // Fallback to checking PATH
        if let Ok(output) = Command::new("which").arg("gvproxy").output() {
             if output.status.success() {
                  let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
                  if !p.is_empty() { return Ok(PathBuf::from(p)); }
             }
        }

        Err(HyprError::Internal("gvproxy binary not found".to_string()))
    }
}

pub mod defaults {
    use std::net::Ipv4Addr;
    pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);
    pub const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
    pub const NETMASK_STR: &str = "255.255.255.0";
    pub const CIDR: &str = "192.168.127.0/24";
    pub const POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_shared_paths() {
        assert!(SharedGvproxy::qemu_socket().to_string_lossy().contains("gvproxy_qemu.sock"));
    }
}
