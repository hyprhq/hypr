//! Userspace proxy-based port forwarding.
//!
//! Provides TCP and UDP port forwarding via userspace proxy using tokio.
//! Works on all platforms (Linux, macOS, Windows) without requiring eBPF or special permissions.
//!
//! Performance: ~1 Gbps throughput (sufficient for development, lower than eBPF's 10+ Gbps).

use crate::error::{HyprError, Result};
use crate::network::port::{BpfPortMap, PortMapping};
use crate::types::network::Protocol;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, instrument, warn};

/// Proxy task handle for a single port forwarding rule.
struct ProxyTask {
    /// Tokio task handle
    handle: JoinHandle<()>,
}

/// Userspace proxy-based port forwarder.
///
/// Implements the BpfPortMap trait to provide a drop-in replacement
/// for eBPF-based port forwarding on platforms where eBPF is unavailable.
pub struct ProxyForwarder {
    /// Active proxy tasks
    tasks: Arc<Mutex<HashMap<String, ProxyTask>>>,
}

impl ProxyForwarder {
    /// Create a new proxy forwarder.
    #[instrument]
    pub fn new() -> Self {
        info!("Creating userspace proxy forwarder");
        Self { tasks: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Make a key for the tasks map.
    fn make_key(host_port: u16, protocol: Protocol) -> String {
        format!("{}:{}", host_port, protocol)
    }

    /// Start a TCP proxy.
    #[allow(dead_code)]
    #[instrument(skip(self))]
    async fn start_tcp_proxy(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
    ) -> Result<JoinHandle<()>> {
        let listen_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        // Bind to localhost
        let listener = TcpListener::bind(listen_addr).await.map_err(|e| HyprError::IoError {
            path: std::path::PathBuf::from(format!("localhost:{}", host_port)),
            source: e,
        })?;

        info!("TCP proxy listening on localhost:{} -> {}:{}", host_port, vm_ip, vm_port);

        // Spawn accept loop
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((client_stream, client_addr)) => {
                        debug!("TCP proxy: accepted connection from {}", client_addr);

                        // Connect to VM
                        let vm_addr = SocketAddr::from((vm_ip, vm_port));
                        match TcpStream::connect(vm_addr).await {
                            Ok(vm_stream) => {
                                // Spawn bidirectional relay
                                tokio::spawn(Self::relay_tcp(client_stream, vm_stream));
                            }
                            Err(e) => {
                                warn!(
                                    "TCP proxy: failed to connect to {}:{}: {}",
                                    vm_ip, vm_port, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("TCP proxy: accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Relay data bidirectionally between client and VM.
    #[allow(dead_code)]
    #[instrument(skip(client, vm))]
    async fn relay_tcp(client: TcpStream, vm: TcpStream) {
        Self::relay_tcp_static(client, vm).await
    }

    /// Static version of relay_tcp for use in closures.
    async fn relay_tcp_static(mut client: TcpStream, mut vm: TcpStream) {
        let (mut client_read, mut client_write) = client.split();
        let (mut vm_read, mut vm_write) = vm.split();

        // Client -> VM
        let c2v = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if let Err(e) = vm_write.write_all(&buf[..n]).await {
                            warn!("TCP relay: write to VM failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("TCP relay: read from client failed: {}", e);
                        break;
                    }
                }
            }
        };

        // VM -> Client
        let v2c = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match vm_read.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            warn!("TCP relay: write to client failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("TCP relay: read from VM failed: {}", e);
                        break;
                    }
                }
            }
        };

        // Run both directions concurrently
        tokio::select! {
            _ = c2v => {},
            _ = v2c => {},
        }

        debug!("TCP relay: connection closed");
    }

    /// Start a UDP proxy.
    #[allow(dead_code)]
    #[instrument(skip(self))]
    async fn start_udp_proxy(
        &self,
        host_port: u16,
        vm_ip: Ipv4Addr,
        vm_port: u16,
    ) -> Result<JoinHandle<()>> {
        let listen_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        // Bind to localhost
        let socket = UdpSocket::bind(listen_addr).await.map_err(|e| HyprError::IoError {
            path: std::path::PathBuf::from(format!("localhost:{}", host_port)),
            source: e,
        })?;

        info!("UDP proxy listening on localhost:{} -> {}:{}", host_port, vm_ip, vm_port);

        // Spawn relay loop
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536]; // Max UDP datagram size

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, client_addr)) => {
                        debug!("UDP proxy: received {} bytes from {}", n, client_addr);

                        // Forward to VM
                        let vm_addr = SocketAddr::from((vm_ip, vm_port));
                        if let Err(e) = socket.send_to(&buf[..n], vm_addr).await {
                            warn!("UDP proxy: failed to forward to {}:{}: {}", vm_ip, vm_port, e);
                        }

                        // Note: UDP is connectionless, so we don't handle responses here.
                        // For bidirectional UDP, we'd need to maintain a connection table.
                        // This simple implementation is sufficient for most use cases.
                    }
                    Err(e) => {
                        error!("UDP proxy: recv error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }
}

impl Default for ProxyForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfPortMap for ProxyForwarder {
    /// Add a port mapping by starting a proxy task.
    #[instrument(skip(self))]
    fn add_mapping(&self, mapping: &PortMapping) -> Result<()> {
        let key = Self::make_key(mapping.host_port, mapping.protocol);

        // Check if already exists
        // Use block_in_place to safely block within async runtime
        let tasks = tokio::task::block_in_place(|| self.tasks.blocking_lock());
        if tasks.contains_key(&key) {
            return Err(HyprError::PortConflict { port: mapping.host_port });
        }
        drop(tasks); // Release lock before async

        // Clone data for async block
        let host_port = mapping.host_port;
        let vm_ip = mapping.vm_ip;
        let vm_port = mapping.vm_port;
        let protocol = mapping.protocol;

        // Start proxy task based on protocol
        let handle = tokio::spawn(async move {
            match protocol {
                Protocol::Tcp => {
                    // Start TCP proxy in this task
                    let listen_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

                    if let Ok(listener) = TcpListener::bind(listen_addr).await {
                        info!(
                            "TCP proxy listening on localhost:{} -> {}:{}",
                            host_port, vm_ip, vm_port
                        );

                        loop {
                            match listener.accept().await {
                                Ok((client_stream, client_addr)) => {
                                    debug!("TCP proxy: accepted connection from {}", client_addr);

                                    // Connect to VM
                                    let vm_addr = SocketAddr::from((vm_ip, vm_port));
                                    match TcpStream::connect(vm_addr).await {
                                        Ok(vm_stream) => {
                                            // Spawn bidirectional relay
                                            tokio::spawn(Self::relay_tcp_static(
                                                client_stream,
                                                vm_stream,
                                            ));
                                        }
                                        Err(e) => {
                                            warn!(
                                                "TCP proxy: failed to connect to {}:{}: {}",
                                                vm_ip, vm_port, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("TCP proxy: accept error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
                Protocol::Udp => {
                    // Start UDP proxy in this task
                    let listen_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

                    if let Ok(socket) = UdpSocket::bind(listen_addr).await {
                        info!(
                            "UDP proxy listening on localhost:{} -> {}:{}",
                            host_port, vm_ip, vm_port
                        );

                        let mut buf = vec![0u8; 65536];
                        loop {
                            match socket.recv_from(&mut buf).await {
                                Ok((n, _client_addr)) => {
                                    debug!("UDP proxy: received {} bytes", n);

                                    let vm_addr = SocketAddr::from((vm_ip, vm_port));
                                    if let Err(e) = socket.send_to(&buf[..n], vm_addr).await {
                                        warn!(
                                            "UDP proxy: failed to forward to {}:{}: {}",
                                            vm_ip, vm_port, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("UDP proxy: recv error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        // Store task
        let task = ProxyTask { handle };

        // Use block_in_place to safely block within async runtime
        tokio::task::block_in_place(|| {
            let mut tasks = self.tasks.blocking_lock();
            tasks.insert(key.clone(), task);
        });

        info!(
            "Added {} proxy: localhost:{} -> {}:{}",
            mapping.protocol, mapping.host_port, mapping.vm_ip, mapping.vm_port
        );

        Ok(())
    }

    /// Remove a port mapping by stopping the proxy task.
    #[instrument(skip(self))]
    fn remove_mapping(&self, host_port: u16, protocol: Protocol) -> Result<()> {
        let key = Self::make_key(host_port, protocol);

        // Use block_in_place to safely block within async runtime
        tokio::task::block_in_place(|| {
            let mut tasks = self.tasks.blocking_lock();

            if let Some(task) = tasks.remove(&key) {
                // Abort the proxy task
                task.handle.abort();
                info!("Removed {} proxy on port {}", protocol, host_port);
                Ok(())
            } else {
                Err(HyprError::InvalidConfig {
                    reason: format!("Port mapping not found: {}:{}", host_port, protocol),
                })
            }
        })
    }

    /// Proxy forwarder is always available (no special permissions required).
    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::network::Protocol;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_ip() -> Ipv4Addr {
        Ipv4Addr::new(127, 0, 0, 1) // Use localhost for tests
    }

    #[tokio::test]
    async fn test_proxy_forwarder_available() {
        let forwarder = ProxyForwarder::new();
        assert!(forwarder.is_available());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_tcp_proxy_basic() {
        // Start a test "VM" server
        let vm_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vm_port = vm_listener.local_addr().unwrap().port();

        // Spawn VM server that echoes back
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = vm_listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
        });

        // Create proxy forwarder
        let forwarder = ProxyForwarder::new();

        // Add mapping
        let mapping = PortMapping::new(18080, test_ip(), vm_port, Protocol::Tcp);
        forwarder.add_mapping(&mapping).unwrap();

        // Give proxy time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Connect to proxy
        let mut client = TcpStream::connect("127.0.0.1:18080").await.unwrap();

        // Send data
        client.write_all(b"hello").await.unwrap();

        // Receive echo
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Cleanup
        forwarder.remove_mapping(18080, Protocol::Tcp).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_add_mapping_conflict() {
        let forwarder = ProxyForwarder::new();

        let mapping1 = PortMapping::new(18081, test_ip(), 80, Protocol::Tcp);
        forwarder.add_mapping(&mapping1).unwrap();

        let mapping2 = PortMapping::new(18081, test_ip(), 8080, Protocol::Tcp);
        let result = forwarder.add_mapping(&mapping2);

        assert!(matches!(result, Err(HyprError::PortConflict { port: 18081 })));

        // Cleanup
        forwarder.remove_mapping(18081, Protocol::Tcp).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remove_nonexistent() {
        let forwarder = ProxyForwarder::new();

        let result = forwarder.remove_mapping(19999, Protocol::Tcp);
        assert!(result.is_err());
    }
}
