//! VM metrics collector - receives pushed metrics from Kestrel via vsock.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Magic number for metrics packet validation ("MTRC" in little-endian).
pub const METRICS_MAGIC: u32 = 0x4D545243;

/// Current metrics protocol version.
pub const METRICS_VERSION: u8 = 1;

/// Binary metrics packet from Kestrel (matches C struct exactly).
/// All values are little-endian.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct VmMetricsPacket {
    pub magic: u32,
    pub version: u8,
    pub reserved: [u8; 3],
    pub timestamp_ns: u64,
    pub cpu_user_ms: u64,
    pub cpu_system_ms: u64,
    pub cpu_idle_ms: u64,
    pub memory_total_kb: u64,
    pub memory_used_kb: u64,
    pub memory_cached_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub process_count: u32,
    pub uptime_secs: u32,
}

impl VmMetricsPacket {
    /// Size of the packet in bytes.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Parse a metrics packet from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        // SAFETY: VmMetricsPacket is repr(C, packed) with only primitive types
        let packet: VmMetricsPacket = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };

        // Validate magic and version
        if packet.magic != METRICS_MAGIC {
            return None;
        }
        if packet.version != METRICS_VERSION {
            return None;
        }

        Some(packet)
    }
}

/// Cached metrics for a VM with computed rates.
#[derive(Clone, Debug)]
pub struct VmMetrics {
    /// VM ID
    pub vm_id: String,

    /// When these metrics were received
    pub received_at: Instant,

    /// Raw packet data
    pub raw: VmMetricsPacket,

    /// CPU usage percentage (0-100)
    pub cpu_percent: f64,

    /// Memory usage percentage (0-100)
    pub memory_percent: f64,

    /// Network receive rate (bytes/sec)
    pub net_rx_rate: f64,

    /// Network transmit rate (bytes/sec)
    pub net_tx_rate: f64,

    /// Disk read rate (bytes/sec)
    pub disk_read_rate: f64,

    /// Disk write rate (bytes/sec)
    pub disk_write_rate: f64,
}

/// State for a single VM's metrics connection.
struct VmMetricsState {
    /// Most recent metrics
    metrics: Option<VmMetrics>,

    /// Previous packet for rate calculation
    prev_packet: Option<VmMetricsPacket>,

    /// Time of previous packet
    prev_time: Option<Instant>,
}

/// Metrics collector that receives pushed metrics from VMs.
pub struct MetricsCollector {
    /// Cached metrics per VM ID
    cache: Arc<RwLock<HashMap<String, VmMetricsState>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self { cache: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Start listening for metrics from a specific VM.
    ///
    /// This spawns a background task that accepts connections on the VM's
    /// metrics vsock socket and caches received metrics.
    pub fn start_vm_metrics(&self, vm_id: String, vsock_path: PathBuf) {
        let cache = self.cache.clone();

        tokio::spawn(async move {
            info!(vm_id = %vm_id, path = %vsock_path.display(), "Starting metrics listener");

            // Initialize state for this VM
            {
                let mut cache = cache.write().await;
                cache.insert(
                    vm_id.clone(),
                    VmMetricsState { metrics: None, prev_packet: None, prev_time: None },
                );
            }

            // For libkrun: The socket is created by the hypervisor with listen=true,
            // so we connect to it and read pushed metrics.
            // For cloud-hypervisor: We listen on the vsock socket and accept connections
            // with CONNECT handshake.
            #[cfg(target_os = "linux")]
            {
                // Cloud-hypervisor: Listen on the socket for incoming CONNECT messages
                Self::listen_for_metrics_ch(cache, vm_id, vsock_path).await;
            }

            #[cfg(not(target_os = "linux"))]
            {
                // libkrun: Connect to the socket created by libkrun
                Self::connect_for_metrics_libkrun(cache, vm_id, vsock_path).await;
            }
        });
    }

    /// Stop collecting metrics for a VM.
    pub async fn stop_vm_metrics(&self, vm_id: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(vm_id);
        info!(vm_id = %vm_id, "Stopped metrics collection");
    }

    /// Get the latest metrics for a VM.
    pub async fn get_metrics(&self, vm_id: &str) -> Option<VmMetrics> {
        let cache = self.cache.read().await;
        cache.get(vm_id).and_then(|state| state.metrics.clone())
    }

    /// Get metrics for all VMs.
    pub async fn get_all_metrics(&self) -> HashMap<String, VmMetrics> {
        let cache = self.cache.read().await;
        cache
            .iter()
            .filter_map(|(id, state)| state.metrics.clone().map(|m| (id.clone(), m)))
            .collect()
    }

    /// Update metrics cache with a new packet.
    async fn update_metrics(
        cache: &Arc<RwLock<HashMap<String, VmMetricsState>>>,
        vm_id: &str,
        packet: VmMetricsPacket,
    ) {
        let now = Instant::now();

        let mut cache = cache.write().await;
        let state = match cache.get_mut(vm_id) {
            Some(s) => s,
            None => return,
        };

        // Calculate rates if we have a previous packet
        let (cpu_percent, net_rx_rate, net_tx_rate, disk_read_rate, disk_write_rate) =
            if let (Some(prev), Some(prev_time)) = (&state.prev_packet, state.prev_time) {
                let elapsed = now.duration_since(prev_time).as_secs_f64();
                if elapsed > 0.0 {
                    // CPU: calculate usage from delta
                    let cpu_user_delta = packet.cpu_user_ms.saturating_sub(prev.cpu_user_ms);
                    let cpu_sys_delta = packet.cpu_system_ms.saturating_sub(prev.cpu_system_ms);
                    let cpu_idle_delta = packet.cpu_idle_ms.saturating_sub(prev.cpu_idle_ms);
                    let cpu_total = cpu_user_delta + cpu_sys_delta + cpu_idle_delta;
                    let cpu_pct = if cpu_total > 0 {
                        ((cpu_user_delta + cpu_sys_delta) as f64 / cpu_total as f64) * 100.0
                    } else {
                        0.0
                    };

                    // Network rates
                    let net_rx = (packet.net_rx_bytes.saturating_sub(prev.net_rx_bytes)) as f64
                        / elapsed;
                    let net_tx = (packet.net_tx_bytes.saturating_sub(prev.net_tx_bytes)) as f64
                        / elapsed;

                    // Disk rates
                    let disk_rd = (packet.disk_read_bytes.saturating_sub(prev.disk_read_bytes))
                        as f64
                        / elapsed;
                    let disk_wr = (packet.disk_write_bytes.saturating_sub(prev.disk_write_bytes))
                        as f64
                        / elapsed;

                    (cpu_pct, net_rx, net_tx, disk_rd, disk_wr)
                } else {
                    (0.0, 0.0, 0.0, 0.0, 0.0)
                }
            } else {
                (0.0, 0.0, 0.0, 0.0, 0.0)
            };

        // Memory percentage
        let memory_percent = if packet.memory_total_kb > 0 {
            (packet.memory_used_kb as f64 / packet.memory_total_kb as f64) * 100.0
        } else {
            0.0
        };

        let metrics = VmMetrics {
            vm_id: vm_id.to_string(),
            received_at: now,
            raw: packet,
            cpu_percent,
            memory_percent,
            net_rx_rate,
            net_tx_rate,
            disk_read_rate,
            disk_write_rate,
        };

        state.metrics = Some(metrics);
        state.prev_packet = Some(packet);
        state.prev_time = Some(now);
    }

    /// libkrun: Connect to the metrics socket and read pushed packets.
    ///
    /// libkrun creates per-port sockets with `add_vsock_port2`. When the guest
    /// connects to a port, the connection appears on the Unix socket.
    #[cfg(not(target_os = "linux"))]
    async fn connect_for_metrics_libkrun(
        cache: Arc<RwLock<HashMap<String, VmMetricsState>>>,
        vm_id: String,
        vsock_path: PathBuf,
    ) {
        // Wait for socket to appear (VM may take time to start)
        for _ in 0..30 {
            if vsock_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        loop {
            // Connect to the socket created by libkrun
            match UnixStream::connect(&vsock_path).await {
                Ok(mut stream) => {
                    debug!(vm_id = %vm_id, "Connected to metrics socket (libkrun)");
                    Self::read_metrics_stream(&cache, &vm_id, &mut stream).await;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound
                        && e.kind() != std::io::ErrorKind::ConnectionRefused
                    {
                        warn!(vm_id = %vm_id, error = %e, "Failed to connect to metrics socket");
                    }
                }
            }

            // Check if VM is still tracked
            {
                let cache_read = cache.read().await;
                if !cache_read.contains_key(&vm_id) {
                    info!(vm_id = %vm_id, "VM removed, stopping metrics listener");
                    return;
                }
            }

            // Retry after delay
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Cloud-hypervisor: Listen on vsock socket for incoming CONNECT messages.
    ///
    /// When a guest connects to host CID port P, cloud-hypervisor sends
    /// `CONNECT P\n` on the Unix socket. We need to listen, accept, and
    /// handle the handshake before reading metrics.
    #[cfg(target_os = "linux")]
    async fn listen_for_metrics_ch(
        cache: Arc<RwLock<HashMap<String, VmMetricsState>>>,
        vm_id: String,
        vsock_path: PathBuf,
    ) {
        use tokio::io::{AsyncBufReadExt, BufReader};

        // Wait for socket to appear
        for _ in 0..30 {
            if vsock_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Cloud-hypervisor creates the socket, we connect and handle CONNECT messages
        loop {
            match UnixStream::connect(&vsock_path).await {
                Ok(stream) => {
                    debug!(vm_id = %vm_id, "Connected to vsock socket (cloud-hypervisor)");

                    // Read the CONNECT handshake
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();

                    match reader.read_line(&mut line).await {
                        Ok(_) if line.starts_with("CONNECT ") => {
                            // Parse port from "CONNECT <port>\n"
                            let port_str = line.trim_start_matches("CONNECT ").trim();
                            if let Ok(port) = port_str.parse::<u32>() {
                                if port == 1025 {
                                    debug!(vm_id = %vm_id, port, "Accepted metrics connection");
                                    let mut stream = reader.into_inner();
                                    Self::read_metrics_stream(&cache, &vm_id, &mut stream).await;
                                } else {
                                    debug!(vm_id = %vm_id, port, "Ignoring non-metrics port");
                                }
                            }
                        }
                        Ok(_) => {
                            debug!(vm_id = %vm_id, line = %line.trim(), "Unexpected handshake");
                        }
                        Err(e) => {
                            debug!(vm_id = %vm_id, error = %e, "Failed to read handshake");
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound
                        && e.kind() != std::io::ErrorKind::ConnectionRefused
                    {
                        warn!(vm_id = %vm_id, error = %e, "Failed to connect to vsock socket");
                    }
                }
            }

            // Check if VM is still tracked
            {
                let cache_read = cache.read().await;
                if !cache_read.contains_key(&vm_id) {
                    info!(vm_id = %vm_id, "VM removed, stopping metrics listener");
                    return;
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Read metrics packets from a connected stream.
    async fn read_metrics_stream(
        cache: &Arc<RwLock<HashMap<String, VmMetricsState>>>,
        vm_id: &str,
        stream: &mut UnixStream,
    ) {
        let mut buf = vec![0u8; VmMetricsPacket::SIZE * 2];
        let mut offset = 0usize;

        loop {
            match stream.read(&mut buf[offset..]).await {
                Ok(0) => {
                    debug!(vm_id = %vm_id, "Metrics connection closed");
                    break;
                }
                Ok(n) => {
                    offset += n;

                    // Process complete packets
                    while offset >= VmMetricsPacket::SIZE {
                        if let Some(packet) =
                            VmMetricsPacket::from_bytes(&buf[..VmMetricsPacket::SIZE])
                        {
                            Self::update_metrics(cache, vm_id, packet).await;
                        }

                        // Shift remaining bytes
                        buf.copy_within(VmMetricsPacket::SIZE..offset, 0);
                        offset -= VmMetricsPacket::SIZE;
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        debug!(vm_id = %vm_id, error = %e, "Metrics read error");
                        break;
                    }
                }
            }
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_size() {
        // Ensure packet size matches what Kestrel sends
        assert_eq!(VmMetricsPacket::SIZE, 112);
    }

    #[test]
    fn test_packet_parse() {
        let mut bytes = vec![0u8; VmMetricsPacket::SIZE];
        // Set magic
        bytes[0..4].copy_from_slice(&METRICS_MAGIC.to_le_bytes());
        // Set version
        bytes[4] = METRICS_VERSION;

        let packet = VmMetricsPacket::from_bytes(&bytes);
        assert!(packet.is_some());
    }

    #[test]
    fn test_packet_invalid_magic() {
        let mut bytes = vec![0u8; VmMetricsPacket::SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        let packet = VmMetricsPacket::from_bytes(&bytes);
        assert!(packet.is_none());
    }
}
