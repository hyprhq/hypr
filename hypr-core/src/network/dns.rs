//! DNS server for HYPR service discovery.
//!
//! Resolves `*.hypr` domains to VM IP addresses and forwards external queries
//! to upstream DNS servers.
//!
//! # Example
//!
//! ```no_run
//! use hypr_core::network::dns::DnsServer;
//! use hypr_core::network::registry::ServiceRegistry;
//! use std::sync::Arc;
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let registry = Arc::new(ServiceRegistry::new_in_memory());
//! let dns = DnsServer::new(
//!     IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
//!     53,
//!     registry,
//!     vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
//! );
//!
//! dns.start().await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{HyprError, Result};
use crate::network::registry::ServiceRegistry;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, instrument, warn};

/// DNS server for HYPR service discovery.
pub struct DnsServer {
    /// Address to bind to (e.g., 10.88.0.1:53)
    bind_addr: SocketAddr,
    /// Service registry for resolving *.hypr domains
    registry: Arc<ServiceRegistry>,
    /// Upstream DNS servers for external queries
    upstream: Vec<IpAddr>,
}

impl DnsServer {
    /// Create a new DNS server.
    ///
    /// # Arguments
    ///
    /// * `bind_ip` - IP address to bind to
    /// * `port` - Port to bind to (typically 53)
    /// * `registry` - Service registry for VM lookups
    /// * `upstream` - Upstream DNS servers (e.g., 1.1.1.1, 8.8.8.8)
    #[instrument(skip(registry))]
    pub fn new(
        bind_ip: IpAddr,
        port: u16,
        registry: Arc<ServiceRegistry>,
        upstream: Vec<IpAddr>,
    ) -> Self {
        info!(
            bind_ip = %bind_ip,
            port = port,
            upstream_count = upstream.len(),
            "Creating DNS server"
        );

        Self {
            bind_addr: SocketAddr::new(bind_ip, port),
            registry,
            upstream,
        }
    }

    /// Start the DNS server.
    ///
    /// This will bind to the configured address and start handling DNS queries.
    #[instrument(skip(self))]
    pub async fn start(self) -> Result<()> {
        info!("Starting DNS server on {}", self.bind_addr);

        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .map_err(|e| HyprError::IoError {
                path: std::path::PathBuf::from(format!("{}", self.bind_addr)),
                source: e,
            })?;

        info!("DNS server listening on {}", self.bind_addr);

        let mut buf = vec![0u8; 512]; // Standard DNS packet size

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let query = buf[..len].to_vec();
                    let registry = self.registry.clone();
                    let upstream = self.upstream.clone();
                    let socket = socket.clone();

                    // Spawn task to handle query
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_query(query, client_addr, registry, upstream, socket).await
                        {
                            error!("Failed to handle DNS query: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to receive DNS query: {}", e);
                }
            }
        }
    }

    /// Handle a DNS query.
    #[instrument(skip(query_bytes, registry, upstream, socket))]
    async fn handle_query(
        query_bytes: Vec<u8>,
        client_addr: SocketAddr,
        registry: Arc<ServiceRegistry>,
        upstream: Vec<IpAddr>,
        socket: UdpSocket,
    ) -> Result<()> {
        // Parse DNS query
        let query = match DnsPacket::parse(&query_bytes) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to parse DNS query: {}", e);
                return Ok(());
            }
        };

        debug!(
            transaction_id = query.transaction_id,
            questions = query.questions.len(),
            client = %client_addr,
            "Received DNS query"
        );

        // Handle each question
        for question in &query.questions {
            let name = &question.name;

            debug!(name = %name, qtype = question.qtype, "Processing DNS question");

            // Check if it's a .hypr domain
            if name.ends_with(".hypr") {
                let service_name = name.trim_end_matches(".hypr");

                // Look up in service registry
                match registry.lookup(service_name).await {
                    Ok(Some(service)) => {
                        if let Some(ip) = service.ip {
                            info!(
                                name = %name,
                                ip = %ip,
                                "Resolved .hypr domain to VM IP"
                            );

                            // Build DNS response
                            let response = Self::build_response(&query, name, ip);
                            if let Err(e) = socket.send_to(&response, client_addr).await {
                                error!("Failed to send DNS response: {}", e);
                            }
                            return Ok(());
                        }
                    }
                    Ok(None) => {
                        debug!(name = %name, "Service not found in registry");
                    }
                    Err(e) => {
                        error!("Failed to lookup service: {}", e);
                    }
                }

                // Service not found, send NXDOMAIN
                let response = Self::build_nxdomain(&query);
                if let Err(e) = socket.send_to(&response, client_addr).await {
                    error!("Failed to send NXDOMAIN response: {}", e);
                }
                return Ok(());
            }
        }

        // Forward to upstream DNS
        debug!("Forwarding query to upstream DNS");
        if let Some(upstream_ip) = upstream.first() {
            match Self::forward_to_upstream(&query_bytes, *upstream_ip).await {
                Ok(response) => {
                    if let Err(e) = socket.send_to(&response, client_addr).await {
                        error!("Failed to send forwarded DNS response: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to forward DNS query: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Forward a DNS query to an upstream server.
    #[instrument(skip(query))]
    async fn forward_to_upstream(query: &[u8], upstream_ip: IpAddr) -> Result<Vec<u8>> {
        let upstream_addr = SocketAddr::new(upstream_ip, 53);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| HyprError::NetworkError(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .send_to(query, upstream_addr)
            .await
            .map_err(|e| HyprError::NetworkError(format!("Failed to send to upstream: {}", e)))?;

        let mut buf = vec![0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| HyprError::NetworkError("Upstream DNS timeout".to_string()))?
        .map_err(|e| HyprError::NetworkError(format!("Failed to receive from upstream: {}", e)))?;

        Ok(buf[..len].to_vec())
    }

    /// Build a DNS response with an A record.
    fn build_response(query: &DnsPacket, name: &str, ip: IpAddr) -> Vec<u8> {
        let mut response = Vec::new();

        // Transaction ID (2 bytes)
        response.extend_from_slice(&query.transaction_id.to_be_bytes());

        // Flags: Response, authoritative, no error
        response.extend_from_slice(&[0x85, 0x00]); // QR=1, AA=1, RCODE=0

        // Questions count (2 bytes)
        response.extend_from_slice(&1u16.to_be_bytes());

        // Answers count (2 bytes)
        response.extend_from_slice(&1u16.to_be_bytes());

        // Authority RRs (2 bytes)
        response.extend_from_slice(&0u16.to_be_bytes());

        // Additional RRs (2 bytes)
        response.extend_from_slice(&0u16.to_be_bytes());

        // Question section (repeat from query)
        Self::encode_name(&mut response, name);
        response.extend_from_slice(&[0x00, 0x01]); // Type A
        response.extend_from_slice(&[0x00, 0x01]); // Class IN

        // Answer section
        Self::encode_name(&mut response, name);
        response.extend_from_slice(&[0x00, 0x01]); // Type A
        response.extend_from_slice(&[0x00, 0x01]); // Class IN
        response.extend_from_slice(&300u32.to_be_bytes()); // TTL: 5 minutes

        if let IpAddr::V4(ipv4) = ip {
            response.extend_from_slice(&4u16.to_be_bytes()); // Data length
            response.extend_from_slice(&ipv4.octets());
        }

        response
    }

    /// Build a DNS NXDOMAIN response.
    fn build_nxdomain(query: &DnsPacket) -> Vec<u8> {
        let mut response = Vec::new();

        // Transaction ID
        response.extend_from_slice(&query.transaction_id.to_be_bytes());

        // Flags: Response, NXDOMAIN (RCODE=3)
        response.extend_from_slice(&[0x81, 0x03]);

        // Questions count
        response.extend_from_slice(&(query.questions.len() as u16).to_be_bytes());

        // No answers
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        // Repeat question
        for q in &query.questions {
            Self::encode_name(&mut response, &q.name);
            response.extend_from_slice(&q.qtype.to_be_bytes());
            response.extend_from_slice(&q.qclass.to_be_bytes());
        }

        response
    }

    /// Encode a DNS name into the response.
    fn encode_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if !label.is_empty() {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
        }
        buf.push(0); // Null terminator
    }
}

/// Simple DNS packet parser.
struct DnsPacket {
    transaction_id: u16,
    questions: Vec<DnsQuestion>,
}

struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

impl DnsPacket {
    /// Parse a DNS packet.
    fn parse(data: &[u8]) -> std::result::Result<Self, String> {
        if data.len() < 12 {
            return Err("Packet too short".to_string());
        }

        let transaction_id = u16::from_be_bytes([data[0], data[1]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);

        let mut questions = Vec::new();
        let mut offset = 12;

        for _ in 0..qdcount {
            let (name, new_offset) = Self::parse_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                return Err("Truncated question".to_string());
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion { name, qtype, qclass });
        }

        Ok(DnsPacket {
            transaction_id,
            questions,
        })
    }

    /// Parse a DNS name from the packet.
    fn parse_name(data: &[u8], mut offset: usize) -> std::result::Result<(String, usize), String> {
        let mut name = String::new();
        let mut jumped = false;
        let mut jump_offset = offset;

        loop {
            if offset >= data.len() {
                return Err("Name extends beyond packet".to_string());
            }

            let len = data[offset] as usize;

            // Check for pointer (compression)
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err("Pointer extends beyond packet".to_string());
                }
                let ptr = ((len & 0x3F) << 8) | data[offset + 1] as usize;
                if !jumped {
                    jump_offset = offset + 2;
                }
                offset = ptr;
                jumped = true;
                continue;
            }

            offset += 1;

            if len == 0 {
                break;
            }

            if offset + len > data.len() {
                return Err("Label extends beyond packet".to_string());
            }

            if !name.is_empty() {
                name.push('.');
            }

            name.push_str(&String::from_utf8_lossy(&data[offset..offset + len]));
            offset += len;
        }

        if jumped {
            Ok((name, jump_offset))
        } else {
            Ok((name, offset))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_name_encoding() {
        let mut buf = Vec::new();
        DnsServer::encode_name(&mut buf, "web.hypr");

        assert_eq!(buf, vec![3, b'w', b'e', b'b', 4, b'h', b'y', b'p', b'r', 0]);
    }

    #[test]
    fn test_dns_packet_parse() {
        // Simple query for "test.hypr" A record
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x04, b't', b'e', b's', b't', // "test"
            0x04, b'h', b'y', b'p', b'r', // "hypr"
            0x00, // End of name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let parsed = DnsPacket::parse(&packet).unwrap();
        assert_eq!(parsed.transaction_id, 0x1234);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "test.hypr");
        assert_eq!(parsed.questions[0].qtype, 1); // A record
    }
}
