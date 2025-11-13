//! HTTP/HTTPS proxy for builder VMs.
//!
//! Builder VMs have no network interface for security and simplicity.
//! Instead, all HTTP/HTTPS traffic is proxied via vsock to the host,
//! which forwards requests to the real internet.
//!
//! This enables package managers (apt, apk, pip, npm, etc.) to work
//! normally via the `http_proxy` environment variable, while maintaining
//! complete network isolation of the builder VM.

use crate::error::{HyprError, Result};
use crate::ports::PORT_BUILD_PROXY;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, instrument, warn};

/// HTTP/HTTPS proxy for builder VMs.
///
/// Listens on a TCP port (which builder VMs access via socat bridge to vsock),
/// forwards HTTP requests to the internet, and streams responses back.
///
/// Supports:
/// - GET, POST, HEAD, PUT, DELETE
/// - HTTPS via HTTP CONNECT tunneling
/// - Request logging and metrics
/// - Optional domain whitelisting
pub struct BuilderHttpProxy {
    /// HTTP client for forwarding requests
    client: Client,

    /// Port to listen on
    port: u16,

    /// Optional domain whitelist (empty = allow all)
    allowed_domains: Vec<String>,
}

impl BuilderHttpProxy {
    /// Create a new HTTP proxy.
    ///
    /// # Arguments
    /// * `port` - Port to listen on (typically PORT_BUILD_PROXY = 41010)
    /// * `allowed_domains` - Optional whitelist of allowed domains (empty = allow all)
    pub fn new(port: u16, allowed_domains: Vec<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(300)) // 5 minute timeout for downloads
            .build()
            .map_err(|e| HyprError::InvalidConfig {
                reason: format!("Failed to create HTTP client: {}", e),
            })?;

        Ok(Self { client, port, allowed_domains })
    }

    /// Create proxy with default configuration (allow all domains).
    pub fn new_default() -> Result<Self> {
        Self::new(PORT_BUILD_PROXY, vec![])
    }

    /// Start the proxy server (runs until cancelled).
    ///
    /// This is a long-running async task that should be spawned with tokio::spawn.
    #[instrument(skip(self))]
    pub async fn run(self) -> Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to bind proxy to {}: {}", addr, e),
        })?;

        info!("Builder HTTP proxy listening on {}", addr);
        metrics::gauge!("hypr_build_proxy_active").set(1.0);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Proxy connection from {}", addr);

                    let client = self.client.clone();
                    let allowed_domains = self.allowed_domains.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_connection(stream, client, allowed_domains).await
                        {
                            debug!("Proxy connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept proxy connection: {}", e);
                }
            }
        }
    }

    /// Handle a single proxy connection.
    #[instrument(skip(stream, client))]
    async fn handle_connection(
        mut stream: TcpStream,
        client: Client,
        allowed_domains: Vec<String>,
    ) -> Result<()> {
        // Read HTTP request line
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to read request line: {}", e),
        })?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HyprError::InvalidConfig {
                reason: "Invalid HTTP request line".to_string(),
            });
        }

        let method = parts[0].to_string();
        let url = parts[1].to_string();

        debug!("Proxy request: {} {}", method, url);
        let method_label = method.clone();
        metrics::counter!("hypr_build_proxy_requests_total", "method" => method_label).increment(1);

        // Check whitelist
        if !Self::is_allowed(&url, &allowed_domains) {
            warn!("Blocked request to: {}", url);
            metrics::counter!("hypr_build_proxy_blocked_total").increment(1);

            let response = b"HTTP/1.1 403 Forbidden\r\n\r\nDomain not allowed\n";
            stream.write_all(response).await.ok();
            return Ok(());
        }

        let start = Instant::now();

        match method.as_str() {
            "CONNECT" => {
                // HTTPS tunneling
                Self::handle_connect(stream, &url).await?;
            }
            "GET" | "POST" | "HEAD" | "PUT" | "DELETE" => {
                // Regular HTTP
                Self::handle_http(stream, &method, &url, client).await?;
            }
            _ => {
                let response = format!(
                    "HTTP/1.1 405 Method Not Allowed\r\n\r\nMethod {} not supported\n",
                    method
                );
                stream.write_all(response.as_bytes()).await.ok();
                return Ok(());
            }
        }

        let duration = start.elapsed();
        metrics::histogram!("hypr_build_proxy_duration_seconds").record(duration.as_secs_f64());

        Ok(())
    }

    /// Handle HTTP CONNECT method for HTTPS tunneling.
    ///
    /// Establishes a TCP tunnel to the target host, allowing the client
    /// to perform TLS handshake and encrypted communication.
    async fn handle_connect(mut client_stream: TcpStream, target: &str) -> Result<()> {
        debug!("CONNECT tunnel to {}", target);

        // Connect to target
        let mut target_stream = TcpStream::connect(target).await.map_err(|e| {
            HyprError::InvalidConfig { reason: format!("Failed to connect to {}: {}", target, e) }
        })?;

        // Send 200 Connection Established
        client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.map_err(
            |e| HyprError::InvalidConfig {
                reason: format!("Failed to send CONNECT response: {}", e),
            },
        )?;

        // Bidirectional copy (tunnel)
        let (mut client_read, mut client_write) = client_stream.split();
        let (mut target_read, mut target_write) = target_stream.split();

        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
        let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

        // Wait for either direction to close
        tokio::select! {
            _ = client_to_target => {},
            _ = target_to_client => {},
        }

        debug!("CONNECT tunnel closed");
        Ok(())
    }

    /// Handle regular HTTP methods (GET, POST, etc.).
    async fn handle_http(
        mut stream: TcpStream,
        method: &str,
        url: &str,
        client: Client,
    ) -> Result<()> {
        // Forward request to internet
        let response = match method {
            "GET" => client.get(url).send().await,
            "HEAD" => client.head(url).send().await,
            "POST" => client.post(url).send().await,
            "PUT" => client.put(url).send().await,
            "DELETE" => client.delete(url).send().await,
            _ => unreachable!(),
        };

        let response = response.map_err(|e| HyprError::InvalidConfig {
            reason: format!("HTTP request failed: {}", e),
        })?;

        // Write status line
        let status = response.status();
        let status_line = format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("OK")
        );
        stream.write_all(status_line.as_bytes()).await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to write status: {}", e),
        })?;

        // Write headers
        for (name, value) in response.headers() {
            let header = format!("{}: {}\r\n", name.as_str(), value.to_str().unwrap_or(""));
            stream.write_all(header.as_bytes()).await.map_err(|e| HyprError::InvalidConfig {
                reason: format!("Failed to write header: {}", e),
            })?;
        }
        stream.write_all(b"\r\n").await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to write header terminator: {}", e),
        })?;

        // Stream body
        let body = response.bytes().await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to read response body: {}", e),
        })?;

        stream.write_all(&body).await.map_err(|e| HyprError::InvalidConfig {
            reason: format!("Failed to write body: {}", e),
        })?;

        Ok(())
    }

    /// Check if a URL is allowed by the domain whitelist.
    fn is_allowed(url: &str, allowed_domains: &[String]) -> bool {
        // Empty whitelist = allow all
        if allowed_domains.is_empty() {
            return true;
        }

        // Check if URL contains any allowed domain
        allowed_domains.iter().any(|domain| url.contains(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_empty_allows_all() {
        assert!(BuilderHttpProxy::is_allowed("https://example.com", &[]));
        assert!(BuilderHttpProxy::is_allowed("http://evil.com", &[]));
    }

    #[test]
    fn test_whitelist_filters_domains() {
        let allowed = vec!["github.com".to_string(), "pypi.org".to_string()];

        assert!(BuilderHttpProxy::is_allowed("https://github.com/user/repo", &allowed));
        assert!(BuilderHttpProxy::is_allowed("https://pypi.org/packages/", &allowed));
        assert!(!BuilderHttpProxy::is_allowed("https://evil.com", &allowed));
    }
}
