//! HYPR dedicated port range.
//!
//! Developers run many services (Prometheus on 9090, proxies on 3128, dev servers
//! on 3000, etc.). To avoid conflicts, HYPR uses a dedicated high port range
//! that's unlikely to conflict with normal applications.
//!
//! All HYPR internal services use ports in the 41000-41999 range.

/// HYPR dedicated port range start (inclusive)
pub const HYPR_PORT_RANGE_START: u16 = 41000;

/// HYPR dedicated port range end (inclusive)
pub const HYPR_PORT_RANGE_END: u16 = 41999;

// ============================================================================
// Core Daemon Ports
// ============================================================================

/// hyprd gRPC API server
pub const PORT_DAEMON_GRPC: u16 = 41000;

/// hyprd REST gateway
pub const PORT_DAEMON_REST: u16 = 41001;

/// hyprd Prometheus /metrics endpoint
pub const PORT_DAEMON_METRICS: u16 = 41002;

// ============================================================================
// Networking Ports
// ============================================================================

/// DNS server (replaces standard port 53 to avoid sudo requirement)
pub const PORT_DNS: u16 = 41003;

/// Service registry API
pub const PORT_SERVICE_REGISTRY: u16 = 41004;

// ============================================================================
// Builder Ports
// ============================================================================

/// HTTP/HTTPS proxy for builder VMs (replaces standard proxy port 3128)
///
/// Builder VMs have no network interface. Instead, they proxy all HTTP traffic
/// through vsock to this port on the host, which forwards to the real internet.
pub const PORT_BUILD_PROXY: u16 = 41010;

/// Builder agent vsock communication port
///
/// The builder-agent.c running in Alpine VMs listens on this vsock port for
/// build commands (RUN, COPY, etc.) from the host.
pub const PORT_BUILD_AGENT: u16 = 41011;

// ============================================================================
// Reserved for Future Use
// ============================================================================

// 41020-41999: Available for future HYPR services
