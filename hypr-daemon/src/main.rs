//! HYPR Daemon (hyprd)
//!
//! The background service that manages VMs, networking, and state.
//!
//! ## Modes of Operation
//!
//! - **Normal mode** (default): Long-running daemon managed by launchd/systemd
//! - **Ephemeral mode**: Starts for a single operation, exits after idle timeout
//!
//! ```bash
//! # Normal mode
//! hyprd
//!
//! # Ephemeral mode (for daemonless builds)
//! hyprd --ephemeral --socket /tmp/hypr-$$.sock --idle-timeout 30
//! ```

use clap::Parser;
use hypr_core::{
    adapters::AdapterFactory, init_observability, shutdown_observability, HealthChecker,
    StateManager,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

#[allow(unused_imports)]
mod api;
mod network_manager;
mod orchestrator;
mod proto_convert;
mod reconcile;
mod shutdown;

/// HYPR Daemon - manages VMs, networking, and state
#[derive(Parser, Debug)]
#[command(name = "hyprd", version, about)]
struct Args {
    /// Run in ephemeral mode (exits after idle timeout)
    #[arg(long)]
    ephemeral: bool,

    /// Custom socket path (default: /tmp/hypr.sock)
    #[arg(long)]
    socket: Option<String>,

    /// Idle timeout in seconds for ephemeral mode (default: 30)
    #[arg(long, default_value = "30")]
    idle_timeout: u64,

    /// Skip DNS resolver setup
    #[arg(long)]
    skip_dns: bool,

    /// Skip state reconciliation
    #[arg(long)]
    skip_reconcile: bool,
}

/// Tracks the last activity time for ephemeral mode idle detection
pub static LAST_ACTIVITY: AtomicU64 = AtomicU64::new(0);

/// Update the last activity timestamp (called on each gRPC request)
pub fn touch_activity() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    LAST_ACTIVITY.store(now, Ordering::Relaxed);
}

/// Get seconds since last activity
fn secs_since_activity() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_ACTIVITY.load(Ordering::Relaxed);
    if last == 0 {
        0 // Never had activity, treat as just started
    } else {
        now.saturating_sub(last)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize observability FIRST
    init_observability()?;

    if args.ephemeral {
        info!("HYPR daemon starting in EPHEMERAL mode (idle timeout: {}s)", args.idle_timeout);
    } else {
        info!("HYPR daemon starting");
    }

    // Initialize activity tracker
    touch_activity();

    // Ensure data directory exists with proper permissions (adds ACL on macOS)
    hypr_core::paths::ensure_data_dir()?;

    // Write PID file for single-instance enforcement (skip in ephemeral mode)
    let pid_path = if args.ephemeral {
        // Use unique PID file for ephemeral instances
        hypr_core::paths::runtime_dir().join(format!("hyprd-{}.pid", std::process::id()))
    } else {
        hypr_core::paths::runtime_dir().join("hyprd.pid")
    };

    if !args.ephemeral {
        write_pid_file(&pid_path)?;
    }

    // Initialize health checker
    let health_checker = HealthChecker::new();
    health_checker.register_subsystem("daemon".to_string()).await;

    // Initialize state manager (uses centralized paths)
    let db_path = hypr_core::paths::db_path();
    let db_path_str = db_path.to_string_lossy().to_string();

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    info!("Initializing state manager at {}", db_path_str);
    let state = Arc::new(
        StateManager::new(&db_path_str).await.expect("Failed to initialize state manager"),
    );
    health_checker.register_subsystem("database".to_string()).await;

    // Create VMM adapter using the factory (auto-detects platform)
    info!("Initializing VMM adapter");
    let adapter = match AdapterFactory::create(None) {
        Ok(adapter) => {
            info!(
                adapter = adapter.name(),
                capabilities = ?adapter.capabilities(),
                "VMM adapter initialized successfully"
            );
            adapter
        }
        Err(e) => {
            error!("Failed to create VMM adapter: {}", e);
            return Err(format!("VMM adapter initialization failed: {}", e).into());
        }
    };

    health_checker.register_subsystem("adapter".to_string()).await;

    // Initialize network manager
    info!("Initializing network manager");
    let network_mgr = match network_manager::NetworkManager::new(state.clone()).await {
        Ok(mgr) => {
            info!("Network manager initialized successfully");
            Arc::new(mgr)
        }
        Err(e) => {
            error!("Failed to create network manager: {}", e);
            return Err(format!("Network manager initialization failed: {}", e).into());
        }
    };

    // Determine socket path
    let socket_path = args.socket.clone().unwrap_or_else(|| "/tmp/hypr.sock".to_string());
    health_checker.register_subsystem("networking".to_string()).await;

    // Start DNS server for service discovery (*.hypr domains) - skip in ephemeral mode
    if !args.ephemeral {
        network_mgr.start_dns_server();
    }

    // Reconcile state from previous run (skip in ephemeral mode or if requested)
    if !args.ephemeral && !args.skip_reconcile {
        info!("Reconciling state from previous session...");
        let reconciler =
            reconcile::StateReconciler::new(state.clone(), adapter.clone(), network_mgr.clone());

        match reconciler.reconcile().await {
            Ok(report) => {
                if report.orphaned > 0
                    || report.orphaned_taps > 0
                    || report.orphaned_vfio > 0
                    || report.orphaned_virtiofsd > 0
                {
                    info!(
                        "Reconciliation cleaned up orphaned resources: {} VMs, {} TAPs, {} VFIO, {} virtiofsd",
                        report.orphaned, report.orphaned_taps, report.orphaned_vfio, report.orphaned_virtiofsd
                    );
                }
                info!("State reconciliation complete: {} running VMs", report.running);
            }
            Err(e) => {
                warn!("State reconciliation failed (continuing anyway): {}", e);
            }
        }
    }

    // Setup host DNS resolver (skip in ephemeral mode or if requested)
    if !args.ephemeral && !args.skip_dns {
        if let Err(e) = setup_host_dns_resolver().await {
            warn!("Failed to setup host DNS resolver: {} (host cannot resolve *.hypr domains)", e);
        }
    }

    info!("HYPR daemon ready (socket: {})", socket_path);

    // Create shutdown manager
    let shutdown_mgr =
        shutdown::ShutdownManager::new(state.clone(), adapter.clone(), network_mgr.clone());

    // Start gRPC API server with custom socket path
    let api_handle = tokio::spawn(api::start_api_server_at(
        state.clone(),
        adapter.clone(),
        network_mgr.clone(),
        socket_path.clone(),
    ));

    // Wait for shutdown signal or idle timeout (in ephemeral mode)
    let mut shutdown_rx = shutdown::shutdown_signal();
    let idle_timeout = args.idle_timeout;
    let is_ephemeral = args.ephemeral;

    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("Received shutdown signal, initiating graceful shutdown...");
        }
        result = api_handle => {
            match result {
                Ok(Ok(())) => info!("API server exited normally"),
                Ok(Err(e)) => error!("API server error: {}", e),
                Err(e) => error!("API server task panicked: {}", e),
            }
        }
        _ = async {
            if is_ephemeral {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let idle_secs = secs_since_activity();
                    if idle_secs >= idle_timeout {
                        info!("Ephemeral daemon idle for {}s, shutting down", idle_secs);
                        break;
                    }
                }
            } else {
                // In non-ephemeral mode, this future never completes
                std::future::pending::<()>().await;
            }
        } => {
            info!("Idle timeout reached, initiating graceful shutdown...");
        }
    }

    // Perform graceful shutdown (skip in ephemeral mode for faster exit)
    if !is_ephemeral {
        if let Err(e) = shutdown_mgr.shutdown().await {
            error!("Error during shutdown: {}", e);
        }
    }

    // Clean up PID file
    let _ = std::fs::remove_file(&pid_path);

    // Clean up ephemeral socket
    if is_ephemeral {
        let _ = std::fs::remove_file(&socket_path);
    }

    info!("HYPR daemon shut down");
    shutdown_observability();
    Ok(())
}

/// Write PID file and check for stale instances.
fn write_pid_file(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check if PID file exists and if process is still running
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                // Check if process is still alive
                if unsafe { libc::kill(pid, 0) } == 0 {
                    return Err(format!(
                        "Another hyprd instance is already running (PID {}). \
                         If this is incorrect, remove {}",
                        pid,
                        path.display()
                    )
                    .into());
                }
            }
        }
        // Stale PID file - remove it
        let _ = std::fs::remove_file(path);
    }

    // Write our PID
    std::fs::write(path, std::process::id().to_string())?;
    Ok(())
}

/// Setup host DNS resolver to resolve *.hypr domains.
async fn setup_host_dns_resolver() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        use std::path::Path;

        let resolver_dir = Path::new("/etc/resolver");
        let resolver_file = resolver_dir.join("hypr");

        // Get the gateway IP (DNS server address)
        let dns_ip = "192.168.64.1"; // macOS vmnet gateway

        // Create /etc/resolver directory if it doesn't exist
        if !resolver_dir.exists() {
            info!("Creating /etc/resolver directory...");
            if let Err(e) = fs::create_dir_all(resolver_dir) {
                return Err(
                    format!("Failed to create /etc/resolver (may require sudo): {}", e).into()
                );
            }
        }

        // Write resolver configuration
        let config = format!("nameserver {}\n", dns_ip);
        info!("Setting up /etc/resolver/hypr to point to {}", dns_ip);

        if let Err(e) = fs::write(&resolver_file, &config) {
            return Err(
                format!("Failed to write /etc/resolver/hypr (may require sudo): {}", e).into()
            );
        }

        info!("Host DNS resolver configured: *.hypr -> {}", dns_ip);
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::path::Path;

        // Try systemd-resolved first
        let resolved_conf_dir = Path::new("/etc/systemd/resolved.conf.d");
        let resolved_conf = resolved_conf_dir.join("hypr.conf");

        // Get the gateway IP (DNS server address)
        let dns_ip = "10.88.0.1"; // Linux bridge gateway

        if resolved_conf_dir.exists() || Path::new("/etc/systemd/resolved.conf").exists() {
            // systemd-resolved is available
            info!("Setting up systemd-resolved for *.hypr domains...");

            // Create config directory if needed
            if !resolved_conf_dir.exists() {
                if let Err(e) = fs::create_dir_all(resolved_conf_dir) {
                    warn!("Could not create resolved.conf.d: {} (may require sudo)", e);
                }
            }

            // Write drop-in configuration
            let config = format!("[Resolve]\nDNS={}\nDomains=~hypr\n", dns_ip);

            if let Err(e) = fs::write(&resolved_conf, &config) {
                warn!("Could not write resolved config: {} (may require sudo)", e);
                // Fall through to try alternative method
            } else {
                // Restart systemd-resolved to pick up the change
                let status = std::process::Command::new("systemctl")
                    .args(["restart", "systemd-resolved"])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        info!(
                            "Host DNS resolver configured via systemd-resolved: *.hypr -> {}",
                            dns_ip
                        );
                        return Ok(());
                    }
                    _ => {
                        warn!("Could not restart systemd-resolved");
                    }
                }
            }
        }

        // Fallback: Try resolvectl directly
        let status =
            std::process::Command::new("resolvectl").args(["dns", "vbr0", dns_ip]).status();

        if let Ok(s) = status {
            if s.success() {
                let _ = std::process::Command::new("resolvectl")
                    .args(["domain", "vbr0", "~hypr"])
                    .status();
                info!("Host DNS resolver configured via resolvectl: *.hypr -> {}", dns_ip);
                return Ok(());
            }
        }

        // Last resort: Log instructions
        warn!(
            "Could not configure host DNS resolver automatically. \
             To resolve *.hypr domains, add 'nameserver {}' to /etc/resolv.conf \
             or configure your DNS server to forward .hypr to {}",
            dns_ip, dns_ip
        );
    }

    Ok(())
}
