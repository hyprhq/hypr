use hypr_core::{init_observability, shutdown_observability, HealthChecker};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize observability FIRST
    init_observability()?;

    info!("HYPR daemon starting");

    // Initialize health checker
    let health_checker = HealthChecker::new();
    health_checker.register_subsystem("daemon".to_string()).await;

    // TODO: Initialize other subsystems here
    // - Database
    // - VMM adapters
    // - Network manager
    // - API server

    info!("HYPR daemon ready");

    // Keep daemon running (placeholder)
    tokio::signal::ctrl_c().await?;

    info!("HYPR daemon shutting down");
    shutdown_observability();
    Ok(())
}
