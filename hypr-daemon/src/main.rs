use hypr_core::{init_observability, HealthChecker, StateManager};
use std::sync::Arc;
use tracing::info;

#[cfg(all(target_os = "macos", feature = "krun"))]
use hypr_core::{adapters::VmmAdapter, shutdown_observability};

#[allow(unused_imports)]
mod api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize observability FIRST
    init_observability()?;

    info!("HYPR daemon starting");

    // Initialize health checker
    let health_checker = HealthChecker::new();
    health_checker.register_subsystem("daemon".to_string()).await;

    // Initialize state manager
    let db_path = std::env::var("HYPR_DB_PATH").unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("HOME not set");
        format!("{}/.hypr/hypr.db", home)
    });

    info!("Initializing state manager at {}", db_path);
    let _state =
        Arc::new(StateManager::new(&db_path).await.expect("Failed to initialize state manager"));
    health_checker.register_subsystem("database".to_string()).await;

    // Create VMM adapter (stub for now - will use KrunAdapter on macOS with feature flag)
    #[cfg(all(target_os = "macos", feature = "krun"))]
    {
        info!("Initializing VMM adapter");
        let _adapter: Arc<dyn VmmAdapter> = Arc::new(
            hypr_core::adapters::KrunAdapter::new().expect("Failed to create KrunAdapter"),
        );

        health_checker.register_subsystem("adapter".to_string()).await;
        info!("HYPR daemon ready");

        // Start gRPC API server (commented out due to adapter not being ready in Phase 2.0)
        // let api_handle = tokio::spawn(api::start_api_server(_state.clone(), _adapter.clone()));

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        info!("Received shutdown signal");

        info!("HYPR daemon shutting down");
        shutdown_observability();
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", feature = "krun")))]
    {
        // For Phase 2.0, we need an adapter but none is available
        // In production, this would be cloud-hypervisor on Linux
        tracing::error!("No VMM adapter available for this platform");
        Err("VMM adapter not available".into())
    }
}
