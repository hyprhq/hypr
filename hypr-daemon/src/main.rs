use hypr_core::{adapters::AdapterFactory, init_observability, shutdown_observability, HealthChecker, StateManager};
use std::sync::Arc;
use tracing::{error, info};

#[allow(unused_imports)]
mod api;
mod orchestrator;
mod proto_convert;

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

    // Create VMM adapter using the factory (auto-detects platform)
    info!("Initializing VMM adapter");
    let _adapter = match AdapterFactory::create(None) {
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
    info!("HYPR daemon ready");

    // Start gRPC API server
    let api_handle = tokio::spawn(api::start_api_server(_state.clone(), _adapter.clone()));

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Received shutdown signal");

    // Abort API server
    api_handle.abort();
    let _ = api_handle.await;

    info!("HYPR daemon shutting down");
    shutdown_observability();
    Ok(())
}
