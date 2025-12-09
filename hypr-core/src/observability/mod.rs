//! Observability infrastructure: tracing, metrics, health checks.
//!
//! This module provides the foundational observability layer for HYPR.
//! All components MUST use this infrastructure from Day 1.

use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod health;
pub mod metrics;

/// Check if OTLP tracing is enabled via environment variable.
/// Set HYPR_OTLP_ENABLED=1 or OTEL_EXPORTER_OTLP_ENDPOINT to enable.
fn otlp_enabled() -> bool {
    std::env::var("HYPR_OTLP_ENABLED").is_ok()
        || std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok()
}

/// Get the OTLP endpoint (default: http://localhost:4317 for Jaeger)
fn otlp_endpoint() -> String {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string())
}

/// Initialize the global observability infrastructure.
///
/// This must be called once at application startup before any other operations.
///
/// # Panics
/// Panics if called more than once or if initialization fails.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Build the base subscriber
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(tracing_subscriber::fmt::layer().with_target(true).with_level(true));

    // Conditionally add OTLP tracing layer
    if otlp_enabled() {
        let endpoint = otlp_endpoint();

        let exporter = opentelemetry_otlp::new_exporter().tonic().with_endpoint(&endpoint);

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(
                trace::config()
                    .with_sampler(Sampler::AlwaysOn)
                    .with_id_generator(RandomIdGenerator::default())
                    .with_resource(Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", "hyprd"),
                        opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        subscriber.with(telemetry).init();
        tracing::info!("Observability initialized with OTLP tracing (endpoint: {})", endpoint);
    } else {
        subscriber.init();
        tracing::info!(
            "Observability initialized (OTLP disabled - set HYPR_OTLP_ENABLED=1 to enable)"
        );
    }

    // Set up Prometheus metrics exporter
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], crate::ports::PORT_DAEMON_METRICS))
        .install()?;

    // Register core metrics
    metrics::register_core_metrics();

    Ok(())
}

/// Shutdown observability infrastructure gracefully.
pub fn shutdown() {
    opentelemetry::global::shutdown_tracer_provider();
}
