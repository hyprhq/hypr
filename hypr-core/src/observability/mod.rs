//! Observability infrastructure: tracing, metrics, health checks.
//!
//! This module provides the foundational observability layer for HYPR.
//! All components MUST use this infrastructure from Day 1.

use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod health;
pub mod metrics;

/// Initialize the global observability infrastructure.
///
/// This must be called once at application startup before any other operations.
///
/// # Panics
/// Panics if called more than once or if initialization fails.
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set up OpenTelemetry tracer
    #[allow(deprecated)]
    let tracer = opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name("hyprd")
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

    // 2. Set up tracing subscriber with multiple layers
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(tracing_subscriber::fmt::layer().with_target(true).with_level(true))
        .with(telemetry)
        .init();

    // 3. Set up Prometheus metrics exporter
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], crate::ports::PORT_DAEMON_METRICS))
        .install()?;

    // 4. Register core metrics
    metrics::register_core_metrics();

    tracing::info!("Observability infrastructure initialized");
    Ok(())
}

/// Shutdown observability infrastructure gracefully.
pub fn shutdown() {
    opentelemetry::global::shutdown_tracer_provider();
}
