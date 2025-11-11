//! Core metrics definitions.
//!
//! All metrics follow Prometheus naming conventions:
//! - `_total` suffix for counters
//! - `_seconds` suffix for histograms measuring duration
//! - `_bytes` suffix for gauges measuring size

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};

/// Register all core metrics with descriptions.
///
/// This ensures metrics appear in `/metrics` with proper metadata.
pub fn register_core_metrics() {
    // VM lifecycle metrics
    describe_histogram!(
        "hypr_vm_boot_duration_seconds",
        "Time taken to boot a VM from create to running state"
    );
    describe_counter!("hypr_vm_created_total", "Total number of VMs created (by adapter)");
    describe_counter!("hypr_vm_started_total", "Total number of VMs successfully started");
    describe_counter!(
        "hypr_vm_start_failures_total",
        "Total number of VM start failures (by reason)"
    );
    describe_gauge!("hypr_vm_count", "Current number of VMs (by state: running, stopped, error)");

    // API metrics
    describe_counter!(
        "hypr_api_requests_total",
        "Total number of API requests (by endpoint, status)"
    );
    describe_histogram!("hypr_api_request_duration_seconds", "API request duration (by endpoint)");

    // Build metrics
    describe_histogram!("hypr_build_duration_seconds", "Image build duration (by image name)");
    describe_counter!("hypr_build_failures_total", "Total number of build failures (by reason)");

    // Network metrics
    describe_counter!(
        "hypr_network_packets_total",
        "Total network packets processed (by direction: ingress, egress)"
    );
    describe_counter!(
        "hypr_network_bytes_total",
        "Total network bytes transferred (by direction: ingress, egress)"
    );

    // Database metrics
    describe_histogram!("hypr_db_query_duration_seconds", "Database query duration (by operation)");
    describe_counter!(
        "hypr_db_query_failures_total",
        "Total database query failures (by operation)"
    );
}

/// Helper functions for common metric patterns
pub fn record_vm_boot(duration_secs: f64, adapter: &str) {
    histogram!("hypr_vm_boot_duration_seconds", "adapter" => adapter.to_string())
        .record(duration_secs);
    counter!("hypr_vm_started_total").increment(1);
}

pub fn record_vm_created(adapter: &str) {
    counter!("hypr_vm_created_total", "adapter" => adapter.to_string()).increment(1);
}

pub fn record_vm_failure(reason: &str) {
    counter!("hypr_vm_start_failures_total", "reason" => reason.to_string()).increment(1);
}

pub fn set_vm_count(state: &str, count: i64) {
    gauge!("hypr_vm_count", "state" => state.to_string()).set(count as f64);
}
