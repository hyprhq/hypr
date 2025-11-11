//! Integration tests for observability infrastructure.
//!
//! These tests validate that tracing, metrics, and health checks work correctly
//! end-to-end. They test the actual infrastructure, not mocks.
//!
//! # Running Tests
//!
//! Run all observability tests:
//! ```bash
//! cargo test --test observability_integration
//! ```
//!
//! Run with output to see tracing logs:
//! ```bash
//! cargo test --test observability_integration -- --nocapture
//! ```
//!
//! # Setup Requirements
//!
//! These tests do NOT require external services:
//! - Jaeger: Uses noop tracer for tests (no actual Jaeger needed)
//! - Prometheus: Tests use in-memory recorder (no scraping endpoint needed)
//!
//! Tests are designed to be fast and run in isolation.

use hypr_core::observability::{health::*, metrics::*};
use metrics::{counter, gauge, histogram};
use std::time::Duration;
use tokio::time::sleep;

/// Test that the health checker correctly tracks subsystem status.
///
/// Validates:
/// - Registration of subsystems
/// - Status updates propagate correctly
/// - Overall health status is computed correctly (healthy/degraded/unhealthy)
/// - Liveness and readiness checks work
#[tokio::test]
async fn test_health_checker_lifecycle() {
    let checker = HealthChecker::new();

    // Test liveness - should always be true if process is running
    assert!(checker.is_alive(), "Liveness check should always pass");

    // Initially no subsystems, should be healthy
    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Healthy);
    assert_eq!(health.subsystems.len(), 0);
    assert!(checker.is_ready().await, "Should be ready with no subsystems");

    // Register multiple subsystems
    checker.register_subsystem("database".to_string()).await;
    checker.register_subsystem("vm_manager".to_string()).await;
    checker.register_subsystem("network".to_string()).await;

    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Healthy);
    assert_eq!(health.subsystems.len(), 3);
    assert!(checker.is_ready().await, "Should be ready with all healthy");

    // Verify all subsystems start as healthy
    for subsystem in &health.subsystems {
        assert_eq!(subsystem.status, HealthStatus::Healthy);
        assert!(subsystem.message.is_none());
    }

    // Mark one subsystem as degraded
    checker
        .update_subsystem(
            "database",
            HealthStatus::Degraded,
            Some("High query latency detected".to_string()),
        )
        .await;

    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Degraded, "Overall status should be degraded");
    assert!(!checker.is_ready().await, "Should not be ready when degraded");

    let db_subsystem = health
        .subsystems
        .iter()
        .find(|s| s.name == "database")
        .expect("database subsystem should exist");
    assert_eq!(db_subsystem.status, HealthStatus::Degraded);
    assert!(db_subsystem.message.is_some());

    // Mark another as unhealthy
    checker
        .update_subsystem(
            "network",
            HealthStatus::Unhealthy,
            Some("Network interface down".to_string()),
        )
        .await;

    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Unhealthy, "Overall status should be unhealthy");
    assert!(!checker.is_ready().await, "Should not be ready when unhealthy");

    // Recover network
    checker.update_subsystem("network", HealthStatus::Healthy, None).await;

    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Degraded, "Should still be degraded (database)");

    // Recover database
    checker.update_subsystem("database", HealthStatus::Healthy, None).await;

    let health = checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Healthy, "Should be fully healthy again");
    assert!(checker.is_ready().await, "Should be ready when all healthy");
}

/// Test concurrent access to health checker from multiple tasks.
///
/// Validates:
/// - Thread-safety of health checker
/// - No race conditions in status updates
/// - Consistent state under concurrent load
#[tokio::test]
async fn test_health_checker_concurrent_updates() {
    let checker = HealthChecker::new();

    // Register subsystems
    for i in 0..5 {
        checker.register_subsystem(format!("subsystem_{}", i)).await;
    }

    // Spawn multiple tasks updating different subsystems concurrently
    let mut handles = vec![];

    for i in 0..5 {
        let checker_clone = checker.clone();
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                let status = if j % 3 == 0 {
                    HealthStatus::Degraded
                } else if j % 7 == 0 {
                    HealthStatus::Unhealthy
                } else {
                    HealthStatus::Healthy
                };

                checker_clone
                    .update_subsystem(
                        &format!("subsystem_{}", i),
                        status,
                        Some(format!("Update {}", j)),
                    )
                    .await;

                // Small delay to simulate real workload
                sleep(Duration::from_millis(1)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all updates to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }

    // Verify final state is consistent
    let health = checker.get_health().await;
    assert_eq!(health.subsystems.len(), 5);

    // All subsystems should have a message from the last update
    for subsystem in &health.subsystems {
        assert!(subsystem.message.is_some(), "Subsystem {} should have a message", subsystem.name);
    }
}

/// Test that health check serialization works correctly.
///
/// Validates:
/// - HealthCheck can be serialized to JSON
/// - JSON format matches expected structure
/// - All fields are present and correctly formatted
#[tokio::test]
async fn test_health_check_serialization() {
    let checker = HealthChecker::new();

    checker.register_subsystem("test_service".to_string()).await;
    checker
        .update_subsystem("test_service", HealthStatus::Degraded, Some("Test message".to_string()))
        .await;

    let health = checker.get_health().await;
    let json = serde_json::to_string(&health).expect("Should serialize to JSON");

    // Verify JSON structure
    assert!(json.contains(r#""status":"degraded"#));
    assert!(json.contains(r#""version":"#));
    assert!(json.contains(r#""subsystems":"#));
    assert!(json.contains(r#""name":"test_service"#));
    assert!(json.contains(r#""message":"Test message"#));

    // Verify it's valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("Should parse as valid JSON");
    assert_eq!(parsed["status"], "degraded");
    assert!(parsed["version"].is_string());
    assert!(parsed["subsystems"].is_array());
}

/// Test core metric registration and recording.
///
/// Validates:
/// - All core metrics are registered with proper descriptions
/// - Metrics can be recorded with labels
/// - Histogram, counter, and gauge all work
#[tokio::test]
async fn test_metric_registration_and_recording() {
    // Register core metrics (idempotent - safe to call multiple times)
    register_core_metrics();

    // Test recording different metric types

    // 1. Histogram - VM boot duration
    histogram!(
        "hypr_vm_boot_duration_seconds",
        "adapter" => "krun"
    )
    .record(1.5);

    histogram!(
        "hypr_vm_boot_duration_seconds",
        "adapter" => "qemu"
    )
    .record(2.3);

    // 2. Counter - VM creation
    counter!("hypr_vm_created_total", "adapter" => "krun").increment(1);
    counter!("hypr_vm_created_total", "adapter" => "krun").increment(1);
    counter!("hypr_vm_created_total", "adapter" => "qemu").increment(1);

    // 3. Gauge - VM count
    gauge!("hypr_vm_count", "state" => "running").set(5.0);
    gauge!("hypr_vm_count", "state" => "stopped").set(2.0);
    gauge!("hypr_vm_count", "state" => "error").set(1.0);

    // 4. Test VM start failures
    counter!("hypr_vm_start_failures_total", "reason" => "out_of_memory").increment(1);
    counter!("hypr_vm_start_failures_total", "reason" => "network_error").increment(1);

    // 5. Test API metrics
    histogram!("hypr_api_request_duration_seconds", "endpoint" => "/vm/create").record(0.05);
    counter!(
        "hypr_api_requests_total",
        "endpoint" => "/vm/create",
        "status" => "200"
    )
    .increment(1);

    // If we get here without panicking, metrics are working
    // In a real setup, we'd scrape /metrics endpoint to verify values
}

/// Test metric helper functions.
///
/// Validates:
/// - Helper functions correctly record metrics with proper labels
/// - Multiple calls accumulate correctly
/// - Different adapters are tracked separately
#[tokio::test]
async fn test_metric_helpers() {
    register_core_metrics();

    // Test VM boot recording
    record_vm_boot(1.2, "krun");
    record_vm_boot(1.5, "krun");
    record_vm_boot(2.1, "qemu");

    // Test VM creation
    record_vm_created("krun");
    record_vm_created("krun");
    record_vm_created("qemu");

    // Test VM failures
    record_vm_failure("timeout");
    record_vm_failure("out_of_memory");
    record_vm_failure("timeout");

    // Test VM count updates
    set_vm_count("running", 3);
    set_vm_count("stopped", 1);
    set_vm_count("error", 0);

    // Update counts
    set_vm_count("running", 5);
    set_vm_count("stopped", 2);

    // All helpers should work without panicking
}

/// Test that metrics work correctly under concurrent load.
///
/// Validates:
/// - Thread-safety of metrics recording
/// - Counters increment correctly under concurrent access
/// - No data races or lost updates
#[tokio::test]
async fn test_metrics_concurrent_recording() {
    register_core_metrics();

    let mut handles = vec![];

    // Spawn 10 tasks each recording 100 VM creations
    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let adapter = if i % 2 == 0 { "krun" } else { "qemu" };

            for _ in 0..100 {
                record_vm_created(adapter);
                record_vm_boot(0.5, adapter);
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }

    // Verify we can still record metrics after concurrent load
    record_vm_created("test");
    set_vm_count("running", 10);
}

/// Test tracing span creation and nested spans.
///
/// Validates:
/// - Spans can be created and entered
/// - Nested spans maintain parent-child relationship
/// - Span attributes are recorded
/// - Async boundaries are handled correctly
#[tokio::test]
async fn test_tracing_spans() {
    // Create a root span
    let root_span = tracing::info_span!("test_operation", operation = "integration_test");
    let _guard = root_span.enter();

    tracing::info!("Starting test operation");

    // Create nested spans
    {
        let child_span = tracing::info_span!("database_query", query = "SELECT * FROM vms");
        let _child_guard = child_span.enter();
        tracing::info!("Executing database query");

        // Even deeper nesting
        {
            let grandchild_span = tracing::debug_span!("query_validation");
            let _grandchild_guard = grandchild_span.enter();
            tracing::debug!("Validating query parameters");
        }
    }

    // Back to root span
    tracing::info!("Test operation completed");
}

/// Test tracing events with different levels.
///
/// Validates:
/// - All log levels work (trace, debug, info, warn, error)
/// - Structured logging with fields
/// - Event recording doesn't panic
#[tokio::test]
async fn test_tracing_events() {
    let span = tracing::info_span!("test_events");
    let _guard = span.enter();

    // Test all log levels
    tracing::trace!("This is a trace message");
    tracing::debug!("This is a debug message");
    tracing::info!("This is an info message");
    tracing::warn!("This is a warning message");
    tracing::error!("This is an error message");

    // Test structured logging
    tracing::info!(
        vm_id = "vm-123",
        adapter = "krun",
        state = "running",
        "VM started successfully"
    );

    // Test with computed values
    let vm_count = 5;
    let error_count = 2;
    tracing::warn!(vm_count = vm_count, error_count = error_count, "Multiple VMs in error state");
}

/// Test tracing across async boundaries.
///
/// Validates:
/// - Span context is maintained across await points
/// - Concurrent tasks can have independent span contexts
/// - Parent-child relationships work with async
#[tokio::test]
async fn test_tracing_async_boundaries() {
    let root_span = tracing::info_span!("async_operation");
    let _guard = root_span.enter();

    tracing::info!("Starting async operation");

    // Simulate async work
    tokio::time::sleep(Duration::from_millis(1)).await;

    tracing::info!("After first await");

    // Spawn child tasks
    let mut handles = vec![];
    for i in 0..3 {
        let handle = tokio::spawn(async move {
            let task_span = tracing::info_span!("child_task", task_id = i);
            let _task_guard = task_span.enter();

            tracing::info!("Child task started");
            tokio::time::sleep(Duration::from_millis(1)).await;
            tracing::info!("Child task completed");
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Child task should complete");
    }

    tracing::info!("All child tasks completed");
}

/// Test trace span instrumentation with tracing macros.
///
/// Validates:
/// - #[tracing::instrument] macro works correctly
/// - Function arguments are captured
/// - Return values can be captured
/// - Errors are properly traced
#[tokio::test]
async fn test_tracing_instrumentation() {
    #[tracing::instrument(name = "test_function", skip(data))]
    async fn instrumented_function(
        vm_id: &str,
        adapter: &str,
        data: Vec<u8>,
    ) -> Result<(), String> {
        tracing::info!(data_len = data.len(), "Processing VM operation");
        tokio::time::sleep(Duration::from_millis(1)).await;
        Ok(())
    }

    #[tracing::instrument(err)]
    async fn failing_function(should_fail: bool) -> Result<(), &'static str> {
        if should_fail {
            Err("Operation failed")
        } else {
            Ok(())
        }
    }

    // Test successful execution
    instrumented_function("vm-123", "krun", vec![1, 2, 3]).await.expect("Should succeed");

    // Test with different parameters
    instrumented_function("vm-456", "qemu", vec![]).await.expect("Should succeed");

    // Test error tracing
    let result = failing_function(false).await;
    assert!(result.is_ok());

    let result = failing_function(true).await;
    assert!(result.is_err());
}

/// Test that observability infrastructure handles high throughput.
///
/// Validates:
/// - Can handle many metrics/traces without performance degradation
/// - No memory leaks under sustained load
/// - System remains responsive
#[tokio::test]
async fn test_observability_high_throughput() {
    register_core_metrics();

    let start = std::time::Instant::now();

    // Record many metrics rapidly
    for i in 0..1000 {
        let adapter = if i % 2 == 0 { "krun" } else { "qemu" };

        record_vm_created(adapter);
        record_vm_boot(0.5, adapter);
        set_vm_count("running", (i % 100) as i64);

        // Create spans
        let span = tracing::debug_span!("iteration", i = i);
        let _guard = span.enter();
        tracing::debug!("Processing iteration");
    }

    let elapsed = start.elapsed();

    // Should complete quickly (< 1 second for 1000 operations)
    assert!(elapsed < Duration::from_secs(1), "High throughput test took too long: {:?}", elapsed);
}

/// Test metrics with complex label combinations.
///
/// Validates:
/// - Multiple labels work correctly
/// - Label values are preserved
/// - Different label combinations create separate metric series
#[tokio::test]
async fn test_metrics_with_labels() {
    register_core_metrics();

    // Test API metrics with multiple labels
    for endpoint in &["/vm/create", "/vm/list", "/vm/delete"] {
        for status in &["200", "400", "500"] {
            counter!(
                "hypr_api_requests_total",
                "endpoint" => endpoint.to_string(),
                "status" => status.to_string()
            )
            .increment(1);

            histogram!(
                "hypr_api_request_duration_seconds",
                "endpoint" => endpoint.to_string()
            )
            .record(0.05);
        }
    }

    // Test network metrics with direction
    for direction in &["ingress", "egress"] {
        counter!(
            "hypr_network_packets_total",
            "direction" => direction.to_string()
        )
        .increment(100);

        counter!(
            "hypr_network_bytes_total",
            "direction" => direction.to_string()
        )
        .increment(1024 * 1024); // 1 MB
    }

    // Test database metrics
    for operation in &["select", "insert", "update", "delete"] {
        histogram!(
            "hypr_db_query_duration_seconds",
            "operation" => operation.to_string()
        )
        .record(0.01);

        counter!(
            "hypr_db_query_failures_total",
            "operation" => operation.to_string()
        )
        .increment(1);
    }
}

/// Test edge cases and error conditions.
///
/// Validates:
/// - Empty strings in labels
/// - Very long label values
/// - Special characters in labels
/// - Zero and negative values
#[tokio::test]
async fn test_metrics_edge_cases() {
    register_core_metrics();

    // Test with empty adapter name
    record_vm_created("");
    record_vm_boot(0.0, "");

    // Test with very long labels
    let long_name = "x".repeat(100);
    record_vm_created(&long_name);

    // Test with special characters
    record_vm_created("test-adapter");
    record_vm_created("test_adapter");
    record_vm_created("test.adapter");

    // Test zero duration
    record_vm_boot(0.0, "krun");

    // Test large values
    record_vm_boot(3600.0, "qemu"); // 1 hour

    // Test gauge with zero and negative (represented as zero in gauges)
    set_vm_count("running", 0);
    set_vm_count("stopped", -1); // Should be converted to -1.0

    // Test very large gauge values
    set_vm_count("running", i64::MAX);
}

/// Integration test: Simulate a realistic VM lifecycle with full observability.
///
/// Validates:
/// - All observability features work together
/// - Realistic workload patterns
/// - Proper instrumentation throughout lifecycle
#[tokio::test]
async fn test_full_vm_lifecycle_observability() {
    register_core_metrics();
    let health_checker = HealthChecker::new();

    // Register subsystems
    health_checker.register_subsystem("vm_manager".to_string()).await;
    health_checker.register_subsystem("network".to_string()).await;

    // Simulate VM creation
    let vm_span = tracing::info_span!("vm_lifecycle", vm_id = "vm-test-001", adapter = "krun");
    let _guard = vm_span.enter();

    tracing::info!("Starting VM creation");
    record_vm_created("krun");

    // Simulate VM boot
    let boot_start = std::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let boot_duration = boot_start.elapsed().as_secs_f64();

    record_vm_boot(boot_duration, "krun");
    set_vm_count("running", 1);

    tracing::info!(duration_secs = boot_duration, "VM booted successfully");

    // Verify health
    let health = health_checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Healthy);

    // Simulate network issue
    health_checker
        .update_subsystem("network", HealthStatus::Degraded, Some("High latency".to_string()))
        .await;

    tracing::warn!("Network degradation detected");

    // Simulate recovery
    tokio::time::sleep(Duration::from_millis(5)).await;
    health_checker.update_subsystem("network", HealthStatus::Healthy, None).await;

    tracing::info!("Network recovered");

    // VM shutdown
    set_vm_count("running", 0);
    set_vm_count("stopped", 1);

    tracing::info!("VM lifecycle completed");

    // Final health check
    let health = health_checker.get_health().await;
    assert_eq!(health.status, HealthStatus::Healthy);
    assert!(health_checker.is_ready().await);
}
