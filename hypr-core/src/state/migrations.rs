//! Database migrations.

use crate::error::{HyprError, Result};
use sqlx::SqlitePool;
use tracing::{info, instrument};

const SCHEMA_VERSION: i64 = 7;

#[instrument(skip(pool))]
pub async fn run(pool: &SqlitePool) -> Result<()> {
    // Create schema_version table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Get current schema version
    let current_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM schema_version LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    let current_version = current_version.unwrap_or(0);

    if current_version >= SCHEMA_VERSION {
        info!("Database schema is up to date (version {})", current_version);
        return Ok(());
    }

    info!("Migrating database from version {} to {}", current_version, SCHEMA_VERSION);

    // Run migrations
    if current_version < 1 {
        migrate_to_v1(pool).await?;
    }

    if current_version < 2 {
        migrate_to_v2(pool).await?;
    }

    if current_version < 3 {
        migrate_to_v3(pool).await?;
    }

    if current_version < 4 {
        migrate_to_v4(pool).await?;
    }

    if current_version < 5 {
        migrate_to_v5(pool).await?;
    }

    if current_version < 6 {
        migrate_to_v6(pool).await?;
    }

    if current_version < 7 {
        migrate_to_v7(pool).await?;
    }

    Ok(())
}

#[instrument(skip(pool))]
async fn migrate_to_v1(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 1");

    // Images table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS images (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            tag TEXT NOT NULL DEFAULT 'latest',
            manifest TEXT NOT NULL,
            rootfs_path TEXT NOT NULL,
            size_bytes INTEGER,
            created_at INTEGER NOT NULL,
            UNIQUE(name, tag)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_images_name_tag ON images(name, tag)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // VMs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vms (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            image_id TEXT NOT NULL,
            status TEXT NOT NULL,
            config TEXT NOT NULL,
            ip_address TEXT,
            pid INTEGER,
            vsock_path TEXT,
            created_at INTEGER NOT NULL,
            started_at INTEGER,
            stopped_at INTEGER
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vms_status ON vms(status)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vms_ip ON vms(ip_address)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Volumes table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS volumes (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            path TEXT NOT NULL,
            size_bytes INTEGER,
            created_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // VM-Volume join table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vm_volumes (
            vm_id TEXT REFERENCES vms(id) ON DELETE CASCADE,
            volume_id TEXT REFERENCES volumes(id) ON DELETE CASCADE,
            mount_path TEXT NOT NULL,
            PRIMARY KEY (vm_id, volume_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Networks table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS networks (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            cidr TEXT NOT NULL,
            bridge_name TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Stacks table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stacks (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            compose_path TEXT,
            state TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Stack-VM join table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stack_vms (
            stack_id TEXT REFERENCES stacks(id) ON DELETE CASCADE,
            vm_id TEXT REFERENCES vms(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            PRIMARY KEY (stack_id, vm_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(1i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 1 complete");
    Ok(())
}

#[instrument(skip(pool))]
async fn migrate_to_v2(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 2");

    // IP allocations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ip_allocations (
            ip_address TEXT PRIMARY KEY,
            vm_id TEXT NOT NULL UNIQUE,
            allocated_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ip_allocations_vm ON ip_allocations(vm_id)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(2i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 2 complete");
    Ok(())
}

#[instrument(skip(pool))]
async fn migrate_to_v3(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 3");

    // Services table for service registry (Phase 2 networking)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS services (
            name TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            ports TEXT NOT NULL,
            labels TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(3i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 3 complete");
    Ok(())
}

/// Migration to schema version 4: Add driver and gateway to networks table.
async fn migrate_to_v4(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 4");

    // Add driver column with default 'bridge'
    sqlx::query(
        r#"
        ALTER TABLE networks ADD COLUMN driver TEXT NOT NULL DEFAULT 'bridge'
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Add gateway column (derived from CIDR - first usable IP)
    // For existing networks, we'll default to .1 of the subnet
    sqlx::query(
        r#"
        ALTER TABLE networks ADD COLUMN gateway TEXT NOT NULL DEFAULT '10.88.0.1'
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(4i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 4 complete");
    Ok(())
}

/// Migration to schema version 5: Add snapshots table.
async fn migrate_to_v5(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 5");

    // Snapshots table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY,
            vm_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'creating',
            snapshot_type TEXT NOT NULL DEFAULT 'disk',
            path TEXT NOT NULL,
            labels TEXT NOT NULL DEFAULT '{}'
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for VM lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_snapshots_vm ON snapshots(vm_id)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for state filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_snapshots_state ON snapshots(state)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(5i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 5 complete");
    Ok(())
}

/// Migration to schema version 6: Add metrics_history table for time-series data.
async fn migrate_to_v6(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 6");

    // Metrics history table for time-series data
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vm_id TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            cpu_percent REAL NOT NULL DEFAULT 0,
            memory_percent REAL NOT NULL DEFAULT 0,
            memory_used_bytes INTEGER NOT NULL DEFAULT 0,
            net_rx_rate REAL NOT NULL DEFAULT 0,
            net_tx_rate REAL NOT NULL DEFAULT 0,
            disk_read_rate REAL NOT NULL DEFAULT 0,
            disk_write_rate REAL NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for efficient time-range queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_vm_time ON metrics_history(vm_id, timestamp)",
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for cleanup queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_time ON metrics_history(timestamp)",
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(6i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 6 complete");
    Ok(())
}

/// Migration to schema version 7: Add security_reports table for vulnerability scans.
async fn migrate_to_v7(pool: &SqlitePool) -> Result<()> {
    info!("Running migration to schema version 7");

    // Security reports table for storing vulnerability scan results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS security_reports (
            id TEXT PRIMARY KEY,
            image_id TEXT NOT NULL,
            image_name TEXT NOT NULL,
            scanned_at INTEGER NOT NULL,
            scanner_version TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL,
            vulnerabilities TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}'
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for image lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_security_reports_image ON security_reports(image_id)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for image name lookups (prefix matching)
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_reports_image_name ON security_reports(image_name)",
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Index for time-based queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_reports_time ON security_reports(scanned_at)",
    )
    .execute(pool)
    .await
    .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(7i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed { reason: e.to_string() })?;

    info!("Migration to schema version 7 complete");
    Ok(())
}
