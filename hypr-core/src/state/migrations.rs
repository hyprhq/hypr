//! Database migrations.

use crate::error::{HyprError, Result};
use sqlx::SqlitePool;
use tracing::{info, instrument};

const SCHEMA_VERSION: i64 = 1;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

    // Get current schema version
    let current_version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM schema_version LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|e| HyprError::MigrationFailed {
                reason: e.to_string(),
            })?;

    let current_version = current_version.unwrap_or(0);

    if current_version >= SCHEMA_VERSION {
        info!(
            "Database schema is up to date (version {})",
            current_version
        );
        return Ok(());
    }

    info!(
        "Migrating database from version {} to {}",
        current_version, SCHEMA_VERSION
    );

    // Run migrations
    if current_version < 1 {
        migrate_to_v1(pool).await?;
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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_images_name_tag ON images(name, tag)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed {
            reason: e.to_string(),
        })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vms_status ON vms(status)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed {
            reason: e.to_string(),
        })?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vms_ip ON vms(ip_address)")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed {
            reason: e.to_string(),
        })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

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
    .map_err(|e| HyprError::MigrationFailed {
        reason: e.to_string(),
    })?;

    // Update schema version
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed {
            reason: e.to_string(),
        })?;

    sqlx::query("INSERT INTO schema_version (version) VALUES (?)")
        .bind(1i64)
        .execute(pool)
        .await
        .map_err(|e| HyprError::MigrationFailed {
            reason: e.to_string(),
        })?;

    info!("Migration to schema version 1 complete");
    Ok(())
}
