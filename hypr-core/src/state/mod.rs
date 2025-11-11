//! State management with SQLite persistence.
//!
//! The StateManager handles all persistent state for HYPR:
//! - VMs and their configurations
//! - Images and manifests
//! - Volumes and mounts
//! - Networks
//! - Stacks (Compose deployments)

use crate::error::{HyprError, Result};
use crate::types::volume::VolumeType;
use crate::types::{Image, Network, Stack, Vm, Volume};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{ConnectOptions, Row};
use std::path::Path;
use std::str::FromStr;
use std::time::SystemTime;
use tracing::{info, instrument};

pub mod migrations;

#[cfg(test)]
mod tests;

/// State manager for persistent storage.
#[derive(Clone)]
pub struct StateManager {
    pool: SqlitePool,
}

impl StateManager {
    /// Create a new StateManager with an in-memory database (for tests).
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// Create a new StateManager with a database at the specified path.
    #[instrument(skip(db_path))]
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref();
        info!("Initializing state manager at {:?}", db_path);

        // Configure SQLite connection
        let mut options = SqliteConnectOptions::from_str(
            db_path
                .to_str()
                .ok_or_else(|| HyprError::InvalidConfig {
                    reason: "Invalid database path".to_string(),
                })?,
        )
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        options = options
            .create_if_missing(true)
            .log_statements(tracing::log::LevelFilter::Debug);

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        let manager = Self { pool };

        // Run migrations
        manager.run_migrations().await?;

        info!("State manager initialized successfully");
        Ok(manager)
    }

    /// Run database migrations.
    #[instrument(skip(self))]
    async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations");
        migrations::run(&self.pool).await?;
        info!("Database migrations complete");
        Ok(())
    }

    // ========================
    // VM Operations
    // ========================

    /// Insert a new VM.
    #[instrument(skip(self), fields(vm_id = %vm.id))]
    pub async fn insert_vm(&self, vm: &Vm) -> Result<()> {
        let config_json = serde_json::to_string(&vm.config).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to serialize config: {}", e))
        })?;

        let created_at = vm
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO vms (id, name, image_id, status, config, ip_address, pid, vsock_path, created_at, started_at, stopped_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&vm.id)
        .bind(&vm.name)
        .bind(&vm.image_id)
        .bind(vm.status.to_string())
        .bind(config_json)
        .bind(&vm.ip_address)
        .bind(vm.pid.map(|p| p as i64))
        .bind(vm.vsock_path.as_ref().and_then(|p| p.to_str()))
        .bind(created_at)
        .bind(vm.started_at.map(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        }))
        .bind(vm.stopped_at.map(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        }))
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a VM by ID.
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn get_vm(&self, id: &str) -> Result<Vm> {
        let row = sqlx::query("SELECT * FROM vms WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::VmNotFound {
                vm_id: id.to_string(),
            })?;

        self.row_to_vm(row)
    }

    /// List all VMs.
    #[instrument(skip(self))]
    pub async fn list_vms(&self) -> Result<Vec<Vm>> {
        let rows = sqlx::query("SELECT * FROM vms ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(|row| self.row_to_vm(row)).collect()
    }

    /// Update VM status.
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn update_vm_status(&self, id: &str, status: crate::types::VmStatus) -> Result<()> {
        sqlx::query("UPDATE vms SET status = ? WHERE id = ?")
            .bind(status.to_string())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete a VM.
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn delete_vm(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM vms WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_vm(&self, row: sqlx::sqlite::SqliteRow) -> Result<Vm> {
        let config_json: String = row.get("config");
        let config = serde_json::from_str(&config_json).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to deserialize config: {}", e))
        })?;

        let status_str: String = row.get("status");
        let status = match status_str.as_str() {
            "creating" => crate::types::VmStatus::Creating,
            "running" => crate::types::VmStatus::Running,
            "stopped" => crate::types::VmStatus::Stopped,
            "failed" => crate::types::VmStatus::Failed,
            "deleting" => crate::types::VmStatus::Deleting,
            _ => crate::types::VmStatus::Failed,
        };

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        let started_at_secs: Option<i64> = row.get("started_at");
        let started_at = started_at_secs
            .map(|s| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s as u64));

        let stopped_at_secs: Option<i64> = row.get("stopped_at");
        let stopped_at = stopped_at_secs
            .map(|s| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s as u64));

        Ok(Vm {
            id: row.get("id"),
            name: row.get("name"),
            image_id: row.get("image_id"),
            status,
            config,
            ip_address: row.get("ip_address"),
            pid: row.get::<Option<i64>, _>("pid").map(|p| p as u32),
            vsock_path: row
                .get::<Option<String>, _>("vsock_path")
                .map(|p| p.into()),
            created_at,
            started_at,
            stopped_at,
        })
    }

    // ========================
    // Image Operations
    // ========================

    /// Insert a new image.
    #[instrument(skip(self), fields(image_id = %image.id))]
    pub async fn insert_image(&self, image: &Image) -> Result<()> {
        let manifest_json = serde_json::to_string(&image.manifest).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to serialize manifest: {}", e))
        })?;

        let created_at = image
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO images (id, name, tag, manifest, rootfs_path, size_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&image.id)
        .bind(&image.name)
        .bind(&image.tag)
        .bind(manifest_json)
        .bind(image.rootfs_path.to_str())
        .bind(image.size_bytes as i64)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get an image by ID.
    #[instrument(skip(self), fields(image_id = %id))]
    pub async fn get_image(&self, id: &str) -> Result<Image> {
        let row = sqlx::query("SELECT * FROM images WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::ImageNotFound {
                image: id.to_string(),
            })?;

        self.row_to_image(row)
    }

    /// List all images.
    #[instrument(skip(self))]
    pub async fn list_images(&self) -> Result<Vec<Image>> {
        let rows = sqlx::query("SELECT * FROM images ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .map(|row| self.row_to_image(row))
            .collect()
    }

    /// Delete an image.
    #[instrument(skip(self), fields(image_id = %id))]
    pub async fn delete_image(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM images WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_image(&self, row: sqlx::sqlite::SqliteRow) -> Result<Image> {
        let manifest_json: String = row.get("manifest");
        let manifest = serde_json::from_str(&manifest_json).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to deserialize manifest: {}", e))
        })?;

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        let size_bytes: i64 = row.get("size_bytes");

        Ok(Image {
            id: row.get("id"),
            name: row.get("name"),
            tag: row.get("tag"),
            manifest,
            rootfs_path: row.get::<String, _>("rootfs_path").into(),
            size_bytes: size_bytes as u64,
            created_at,
        })
    }

    // ========================
    // Volume Operations
    // ========================

    /// Insert a new volume.
    #[instrument(skip(self), fields(volume_id = %volume.id))]
    pub async fn insert_volume(&self, volume: &Volume) -> Result<()> {
        let created_at = volume
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let volume_type_str = match volume.volume_type {
            VolumeType::Ext4 => "ext4",
            VolumeType::Xfs => "xfs",
            VolumeType::Bind => "bind",
        };

        sqlx::query(
            r#"
            INSERT INTO volumes (id, name, type, path, size_bytes, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&volume.id)
        .bind(&volume.name)
        .bind(volume_type_str)
        .bind(volume.path.to_str())
        .bind(volume.size_bytes as i64)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a volume by ID.
    #[instrument(skip(self), fields(volume_id = %id))]
    pub async fn get_volume(&self, id: &str) -> Result<Volume> {
        let row = sqlx::query("SELECT * FROM volumes WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::DatabaseError(format!("Volume not found: {}", id)))?;

        self.row_to_volume(row)
    }

    /// List all volumes.
    #[instrument(skip(self))]
    pub async fn list_volumes(&self) -> Result<Vec<Volume>> {
        let rows = sqlx::query("SELECT * FROM volumes ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .map(|row| self.row_to_volume(row))
            .collect()
    }

    /// Delete a volume.
    #[instrument(skip(self), fields(volume_id = %id))]
    pub async fn delete_volume(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM volumes WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_volume(&self, row: sqlx::sqlite::SqliteRow) -> Result<Volume> {
        let volume_type_str: String = row.get("type");
        let volume_type = match volume_type_str.as_str() {
            "ext4" => VolumeType::Ext4,
            "xfs" => VolumeType::Xfs,
            "bind" => VolumeType::Bind,
            _ => VolumeType::Ext4,
        };

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        let size_bytes: i64 = row.get("size_bytes");

        Ok(Volume {
            id: row.get("id"),
            name: row.get("name"),
            volume_type,
            path: row.get::<String, _>("path").into(),
            size_bytes: size_bytes as u64,
            created_at,
        })
    }

    // ========================
    // Network Operations
    // ========================

    /// Insert a new network.
    #[instrument(skip(self), fields(network_id = %network.id))]
    pub async fn insert_network(&self, network: &Network) -> Result<()> {
        let created_at = network
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO networks (id, name, cidr, bridge_name, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&network.id)
        .bind(&network.name)
        .bind(&network.cidr)
        .bind(&network.bridge_name)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a network by ID.
    #[instrument(skip(self), fields(network_id = %id))]
    pub async fn get_network(&self, id: &str) -> Result<Network> {
        let row = sqlx::query("SELECT * FROM networks WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::DatabaseError(format!("Network not found: {}", id)))?;

        self.row_to_network(row)
    }

    /// List all networks.
    #[instrument(skip(self))]
    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        let rows = sqlx::query("SELECT * FROM networks ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .map(|row| self.row_to_network(row))
            .collect()
    }

    /// Delete a network.
    #[instrument(skip(self), fields(network_id = %id))]
    pub async fn delete_network(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM networks WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_network(&self, row: sqlx::sqlite::SqliteRow) -> Result<Network> {
        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        Ok(Network {
            id: row.get("id"),
            name: row.get("name"),
            cidr: row.get("cidr"),
            bridge_name: row.get("bridge_name"),
            created_at,
        })
    }

    // ========================
    // Stack Operations
    // ========================

    /// Insert a new stack.
    #[instrument(skip(self), fields(stack_id = %stack.id))]
    pub async fn insert_stack(&self, stack: &Stack) -> Result<()> {
        let state_json = serde_json::to_string(&stack.services).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to serialize services: {}", e))
        })?;

        let created_at = stack
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO stacks (id, name, compose_path, state, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&stack.id)
        .bind(&stack.name)
        .bind(&stack.compose_path)
        .bind(state_json)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a stack by ID.
    #[instrument(skip(self), fields(stack_id = %id))]
    pub async fn get_stack(&self, id: &str) -> Result<Stack> {
        let row = sqlx::query("SELECT * FROM stacks WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::DatabaseError(format!("Stack not found: {}", id)))?;

        self.row_to_stack(row)
    }

    /// List all stacks.
    #[instrument(skip(self))]
    pub async fn list_stacks(&self) -> Result<Vec<Stack>> {
        let rows = sqlx::query("SELECT * FROM stacks ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .map(|row| self.row_to_stack(row))
            .collect()
    }

    /// Delete a stack.
    #[instrument(skip(self), fields(stack_id = %id))]
    pub async fn delete_stack(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM stacks WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_stack(&self, row: sqlx::sqlite::SqliteRow) -> Result<Stack> {
        let state_json: String = row.get("state");
        let services = serde_json::from_str(&state_json).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to deserialize services: {}", e))
        })?;

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        Ok(Stack {
            id: row.get("id"),
            name: row.get("name"),
            services,
            compose_path: row.get("compose_path"),
            created_at,
        })
    }
}
