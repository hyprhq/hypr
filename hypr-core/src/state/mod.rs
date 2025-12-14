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
use crate::types::{Image, Network, NetworkDriver, Stack, Vm, Volume};
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

    /// Get a reference to the underlying SQLite pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Create a new StateManager with a database at the specified path.
    #[instrument(skip(db_path))]
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref();
        info!("Initializing state manager at {:?}", db_path);

        // Create parent directory if it doesn't exist (but not for :memory:)
        if db_path != Path::new(":memory:") {
            if let Some(parent) = db_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| HyprError::InvalidConfig {
                    reason: format!("Failed to create directory {}: {}", parent.display(), e),
                })?;
            }
        }

        // Configure SQLite connection
        let mut options = SqliteConnectOptions::from_str(db_path.to_str().ok_or_else(|| {
            HyprError::InvalidConfig { reason: "Invalid database path".to_string() }
        })?)
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        options = options.create_if_missing(true).log_statements(tracing::log::LevelFilter::Debug);

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
        let config_json = serde_json::to_string(&vm.config)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize config: {}", e)))?;

        let created_at =
            vm.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO vms (id, name, image_id, status, config, ip_address, pid, created_at, started_at, stopped_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&vm.id)
        .bind(&vm.name)
        .bind(&vm.image_id)
        .bind(vm.status.to_string())
        .bind(config_json)
        .bind(&vm.ip_address)
        .bind(vm.pid.map(|p| p as i64))
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
        .map_err(|e| {
            metrics::counter!("hypr_db_errors_total", "operation" => "insert_vm").increment(1);
            HyprError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    /// Get a VM by ID (supports partial ID matching like Docker).
    #[instrument(skip(self), fields(vm_id = %id))]
    pub async fn get_vm(&self, id: &str) -> Result<Vm> {
        // Try exact match first
        if let Some(row) = sqlx::query("SELECT * FROM vms WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                metrics::counter!("hypr_db_errors_total", "operation" => "get_vm").increment(1);
                HyprError::DatabaseError(e.to_string())
            })?
        {
            return self.row_to_vm(row);
        }

        // Try prefix match (like Docker)
        let pattern = format!("{}%", id);
        let rows = sqlx::query("SELECT * FROM vms WHERE id LIKE ?")
            .bind(&pattern)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        match rows.len() {
            0 => Err(HyprError::VmNotFound { vm_id: id.to_string() }),
            1 => self.row_to_vm(rows.into_iter().next().unwrap()),
            _ => Err(HyprError::InvalidConfig {
                reason: format!(
                    "Ambiguous VM ID '{}': matches {} VMs. Please use a longer prefix.",
                    id,
                    rows.len()
                ),
            }),
        }
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
        sqlx::query("DELETE FROM vms WHERE id = ?").bind(id).execute(&self.pool).await.map_err(
            |e| {
                metrics::counter!("hypr_db_errors_total", "operation" => "delete_vm").increment(1);
                HyprError::DatabaseError(e.to_string())
            },
        )?;

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

        let created_at =
            image.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

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
        .map_err(|e| {
            metrics::counter!("hypr_db_errors_total", "operation" => "insert_image").increment(1);
            HyprError::DatabaseError(e.to_string())
        })?;

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
            .ok_or_else(|| HyprError::ImageNotFound { image: id.to_string() })?;

        self.row_to_image(row)
    }

    /// List all images.
    #[instrument(skip(self))]
    pub async fn list_images(&self) -> Result<Vec<Image>> {
        let rows = sqlx::query("SELECT * FROM images ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        rows.into_iter().map(|row| self.row_to_image(row)).collect()
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

    /// Get an image by name and tag.
    #[instrument(skip(self), fields(name = %name, tag = %tag))]
    pub async fn get_image_by_name_tag(&self, name: &str, tag: &str) -> Result<Image> {
        let row = sqlx::query("SELECT * FROM images WHERE name = ? AND tag = ?")
            .bind(name)
            .bind(tag)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::ImageNotFound { image: format!("{}:{}", name, tag) })?;

        self.row_to_image(row)
    }

    pub async fn delete_image_by_name_tag(&self, name: &str, tag: &str) -> Result<()> {
        sqlx::query("DELETE FROM images WHERE name = ? AND tag = ?")
            .bind(name)
            .bind(tag)
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
        let created_at =
            volume.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

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

        rows.into_iter().map(|row| self.row_to_volume(row)).collect()
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
        let created_at =
            network.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO networks (id, name, driver, cidr, gateway, bridge_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&network.id)
        .bind(&network.name)
        .bind(network.driver.to_string())
        .bind(&network.cidr)
        .bind(network.gateway.to_string())
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

        rows.into_iter().map(|row| self.row_to_network(row)).collect()
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
        use std::str::FromStr;

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        let driver_str: String = row.get("driver");
        let driver = NetworkDriver::from_str(&driver_str).map_err(HyprError::DatabaseError)?;

        let gateway_str: String = row.get("gateway");
        let gateway: std::net::Ipv4Addr = gateway_str
            .parse()
            .map_err(|e: std::net::AddrParseError| HyprError::DatabaseError(e.to_string()))?;

        Ok(Network {
            id: row.get("id"),
            name: row.get("name"),
            driver,
            cidr: row.get("cidr"),
            gateway,
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

        let created_at =
            stack.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

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

        rows.into_iter().map(|row| self.row_to_stack(row)).collect()
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

    // ========================
    // IP Allocation Operations
    // ========================

    /// List all allocated IP addresses.
    #[instrument(skip(self))]
    pub async fn list_allocated_ips(&self) -> Result<Vec<std::net::Ipv4Addr>> {
        let rows = sqlx::query("SELECT ip_address FROM ip_allocations ORDER BY allocated_at")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let ip_str: String = row.get("ip_address");
                ip_str.parse().ok()
            })
            .collect())
    }

    /// Allocate an IP address to a VM.
    #[instrument(skip(self), fields(vm_id = %vm_id, ip = %ip))]
    pub async fn insert_ip_allocation(&self, vm_id: &str, ip: std::net::Ipv4Addr) -> Result<()> {
        let allocated_at =
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO ip_allocations (ip_address, vm_id, allocated_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(ip.to_string())
        .bind(vm_id)
        .bind(allocated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Release an IP address from a VM.
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub async fn delete_ip_allocation(&self, vm_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM ip_allocations WHERE vm_id = ?")
            .bind(vm_id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get the IP address allocated to a VM.
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub async fn get_ip_allocation(&self, vm_id: &str) -> Result<Option<std::net::Ipv4Addr>> {
        let row = sqlx::query("SELECT ip_address FROM ip_allocations WHERE vm_id = ?")
            .bind(vm_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(row.and_then(|r| {
            let ip_str: String = r.get("ip_address");
            ip_str.parse().ok()
        }))
    }



    // ========================
    // Snapshot Operations
    // ========================

    /// Insert a new snapshot.
    #[instrument(skip(self), fields(snapshot_id = %snapshot.id))]
    pub async fn insert_snapshot(&self, snapshot: &crate::snapshots::Snapshot) -> Result<()> {
        let created_at =
            snapshot.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

        let labels_json = serde_json::to_string(&snapshot.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO snapshots (id, vm_id, name, description, size_bytes, created_at, state, snapshot_type, path, labels)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&snapshot.id)
        .bind(&snapshot.vm_id)
        .bind(&snapshot.name)
        .bind(&snapshot.description)
        .bind(snapshot.size_bytes as i64)
        .bind(created_at)
        .bind(snapshot.state.as_str())
        .bind(snapshot.snapshot_type.as_str())
        .bind(snapshot.path.to_str())
        .bind(labels_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a snapshot by ID.
    #[instrument(skip(self), fields(snapshot_id = %id))]
    pub async fn get_snapshot(&self, id: &str) -> Result<crate::snapshots::Snapshot> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::DatabaseError(format!("Snapshot not found: {}", id)))?;

        self.row_to_snapshot(row)
    }

    /// List all snapshots, optionally filtered by VM ID.
    #[instrument(skip(self))]
    pub async fn list_snapshots(
        &self,
        vm_id: Option<&str>,
    ) -> Result<Vec<crate::snapshots::Snapshot>> {
        let rows = if let Some(vm_id) = vm_id {
            sqlx::query("SELECT * FROM snapshots WHERE vm_id = ? ORDER BY created_at DESC")
                .bind(vm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else {
            sqlx::query("SELECT * FROM snapshots ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        };

        rows.into_iter().map(|row| self.row_to_snapshot(row)).collect()
    }

    /// Update a snapshot.
    #[instrument(skip(self), fields(snapshot_id = %snapshot.id))]
    pub async fn update_snapshot(&self, snapshot: &crate::snapshots::Snapshot) -> Result<()> {
        let labels_json = serde_json::to_string(&snapshot.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE snapshots
            SET size_bytes = ?, state = ?, labels = ?
            WHERE id = ?
            "#,
        )
        .bind(snapshot.size_bytes as i64)
        .bind(snapshot.state.as_str())
        .bind(labels_json)
        .bind(&snapshot.id)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete a snapshot.
    #[instrument(skip(self), fields(snapshot_id = %id))]
    pub async fn delete_snapshot(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM snapshots WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_snapshot(&self, row: sqlx::sqlite::SqliteRow) -> Result<crate::snapshots::Snapshot> {
        use crate::snapshots::{SnapshotState, SnapshotType};

        let created_at_secs: i64 = row.get("created_at");
        let created_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

        let state_str: String = row.get("state");
        let state = SnapshotState::parse(&state_str).unwrap_or(SnapshotState::Failed);

        let snapshot_type_str: String = row.get("snapshot_type");
        let snapshot_type = SnapshotType::parse(&snapshot_type_str).unwrap_or(SnapshotType::Disk);

        let labels_json: String = row.get("labels");
        let labels: std::collections::HashMap<String, String> =
            serde_json::from_str(&labels_json).unwrap_or_default();

        let size_bytes: i64 = row.get("size_bytes");

        Ok(crate::snapshots::Snapshot {
            id: row.get("id"),
            vm_id: row.get("vm_id"),
            name: row.get("name"),
            description: row.get("description"),
            size_bytes: size_bytes as u64,
            created_at,
            state,
            snapshot_type,
            path: row.get::<String, _>("path").into(),
            labels,
        })
    }

    // ========================
    // Security Report Operations
    // ========================

    /// Insert a new security report.
    #[instrument(skip(self), fields(report_id = %report.id))]
    pub async fn insert_security_report(
        &self,
        report: &crate::security::SecurityReport,
    ) -> Result<()> {
        let summary_json = serde_json::to_string(&report.summary)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize summary: {}", e)))?;

        let vulns_json = serde_json::to_string(&report.vulnerabilities).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to serialize vulnerabilities: {}", e))
        })?;

        let metadata_json = serde_json::to_string(&report.metadata).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to serialize metadata: {}", e))
        })?;

        sqlx::query(
            r#"
            INSERT INTO security_reports (id, image_id, image_name, scanned_at, scanner_version, risk_level, summary, vulnerabilities, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&report.id)
        .bind(&report.image_id)
        .bind(&report.image_name)
        .bind(report.scanned_at)
        .bind(&report.scanner_version)
        .bind(report.risk_level.as_str())
        .bind(summary_json)
        .bind(vulns_json)
        .bind(metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a security report by ID.
    #[instrument(skip(self), fields(report_id = %id))]
    pub async fn get_security_report(&self, id: &str) -> Result<crate::security::SecurityReport> {
        let row = sqlx::query("SELECT * FROM security_reports WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::Internal(format!("Security report not found: {}", id)))?;

        self.row_to_security_report(row)
    }

    /// List security reports with optional filters.
    #[instrument(skip(self))]
    pub async fn list_security_reports(
        &self,
        image_id: Option<&str>,
        image_name: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<crate::security::SecurityReport>> {
        let limit = limit.unwrap_or(50) as i64;

        let rows = if let Some(image_id) = image_id {
            sqlx::query(
                "SELECT * FROM security_reports WHERE image_id = ? ORDER BY scanned_at DESC LIMIT ?",
            )
            .bind(image_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else if let Some(image_name) = image_name {
            let pattern = format!("{}%", image_name);
            sqlx::query(
                "SELECT * FROM security_reports WHERE image_name LIKE ? ORDER BY scanned_at DESC LIMIT ?",
            )
            .bind(&pattern)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else {
            sqlx::query("SELECT * FROM security_reports ORDER BY scanned_at DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        };

        rows.into_iter().map(|row| self.row_to_security_report(row)).collect()
    }

    /// Delete a security report.
    #[instrument(skip(self), fields(report_id = %id))]
    pub async fn delete_security_report(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM security_reports WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_security_report(
        &self,
        row: sqlx::sqlite::SqliteRow,
    ) -> Result<crate::security::SecurityReport> {
        use crate::security::{RiskLevel, Vulnerability, VulnerabilitySummary};

        let risk_level_str: String = row.get("risk_level");
        let risk_level = RiskLevel::parse(&risk_level_str);

        let summary_json: String = row.get("summary");
        let summary: VulnerabilitySummary = serde_json::from_str(&summary_json).map_err(|e| {
            HyprError::DatabaseError(format!("Failed to deserialize summary: {}", e))
        })?;

        let vulns_json: String = row.get("vulnerabilities");
        let vulnerabilities: Vec<Vulnerability> =
            serde_json::from_str(&vulns_json).map_err(|e| {
                HyprError::DatabaseError(format!("Failed to deserialize vulnerabilities: {}", e))
            })?;

        let metadata_json: String = row.get("metadata");
        let metadata: std::collections::HashMap<String, String> =
            serde_json::from_str(&metadata_json).unwrap_or_default();

        Ok(crate::security::SecurityReport {
            id: row.get("id"),
            image_id: row.get("image_id"),
            image_name: row.get("image_name"),
            scanned_at: row.get("scanned_at"),
            scanner_version: row.get("scanner_version"),
            risk_level,
            summary,
            vulnerabilities,
            metadata,
        })
    }

    // ========================
    // Cron Job Operations
    // ========================

    /// Insert a new cron job.
    #[instrument(skip(self), fields(job_id = %job.id))]
    pub async fn insert_cron_job(&self, job: &crate::scheduler::CronJob) -> Result<()> {
        let command_json = serde_json::to_string(&job.command)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize command: {}", e)))?;

        let env_json = serde_json::to_string(&job.env)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize env: {}", e)))?;

        let labels_json = serde_json::to_string(&job.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO cron_jobs (id, name, schedule, image, command, env, resources_cpus, resources_memory_mb, enabled, created_at, last_run, next_run, timeout_sec, max_retries, labels)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&job.id)
        .bind(&job.name)
        .bind(&job.schedule)
        .bind(&job.image)
        .bind(command_json)
        .bind(env_json)
        .bind(job.resources_cpus as i64)
        .bind(job.resources_memory_mb as i64)
        .bind(job.enabled)
        .bind(job.created_at)
        .bind(job.last_run)
        .bind(job.next_run)
        .bind(job.timeout_sec as i64)
        .bind(job.max_retries as i64)
        .bind(labels_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a cron job by ID.
    #[instrument(skip(self), fields(job_id = %id))]
    pub async fn get_cron_job(&self, id: &str) -> Result<crate::scheduler::CronJob> {
        let row = sqlx::query("SELECT * FROM cron_jobs WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::Internal(format!("Cron job not found: {}", id)))?;

        self.row_to_cron_job(row)
    }

    /// Get a cron job by name.
    #[instrument(skip(self), fields(job_name = %name))]
    pub async fn get_cron_job_by_name(&self, name: &str) -> Result<crate::scheduler::CronJob> {
        let row = sqlx::query("SELECT * FROM cron_jobs WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::Internal(format!("Cron job not found: {}", name)))?;

        self.row_to_cron_job(row)
    }

    /// List cron jobs with optional filters.
    #[instrument(skip(self))]
    pub async fn list_cron_jobs(
        &self,
        enabled_only: Option<bool>,
    ) -> Result<Vec<crate::scheduler::CronJob>> {
        let rows = if let Some(true) = enabled_only {
            sqlx::query("SELECT * FROM cron_jobs WHERE enabled = 1 ORDER BY next_run ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else {
            sqlx::query("SELECT * FROM cron_jobs ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        };

        rows.into_iter().map(|row| self.row_to_cron_job(row)).collect()
    }

    /// Update a cron job.
    #[instrument(skip(self), fields(job_id = %job.id))]
    pub async fn update_cron_job(&self, job: &crate::scheduler::CronJob) -> Result<()> {
        let command_json = serde_json::to_string(&job.command)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize command: {}", e)))?;

        let env_json = serde_json::to_string(&job.env)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize env: {}", e)))?;

        let labels_json = serde_json::to_string(&job.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE cron_jobs SET
                name = ?, schedule = ?, image = ?, command = ?, env = ?,
                resources_cpus = ?, resources_memory_mb = ?, enabled = ?,
                last_run = ?, next_run = ?, timeout_sec = ?, max_retries = ?, labels = ?
            WHERE id = ?
            "#,
        )
        .bind(&job.name)
        .bind(&job.schedule)
        .bind(&job.image)
        .bind(command_json)
        .bind(env_json)
        .bind(job.resources_cpus as i64)
        .bind(job.resources_memory_mb as i64)
        .bind(job.enabled)
        .bind(job.last_run)
        .bind(job.next_run)
        .bind(job.timeout_sec as i64)
        .bind(job.max_retries as i64)
        .bind(labels_json)
        .bind(&job.id)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete a cron job.
    #[instrument(skip(self), fields(job_id = %id))]
    pub async fn delete_cron_job(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM cron_jobs WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_cron_job(&self, row: sqlx::sqlite::SqliteRow) -> Result<crate::scheduler::CronJob> {
        let command_json: String = row.get("command");
        let command: Vec<String> = serde_json::from_str(&command_json).unwrap_or_default();

        let env_json: String = row.get("env");
        let env: std::collections::HashMap<String, String> =
            serde_json::from_str(&env_json).unwrap_or_default();

        let labels_json: String = row.get("labels");
        let labels: std::collections::HashMap<String, String> =
            serde_json::from_str(&labels_json).unwrap_or_default();

        Ok(crate::scheduler::CronJob {
            id: row.get("id"),
            name: row.get("name"),
            schedule: row.get("schedule"),
            image: row.get("image"),
            command,
            env,
            resources_cpus: row.get::<i64, _>("resources_cpus") as u32,
            resources_memory_mb: row.get::<i64, _>("resources_memory_mb") as u32,
            enabled: row.get("enabled"),
            created_at: row.get("created_at"),
            last_run: row.get("last_run"),
            next_run: row.get("next_run"),
            timeout_sec: row.get::<i64, _>("timeout_sec") as u32,
            max_retries: row.get::<i64, _>("max_retries") as u32,
            labels,
        })
    }

    // ========================
    // Cron Job Run Operations
    // ========================

    /// Insert a new cron job run.
    #[instrument(skip(self), fields(run_id = %run.id))]
    pub async fn insert_cron_job_run(&self, run: &crate::scheduler::CronJobRun) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO cron_job_runs (id, job_id, started_at, finished_at, exit_code, status, output, error_message, attempt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&run.id)
        .bind(&run.job_id)
        .bind(run.started_at)
        .bind(run.finished_at)
        .bind(run.exit_code)
        .bind(run.status.as_str())
        .bind(&run.output)
        .bind(&run.error_message)
        .bind(run.attempt as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get cron job runs for a job.
    #[instrument(skip(self), fields(job_id = %job_id))]
    pub async fn get_cron_job_runs(
        &self,
        job_id: &str,
        limit: Option<u32>,
        status: Option<crate::scheduler::CronJobRunStatus>,
    ) -> Result<Vec<crate::scheduler::CronJobRun>> {
        let limit = limit.unwrap_or(20) as i64;

        let rows = if let Some(status) = status {
            sqlx::query(
                "SELECT * FROM cron_job_runs WHERE job_id = ? AND status = ? ORDER BY started_at DESC LIMIT ?",
            )
            .bind(job_id)
            .bind(status.as_str())
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else {
            sqlx::query(
                "SELECT * FROM cron_job_runs WHERE job_id = ? ORDER BY started_at DESC LIMIT ?",
            )
            .bind(job_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        };

        rows.into_iter().map(|row| self.row_to_cron_job_run(row)).collect()
    }

    /// Update a cron job run.
    #[instrument(skip(self), fields(run_id = %run.id))]
    pub async fn update_cron_job_run(&self, run: &crate::scheduler::CronJobRun) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE cron_job_runs SET
                finished_at = ?, exit_code = ?, status = ?, output = ?, error_message = ?
            WHERE id = ?
            "#,
        )
        .bind(run.finished_at)
        .bind(run.exit_code)
        .bind(run.status.as_str())
        .bind(&run.output)
        .bind(&run.error_message)
        .bind(&run.id)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_cron_job_run(
        &self,
        row: sqlx::sqlite::SqliteRow,
    ) -> Result<crate::scheduler::CronJobRun> {
        let status_str: String = row.get("status");
        let status = crate::scheduler::CronJobRunStatus::parse(&status_str);

        Ok(crate::scheduler::CronJobRun {
            id: row.get("id"),
            job_id: row.get("job_id"),
            started_at: row.get("started_at"),
            finished_at: row.get("finished_at"),
            exit_code: row.get("exit_code"),
            status,
            output: row.get("output"),
            error_message: row.get("error_message"),
            attempt: row.get::<i64, _>("attempt") as u32,
        })
    }

    // ========================
    // Dev Environment Operations
    // ========================

    /// Insert a new dev environment.
    #[instrument(skip(self), fields(env_id = %env.id))]
    pub async fn insert_dev_environment(&self, env: &DevEnvironment) -> Result<()> {
        let ports_json = serde_json::to_string(&env.forwarded_ports)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize ports: {}", e)))?;

        let config_json = serde_json::to_string(&env.config)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize config: {}", e)))?;

        let labels_json = serde_json::to_string(&env.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO dev_environments (id, name, repo_url, branch, vm_id, workspace_path, ssh_port, forwarded_ports, status, created_at, started_at, config, labels)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&env.id)
        .bind(&env.name)
        .bind(&env.repo_url)
        .bind(&env.branch)
        .bind(&env.vm_id)
        .bind(&env.workspace_path)
        .bind(env.ssh_port.map(|p| p as i64))
        .bind(ports_json)
        .bind(env.status.as_str())
        .bind(env.created_at)
        .bind(env.started_at)
        .bind(config_json)
        .bind(labels_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get a dev environment by ID.
    #[instrument(skip(self), fields(env_id = %id))]
    pub async fn get_dev_environment(&self, id: &str) -> Result<DevEnvironment> {
        let row = sqlx::query("SELECT * FROM dev_environments WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?
            .ok_or_else(|| HyprError::Internal(format!("Dev environment not found: {}", id)))?;

        self.row_to_dev_environment(row)
    }

    /// List dev environments with optional filters.
    #[instrument(skip(self))]
    pub async fn list_dev_environments(
        &self,
        status: Option<DevEnvStatus>,
    ) -> Result<Vec<DevEnvironment>> {
        let rows = if let Some(status) = status {
            sqlx::query("SELECT * FROM dev_environments WHERE status = ? ORDER BY created_at DESC")
                .bind(status.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        } else {
            sqlx::query("SELECT * FROM dev_environments ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| HyprError::DatabaseError(e.to_string()))?
        };

        rows.into_iter().map(|row| self.row_to_dev_environment(row)).collect()
    }

    /// Update a dev environment.
    #[instrument(skip(self), fields(env_id = %env.id))]
    pub async fn update_dev_environment(&self, env: &DevEnvironment) -> Result<()> {
        let ports_json = serde_json::to_string(&env.forwarded_ports)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize ports: {}", e)))?;

        let config_json = serde_json::to_string(&env.config)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize config: {}", e)))?;

        let labels_json = serde_json::to_string(&env.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE dev_environments SET
                vm_id = ?, workspace_path = ?, ssh_port = ?, forwarded_ports = ?,
                status = ?, started_at = ?, config = ?, labels = ?
            WHERE id = ?
            "#,
        )
        .bind(&env.vm_id)
        .bind(&env.workspace_path)
        .bind(env.ssh_port.map(|p| p as i64))
        .bind(ports_json)
        .bind(env.status.as_str())
        .bind(env.started_at)
        .bind(config_json)
        .bind(labels_json)
        .bind(&env.id)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete a dev environment.
    #[instrument(skip(self), fields(env_id = %id))]
    pub async fn delete_dev_environment(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM dev_environments WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn row_to_dev_environment(&self, row: sqlx::sqlite::SqliteRow) -> Result<DevEnvironment> {
        let ports_json: String = row.get("forwarded_ports");
        let forwarded_ports: Vec<u32> = serde_json::from_str(&ports_json).unwrap_or_default();

        let config_json: String = row.get("config");
        let config: DevContainerConfig = serde_json::from_str(&config_json).unwrap_or_default();

        let labels_json: String = row.get("labels");
        let labels: std::collections::HashMap<String, String> =
            serde_json::from_str(&labels_json).unwrap_or_default();

        let status_str: String = row.get("status");
        let status = DevEnvStatus::parse(&status_str);

        let ssh_port: Option<i64> = row.get("ssh_port");

        Ok(DevEnvironment {
            id: row.get("id"),
            name: row.get("name"),
            repo_url: row.get("repo_url"),
            branch: row.get("branch"),
            vm_id: row.get("vm_id"),
            workspace_path: row.get("workspace_path"),
            ssh_port: ssh_port.map(|p| p as u32),
            forwarded_ports,
            status,
            created_at: row.get("created_at"),
            started_at: row.get("started_at"),
            config,
            labels,
        })
    }
}

// ========================
// Dev Environment Types
// ========================

/// Status of a dev environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DevEnvStatus {
    /// Being created (cloning, building).
    #[default]
    Creating,
    /// VM starting.
    Starting,
    /// Ready for use.
    Running,
    /// VM stopped.
    Stopped,
    /// Creation/start failed.
    Failed,
}

impl DevEnvStatus {
    /// Parse status from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "creating" => DevEnvStatus::Creating,
            "starting" => DevEnvStatus::Starting,
            "running" => DevEnvStatus::Running,
            "stopped" => DevEnvStatus::Stopped,
            "failed" => DevEnvStatus::Failed,
            _ => DevEnvStatus::Creating,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DevEnvStatus::Creating => "creating",
            DevEnvStatus::Starting => "starting",
            DevEnvStatus::Running => "running",
            DevEnvStatus::Stopped => "stopped",
            DevEnvStatus::Failed => "failed",
        }
    }
}

/// A development environment created from a devcontainer.json.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DevEnvironment {
    /// Unique environment ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Git repository URL.
    pub repo_url: String,
    /// Git branch.
    pub branch: String,
    /// Associated VM ID.
    pub vm_id: Option<String>,
    /// Path to workspace inside VM.
    pub workspace_path: String,
    /// SSH port for IDE connection.
    pub ssh_port: Option<u32>,
    /// Additional forwarded ports.
    pub forwarded_ports: Vec<u32>,
    /// Current status.
    pub status: DevEnvStatus,
    /// Unix timestamp when created.
    pub created_at: i64,
    /// Unix timestamp when last started.
    pub started_at: Option<i64>,
    /// Parsed devcontainer configuration.
    pub config: DevContainerConfig,
    /// Custom labels/metadata.
    pub labels: std::collections::HashMap<String, String>,
}

impl Default for DevEnvironment {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            repo_url: String::new(),
            branch: "main".to_string(),
            vm_id: None,
            workspace_path: "/workspace".to_string(),
            ssh_port: None,
            forwarded_ports: Vec::new(),
            status: DevEnvStatus::Creating,
            created_at: 0,
            started_at: None,
            config: DevContainerConfig::default(),
            labels: std::collections::HashMap::new(),
        }
    }
}

/// Parsed devcontainer.json configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DevContainerConfig {
    /// Pre-built image to use.
    pub image: Option<String>,
    /// Dockerfile to build.
    pub dockerfile: Option<String>,
    /// Docker Compose file.
    pub docker_compose_file: Option<String>,
    /// Devcontainer features to install.
    pub features: Vec<String>,
    /// Ports to forward.
    pub forward_ports: Vec<u32>,
    /// Command to run after creation.
    pub post_create_command: Option<String>,
    /// Command to run after each start.
    pub post_start_command: Option<String>,
    /// Environment variables in container.
    pub remote_env: std::collections::HashMap<String, String>,
    /// VS Code extensions to install.
    pub extensions: Vec<String>,
    /// Workspace folder in container.
    pub workspace_folder: Option<String>,
}
