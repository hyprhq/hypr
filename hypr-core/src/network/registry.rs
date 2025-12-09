//! Service registry for tracking running services and their network endpoints.
//!
//! The ServiceRegistry enables service discovery by tracking services, their IP addresses,
//! ports, and metadata labels. This is used by the DNS server for name resolution.

use crate::error::{HyprError, Result};
use metrics::counter;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

/// Service information tracked by the registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceInfo {
    /// Service name (e.g., "web", "database")
    pub name: String,
    /// IP address of the service
    pub ip: IpAddr,
    /// Ports exposed by the service
    pub ports: Vec<u16>,
    /// Metadata labels for service discovery (e.g., role=web, env=prod)
    pub labels: HashMap<String, String>,
    /// When the service was registered
    pub created_at: SystemTime,
}

impl ServiceInfo {
    /// Create a new ServiceInfo.
    pub fn new(name: String, ip: IpAddr, ports: Vec<u16>, labels: HashMap<String, String>) -> Self {
        Self { name, ip, ports, labels, created_at: SystemTime::now() }
    }

    /// Check if this service matches all the given labels.
    pub fn matches_labels(&self, query_labels: &HashMap<String, String>) -> bool {
        query_labels
            .iter()
            .all(|(key, value)| self.labels.get(key).map(|v| v == value).unwrap_or(false))
    }
}

/// Service registry for tracking running services.
///
/// Provides thread-safe access to service information with SQLite persistence.
/// Uses RwLock for read-heavy workloads (many lookups, few writes).
#[derive(Clone)]
pub struct ServiceRegistry {
    /// In-memory cache of services for fast lookups
    services: Arc<RwLock<HashMap<String, ServiceInfo>>>,
    /// Database connection pool for persistence
    pool: sqlx::SqlitePool,
}

impl ServiceRegistry {
    /// Create a new ServiceRegistry with the given database pool.
    #[instrument(skip(pool))]
    pub async fn new(pool: sqlx::SqlitePool) -> Result<Self> {
        info!("Initializing service registry");

        let registry = Self { services: Arc::new(RwLock::new(HashMap::new())), pool };

        // Load services from database
        registry.load_from_db().await?;

        info!("Service registry initialized");
        Ok(registry)
    }

    /// Register a new service or update an existing one.
    #[instrument(skip(self), fields(service_name = %name))]
    pub async fn register(
        &self,
        name: String,
        ip: IpAddr,
        ports: Vec<u16>,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let service_info = ServiceInfo::new(name.clone(), ip, ports, labels);

        // Persist to database FIRST to ensure consistency
        // If DB write fails, we don't want stale data in the cache
        self.persist_service(&service_info).await?;

        // Update in-memory cache only after successful DB persist
        {
            let mut services = self.services.write().await;
            services.insert(name.clone(), service_info.clone());
        }

        counter!("hypr.registry.register").increment(1);
        info!("Registered service: {}", name);

        Ok(())
    }

    /// Unregister a service by name.
    #[instrument(skip(self), fields(service_name = %name))]
    pub async fn unregister(&self, name: &str) -> Result<()> {
        // Remove from in-memory cache
        let removed = {
            let mut services = self.services.write().await;
            services.remove(name).is_some()
        };

        if !removed {
            warn!("Attempted to unregister non-existent service: {}", name);
            return Err(HyprError::DatabaseError(format!("Service not found: {}", name)));
        }

        // Remove from database
        sqlx::query("DELETE FROM services WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        counter!("hypr.registry.unregister").increment(1);
        info!("Unregistered service: {}", name);

        Ok(())
    }

    /// Look up a service by name.
    #[instrument(skip(self), fields(service_name = %name))]
    pub async fn lookup(&self, name: &str) -> Option<ServiceInfo> {
        let services = self.services.read().await;
        let result = services.get(name).cloned();

        if result.is_some() {
            counter!("hypr.registry.lookup.hit").increment(1);
            debug!("Service lookup hit: {}", name);
        } else {
            counter!("hypr.registry.lookup.miss").increment(1);
            debug!("Service lookup miss: {}", name);
        }

        result
    }

    /// Query services by labels.
    ///
    /// Returns all services that match ALL the given labels.
    #[instrument(skip(self), fields(label_count = query_labels.len()))]
    pub async fn query_by_labels(
        &self,
        query_labels: &HashMap<String, String>,
    ) -> Vec<ServiceInfo> {
        let services = self.services.read().await;
        let results: Vec<ServiceInfo> = services
            .values()
            .filter(|service| service.matches_labels(query_labels))
            .cloned()
            .collect();

        counter!("hypr.registry.query_by_labels").increment(1);
        debug!("Label query returned {} services", results.len());

        results
    }

    /// List all registered services.
    #[instrument(skip(self))]
    pub async fn list_all(&self) -> Vec<ServiceInfo> {
        let services = self.services.read().await;
        services.values().cloned().collect()
    }

    /// Load services from database into in-memory cache.
    #[instrument(skip(self))]
    async fn load_from_db(&self) -> Result<()> {
        let rows = sqlx::query(
            r#"
            SELECT name, ip, ports, labels, created_at
            FROM services
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        let mut services = self.services.write().await;
        for row in rows {
            let name: String = row.get("name");
            let ip_str: String = row.get("ip");
            let ip: IpAddr = ip_str.parse().map_err(|e| {
                HyprError::DatabaseError(format!("Invalid IP address in database: {}", e))
            })?;

            let ports_json: String = row.get("ports");
            let ports: Vec<u16> = serde_json::from_str(&ports_json)
                .map_err(|e| HyprError::DatabaseError(format!("Failed to parse ports: {}", e)))?;

            let labels_json: String = row.get("labels");
            let labels: HashMap<String, String> = serde_json::from_str(&labels_json)
                .map_err(|e| HyprError::DatabaseError(format!("Failed to parse labels: {}", e)))?;

            let created_at_secs: i64 = row.get("created_at");
            let created_at =
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs as u64);

            let service_info = ServiceInfo { name: name.clone(), ip, ports, labels, created_at };

            services.insert(name, service_info);
        }

        info!("Loaded {} services from database", services.len());
        Ok(())
    }

    /// Persist a service to the database.
    #[instrument(skip(self, service), fields(service_name = %service.name))]
    async fn persist_service(&self, service: &ServiceInfo) -> Result<()> {
        let ports_json = serde_json::to_string(&service.ports)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize ports: {}", e)))?;

        let labels_json = serde_json::to_string(&service.labels)
            .map_err(|e| HyprError::DatabaseError(format!("Failed to serialize labels: {}", e)))?;

        let created_at =
            service.created_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;

        // Insert or replace
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO services (name, ip, ports, labels, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&service.name)
        .bind(service.ip.to_string())
        .bind(ports_json)
        .bind(labels_json)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    async fn setup_test_registry() -> ServiceRegistry {
        let pool = sqlx::SqlitePool::connect(":memory:")
            .await
            .expect("Failed to create in-memory database");

        // Create services table
        sqlx::query(
            r#"
            CREATE TABLE services (
                name TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                ports TEXT NOT NULL,
                labels TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create services table");

        ServiceRegistry::new(pool).await.expect("Failed to create registry")
    }

    #[tokio::test]
    async fn test_register_and_lookup() {
        let registry = setup_test_registry().await;

        let mut labels = HashMap::new();
        labels.insert("role".to_string(), "web".to_string());

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ports = vec![80, 443];

        registry
            .register("web-service".to_string(), ip, ports.clone(), labels.clone())
            .await
            .expect("Failed to register service");

        let service = registry.lookup("web-service").await.expect("Service not found");

        assert_eq!(service.name, "web-service");
        assert_eq!(service.ip, ip);
        assert_eq!(service.ports, ports);
        assert_eq!(service.labels, labels);
    }

    #[tokio::test]
    async fn test_unregister() {
        let registry = setup_test_registry().await;

        let labels = HashMap::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        registry
            .register("test-service".to_string(), ip, vec![8080], labels)
            .await
            .expect("Failed to register service");

        assert!(registry.lookup("test-service").await.is_some());

        registry.unregister("test-service").await.expect("Failed to unregister service");

        assert!(registry.lookup("test-service").await.is_none());
    }

    #[tokio::test]
    async fn test_query_by_labels() {
        let registry = setup_test_registry().await;

        // Register web service
        let mut web_labels = HashMap::new();
        web_labels.insert("role".to_string(), "web".to_string());
        web_labels.insert("env".to_string(), "prod".to_string());

        registry
            .register(
                "web-1".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                vec![80],
                web_labels.clone(),
            )
            .await
            .expect("Failed to register web-1");

        // Register database service
        let mut db_labels = HashMap::new();
        db_labels.insert("role".to_string(), "database".to_string());
        db_labels.insert("env".to_string(), "prod".to_string());

        registry
            .register(
                "db-1".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                vec![5432],
                db_labels,
            )
            .await
            .expect("Failed to register db-1");

        // Register another web service in dev
        let mut web_dev_labels = HashMap::new();
        web_dev_labels.insert("role".to_string(), "web".to_string());
        web_dev_labels.insert("env".to_string(), "dev".to_string());

        registry
            .register(
                "web-dev".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                vec![8080],
                web_dev_labels,
            )
            .await
            .expect("Failed to register web-dev");

        // Query for web services
        let mut query = HashMap::new();
        query.insert("role".to_string(), "web".to_string());
        let results = registry.query_by_labels(&query).await;
        assert_eq!(results.len(), 2);

        // Query for prod web services
        let mut query = HashMap::new();
        query.insert("role".to_string(), "web".to_string());
        query.insert("env".to_string(), "prod".to_string());
        let results = registry.query_by_labels(&query).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "web-1");

        // Query for prod services (any role)
        let mut query = HashMap::new();
        query.insert("env".to_string(), "prod".to_string());
        let results = registry.query_by_labels(&query).await;
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    #[ignore = "tempfile crate not in Cargo.toml"]
    async fn test_persistence() {
        // Create a temporary file for the database
        // let temp_db = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        // let db_path = temp_db.path().to_str().unwrap();

        // let pool1 =
        //     sqlx::SqlitePool::connect(db_path).await.expect("Failed to connect to database");

        // // Create services table
        // sqlx::query(
        //     r#"
        //     CREATE TABLE services (
        //         name TEXT PRIMARY KEY,
        //         ip TEXT NOT NULL,
        //         ports TEXT NOT NULL,
        //         labels TEXT NOT NULL,
        //         created_at INTEGER NOT NULL
        //     )
        //     "#,
        // )
        // .execute(&pool1)
        // .await
        // .expect("Failed to create services table");

        // let registry1 = ServiceRegistry::new(pool1).await.expect("Failed to create registry");

        // let mut labels = HashMap::new();
        // labels.insert("role".to_string(), "web".to_string());

        // registry1
        //     .register(
        //         "persistent-service".to_string(),
        //         IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        //         vec![80],
        //         labels.clone(),
        //     )
        //     .await
        //     .expect("Failed to register service");

        // // Drop the first registry
        // drop(registry1);

        // // Create a new registry with the same database
        // let pool2 =
        //     sqlx::SqlitePool::connect(db_path).await.expect("Failed to connect to database");

        // let registry2 = ServiceRegistry::new(pool2).await.expect("Failed to create registry");

        // let service =
        //     registry2.lookup("persistent-service").await.expect("Service not found after reload");

        // assert_eq!(service.name, "persistent-service");
        // assert_eq!(service.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        // assert_eq!(service.ports, vec![80]);
        // assert_eq!(service.labels.get("role").unwrap(), "web");
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let registry = setup_test_registry().await;

        let mut handles = vec![];

        // Spawn multiple tasks to register services concurrently
        for i in 0..10 {
            let registry_clone = registry.clone();
            let handle = tokio::spawn(async move {
                let labels = HashMap::new();
                registry_clone
                    .register(
                        format!("service-{}", i),
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                        vec![8000 + i],
                        labels,
                    )
                    .await
                    .expect("Failed to register service");
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task failed");
        }

        // Verify all services were registered
        let all_services = registry.list_all().await;
        assert_eq!(all_services.len(), 10);

        // Lookup each service
        for i in 0..10 {
            let service =
                registry.lookup(&format!("service-{}", i)).await.expect("Service not found");
            assert_eq!(service.name, format!("service-{}", i));
        }
    }

    #[tokio::test]
    async fn test_update_existing_service() {
        let registry = setup_test_registry().await;

        let mut labels = HashMap::new();
        labels.insert("version".to_string(), "1.0".to_string());

        registry
            .register(
                "app".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                vec![80],
                labels.clone(),
            )
            .await
            .expect("Failed to register service");

        // Update the service with new IP and labels
        let mut new_labels = HashMap::new();
        new_labels.insert("version".to_string(), "2.0".to_string());

        registry
            .register(
                "app".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                vec![80, 443],
                new_labels.clone(),
            )
            .await
            .expect("Failed to update service");

        let service = registry.lookup("app").await.expect("Service not found");
        assert_eq!(service.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(service.ports, vec![80, 443]);
        assert_eq!(service.labels.get("version").unwrap(), "2.0");
    }

    #[tokio::test]
    async fn test_unregister_nonexistent() {
        let registry = setup_test_registry().await;

        let result = registry.unregister("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_labels_query() {
        let registry = setup_test_registry().await;

        let mut labels = HashMap::new();
        labels.insert("role".to_string(), "web".to_string());

        registry
            .register("web".to_string(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), vec![80], labels)
            .await
            .expect("Failed to register service");

        // Query with empty labels should match all services
        let query = HashMap::new();
        let results = registry.query_by_labels(&query).await;
        assert_eq!(results.len(), 1);
    }
}
