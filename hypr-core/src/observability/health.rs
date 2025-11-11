//! Health check endpoints.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Overall system health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub version: &'static str,
    pub subsystems: Vec<SubsystemHealth>,
}

/// Subsystem health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
}

/// Health checker that tracks subsystem status.
#[derive(Clone)]
pub struct HealthChecker {
    subsystems: Arc<RwLock<Vec<SubsystemHealth>>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self { subsystems: Arc::new(RwLock::new(Vec::new())) }
    }

    /// Register a subsystem for health tracking.
    pub async fn register_subsystem(&self, name: String) {
        let mut subsystems = self.subsystems.write().await;
        subsystems.push(SubsystemHealth { name, status: HealthStatus::Healthy, message: None });
    }

    /// Update subsystem health status.
    pub async fn update_subsystem(
        &self,
        name: &str,
        status: HealthStatus,
        message: Option<String>,
    ) {
        let mut subsystems = self.subsystems.write().await;
        if let Some(subsystem) = subsystems.iter_mut().find(|s| s.name == name) {
            subsystem.status = status;
            subsystem.message = message;
        }
    }

    /// Get overall health status.
    ///
    /// Returns:
    /// - Healthy: All subsystems healthy
    /// - Degraded: At least one subsystem degraded, none unhealthy
    /// - Unhealthy: At least one subsystem unhealthy
    pub async fn get_health(&self) -> HealthCheck {
        let subsystems = self.subsystems.read().await.clone();

        let status = if subsystems.iter().any(|s| s.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if subsystems.iter().any(|s| s.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthCheck { status, version: env!("CARGO_PKG_VERSION"), subsystems }
    }

    /// Simple liveness check - is the process alive?
    pub fn is_alive(&self) -> bool {
        true // If this function runs, we're alive
    }

    /// Readiness check - are all subsystems ready?
    pub async fn is_ready(&self) -> bool {
        let health = self.get_health().await;
        health.status == HealthStatus::Healthy
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker() {
        let checker = HealthChecker::new();

        // Initially healthy
        assert!(checker.is_alive());

        // Register subsystems
        checker.register_subsystem("test1".to_string()).await;
        checker.register_subsystem("test2".to_string()).await;

        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.subsystems.len(), 2);

        // Mark one as degraded
        checker.update_subsystem("test1", HealthStatus::Degraded, Some("slow".to_string())).await;
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Degraded);

        // Mark one as unhealthy
        checker.update_subsystem("test2", HealthStatus::Unhealthy, Some("down".to_string())).await;
        let health = checker.get_health().await;
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }
}
