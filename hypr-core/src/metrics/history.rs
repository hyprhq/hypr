//! Metrics history storage and retrieval.
//!
//! Stores VM metrics in SQLite for historical analysis and aggregation.

use crate::error::{HyprError, Result};
use crate::StateManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, instrument};

/// Resolution for metrics aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricsResolution {
    /// No aggregation, raw data points (1-second intervals)
    Raw,
    /// 1-minute aggregation buckets
    Minute,
    /// 1-hour aggregation buckets
    Hour,
    /// 1-day aggregation buckets
    Day,
}

impl MetricsResolution {
    /// Get the bucket size in seconds.
    pub fn bucket_seconds(&self) -> u64 {
        match self {
            Self::Raw => 1,
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86400,
        }
    }

    /// Parse from i32 (proto enum value).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 | 1 => Some(Self::Raw),
            2 => Some(Self::Minute),
            3 => Some(Self::Hour),
            4 => Some(Self::Day),
            _ => None,
        }
    }

    /// Convert to i32 (proto enum value).
    pub fn to_i32(&self) -> i32 {
        match self {
            Self::Raw => 1,
            Self::Minute => 2,
            Self::Hour => 3,
            Self::Day => 4,
        }
    }
}

/// A single metrics data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsDataPoint {
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// CPU usage percentage (0-100).
    pub cpu_percent: f64,
    /// Memory usage percentage (0-100).
    pub memory_percent: f64,
    /// Memory used in bytes.
    pub memory_used_bytes: u64,
    /// Network receive rate (bytes/sec).
    pub net_rx_rate: f64,
    /// Network transmit rate (bytes/sec).
    pub net_tx_rate: f64,
    /// Disk read rate (bytes/sec).
    pub disk_read_rate: f64,
    /// Disk write rate (bytes/sec).
    pub disk_write_rate: f64,
}

/// Metrics history manager.
#[derive(Clone)]
pub struct MetricsHistory {
    state: Arc<StateManager>,
    /// Maximum age of metrics to keep (default: 7 days).
    retention: Duration,
}

impl MetricsHistory {
    /// Create a new metrics history manager.
    pub fn new(state: Arc<StateManager>) -> Self {
        Self { state, retention: Duration::from_secs(7 * 24 * 3600) }
    }

    /// Create with custom retention period.
    pub fn with_retention(state: Arc<StateManager>, retention: Duration) -> Self {
        Self { state, retention }
    }

    /// Record a metrics data point for a VM.
    #[instrument(skip(self))]
    pub async fn record(&self, vm_id: &str, point: &MetricsDataPoint) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO metrics_history (vm_id, timestamp, cpu_percent, memory_percent,
                                          memory_used_bytes, net_rx_rate, net_tx_rate,
                                          disk_read_rate, disk_write_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(vm_id)
        .bind(point.timestamp)
        .bind(point.cpu_percent)
        .bind(point.memory_percent)
        .bind(point.memory_used_bytes as i64)
        .bind(point.net_rx_rate)
        .bind(point.net_tx_rate)
        .bind(point.disk_read_rate)
        .bind(point.disk_write_rate)
        .execute(self.state.pool())
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Query metrics history for a VM.
    #[instrument(skip(self))]
    pub async fn query(
        &self,
        vm_id: &str,
        start_time: i64,
        end_time: i64,
        resolution: MetricsResolution,
    ) -> Result<Vec<MetricsDataPoint>> {
        let bucket_seconds = resolution.bucket_seconds() as i64;

        // For raw resolution, just fetch data points directly
        if resolution == MetricsResolution::Raw {
            return self.query_raw(vm_id, start_time, end_time).await;
        }

        // For aggregated resolution, group by time buckets
        let rows = sqlx::query(
            r#"
            SELECT
                (timestamp / ?) * ? as bucket_ts,
                AVG(cpu_percent) as avg_cpu,
                AVG(memory_percent) as avg_memory,
                AVG(memory_used_bytes) as avg_memory_bytes,
                AVG(net_rx_rate) as avg_net_rx,
                AVG(net_tx_rate) as avg_net_tx,
                AVG(disk_read_rate) as avg_disk_rd,
                AVG(disk_write_rate) as avg_disk_wr
            FROM metrics_history
            WHERE vm_id = ? AND timestamp >= ? AND timestamp <= ?
            GROUP BY bucket_ts
            ORDER BY bucket_ts
            "#,
        )
        .bind(bucket_seconds)
        .bind(bucket_seconds)
        .bind(vm_id)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(self.state.pool())
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        use sqlx::Row;
        let points: Vec<MetricsDataPoint> = rows
            .into_iter()
            .map(|row| MetricsDataPoint {
                timestamp: row.get::<i64, _>("bucket_ts"),
                cpu_percent: row.get::<f64, _>("avg_cpu"),
                memory_percent: row.get::<f64, _>("avg_memory"),
                memory_used_bytes: row.get::<i64, _>("avg_memory_bytes") as u64,
                net_rx_rate: row.get::<f64, _>("avg_net_rx"),
                net_tx_rate: row.get::<f64, _>("avg_net_tx"),
                disk_read_rate: row.get::<f64, _>("avg_disk_rd"),
                disk_write_rate: row.get::<f64, _>("avg_disk_wr"),
            })
            .collect();

        Ok(points)
    }

    /// Query raw (non-aggregated) metrics.
    async fn query_raw(
        &self,
        vm_id: &str,
        start_time: i64,
        end_time: i64,
    ) -> Result<Vec<MetricsDataPoint>> {
        let rows = sqlx::query(
            r#"
            SELECT timestamp, cpu_percent, memory_percent, memory_used_bytes,
                   net_rx_rate, net_tx_rate, disk_read_rate, disk_write_rate
            FROM metrics_history
            WHERE vm_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp
            LIMIT 10000
            "#,
        )
        .bind(vm_id)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(self.state.pool())
        .await
        .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        use sqlx::Row;
        let points: Vec<MetricsDataPoint> = rows
            .into_iter()
            .map(|row| MetricsDataPoint {
                timestamp: row.get::<i64, _>("timestamp"),
                cpu_percent: row.get::<f64, _>("cpu_percent"),
                memory_percent: row.get::<f64, _>("memory_percent"),
                memory_used_bytes: row.get::<i64, _>("memory_used_bytes") as u64,
                net_rx_rate: row.get::<f64, _>("net_rx_rate"),
                net_tx_rate: row.get::<f64, _>("net_tx_rate"),
                disk_read_rate: row.get::<f64, _>("disk_read_rate"),
                disk_write_rate: row.get::<f64, _>("disk_write_rate"),
            })
            .collect();

        Ok(points)
    }

    /// Clean up old metrics data beyond the retention period.
    #[instrument(skip(self))]
    pub async fn cleanup(&self) -> Result<u64> {
        let cutoff = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            as i64
            - self.retention.as_secs() as i64;

        let result = sqlx::query("DELETE FROM metrics_history WHERE timestamp < ?")
            .bind(cutoff)
            .execute(self.state.pool())
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            debug!(deleted, "Cleaned up old metrics data");
        }

        Ok(deleted)
    }

    /// Delete all metrics for a specific VM.
    #[instrument(skip(self))]
    pub async fn delete_vm_metrics(&self, vm_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM metrics_history WHERE vm_id = ?")
            .bind(vm_id)
            .execute(self.state.pool())
            .await
            .map_err(|e| HyprError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_bucket_seconds() {
        assert_eq!(MetricsResolution::Raw.bucket_seconds(), 1);
        assert_eq!(MetricsResolution::Minute.bucket_seconds(), 60);
        assert_eq!(MetricsResolution::Hour.bucket_seconds(), 3600);
        assert_eq!(MetricsResolution::Day.bucket_seconds(), 86400);
    }

    #[test]
    fn test_resolution_conversions() {
        assert_eq!(MetricsResolution::from_i32(1), Some(MetricsResolution::Raw));
        assert_eq!(MetricsResolution::from_i32(2), Some(MetricsResolution::Minute));
        assert_eq!(MetricsResolution::from_i32(3), Some(MetricsResolution::Hour));
        assert_eq!(MetricsResolution::from_i32(4), Some(MetricsResolution::Day));
        assert_eq!(MetricsResolution::from_i32(99), None);
    }
}
