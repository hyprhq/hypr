//! Cron job scheduling types and utilities.
//!
//! This module provides types for scheduled task execution in HYPR.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a cron job run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CronJobRunStatus {
    /// Scheduled but not yet started.
    #[default]
    Pending,
    /// Currently executing.
    Running,
    /// Completed successfully (exit code 0).
    Succeeded,
    /// Failed (non-zero exit code or error).
    Failed,
    /// Cancelled by user.
    Cancelled,
    /// Exceeded timeout limit.
    Timeout,
}

impl CronJobRunStatus {
    /// Parse status from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pending" => CronJobRunStatus::Pending,
            "running" => CronJobRunStatus::Running,
            "succeeded" => CronJobRunStatus::Succeeded,
            "failed" => CronJobRunStatus::Failed,
            "cancelled" => CronJobRunStatus::Cancelled,
            "timeout" => CronJobRunStatus::Timeout,
            _ => CronJobRunStatus::Pending,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            CronJobRunStatus::Pending => "pending",
            CronJobRunStatus::Running => "running",
            CronJobRunStatus::Succeeded => "succeeded",
            CronJobRunStatus::Failed => "failed",
            CronJobRunStatus::Cancelled => "cancelled",
            CronJobRunStatus::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for CronJobRunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A scheduled cron job that runs VMs on a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// Unique job ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Cron expression (e.g., "*/5 * * * *").
    pub schedule: String,
    /// Container image to run.
    pub image: String,
    /// Command to execute.
    pub command: Vec<String>,
    /// Environment variables.
    pub env: HashMap<String, String>,
    /// Number of CPUs to allocate.
    pub resources_cpus: u32,
    /// Memory in MB to allocate.
    pub resources_memory_mb: u32,
    /// Whether the job is active.
    pub enabled: bool,
    /// Unix timestamp when created.
    pub created_at: i64,
    /// Unix timestamp of last execution.
    pub last_run: Option<i64>,
    /// Unix timestamp of next scheduled run.
    pub next_run: Option<i64>,
    /// Max execution time in seconds.
    pub timeout_sec: u32,
    /// Max retry attempts on failure.
    pub max_retries: u32,
    /// Custom labels/metadata.
    pub labels: HashMap<String, String>,
}

impl Default for CronJob {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            schedule: String::new(),
            image: String::new(),
            command: Vec::new(),
            env: HashMap::new(),
            resources_cpus: 1,
            resources_memory_mb: 512,
            enabled: true,
            created_at: 0,
            last_run: None,
            next_run: None,
            timeout_sec: 3600,
            max_retries: 0,
            labels: HashMap::new(),
        }
    }
}

/// A single run/execution of a cron job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJobRun {
    /// Unique run ID.
    pub id: String,
    /// Parent cron job ID.
    pub job_id: String,
    /// Unix timestamp when started.
    pub started_at: i64,
    /// Unix timestamp when finished.
    pub finished_at: Option<i64>,
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Current status.
    pub status: CronJobRunStatus,
    /// Combined stdout/stderr output.
    pub output: String,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// Attempt number (1-based).
    pub attempt: u32,
}

impl Default for CronJobRun {
    fn default() -> Self {
        Self {
            id: String::new(),
            job_id: String::new(),
            started_at: 0,
            finished_at: None,
            exit_code: 0,
            status: CronJobRunStatus::Pending,
            output: String::new(),
            error_message: None,
            attempt: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_job_run_status_parse() {
        assert_eq!(CronJobRunStatus::parse("pending"), CronJobRunStatus::Pending);
        assert_eq!(CronJobRunStatus::parse("RUNNING"), CronJobRunStatus::Running);
        assert_eq!(
            CronJobRunStatus::parse("succeeded"),
            CronJobRunStatus::Succeeded
        );
        assert_eq!(CronJobRunStatus::parse("failed"), CronJobRunStatus::Failed);
        assert_eq!(CronJobRunStatus::parse("timeout"), CronJobRunStatus::Timeout);
        assert_eq!(
            CronJobRunStatus::parse("unknown"),
            CronJobRunStatus::Pending
        );
    }

    #[test]
    fn test_cron_job_default() {
        let job = CronJob::default();
        assert!(job.enabled);
        assert_eq!(job.resources_cpus, 1);
        assert_eq!(job.resources_memory_mb, 512);
        assert_eq!(job.timeout_sec, 3600);
        assert_eq!(job.max_retries, 0);
    }
}
