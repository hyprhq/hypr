//! Process Explorer for VM introspection.
//!
//! Provides the ability to list and manage processes running inside VMs
//! by communicating with the Kestrel guest agent.

use crate::error::{HyprError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, instrument, warn};

/// A process running inside a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMProcess {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Process name.
    pub name: String,
    /// Full command line.
    pub command: String,
    /// User running the process.
    pub user: String,
    /// CPU usage percentage (0-100).
    pub cpu_percent: f64,
    /// Memory usage percentage (0-100).
    pub memory_percent: f64,
    /// Resident set size in bytes.
    pub memory_rss: u64,
    /// Virtual memory size in bytes.
    pub memory_vsz: u64,
    /// Process state (R, S, D, Z, etc.).
    pub state: String,
    /// Process start time (Unix timestamp).
    pub start_time: i64,
    /// Total CPU time used (milliseconds).
    pub cpu_time_ms: u64,
}

/// Sort order for process listing.
#[derive(Debug, Clone, Copy, Default)]
pub enum ProcessSortBy {
    /// Sort by CPU usage.
    #[default]
    Cpu,
    /// Sort by memory usage.
    Memory,
    /// Sort by process ID.
    Pid,
    /// Sort by process name.
    Name,
}

impl ProcessSortBy {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cpu" => Some(Self::Cpu),
            "memory" | "mem" => Some(Self::Memory),
            "pid" => Some(Self::Pid),
            "name" => Some(Self::Name),
            _ => None,
        }
    }
}

/// Process explorer for VM introspection.
#[derive(Clone)]
pub struct ProcessExplorer {
    /// Default limit for process listing.
    default_limit: usize,
}

impl Default for ProcessExplorer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessExplorer {
    /// Create a new process explorer.
    pub fn new() -> Self {
        Self { default_limit: 50 }
    }

    /// List processes running in a VM.
    ///
    /// This connects to the Kestrel agent via vsock to retrieve process information.
    #[instrument(skip(self, vsock_path))]
    pub async fn list_processes(
        &self,
        vsock_path: &Path,
        sort_by: ProcessSortBy,
        descending: bool,
        limit: Option<usize>,
    ) -> Result<Vec<VMProcess>> {
        let limit = limit.unwrap_or(self.default_limit);

        // Connect to Kestrel agent
        let mut stream = UnixStream::connect(vsock_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to VM agent: {}", e)))?;

        // Send process list request
        let request = serde_json::json!({
            "type": "list_processes",
            "sort_by": match sort_by {
                ProcessSortBy::Cpu => "cpu",
                ProcessSortBy::Memory => "memory",
                ProcessSortBy::Pid => "pid",
                ProcessSortBy::Name => "name",
            },
            "descending": descending,
            "limit": limit,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| HyprError::Internal(format!("Failed to serialize request: {}", e)))?;

        // Write length-prefixed request
        stream
            .write_u32(request_bytes.len() as u32)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        // Read length-prefixed response
        let response_len = stream
            .read_u32()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response length: {}", e)))?;

        if response_len > 10 * 1024 * 1024 {
            return Err(HyprError::Internal("Response too large".to_string()));
        }

        let mut response_buf = vec![0u8; response_len as usize];
        stream
            .read_exact(&mut response_buf)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response: {}", e)))?;

        // Parse response
        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| HyprError::Internal(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = response.get("error") {
            return Err(HyprError::Internal(error.as_str().unwrap_or("Unknown error").to_string()));
        }

        let processes: Vec<VMProcess> = serde_json::from_value(response["processes"].clone())
            .map_err(|e| HyprError::Internal(format!("Failed to parse processes: {}", e)))?;

        debug!("Retrieved {} processes from VM", processes.len());
        Ok(processes)
    }

    /// Get details of a specific process.
    #[instrument(skip(self, vsock_path))]
    pub async fn get_process(&self, vsock_path: &Path, pid: u32) -> Result<VMProcess> {
        let mut stream = UnixStream::connect(vsock_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to VM agent: {}", e)))?;

        let request = serde_json::json!({
            "type": "get_process",
            "pid": pid,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| HyprError::Internal(format!("Failed to serialize request: {}", e)))?;

        stream
            .write_u32(request_bytes.len() as u32)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        let response_len = stream
            .read_u32()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response length: {}", e)))?;

        if response_len > 1024 * 1024 {
            return Err(HyprError::Internal("Response too large".to_string()));
        }

        let mut response_buf = vec![0u8; response_len as usize];
        stream
            .read_exact(&mut response_buf)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response: {}", e)))?;

        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| HyprError::Internal(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = response.get("error") {
            return Err(HyprError::Internal(error.as_str().unwrap_or("Unknown error").to_string()));
        }

        let process: VMProcess = serde_json::from_value(response["process"].clone())
            .map_err(|e| HyprError::Internal(format!("Failed to parse process: {}", e)))?;

        Ok(process)
    }

    /// Send a signal to a process in the VM.
    #[instrument(skip(self, vsock_path))]
    pub async fn signal_process(&self, vsock_path: &Path, pid: u32, signal: i32) -> Result<()> {
        let mut stream = UnixStream::connect(vsock_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to VM agent: {}", e)))?;

        let request = serde_json::json!({
            "type": "signal_process",
            "pid": pid,
            "signal": signal,
        });

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| HyprError::Internal(format!("Failed to serialize request: {}", e)))?;

        stream
            .write_u32(request_bytes.len() as u32)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to write request: {}", e)))?;

        let response_len = stream
            .read_u32()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response length: {}", e)))?;

        let mut response_buf = vec![0u8; response_len as usize];
        stream
            .read_exact(&mut response_buf)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to read response: {}", e)))?;

        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| HyprError::Internal(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = response.get("error") {
            return Err(HyprError::Internal(error.as_str().unwrap_or("Unknown error").to_string()));
        }

        if response.get("success").and_then(|v| v.as_bool()) != Some(true) {
            warn!(pid, signal, "Signal may not have been delivered");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_by_parse() {
        assert!(matches!(ProcessSortBy::parse("cpu"), Some(ProcessSortBy::Cpu)));
        assert!(matches!(ProcessSortBy::parse("CPU"), Some(ProcessSortBy::Cpu)));
        assert!(matches!(ProcessSortBy::parse("memory"), Some(ProcessSortBy::Memory)));
        assert!(matches!(ProcessSortBy::parse("mem"), Some(ProcessSortBy::Memory)));
        assert!(matches!(ProcessSortBy::parse("pid"), Some(ProcessSortBy::Pid)));
        assert!(matches!(ProcessSortBy::parse("name"), Some(ProcessSortBy::Name)));
        assert!(ProcessSortBy::parse("invalid").is_none());
    }
}
