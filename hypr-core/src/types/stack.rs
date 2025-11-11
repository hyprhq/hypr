//! Stack domain types (Compose).

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Multi-service stack (from compose file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stack {
    /// Stack ID
    pub id: String,

    /// Stack name
    pub name: String,

    /// Services in stack
    pub services: Vec<Service>,

    /// Compose file path
    pub compose_path: Option<String>,

    /// Creation timestamp
    pub created_at: SystemTime,
}

/// Service in a stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service name
    pub name: String,

    /// VM ID for this service instance
    pub vm_id: String,

    /// Service status
    pub status: String,
}
