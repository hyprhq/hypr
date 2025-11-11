//! Proto conversions for daemon-specific types.

use crate::orchestrator::{ServiceStatus, StackInfo, StackState};
use hypr_api::hypr::v1::{Stack, StackService};
use std::time::UNIX_EPOCH;

impl From<StackInfo> for Stack {
    fn from(info: StackInfo) -> Self {
        Self {
            id: info.id,
            name: info.name,
            services: info.services.into_iter().map(|s| s.into()).collect(),
            compose_path: None,
            created_at: info.created_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        }
    }
}

impl From<ServiceStatus> for StackService {
    fn from(status: ServiceStatus) -> Self {
        Self { name: status.name, vm_id: status.vm_id, status: status.status.to_string() }
    }
}

impl From<StackState> for String {
    fn from(state: StackState) -> Self {
        match state {
            StackState::Deploying => "deploying".to_string(),
            StackState::Running => "running".to_string(),
            StackState::Failed => "failed".to_string(),
            StackState::Stopped => "stopped".to_string(),
            StackState::Partial => "partial".to_string(),
        }
    }
}
