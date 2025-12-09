//! Runtime manifest format for HYPR VMs.
//!
//! This manifest is passed to kestrel via kernel cmdline as `manifest=<base64-gzip-json>`.
//! It contains everything kestrel needs to run the workload.

use serde::{Deserialize, Serialize};

/// Runtime manifest passed to kestrel via kernel cmdline.
///
/// This is compressed (gzip) and base64-encoded before being added to kernel args.
/// Kestrel decodes, decompresses, and parses this to determine how to run the workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeManifest {
    /// Manifest version (for future compatibility)
    pub version: String,

    /// Workload configuration
    pub workload: WorkloadConfig,

    /// Network configuration (optional - kestrel will configure if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,

    /// Restart policy
    #[serde(default)]
    pub restart: RestartPolicy,

    /// Health check configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthCheckConfig>,
}

/// Workload configuration (what to run)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    /// Entrypoint (executable)
    pub entrypoint: Vec<String>,

    /// Arguments to entrypoint (if any)
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub env: Vec<String>,

    /// Working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,

    /// User to run as (optional, defaults to root)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Network configuration for the VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// IP address (e.g., "192.168.64.2")
    pub ip: String,

    /// Netmask (e.g., "255.255.255.0" or "/24" CIDR)
    pub netmask: String,

    /// Gateway (e.g., "192.168.64.1")
    pub gateway: String,

    /// DNS servers
    #[serde(default)]
    pub dns: Vec<String>,
}

/// Restart policy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RestartPolicy {
    /// Never restart
    #[default]
    Never,

    /// Always restart (even on clean exit)
    Always,

    /// Restart only on failure (non-zero exit code or signal)
    OnFailure,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Type of health check
    #[serde(rename = "type")]
    pub check_type: HealthCheckType,

    /// Interval between checks (seconds)
    #[serde(default = "default_health_interval")]
    pub interval_sec: u32,

    /// Timeout for each check (seconds)
    #[serde(default = "default_health_timeout")]
    pub timeout_sec: u32,

    /// Number of retries before marking unhealthy
    #[serde(default = "default_health_retries")]
    pub retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HealthCheckType {
    /// HTTP health check
    Http {
        /// Endpoint to check (e.g., "/healthz")
        endpoint: String,
        /// Port to check
        port: u16,
    },

    /// TCP port check
    Tcp {
        /// Port to check
        port: u16,
    },

    /// Command to run
    Exec {
        /// Command to execute
        command: Vec<String>,
    },
}

fn default_health_interval() -> u32 {
    30
}

fn default_health_timeout() -> u32 {
    5
}

fn default_health_retries() -> u32 {
    3
}

impl RuntimeManifest {
    /// Create a new minimal runtime manifest
    pub fn new(entrypoint: Vec<String>) -> Self {
        Self {
            version: "1".to_string(),
            workload: WorkloadConfig {
                entrypoint,
                args: vec![],
                env: vec![],
                workdir: None,
                user: None,
            },
            network: None,
            restart: RestartPolicy::Never,
            health: None,
        }
    }

    /// Set environment variables
    pub fn with_env(mut self, env: Vec<String>) -> Self {
        self.workload.env = env;
        self
    }

    /// Set working directory
    pub fn with_workdir(mut self, workdir: String) -> Self {
        self.workload.workdir = Some(workdir);
        self
    }

    /// Set network configuration
    pub fn with_network(mut self, network: NetworkConfig) -> Self {
        self.network = Some(network);
        self
    }

    /// Set restart policy
    pub fn with_restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    /// Set user to run as
    pub fn with_user(mut self, user: String) -> Self {
        self.workload.user = Some(user);
        self
    }

    /// Encode manifest as base64 string for kernel cmdline.
    ///
    /// This produces the value for `manifest=<encoded>` kernel argument.
    /// Uses URL-safe base64 encoding without padding (same format kestrel expects).
    pub fn encode(&self) -> Result<String, std::io::Error> {
        use base64::Engine;

        // Serialize to JSON (compact, no pretty printing)
        let json = serde_json::to_string(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Base64 encode (URL-safe, no padding)
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());

        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_serialization() {
        let manifest = RuntimeManifest::new(vec!["/bin/sh".to_string(), "-c".to_string()])
            .with_env(vec!["PATH=/usr/bin".to_string()])
            .with_workdir("/app".to_string())
            .with_restart(RestartPolicy::Always);

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        println!("Manifest JSON:\n{}", json);

        // Verify it round-trips
        let deserialized: RuntimeManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.workload.entrypoint.len(), 2);
        assert_eq!(deserialized.restart, RestartPolicy::Always);
    }

    #[test]
    fn test_network_config() {
        let network = NetworkConfig {
            ip: "192.168.64.2".to_string(),
            netmask: "255.255.255.0".to_string(),
            gateway: "192.168.64.1".to_string(),
            dns: vec!["8.8.8.8".to_string()],
        };

        let manifest = RuntimeManifest::new(vec!["/usr/bin/bun".to_string()]).with_network(network);

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: RuntimeManifest = serde_json::from_str(&json).unwrap();

        assert!(deserialized.network.is_some());
        assert_eq!(deserialized.network.unwrap().ip, "192.168.64.2");
    }
}
