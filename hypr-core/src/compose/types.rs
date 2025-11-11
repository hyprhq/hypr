//! Docker Compose file format types.
//!
//! Types matching the Docker Compose specification v2 and v3.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root structure of a docker-compose.yml file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeFile {
    /// Compose file format version (e.g., "2", "3", "3.8")
    #[serde(default)]
    pub version: String,

    /// Services to be created
    pub services: HashMap<String, Service>,

    /// Named volumes
    #[serde(default)]
    pub volumes: HashMap<String, VolumeDefinition>,

    /// Networks
    #[serde(default)]
    pub networks: HashMap<String, NetworkDefinition>,
}

/// A service in a docker-compose file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Container image to use
    pub image: String,

    /// Port mappings (e.g., ["8080:80", "443:443"])
    #[serde(default)]
    pub ports: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub environment: Environment,

    /// Volume mounts (e.g., ["./data:/data", "db:/var/lib/db"])
    #[serde(default)]
    pub volumes: Vec<String>,

    /// Networks to connect to
    #[serde(default)]
    pub networks: Vec<String>,

    /// Services this service depends on
    #[serde(default)]
    pub depends_on: Vec<String>,

    /// Override the default command
    #[serde(default)]
    pub command: Option<Vec<String>>,

    /// Override the default entrypoint
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,

    /// Working directory inside the container
    #[serde(default)]
    pub working_dir: Option<String>,

    /// User to run as
    #[serde(default)]
    pub user: Option<String>,

    /// Metadata labels
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Deployment configuration (Compose v3 swarm mode)
    #[serde(default)]
    pub deploy: Option<DeployConfig>,
}

/// Environment variables can be specified as a map or list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Environment {
    /// Environment as key-value map
    Map(HashMap<String, String>),
    /// Environment as list of KEY=value strings
    List(Vec<String>),
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Map(HashMap::new())
    }
}

impl Environment {
    /// Convert environment to a HashMap regardless of input format.
    pub fn to_map(&self) -> HashMap<String, String> {
        match self {
            Environment::Map(map) => map.clone(),
            Environment::List(list) => list
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

/// Deployment configuration (Compose v3 swarm mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployConfig {
    /// Resource limits and reservations
    #[serde(default)]
    pub resources: Option<Resources>,
}

/// Resource configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resources {
    /// Resource limits (maximum)
    #[serde(default)]
    pub limits: Option<ResourceLimit>,

    /// Resource reservations (minimum)
    #[serde(default)]
    pub reservations: Option<ResourceLimit>,
}

impl Resources {
    /// Get CPU limit as a float (e.g., "2.0" -> 2.0)
    pub fn get_cpu_limit(&self) -> Option<f64> {
        self.limits
            .as_ref()
            .and_then(|l| l.cpus.as_ref())
            .and_then(|s| s.parse().ok())
    }

    /// Get memory limit in megabytes
    pub fn get_memory_mb(&self) -> Option<u64> {
        self.limits
            .as_ref()
            .and_then(|l| l.memory.as_ref())
            .and_then(|s| parse_memory_string(s))
    }
}

/// Resource limits for CPU and memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimit {
    /// CPU limit (e.g., "2.0" for 2 cores)
    #[serde(default)]
    pub cpus: Option<String>,

    /// Memory limit (e.g., "1024M", "1G")
    #[serde(default)]
    pub memory: Option<String>,
}

/// Volume definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDefinition {
    /// Volume driver to use
    #[serde(default)]
    pub driver: Option<String>,

    /// Driver-specific options
    #[serde(default)]
    pub driver_opts: HashMap<String, String>,
}

/// Network definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDefinition {
    /// Network driver to use
    #[serde(default)]
    pub driver: Option<String>,

    /// IPAM configuration
    #[serde(default)]
    pub ipam: Option<IpamConfig>,
}

/// IP Address Management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamConfig {
    /// IPAM driver
    #[serde(default)]
    pub driver: Option<String>,

    /// IPAM configuration entries
    #[serde(default)]
    pub config: Vec<HashMap<String, String>>,
}

/// Parse memory string (e.g., "1G", "512M", "1024") to megabytes.
fn parse_memory_string(s: &str) -> Option<u64> {
    let s = s.trim().to_uppercase();

    if s.ends_with('G') {
        s[..s.len() - 1].parse::<u64>().ok().map(|n| n * 1024)
    } else if s.ends_with('M') {
        s[..s.len() - 1].parse::<u64>().ok()
    } else {
        // Assume bytes if no suffix
        s.parse::<u64>().ok().map(|n| n / (1024 * 1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_to_map_from_list() {
        let env = Environment::List(vec![
            "ENV=production".to_string(),
            "DEBUG=false".to_string(),
        ]);
        let map = env.to_map();
        assert_eq!(map.get("ENV"), Some(&"production".to_string()));
        assert_eq!(map.get("DEBUG"), Some(&"false".to_string()));
    }

    #[test]
    fn test_environment_to_map_from_map() {
        let mut expected = HashMap::new();
        expected.insert("ENV".to_string(), "production".to_string());
        let env = Environment::Map(expected.clone());
        let map = env.to_map();
        assert_eq!(map, expected);
    }

    #[test]
    fn test_parse_memory_string_gigabytes() {
        assert_eq!(parse_memory_string("1G"), Some(1024));
        assert_eq!(parse_memory_string("2g"), Some(2048));
    }

    #[test]
    fn test_parse_memory_string_megabytes() {
        assert_eq!(parse_memory_string("512M"), Some(512));
        assert_eq!(parse_memory_string("1024m"), Some(1024));
    }

    #[test]
    fn test_parse_memory_string_bytes() {
        assert_eq!(parse_memory_string("1073741824"), Some(1024)); // 1GB in bytes
    }

    #[test]
    fn test_resources_get_cpu_limit() {
        let resources = Resources {
            limits: Some(ResourceLimit {
                cpus: Some("2.5".to_string()),
                memory: None,
            }),
            reservations: None,
        };
        assert_eq!(resources.get_cpu_limit(), Some(2.5));
    }

    #[test]
    fn test_resources_get_memory_mb() {
        let resources = Resources {
            limits: Some(ResourceLimit {
                cpus: None,
                memory: Some("2G".to_string()),
            }),
            reservations: None,
        };
        assert_eq!(resources.get_memory_mb(), Some(2048));
    }
}
