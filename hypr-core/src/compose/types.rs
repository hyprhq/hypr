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

    /// Named volumes (null/~ means default options)
    #[serde(default)]
    pub volumes: HashMap<String, Option<VolumeDefinition>>,

    /// Networks (null/~ means default options)
    #[serde(default)]
    pub networks: HashMap<String, Option<NetworkDefinition>>,
}

/// A service in a docker-compose file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Service {
    /// Container image to use (mutually exclusive with build)
    #[serde(default)]
    pub image: String,

    /// Build configuration (mutually exclusive with image for source)
    #[serde(default)]
    pub build: Option<BuildSpec>,

    /// Port mappings (e.g., ["8080:80", "443:443"])
    #[serde(default)]
    pub ports: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub environment: Environment,

    /// Path(s) to env file(s) to load environment variables from
    #[serde(default)]
    pub env_file: EnvFile,

    /// Volume mounts (e.g., ["./data:/data", "db:/var/lib/db"])
    #[serde(default)]
    pub volumes: Vec<String>,

    /// Networks to connect to
    #[serde(default)]
    pub networks: ServiceNetworks,

    /// Services this service depends on
    #[serde(default)]
    pub depends_on: DependsOn,

    /// Override the default command (string or array)
    #[serde(default)]
    pub command: Option<Command>,

    /// Override the default entrypoint (string or array)
    #[serde(default)]
    pub entrypoint: Option<Command>,

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

    /// Container name
    #[serde(default)]
    pub container_name: Option<String>,

    /// Restart policy
    #[serde(default)]
    pub restart: Option<String>,
}

/// Build configuration for a service.
/// Can be a simple string path or a full build configuration object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BuildSpec {
    /// Simple form: "build: ./path"
    Path(String),
    /// Full form: "build: { context: ..., dockerfile: ..., args: ... }"
    Full(BuildConfig),
}

/// Full build configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildConfig {
    /// Build context directory
    pub context: String,

    /// Dockerfile path (relative to context, defaults to "Dockerfile")
    #[serde(default = "default_dockerfile")]
    pub dockerfile: String,

    /// Build arguments
    #[serde(default)]
    pub args: BuildArgs,

    /// Target stage for multi-stage builds
    #[serde(default)]
    pub target: Option<String>,

    /// Images to use as cache sources
    #[serde(default)]
    pub cache_from: Vec<String>,

    /// Labels to add to the built image
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_dockerfile() -> String {
    "Dockerfile".to_string()
}

/// Build arguments can be specified as a map or list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BuildArgs {
    /// Args as key-value map
    Map(HashMap<String, String>),
    /// Args as list of KEY=value strings
    List(Vec<String>),
}

impl Default for BuildArgs {
    fn default() -> Self {
        BuildArgs::Map(HashMap::new())
    }
}

impl BuildArgs {
    /// Convert build args to a HashMap regardless of input format.
    pub fn to_map(&self) -> HashMap<String, String> {
        match self {
            BuildArgs::Map(map) => map.clone(),
            BuildArgs::List(list) => list
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

/// Env file paths can be a single string or a list of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvFile {
    /// Single env file path
    Single(String),
    /// Multiple env file paths
    List(Vec<String>),
}

impl Default for EnvFile {
    fn default() -> Self {
        EnvFile::List(vec![])
    }
}

impl EnvFile {
    /// Get env file paths as a list.
    pub fn to_list(&self) -> Vec<String> {
        match self {
            EnvFile::Single(path) => vec![path.clone()],
            EnvFile::List(paths) => paths.clone(),
        }
    }
}

/// Command can be a string or array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Command {
    /// Shell form: "cmd arg1 arg2"
    Shell(String),
    /// Exec form: ["cmd", "arg1", "arg2"]
    Exec(Vec<String>),
}

impl Command {
    /// Convert command to a list of strings (splitting shell form on whitespace).
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Command::Shell(s) => {
                // Simple shell-like parsing (doesn't handle quotes perfectly, but good enough)
                shell_words::split(s).unwrap_or_else(|_| {
                    s.split_whitespace().map(|s| s.to_string()).collect()
                })
            }
            Command::Exec(v) => v.clone(),
        }
    }
}

/// Service networks can be a list of network names or a map with config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceNetworks {
    /// List form: ["network1", "network2"]
    List(Vec<String>),
    /// Map form with per-network config
    Map(HashMap<String, Option<ServiceNetworkConfig>>),
}

impl Default for ServiceNetworks {
    fn default() -> Self {
        ServiceNetworks::List(vec![])
    }
}

impl ServiceNetworks {
    /// Get network names as a list.
    pub fn to_list(&self) -> Vec<String> {
        match self {
            ServiceNetworks::List(names) => names.clone(),
            ServiceNetworks::Map(map) => map.keys().cloned().collect(),
        }
    }
}

/// Per-service network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNetworkConfig {
    /// Static IP address
    #[serde(default)]
    pub ipv4_address: Option<String>,
    /// Aliases
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// depends_on can be a simple list or a map with condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DependsOn {
    /// List form: ["service1", "service2"]
    List(Vec<String>),
    /// Map form with conditions
    Map(HashMap<String, DependsOnCondition>),
}

impl Default for DependsOn {
    fn default() -> Self {
        DependsOn::List(vec![])
    }
}

impl DependsOn {
    /// Get dependency service names as a list.
    pub fn to_list(&self) -> Vec<String> {
        match self {
            DependsOn::List(names) => names.clone(),
            DependsOn::Map(map) => map.keys().cloned().collect(),
        }
    }
}

/// Dependency condition configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependsOnCondition {
    /// Condition for starting (service_started, service_healthy, service_completed_successfully)
    #[serde(default)]
    pub condition: Option<String>,
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
        self.limits.as_ref().and_then(|l| l.cpus.as_ref()).and_then(|s| s.parse().ok())
    }

    /// Get memory limit in megabytes
    pub fn get_memory_mb(&self) -> Option<u64> {
        self.limits.as_ref().and_then(|l| l.memory.as_ref()).and_then(|s| parse_memory_string(s))
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
        let env = Environment::List(vec!["ENV=production".to_string(), "DEBUG=false".to_string()]);
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
            limits: Some(ResourceLimit { cpus: Some("2.5".to_string()), memory: None }),
            reservations: None,
        };
        assert_eq!(resources.get_cpu_limit(), Some(2.5));
    }

    #[test]
    fn test_resources_get_memory_mb() {
        let resources = Resources {
            limits: Some(ResourceLimit { cpus: None, memory: Some("2G".to_string()) }),
            reservations: None,
        };
        assert_eq!(resources.get_memory_mb(), Some(2048));
    }
}
