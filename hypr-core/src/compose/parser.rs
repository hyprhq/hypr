//! Docker Compose file parser.
//!
//! Parses docker-compose.yml files and validates them.

use super::types::*;
use crate::error::{HyprError, Result};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, instrument};

/// Parser for docker-compose.yml files.
pub struct ComposeParser;

impl ComposeParser {
    /// Parse a docker-compose.yml file from a string.
    ///
    /// # Arguments
    ///
    /// * `content` - The YAML content of the compose file
    ///
    /// # Returns
    ///
    /// A parsed and validated `ComposeFile` structure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The YAML is invalid
    /// - The compose version is unsupported
    /// - Required fields are missing
    /// - Services are invalid
    #[instrument(skip(content))]
    pub fn parse(content: &str) -> Result<ComposeFile> {
        info!("Parsing docker-compose.yml");

        let compose: ComposeFile = serde_yaml::from_str(content).map_err(|e| {
            HyprError::ComposeParseError {
                reason: e.to_string(),
            }
        })?;

        // Validate version (support v2, v3)
        Self::validate_version(&compose.version)?;

        // Validate services
        Self::validate_services(&compose.services)?;

        Ok(compose)
    }

    /// Parse a docker-compose.yml file from a file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the compose file
    ///
    /// # Returns
    ///
    /// A parsed and validated `ComposeFile` structure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The file content is invalid (see `parse`)
    #[instrument]
    pub fn parse_file<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Result<ComposeFile> {
        let path = path.as_ref();
        info!("Reading compose file from {:?}", path);

        let content = std::fs::read_to_string(path).map_err(|e| HyprError::FileReadError {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;

        Self::parse(&content)
    }

    /// Validate that the compose version is supported.
    ///
    /// Supports compose file format versions 2 and 3.
    fn validate_version(version: &str) -> Result<()> {
        if version.is_empty() || version.starts_with('2') || version.starts_with('3') {
            Ok(())
        } else {
            Err(HyprError::UnsupportedComposeVersion {
                version: version.to_string(),
            })
        }
    }

    /// Validate that services are properly defined.
    fn validate_services(services: &HashMap<String, Service>) -> Result<()> {
        if services.is_empty() {
            return Err(HyprError::ComposeParseError {
                reason: "No services defined".to_string(),
            });
        }

        for (name, service) in services {
            if service.image.is_empty() {
                return Err(HyprError::ComposeParseError {
                    reason: format!("Service '{}' missing image", name),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_version_v2() {
        assert!(ComposeParser::validate_version("2").is_ok());
        assert!(ComposeParser::validate_version("2.1").is_ok());
    }

    #[test]
    fn test_validate_version_v3() {
        assert!(ComposeParser::validate_version("3").is_ok());
        assert!(ComposeParser::validate_version("3.8").is_ok());
    }

    #[test]
    fn test_validate_version_empty() {
        assert!(ComposeParser::validate_version("").is_ok());
    }

    #[test]
    fn test_validate_version_unsupported() {
        assert!(ComposeParser::validate_version("1").is_err());
        assert!(ComposeParser::validate_version("4").is_err());
    }

    #[test]
    fn test_validate_services_empty() {
        let services = HashMap::new();
        assert!(ComposeParser::validate_services(&services).is_err());
    }

    #[test]
    fn test_validate_services_missing_image() {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            Service {
                image: "".to_string(),
                ports: vec![],
                environment: Environment::default(),
                volumes: vec![],
                networks: vec![],
                depends_on: vec![],
                command: None,
                entrypoint: None,
                working_dir: None,
                user: None,
                labels: HashMap::new(),
                deploy: None,
            },
        );
        assert!(ComposeParser::validate_services(&services).is_err());
    }

    #[test]
    fn test_validate_services_valid() {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            Service {
                image: "nginx:latest".to_string(),
                ports: vec![],
                environment: Environment::default(),
                volumes: vec![],
                networks: vec![],
                depends_on: vec![],
                command: None,
                entrypoint: None,
                working_dir: None,
                user: None,
                labels: HashMap::new(),
                deploy: None,
            },
        );
        assert!(ComposeParser::validate_services(&services).is_ok());
    }
}
