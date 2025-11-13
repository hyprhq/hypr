//! Manifest generation for HYPR images.
//!
//! Extracts metadata from build graph (ENV, EXPOSE, CMD, etc.)
//! and generates the final image manifest.

use crate::builder::executor::{ImageConfig, ImageManifest};
use crate::builder::graph::{BuildGraph, BuildNode};
use crate::builder::parser::Instruction;
use std::collections::HashMap;

/// Error type for manifest generation.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Invalid instruction: {0}")]
    InvalidInstruction(String),
}

/// Result type for manifest operations.
pub type ManifestResult<T> = Result<T, ManifestError>;

/// Manifest generator that extracts metadata from build graph.
pub struct ManifestGenerator {
    /// Accumulated environment variables
    env: HashMap<String, String>,
    /// Accumulated exposed ports
    exposed_ports: Vec<String>,
    /// Accumulated volumes
    volumes: Vec<String>,
    /// Accumulated labels
    labels: HashMap<String, String>,
    /// Current working directory
    workdir: Option<String>,
    /// Current user
    user: Option<String>,
    /// Entrypoint command
    entrypoint: Option<Vec<String>>,
    /// CMD command
    cmd: Option<Vec<String>>,
}

impl ManifestGenerator {
    /// Creates a new manifest generator.
    pub fn new() -> Self {
        Self {
            env: HashMap::new(),
            exposed_ports: Vec::new(),
            volumes: Vec::new(),
            labels: HashMap::new(),
            workdir: None,
            user: None,
            entrypoint: None,
            cmd: None,
        }
    }

    /// Generates a manifest from a build graph.
    ///
    /// # Arguments
    /// * `graph` - The build graph to extract metadata from
    /// * `name` - Image name
    /// * `tag` - Image tag
    /// * `target_stage` - Optional target stage (for multi-stage builds)
    ///
    /// # Returns
    /// * `Ok(ImageManifest)` - Successfully generated manifest
    /// * `Err(ManifestError)` - Error generating manifest
    pub fn generate(
        &mut self,
        graph: &BuildGraph,
        name: String,
        tag: String,
        target_stage: Option<usize>,
    ) -> ManifestResult<ImageManifest> {
        // Get execution order
        let order = graph.topological_sort().map_err(|e| ManifestError::Graph(e.to_string()))?;

        // Process nodes in order, filtering by target stage if specified
        for node_id in order {
            let node = graph
                .get_node(node_id)
                .ok_or_else(|| ManifestError::Graph(format!("Node {} not found", node_id)))?;

            // If target stage is specified, only process nodes from that stage
            if let Some(target) = target_stage {
                if node.stage_index != target {
                    continue;
                }
            }

            self.process_instruction(node)?;
        }

        // Build the manifest
        let manifest = ImageManifest {
            name,
            tag,
            created: chrono::Utc::now().to_rfc3339(),
            architecture: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            config: ImageConfig {
                entrypoint: self.entrypoint.clone(),
                cmd: self.cmd.clone(),
                env: self.env.clone(),
                workdir: self.workdir.clone(),
                user: self.user.clone(),
                exposed_ports: self.exposed_ports.clone(),
                volumes: self.volumes.clone(),
                labels: self.labels.clone(),
            },
        };

        Ok(manifest)
    }

    /// Converts RunCommand to Vec<String>.
    ///
    /// Shell form is converted to ["/bin/sh", "-c", "command"]
    /// Exec form is used as-is.
    fn run_command_to_vec(command: &crate::builder::parser::RunCommand) -> Vec<String> {
        use crate::builder::parser::RunCommand;
        match command {
            RunCommand::Shell(cmd) => vec!["/bin/sh".to_string(), "-c".to_string(), cmd.clone()],
            RunCommand::Exec(args) => args.clone(),
        }
    }

    /// Processes a single instruction to extract metadata.
    fn process_instruction(&mut self, node: &BuildNode) -> ManifestResult<()> {
        match &node.instruction {
            Instruction::Env { vars } => {
                // Merge environment variables
                for (key, value) in vars {
                    self.env.insert(key.clone(), value.clone());
                }
            }

            Instruction::Expose { ports } => {
                // Add exposed ports (deduplicate)
                for port_spec in ports {
                    let port_str = format!(
                        "{}/{}",
                        port_spec.port,
                        match port_spec.protocol {
                            crate::builder::parser::Protocol::Tcp => "tcp",
                            crate::builder::parser::Protocol::Udp => "udp",
                        }
                    );
                    if !self.exposed_ports.contains(&port_str) {
                        self.exposed_ports.push(port_str);
                    }
                }
            }

            Instruction::Volume { paths } => {
                // Add volumes (deduplicate)
                for path in paths {
                    if !self.volumes.contains(path) {
                        self.volumes.push(path.clone());
                    }
                }
            }

            Instruction::Label { labels } => {
                // Merge labels
                for (key, value) in labels {
                    self.labels.insert(key.clone(), value.clone());
                }
            }

            Instruction::Workdir { path } => {
                // Update working directory (last one wins)
                self.workdir = Some(path.clone());
            }

            Instruction::User { user } => {
                // Update user (last one wins)
                self.user = Some(user.clone());
            }

            Instruction::Entrypoint { command } => {
                // Update entrypoint (last one wins)
                self.entrypoint = Some(Self::run_command_to_vec(command));
            }

            Instruction::Cmd { command } => {
                // Update CMD (last one wins)
                self.cmd = Some(Self::run_command_to_vec(command));
            }

            // Other instructions don't affect manifest metadata
            _ => {}
        }

        Ok(())
    }

    /// Resets the generator state (for processing multiple manifests).
    pub fn reset(&mut self) {
        self.env.clear();
        self.exposed_ports.clear();
        self.volumes.clear();
        self.labels.clear();
        self.workdir = None;
        self.user = None;
        self.entrypoint = None;
        self.cmd = None;
    }
}

impl Default for ManifestGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::parser::parse_dockerfile;

    #[test]
    fn test_simple_manifest() {
        let dockerfile = r#"
FROM alpine:3.19
ENV FOO=bar BAZ=qux
EXPOSE 80/tcp
CMD ["nginx"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "myapp".to_string(), "latest".to_string(), None).unwrap();

        assert_eq!(manifest.name, "myapp");
        assert_eq!(manifest.tag, "latest");
        assert_eq!(manifest.config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(manifest.config.env.get("BAZ"), Some(&"qux".to_string()));
        assert_eq!(manifest.config.exposed_ports.len(), 1);
        assert_eq!(manifest.config.exposed_ports[0], "80/tcp");
        assert_eq!(manifest.config.cmd, Some(vec!["nginx".to_string()]));
    }

    #[test]
    fn test_full_metadata_extraction() {
        let dockerfile = r#"
FROM ubuntu:22.04
ENV PATH=/usr/local/bin:$PATH
ENV NODE_VERSION=20.0.0
WORKDIR /app
USER node
EXPOSE 3000/tcp
EXPOSE 3001/tcp
VOLUME /data
VOLUME /logs
LABEL version="1.0"
LABEL maintainer="test@example.com"
ENTRYPOINT ["node"]
CMD ["server.js"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "nodeapp".to_string(), "v1".to_string(), None).unwrap();

        // Check environment
        assert_eq!(manifest.config.env.len(), 2);
        assert!(manifest.config.env.contains_key("PATH"));
        assert!(manifest.config.env.contains_key("NODE_VERSION"));

        // Check workdir and user
        assert_eq!(manifest.config.workdir, Some("/app".to_string()));
        assert_eq!(manifest.config.user, Some("node".to_string()));

        // Check exposed ports
        assert_eq!(manifest.config.exposed_ports.len(), 2);
        assert!(manifest.config.exposed_ports.contains(&"3000/tcp".to_string()));
        assert!(manifest.config.exposed_ports.contains(&"3001/tcp".to_string()));

        // Check volumes
        assert_eq!(manifest.config.volumes.len(), 2);
        assert!(manifest.config.volumes.contains(&"/data".to_string()));
        assert!(manifest.config.volumes.contains(&"/logs".to_string()));

        // Check labels
        assert_eq!(manifest.config.labels.len(), 2);
        assert_eq!(manifest.config.labels.get("version"), Some(&"1.0".to_string()));
        assert_eq!(manifest.config.labels.get("maintainer"), Some(&"test@example.com".to_string()));

        // Check entrypoint and cmd
        assert_eq!(manifest.config.entrypoint, Some(vec!["node".to_string()]));
        assert_eq!(manifest.config.cmd, Some(vec!["server.js".to_string()]));
    }

    #[test]
    fn test_last_wins_semantics() {
        let dockerfile = r#"
FROM alpine:3.19
WORKDIR /first
WORKDIR /second
WORKDIR /final
USER root
USER nobody
CMD ["old"]
CMD ["new"]
ENTRYPOINT ["old-entry"]
ENTRYPOINT ["new-entry"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "test".to_string(), "latest".to_string(), None).unwrap();

        // Last instruction should win
        assert_eq!(manifest.config.workdir, Some("/final".to_string()));
        assert_eq!(manifest.config.user, Some("nobody".to_string()));
        assert_eq!(manifest.config.cmd, Some(vec!["new".to_string()]));
        assert_eq!(manifest.config.entrypoint, Some(vec!["new-entry".to_string()]));
    }

    #[test]
    fn test_accumulation_semantics() {
        let dockerfile = r#"
FROM alpine:3.19
ENV A=1
ENV B=2
ENV C=3
EXPOSE 80/tcp
EXPOSE 443/tcp
VOLUME /data1
VOLUME /data2
LABEL key1=val1
LABEL key2=val2
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "test".to_string(), "latest".to_string(), None).unwrap();

        // ENV, EXPOSE, VOLUME, LABEL should accumulate
        assert_eq!(manifest.config.env.len(), 3);
        assert_eq!(manifest.config.exposed_ports.len(), 2);
        assert_eq!(manifest.config.volumes.len(), 2);
        assert_eq!(manifest.config.labels.len(), 2);
    }

    #[test]
    fn test_env_override() {
        let dockerfile = r#"
FROM alpine:3.19
ENV FOO=initial
ENV FOO=overridden
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "test".to_string(), "latest".to_string(), None).unwrap();

        // Later ENV should override earlier one
        assert_eq!(manifest.config.env.get("FOO"), Some(&"overridden".to_string()));
    }

    #[test]
    fn test_multi_stage_manifest() {
        let dockerfile = r#"
FROM golang:1.21 AS builder
ENV GOOS=linux
WORKDIR /build
CMD ["go", "build"]

FROM alpine:3.19
ENV APP_ENV=production
WORKDIR /app
EXPOSE 8080/tcp
CMD ["./myapp"]
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();

        // Generate manifest for final stage only (stage 1)
        let manifest =
            generator.generate(&graph, "myapp".to_string(), "latest".to_string(), Some(1)).unwrap();

        // Should only have metadata from stage 1 (alpine)
        assert_eq!(manifest.config.env.len(), 1);
        assert_eq!(manifest.config.env.get("APP_ENV"), Some(&"production".to_string()));
        assert!(!manifest.config.env.contains_key("GOOS")); // From builder stage

        assert_eq!(manifest.config.workdir, Some("/app".to_string()));
        assert_eq!(manifest.config.exposed_ports.len(), 1);
        assert_eq!(manifest.config.cmd, Some(vec!["./myapp".to_string()]));
    }

    #[test]
    fn test_deduplication() {
        let dockerfile = r#"
FROM alpine:3.19
EXPOSE 80/tcp
EXPOSE 80/tcp
EXPOSE 80/tcp
VOLUME /data
VOLUME /data
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "test".to_string(), "latest".to_string(), None).unwrap();

        // Should deduplicate
        assert_eq!(manifest.config.exposed_ports.len(), 1);
        assert_eq!(manifest.config.volumes.len(), 1);
    }

    #[test]
    fn test_generator_reset() {
        let dockerfile = r#"
FROM alpine:3.19
ENV FOO=bar
EXPOSE 80/tcp
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();

        // Generate first manifest
        let _manifest1 =
            generator.generate(&graph, "app1".to_string(), "v1".to_string(), None).unwrap();

        // Reset
        generator.reset();

        // Generate second manifest
        let manifest2 =
            generator.generate(&graph, "app2".to_string(), "v2".to_string(), None).unwrap();

        // Should have fresh metadata
        assert_eq!(manifest2.name, "app2");
        assert_eq!(manifest2.tag, "v2");
        assert_eq!(manifest2.config.env.get("FOO"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_empty_dockerfile() {
        let dockerfile = r#"
FROM scratch
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "empty".to_string(), "latest".to_string(), None).unwrap();

        // Should have empty config
        assert_eq!(manifest.config.env.len(), 0);
        assert_eq!(manifest.config.exposed_ports.len(), 0);
        assert_eq!(manifest.config.volumes.len(), 0);
        assert_eq!(manifest.config.labels.len(), 0);
        assert_eq!(manifest.config.workdir, None);
        assert_eq!(manifest.config.user, None);
        assert_eq!(manifest.config.entrypoint, None);
        assert_eq!(manifest.config.cmd, None);
    }

    #[test]
    fn test_architecture_and_os() {
        let dockerfile = r#"
FROM alpine:3.19
        "#;

        let parsed = parse_dockerfile(dockerfile).unwrap();
        let graph = BuildGraph::from_dockerfile(&parsed).unwrap();

        let mut generator = ManifestGenerator::new();
        let manifest =
            generator.generate(&graph, "test".to_string(), "latest".to_string(), None).unwrap();

        // Should match current platform
        assert!(!manifest.architecture.is_empty());
        assert!(!manifest.os.is_empty());
    }
}
