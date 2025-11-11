//! Compose file to stack configuration converter.
//!
//! Converts parsed docker-compose structures into HYPR's internal VM configurations,
//! handling service-to-VM mapping, dependency ordering, and resource allocation.

use super::types::*;
use crate::error::{HyprError, Result};
use crate::types::{
    DiskConfig, DiskFormat, NetworkConfig, NetworkStackConfig, PortMapping, Protocol,
    ServiceConfig, StackConfig, VmConfig, VmResources, VolumeConfig, VolumeSource, VolumeMount,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{info, instrument, warn};

/// Converter for docker-compose files to HYPR stack configurations.
pub struct ComposeConverter;

impl ComposeConverter {
    /// Convert a compose file to a stack configuration.
    #[instrument(skip(compose), fields(stack_name = %stack_name.as_ref().unwrap_or(&"default".to_string())))]
    pub fn convert(compose: ComposeFile, stack_name: Option<String>) -> Result<StackConfig> {
        info!("Converting compose file to stack config");

        let name = stack_name.unwrap_or_else(|| "default".to_string());

        // Convert services to VM configs
        let services = Self::convert_services(&compose.services)?;

        // Convert volumes
        let volumes = Self::convert_volumes(&compose.volumes, &compose.services);

        // Create network config
        let network = NetworkStackConfig {
            name: format!("{}_network", name),
            subnet: "100.64.0.0/10".to_string(),
        };

        // Validate dependency graph (no cycles)
        Self::validate_dependencies(&services)?;

        Ok(StackConfig {
            name,
            services,
            volumes,
            network,
        })
    }

    /// Convert compose services to service configurations.
    #[instrument(skip(services))]
    fn convert_services(services: &HashMap<String, Service>) -> Result<Vec<ServiceConfig>> {
        let mut configs = Vec::new();

        for (name, service) in services {
            let vm_config = Self::service_to_vm_config(name, service)?;

            let config = ServiceConfig {
                name: name.clone(),
                vm_config,
                depends_on: service.depends_on.clone(),
                healthcheck: None, // TODO: parse from compose healthcheck
            };

            configs.push(config);
        }

        Ok(configs)
    }

    /// Convert a single service to a VM configuration.
    #[instrument(skip(service), fields(name = %name))]
    fn service_to_vm_config(name: &str, service: &Service) -> Result<VmConfig> {
        info!("Converting service to VM config");

        // Parse resources
        let (cpus, memory_mb) = Self::parse_resources(service)?;

        // Parse ports
        let ports = Self::parse_ports(&service.ports)?;

        // Parse environment
        let env = service.environment.to_map();

        // Create disk config for rootfs
        let rootfs = DiskConfig {
            path: PathBuf::from(format!(
                "/var/lib/hypr/images/{}/rootfs.squashfs",
                service.image
            )),
            readonly: true,
            format: DiskFormat::Squashfs,
        };

        // Parse volume mounts (as disks for now)
        let mut disks = vec![rootfs];
        for volume_spec in &service.volumes {
            if let Some(disk) = Self::parse_volume_mount(volume_spec) {
                disks.push(disk);
            }
        }

        // Parse volume mounts for VmConfig
        let volumes = Self::parse_volume_mounts(&service.volumes);

        // Generate unique VM ID
        let vm_id = format!("{}_{}", name, uuid::Uuid::new_v4().as_simple());

        Ok(VmConfig {
            id: vm_id.clone(),
            name: name.to_string(),
            resources: VmResources {
                cpus,
                memory_mb,
            },
            kernel_path: None, // Use default kernel
            kernel_args: vec![],
            disks,
            network: NetworkConfig::default(),
            ports,
            env,
            volumes,
            gpu: None,
            vsock_path: PathBuf::from(format!("/var/run/hypr/{}.vsock", vm_id)),
        })
    }

    /// Parse resource limits from deploy config.
    #[instrument(skip(service))]
    fn parse_resources(service: &Service) -> Result<(u32, u32)> {
        let mut cpus = 1u32;
        let mut memory_mb = 512u32;

        if let Some(deploy) = &service.deploy {
            if let Some(resources) = &deploy.resources {
                if let Some(cpu) = resources.get_cpu_limit() {
                    cpus = cpu.ceil() as u32;
                    if cpus == 0 {
                        cpus = 1; // Minimum 1 CPU
                    }
                }
                if let Some(mem) = resources.get_memory_mb() {
                    memory_mb = mem as u32;
                    if memory_mb < 128 {
                        memory_mb = 128; // Minimum 128MB
                    }
                }
            }
        }

        Ok((cpus, memory_mb))
    }

    /// Parse port mappings from compose format.
    #[instrument(skip(ports))]
    fn parse_ports(ports: &[String]) -> Result<Vec<PortMapping>> {
        let mut mappings = Vec::new();

        for spec in ports {
            // Format: "HOST:GUEST" or "HOST:GUEST/tcp" or "GUEST"
            let parts: Vec<&str> = spec.split(':').collect();

            if parts.len() == 2 {
                // "HOST:GUEST" or "HOST:GUEST/tcp"
                let host_str = parts[0];
                let guest_spec = parts[1];

                let (guest_str, protocol) = if guest_spec.contains('/') {
                    let guest_parts: Vec<&str> = guest_spec.split('/').collect();
                    (guest_parts[0], *guest_parts.get(1).unwrap_or(&"tcp"))
                } else {
                    (guest_spec, "tcp")
                };

                if let (Ok(host_port), Ok(guest_port)) =
                    (host_str.parse::<u16>(), guest_str.parse::<u16>())
                {
                    let protocol = match protocol.to_lowercase().as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => {
                            warn!("Unknown protocol '{}', defaulting to TCP", protocol);
                            Protocol::Tcp
                        }
                    };

                    mappings.push(PortMapping {
                        host_port,
                        vm_port: guest_port,
                        protocol,
                    });
                } else {
                    warn!("Invalid port spec: {}", spec);
                }
            } else if parts.len() == 1 {
                // "GUEST" - use same port for host
                let guest_spec = parts[0];
                let (guest_str, protocol) = if guest_spec.contains('/') {
                    let guest_parts: Vec<&str> = guest_spec.split('/').collect();
                    (guest_parts[0], *guest_parts.get(1).unwrap_or(&"tcp"))
                } else {
                    (guest_spec, "tcp")
                };

                if let Ok(port) = guest_str.parse::<u16>() {
                    let protocol = match protocol.to_lowercase().as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => Protocol::Tcp,
                    };

                    mappings.push(PortMapping {
                        host_port: port,
                        vm_port: port,
                        protocol,
                    });
                } else {
                    warn!("Invalid port spec: {}", spec);
                }
            } else {
                warn!("Invalid port spec: {}", spec);
            }
        }

        Ok(mappings)
    }

    /// Parse a single volume mount spec into a disk config.
    fn parse_volume_mount(spec: &str) -> Option<DiskConfig> {
        // Format: "HOST:GUEST" or "HOST:GUEST:ro" or "NAME:GUEST"
        let parts: Vec<&str> = spec.split(':').collect();

        if parts.len() >= 2 {
            let readonly = parts.get(2) == Some(&"ro");

            // For now, create a disk config pointing to the source
            // The actual path resolution will happen at runtime
            Some(DiskConfig {
                path: PathBuf::from(parts[0]),
                readonly,
                format: DiskFormat::Ext4, // Default for volumes
            })
        } else {
            warn!("Invalid volume spec: {}", spec);
            None
        }
    }

    /// Parse volume mounts for VmConfig volumes field.
    fn parse_volume_mounts(volume_specs: &[String]) -> Vec<VolumeMount> {
        volume_specs
            .iter()
            .filter_map(|spec| {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() >= 2 {
                    let readonly = parts.get(2) == Some(&"ro");
                    Some(VolumeMount {
                        source: parts[0].to_string(),
                        target: parts[1].to_string(),
                        readonly,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Convert volume definitions.
    #[instrument(skip(volume_defs, services))]
    fn convert_volumes(
        volume_defs: &HashMap<String, VolumeDefinition>,
        services: &HashMap<String, Service>,
    ) -> Vec<VolumeConfig> {
        let mut volumes = Vec::new();

        // Collect all named volumes from services
        for (service_name, service) in services {
            for volume_spec in &service.volumes {
                let parts: Vec<&str> = volume_spec.split(':').collect();
                if parts.len() >= 2 {
                    let source = parts[0];
                    let mount_path = parts[1];

                    // Check if it's a named volume (exists in volume_defs)
                    if volume_defs.contains_key(source) {
                        // Skip if already added
                        if volumes.iter().any(|v: &VolumeConfig| v.name == source) {
                            continue;
                        }

                        volumes.push(VolumeConfig {
                            name: source.to_string(),
                            mount_path: mount_path.to_string(),
                            source: VolumeSource::Named(source.to_string()),
                        });
                    } else if !source.starts_with('.') && !source.starts_with('/') {
                        // Looks like a named volume but not defined - treat as named
                        if volumes.iter().any(|v: &VolumeConfig| v.name == source) {
                            continue;
                        }

                        volumes.push(VolumeConfig {
                            name: source.to_string(),
                            mount_path: mount_path.to_string(),
                            source: VolumeSource::Named(source.to_string()),
                        });
                    } else {
                        // Host path mount
                        let volume_name = format!("{}_bind_{}", service_name, volumes.len());
                        volumes.push(VolumeConfig {
                            name: volume_name,
                            mount_path: mount_path.to_string(),
                            source: VolumeSource::HostPath(PathBuf::from(source)),
                        });
                    }
                }
            }
        }

        volumes
    }

    /// Validate that there are no circular dependencies.
    #[instrument(skip(services))]
    fn validate_dependencies(services: &[ServiceConfig]) -> Result<()> {
        // Build dependency graph
        let mut graph: HashMap<&str, Vec<&str>> = HashMap::new();

        for service in services {
            graph.insert(
                &service.name,
                service.depends_on.iter().map(|s| s.as_str()).collect(),
            );
        }

        // Check for missing dependencies
        for service in services {
            for dep in &service.depends_on {
                if !services.iter().any(|s| &s.name == dep) {
                    return Err(HyprError::MissingDependency {
                        service: service.name.clone(),
                        dependency: dep.clone(),
                    });
                }
            }
        }

        // Check for cycles using DFS
        for service in services {
            let mut visited = HashSet::new();
            let mut stack = HashSet::new();

            if Self::has_cycle(&graph, &service.name, &mut visited, &mut stack) {
                return Err(HyprError::CircularDependency {
                    service: service.name.clone(),
                });
            }
        }

        Ok(())
    }

    /// Detect cycles in dependency graph using DFS.
    fn has_cycle(
        graph: &HashMap<&str, Vec<&str>>,
        node: &str,
        visited: &mut HashSet<String>,
        stack: &mut HashSet<String>,
    ) -> bool {
        if stack.contains(node) {
            return true; // Cycle detected
        }

        if visited.contains(node) {
            return false; // Already checked
        }

        visited.insert(node.to_string());
        stack.insert(node.to_string());

        if let Some(deps) = graph.get(node) {
            for dep in deps {
                if Self::has_cycle(graph, dep, visited, stack) {
                    return true;
                }
            }
        }

        stack.remove(node);
        false
    }

    /// Sort services by dependency order (dependencies first).
    #[instrument(skip(services))]
    pub fn topological_sort(services: &[ServiceConfig]) -> Vec<ServiceConfig> {
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();

        fn visit(
            service: &ServiceConfig,
            services: &[ServiceConfig],
            visited: &mut HashSet<String>,
            sorted: &mut Vec<ServiceConfig>,
        ) {
            if visited.contains(&service.name) {
                return;
            }

            visited.insert(service.name.clone());

            // Visit dependencies first
            for dep_name in &service.depends_on {
                if let Some(dep) = services.iter().find(|s| &s.name == dep_name) {
                    visit(dep, services, visited, sorted);
                }
            }

            sorted.push(service.clone());
        }

        for service in services {
            visit(service, services, &mut visited, &mut sorted);
        }

        sorted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_basic_service() {
        let compose = ComposeFile {
            version: "3".to_string(),
            services: HashMap::from([(
                "web".to_string(),
                Service {
                    image: "nginx:latest".to_string(),
                    ports: vec!["8080:80".to_string()],
                    ..Default::default()
                },
            )]),
            volumes: HashMap::new(),
            networks: HashMap::new(),
        };

        let stack = ComposeConverter::convert(compose, Some("test".to_string())).unwrap();
        assert_eq!(stack.services.len(), 1);
        assert_eq!(stack.services[0].name, "web");
        assert_eq!(stack.services[0].vm_config.ports.len(), 1);
        assert_eq!(stack.services[0].vm_config.ports[0].host_port, 8080);
        assert_eq!(stack.services[0].vm_config.ports[0].vm_port, 80);
    }

    #[test]
    fn test_parse_ports() {
        let ports = vec![
            "8080:80".to_string(),
            "3000:3000/tcp".to_string(),
            "53:53/udp".to_string(),
            "9000".to_string(),
        ];

        let mappings = ComposeConverter::parse_ports(&ports).unwrap();
        assert_eq!(mappings.len(), 4);

        assert_eq!(mappings[0].host_port, 8080);
        assert_eq!(mappings[0].vm_port, 80);
        assert_eq!(mappings[0].protocol, Protocol::Tcp);

        assert_eq!(mappings[1].host_port, 3000);
        assert_eq!(mappings[1].vm_port, 3000);

        assert_eq!(mappings[2].protocol, Protocol::Udp);

        assert_eq!(mappings[3].host_port, 9000);
        assert_eq!(mappings[3].vm_port, 9000);
    }

    #[test]
    fn test_dependency_ordering() {
        // web depends on db
        let services = vec![
            ServiceConfig {
                name: "web".to_string(),
                vm_config: VmConfig {
                    id: "web".to_string(),
                    name: "web".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    vsock_path: PathBuf::from("/tmp/web.vsock"),
                },
                depends_on: vec!["db".to_string()],
                healthcheck: None,
            },
            ServiceConfig {
                name: "db".to_string(),
                vm_config: VmConfig {
                    id: "db".to_string(),
                    name: "db".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    vsock_path: PathBuf::from("/tmp/db.vsock"),
                },
                depends_on: vec![],
                healthcheck: None,
            },
        ];

        let sorted = ComposeConverter::topological_sort(&services);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].name, "db");
        assert_eq!(sorted[1].name, "web");
    }

    #[test]
    fn test_circular_dependency_detection() {
        let services = vec![
            ServiceConfig {
                name: "a".to_string(),
                vm_config: VmConfig {
                    id: "a".to_string(),
                    name: "a".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    vsock_path: PathBuf::from("/tmp/a.vsock"),
                },
                depends_on: vec!["b".to_string()],
                healthcheck: None,
            },
            ServiceConfig {
                name: "b".to_string(),
                vm_config: VmConfig {
                    id: "b".to_string(),
                    name: "b".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    vsock_path: PathBuf::from("/tmp/b.vsock"),
                },
                depends_on: vec!["a".to_string()],
                healthcheck: None,
            },
        ];

        let result = ComposeConverter::validate_dependencies(&services);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HyprError::CircularDependency { .. }
        ));
    }

    #[test]
    fn test_missing_dependency_detection() {
        let services = vec![ServiceConfig {
            name: "web".to_string(),
            vm_config: VmConfig {
                id: "web".to_string(),
                name: "web".to_string(),
                resources: VmResources::default(),
                kernel_path: None,
                kernel_args: vec![],
                disks: vec![],
                network: NetworkConfig::default(),
                ports: vec![],
                env: HashMap::new(),
                volumes: vec![],
                gpu: None,
                vsock_path: PathBuf::from("/tmp/web.vsock"),
            },
            depends_on: vec!["nonexistent".to_string()],
            healthcheck: None,
        }];

        let result = ComposeConverter::validate_dependencies(&services);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HyprError::MissingDependency { .. }
        ));
    }

    #[test]
    fn test_resource_parsing() {
        let service = Service {
            image: "test".to_string(),
            deploy: Some(DeployConfig {
                resources: Some(Resources {
                    limits: Some(ResourceLimit {
                        cpus: Some("2.5".to_string()),
                        memory: Some("1024m".to_string()),
                    }),
                    reservations: None,
                }),
            }),
            ..Default::default()
        };

        let (cpus, memory_mb) = ComposeConverter::parse_resources(&service).unwrap();
        assert_eq!(cpus, 3); // Ceiling of 2.5
        assert_eq!(memory_mb, 1024);
    }

    #[test]
    fn test_resource_defaults() {
        let service = Service {
            image: "test".to_string(),
            ..Default::default()
        };

        let (cpus, memory_mb) = ComposeConverter::parse_resources(&service).unwrap();
        assert_eq!(cpus, 1); // Default
        assert_eq!(memory_mb, 512); // Default
    }

    #[test]
    fn test_volume_parsing() {
        let volume_defs = HashMap::from([
            (
                "db-data".to_string(),
                VolumeDefinition {
                    driver: None,
                    driver_opts: HashMap::new(),
                },
            ),
        ]);

        let services = HashMap::from([
            (
                "db".to_string(),
                Service {
                    image: "postgres".to_string(),
                    volumes: vec![
                        "db-data:/var/lib/postgresql/data".to_string(),
                        "./config:/etc/config:ro".to_string(),
                    ],
                    ..Default::default()
                },
            ),
        ]);

        let volumes = ComposeConverter::convert_volumes(&volume_defs, &services);

        // Should have 2 volumes: one named, one host path
        assert_eq!(volumes.len(), 2);

        // Find the named volume
        let named_vol = volumes.iter().find(|v| v.name == "db-data").unwrap();
        assert!(matches!(named_vol.source, VolumeSource::Named(_)));

        // Find the host path volume
        let host_vol = volumes.iter().find(|v| v.name.contains("bind")).unwrap();
        assert!(matches!(host_vol.source, VolumeSource::HostPath(_)));
    }
}
