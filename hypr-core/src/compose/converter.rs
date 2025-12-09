//! Compose file to stack configuration converter.
//!
//! Converts parsed docker-compose structures into HYPR's internal VM configurations,
//! handling service-to-VM mapping, dependency ordering, and resource allocation.

use super::types::*;
use crate::builder::parser::parse_dockerfile;
use crate::builder::{create_builder, BuildContext, BuildGraph, CacheManager};
use crate::error::{HyprError, Result};
use crate::types::{
    DiskConfig, DiskFormat, NetworkConfig, NetworkStackConfig, PortMapping, Protocol,
    ServiceConfig, StackConfig, VmConfig, VmResources, VolumeConfig, VolumeMount, VolumeSource,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{info, instrument, warn};

/// Converter for docker-compose files to HYPR stack configurations.
pub struct ComposeConverter;

impl ComposeConverter {
    /// Convert a compose file to a stack configuration.
    /// This synchronous version does not build images - use `convert_async` for full build support.
    #[instrument(skip(compose), fields(stack_name = %stack_name.as_ref().unwrap_or(&"default".to_string())))]
    pub fn convert(compose: ComposeFile, stack_name: Option<String>) -> Result<StackConfig> {
        info!("Converting compose file to stack config");

        let name = stack_name.unwrap_or_else(|| "default".to_string());

        // Convert services to VM configs
        let services = Self::convert_services(&compose.services, &HashMap::new())?;

        // Convert volumes
        let volumes = Self::convert_volumes(&compose.volumes, &compose.services);

        // Create network config
        let network = NetworkStackConfig {
            name: format!("{}_network", name),
            subnet: "100.64.0.0/10".to_string(),
        };

        // Validate dependency graph (no cycles)
        Self::validate_dependencies(&services)?;

        Ok(StackConfig { name, services, volumes, network })
    }

    /// Convert a compose file to a stack configuration, building images as needed.
    ///
    /// This async version will build any services that have a `build` configuration
    /// before converting them to VM configs.
    #[instrument(skip(compose, compose_dir), fields(stack_name = %stack_name.as_ref().unwrap_or(&"default".to_string())))]
    pub async fn convert_async(
        compose: ComposeFile,
        stack_name: Option<String>,
        compose_dir: PathBuf,
    ) -> Result<StackConfig> {
        info!("Converting compose file to stack config (async with build support)");

        let name = stack_name.unwrap_or_else(|| "default".to_string());

        // Build images for services with build config
        let built_images = Self::build_service_images(&compose.services, &compose_dir).await?;

        // Convert services to VM configs, using built images where available
        let services = Self::convert_services(&compose.services, &built_images)?;

        // Convert volumes
        let volumes = Self::convert_volumes(&compose.volumes, &compose.services);

        // Create network config
        let network = NetworkStackConfig {
            name: format!("{}_network", name),
            subnet: "100.64.0.0/10".to_string(),
        };

        // Validate dependency graph (no cycles)
        Self::validate_dependencies(&services)?;

        Ok(StackConfig { name, services, volumes, network })
    }

    /// Build images for services that have build configurations.
    /// Returns a map of service name -> built image path.
    ///
    /// Supports parallel builds for services without dependencies on each other.
    #[instrument(skip(services, compose_dir))]
    async fn build_service_images(
        services: &HashMap<String, Service>,
        compose_dir: &Path,
    ) -> Result<HashMap<String, PathBuf>> {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // Collect services that need building
        let mut build_tasks: Vec<(String, BuildSpec, Vec<String>)> = Vec::new();

        for (name, service) in services {
            if let Some(build_spec) = &service.build {
                // Get depends_on for ordering (services that must be built first)
                let deps: Vec<String> = service
                    .depends_on
                    .iter()
                    .filter(|dep| services.get(*dep).map(|s| s.build.is_some()).unwrap_or(false))
                    .cloned()
                    .collect();
                build_tasks.push((name.clone(), build_spec.clone(), deps));
            }
        }

        if build_tasks.is_empty() {
            return Ok(HashMap::new());
        }

        // Sort by dependencies (simple topological sort)
        let mut ordered_tasks = Vec::new();
        let mut completed: std::collections::HashSet<String> = std::collections::HashSet::new();

        while ordered_tasks.len() < build_tasks.len() {
            let mut progress = false;
            for (name, spec, deps) in &build_tasks {
                if completed.contains(name) {
                    continue;
                }
                if deps.iter().all(|d| completed.contains(d)) {
                    ordered_tasks.push((name.clone(), spec.clone()));
                    completed.insert(name.clone());
                    progress = true;
                }
            }
            if !progress {
                // Circular dependency or missing dependency - just add remaining
                for (name, spec, _) in &build_tasks {
                    if !completed.contains(name) {
                        ordered_tasks.push((name.clone(), spec.clone()));
                        completed.insert(name.clone());
                    }
                }
                break;
            }
        }

        // Find batches that can run in parallel (services with same dependency depth)
        // For now, keep it simple: build sequentially but with parallel potential
        let built_images = Arc::new(Mutex::new(HashMap::new()));

        // Group tasks by dependency depth for potential parallel execution
        let mut batches: Vec<Vec<(String, BuildSpec)>> = Vec::new();
        let mut batch_completed: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (name, spec) in ordered_tasks {
            // Check if this can be in the current batch (all deps in batch_completed)
            let deps: Vec<String> = build_tasks
                .iter()
                .find(|(n, _, _)| n == &name)
                .map(|(_, _, d)| d.clone())
                .unwrap_or_default();

            let can_be_parallel = deps.iter().all(|d| batch_completed.contains(d));

            if batches.is_empty() || !can_be_parallel {
                // Start new batch
                for task in batches.last().unwrap_or(&vec![]) {
                    batch_completed.insert(task.0.clone());
                }
                batches.push(vec![(name, spec)]);
            } else {
                // Add to current batch (can run in parallel)
                batches.last_mut().unwrap().push((name, spec));
            }
        }

        // Execute batches
        for batch in batches {
            if batch.len() == 1 {
                // Single task - run directly
                let (name, spec) = &batch[0];
                let (context_path, dockerfile, build_args, target, cache_from) =
                    Self::extract_build_config(spec, compose_dir);

                info!("Building image for service: {}", name);
                let image_path = Self::build_image(
                    name,
                    &context_path,
                    &dockerfile,
                    build_args,
                    target,
                    cache_from,
                )
                .await?;

                built_images.lock().await.insert(name.clone(), image_path);
            } else {
                // Multiple tasks - run in parallel
                info!(
                    "Building {} services in parallel: {:?}",
                    batch.len(),
                    batch.iter().map(|(n, _)| n).collect::<Vec<_>>()
                );

                let mut handles = Vec::new();
                for (name, spec) in batch {
                    let name = name.clone();
                    let compose_dir = compose_dir.to_path_buf();
                    let built_images = Arc::clone(&built_images);
                    let (context_path, dockerfile, build_args, target, cache_from) =
                        Self::extract_build_config(&spec, &compose_dir);

                    let handle = tokio::spawn(async move {
                        let result = Self::build_image(
                            &name,
                            &context_path,
                            &dockerfile,
                            build_args,
                            target,
                            cache_from,
                        )
                        .await;

                        match result {
                            Ok(path) => {
                                built_images.lock().await.insert(name.clone(), path);
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all parallel builds
                for handle in handles {
                    handle.await.map_err(|e| HyprError::BuildFailed {
                        reason: format!("Parallel build task failed: {}", e),
                    })??;
                }
            }
        }

        Ok(Arc::try_unwrap(built_images).unwrap().into_inner())
    }

    /// Extract build configuration from BuildSpec.
    fn extract_build_config(
        spec: &BuildSpec,
        compose_dir: &Path,
    ) -> (PathBuf, String, HashMap<String, String>, Option<String>, Vec<String>) {
        match spec {
            BuildSpec::Path(path) => {
                let context = compose_dir.join(path);
                (context, "Dockerfile".to_string(), HashMap::new(), None, Vec::new())
            }
            BuildSpec::Full(config) => {
                let context = compose_dir.join(&config.context);
                (
                    context,
                    config.dockerfile.clone(),
                    config.args.to_map(),
                    config.target.clone(),
                    config.cache_from.clone(),
                )
            }
        }
    }

    /// Build a single image using the hypr build system.
    #[instrument(skip(build_args, cache_from))]
    async fn build_image(
        service_name: &str,
        context_path: &PathBuf,
        dockerfile: &str,
        build_args: HashMap<String, String>,
        target: Option<String>,
        cache_from: Vec<String>,
    ) -> Result<PathBuf> {
        info!("Building image for service {} from {:?}", service_name, context_path);

        // Read the Dockerfile
        let dockerfile_path = context_path.join(dockerfile);
        let dockerfile_content =
            std::fs::read_to_string(&dockerfile_path).map_err(|e| HyprError::FileReadError {
                path: dockerfile_path.to_string_lossy().to_string(),
                source: e,
            })?;

        // Parse the Dockerfile
        let parsed_dockerfile = parse_dockerfile(&dockerfile_content).map_err(|e| {
            HyprError::InvalidDockerfile { path: dockerfile_path.clone(), reason: e.to_string() }
        })?;

        // Build the graph
        let graph = BuildGraph::from_dockerfile(&parsed_dockerfile).map_err(|e| {
            HyprError::BuildFailed { reason: format!("Failed to construct build graph: {}", e) }
        })?;

        // Create build context
        let context = BuildContext {
            context_path: context_path.clone(),
            dockerfile_path: PathBuf::from(dockerfile),
            build_args,
            target,
            no_cache: false,
        };

        // Initialize cache manager
        let mut cache = CacheManager::new().map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to initialize cache: {}", e),
        })?;

        // Handle cache_from: import layers from specified images as cache sources
        if !cache_from.is_empty() {
            info!("Processing cache_from sources: {:?}", cache_from);
            for cache_image in &cache_from {
                match Self::import_cache_from_image(&mut cache, cache_image).await {
                    Ok(layers) => {
                        info!("Imported {} cached layers from {}", layers, cache_image);
                    }
                    Err(e) => {
                        // cache_from failures are non-fatal - just log and continue
                        warn!("Failed to import cache from {}: {}", cache_image, e);
                    }
                }
            }
        }

        // Create and run the builder
        let mut builder = create_builder().map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create builder: {}", e),
        })?;

        let output = builder
            .execute(&graph, &context, &mut cache)
            .await
            .map_err(|e| HyprError::BuildFailed { reason: format!("Build failed: {}", e) })?;

        // Move the rootfs to the images directory (similar to CLI)
        let images_dir = crate::paths::images_dir();
        let image_dir = images_dir.join(&output.image_id);

        std::fs::create_dir_all(&image_dir)
            .map_err(|e| HyprError::IoError { path: image_dir.clone(), source: e })?;

        let permanent_rootfs = image_dir.join("rootfs.squashfs");

        std::fs::rename(&output.rootfs_path, &permanent_rootfs)
            .map_err(|e| HyprError::IoError { path: permanent_rootfs.clone(), source: e })?;

        info!("Built image {} for service {}", output.image_id, service_name);

        // Return the path to the squashfs image
        Ok(permanent_rootfs)
    }

    /// Import layers from a cache_from image into the cache manager.
    /// This allows reusing layers from previously built images.
    ///
    /// Returns the number of layers imported.
    #[instrument(skip(cache))]
    async fn import_cache_from_image(cache: &mut CacheManager, image_ref: &str) -> Result<usize> {
        use crate::builder::oci::OciClient;

        info!("Attempting to import cache from image: {}", image_ref);

        // Check if it's a local image first (in our images directory)
        let images_dir = crate::paths::images_dir();

        // Try to find a local image with this name
        // Format could be "name:tag" or just "name" (defaults to latest)
        let name = if image_ref.contains(':') {
            image_ref.split(':').next().unwrap_or(image_ref)
        } else {
            image_ref
        };

        // Look for the image in the local images directory
        // First check if there's a directory matching the image name
        let local_image_dir = images_dir.join(name);
        if local_image_dir.exists() {
            // Found local image - import its layers into cache
            let layers_imported = Self::import_local_image_cache(cache, &local_image_dir)?;
            return Ok(layers_imported);
        }

        // Try to pull the image and extract layers
        // Create a temporary directory for the pulled image
        let temp_dir =
            std::env::temp_dir().join(format!("hypr-cache-from-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir)
            .map_err(|e| HyprError::IoError { path: temp_dir.clone(), source: e })?;

        // Pull the image
        let mut oci_client = OciClient::new().map_err(|e| HyprError::BuildFailed {
            reason: format!("Failed to create OCI client: {}", e),
        })?;

        match oci_client.pull_image(image_ref, &temp_dir).await {
            Ok(_) => {
                let layers_imported = Self::import_local_image_cache(cache, &temp_dir)?;
                // Clean up temp directory
                let _ = std::fs::remove_dir_all(&temp_dir);
                Ok(layers_imported)
            }
            Err(e) => {
                // Clean up temp directory
                let _ = std::fs::remove_dir_all(&temp_dir);
                Err(HyprError::BuildFailed {
                    reason: format!("Failed to pull cache_from image {}: {}", image_ref, e),
                })
            }
        }
    }

    /// Import layers from a local image directory into the cache.
    fn import_local_image_cache(cache: &mut CacheManager, image_dir: &Path) -> Result<usize> {
        let mut layers_imported = 0;

        // Look for layer files in the image directory
        // Typically these would be .tar files or a layers/ subdirectory
        let layers_dir = image_dir.join("layers");

        if layers_dir.exists() {
            for entry in std::fs::read_dir(&layers_dir)
                .map_err(|e| HyprError::IoError { path: layers_dir.clone(), source: e })?
            {
                let entry = entry
                    .map_err(|e| HyprError::IoError { path: layers_dir.clone(), source: e })?;
                let path = entry.path();

                if path.extension().and_then(|s| s.to_str()) == Some("tar") {
                    // Generate a cache key from the layer filename
                    let cache_key = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");

                    // Read the layer data
                    match std::fs::read(&path) {
                        Ok(data) => {
                            let description =
                                format!("Imported from cache_from: {}", path.display());
                            if cache.insert(cache_key, &data, description, 0).is_ok() {
                                layers_imported += 1;
                            }
                        }
                        Err(_) => continue, // Skip unreadable layers
                    }
                }
            }
        }

        // Also check for a manifest that might list layer digests
        let manifest_path = image_dir.join("manifest.json");
        if manifest_path.exists() {
            // Could parse manifest and import layers based on digests
            // For now, this is handled by the layers directory approach above
        }

        Ok(layers_imported)
    }

    /// Convert compose services to service configurations.
    #[instrument(skip(services, built_images))]
    fn convert_services(
        services: &HashMap<String, Service>,
        built_images: &HashMap<String, PathBuf>,
    ) -> Result<Vec<ServiceConfig>> {
        let mut configs = Vec::new();

        for (name, service) in services {
            let vm_config = Self::service_to_vm_config(name, service, built_images.get(name))?;

            let config = ServiceConfig {
                name: name.clone(),
                vm_config,
                depends_on: service.depends_on.clone(),
                healthcheck: None, // Health check parsing will be added when Phase 2 health checks are implemented
            };

            configs.push(config);
        }

        Ok(configs)
    }

    /// Convert a single service to a VM configuration.
    #[instrument(skip(service, built_image_path), fields(name = %name))]
    fn service_to_vm_config(
        name: &str,
        service: &Service,
        built_image_path: Option<&PathBuf>,
    ) -> Result<VmConfig> {
        info!("Converting service to VM config");

        // Parse resources
        let (cpus, memory_mb) = Self::parse_resources(service)?;

        // Parse ports
        let ports = Self::parse_ports(&service.ports)?;

        // Parse environment
        let env = service.environment.to_map();

        // Create disk config for rootfs
        // Use built image path if available, otherwise use pre-built image
        let rootfs_path = if let Some(built_path) = built_image_path {
            // Use the built image
            built_path.clone()
        } else if !service.image.is_empty() {
            // Use a pre-built image from the images directory
            crate::paths::images_dir().join(&service.image).join("rootfs.squashfs")
        } else {
            return Err(HyprError::ComposeParseError {
                reason: format!("Service '{}' has no image and was not built", name),
            });
        };

        let rootfs = DiskConfig { path: rootfs_path, readonly: true, format: DiskFormat::Squashfs };

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
            network_enabled: true, // Runtime VMs need network
            id: vm_id.clone(),
            name: name.to_string(),
            resources: VmResources { cpus, memory_mb },
            kernel_path: None, // Use default kernel
            kernel_args: vec![],
            initramfs_path: None, // Only used for build VMs
            disks,
            network: NetworkConfig::default(),
            ports,
            env,
            volumes,
            gpu: None,
            virtio_fs_mounts: vec![],
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

                    mappings.push(PortMapping { host_port, vm_port: guest_port, protocol });
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

                    mappings.push(PortMapping { host_port: port, vm_port: port, protocol });
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
            graph.insert(&service.name, service.depends_on.iter().map(|s| s.as_str()).collect());
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
                return Err(HyprError::CircularDependency { service: service.name.clone() });
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
                    network_enabled: true,
                    id: "web".to_string(),
                    name: "web".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    initramfs_path: None,
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    virtio_fs_mounts: vec![],
                },
                depends_on: vec!["db".to_string()],
                healthcheck: None,
            },
            ServiceConfig {
                name: "db".to_string(),
                vm_config: VmConfig {
                    network_enabled: true,
                    id: "db".to_string(),
                    name: "db".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    initramfs_path: None,
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    virtio_fs_mounts: vec![],
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
                    network_enabled: true,
                    id: "a".to_string(),
                    name: "a".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    initramfs_path: None,
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    virtio_fs_mounts: vec![],
                },
                depends_on: vec!["b".to_string()],
                healthcheck: None,
            },
            ServiceConfig {
                name: "b".to_string(),
                vm_config: VmConfig {
                    network_enabled: true,
                    id: "b".to_string(),
                    name: "b".to_string(),
                    resources: VmResources::default(),
                    kernel_path: None,
                    kernel_args: vec![],
                    initramfs_path: None,
                    disks: vec![],
                    network: NetworkConfig::default(),
                    ports: vec![],
                    env: HashMap::new(),
                    volumes: vec![],
                    gpu: None,
                    virtio_fs_mounts: vec![],
                },
                depends_on: vec!["a".to_string()],
                healthcheck: None,
            },
        ];

        let result = ComposeConverter::validate_dependencies(&services);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HyprError::CircularDependency { .. }));
    }

    #[test]
    fn test_missing_dependency_detection() {
        let services = vec![ServiceConfig {
            name: "web".to_string(),
            vm_config: VmConfig {
                network_enabled: true,
                id: "web".to_string(),
                name: "web".to_string(),
                resources: VmResources::default(),
                kernel_path: None,
                kernel_args: vec![],
                initramfs_path: None,
                disks: vec![],
                network: NetworkConfig::default(),
                ports: vec![],
                env: HashMap::new(),
                volumes: vec![],
                gpu: None,
                virtio_fs_mounts: vec![],
            },
            depends_on: vec!["nonexistent".to_string()],
            healthcheck: None,
        }];

        let result = ComposeConverter::validate_dependencies(&services);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HyprError::MissingDependency { .. }));
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
        let service = Service { image: "test".to_string(), ..Default::default() };

        let (cpus, memory_mb) = ComposeConverter::parse_resources(&service).unwrap();
        assert_eq!(cpus, 1); // Default
        assert_eq!(memory_mb, 512); // Default
    }

    #[test]
    fn test_volume_parsing() {
        let volume_defs = HashMap::from([(
            "db-data".to_string(),
            VolumeDefinition { driver: None, driver_opts: HashMap::new() },
        )]);

        let services = HashMap::from([(
            "db".to_string(),
            Service {
                image: "postgres".to_string(),
                volumes: vec![
                    "db-data:/var/lib/postgresql/data".to_string(),
                    "./config:/etc/config:ro".to_string(),
                ],
                ..Default::default()
            },
        )]);

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
