//! Build command implementation for HYPR CLI.
//!
//! Builds HYPR images from Dockerfiles with progress bars and caching.

use anyhow::{Context, Result};
use colored::Colorize;
use hypr_core::builder::parser::parse_dockerfile;
use hypr_core::builder::{create_builder, BuildContext, BuildGraph, CacheManager};
use hypr_core::state::StateManager;
use hypr_core::types::Image;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

/// Builds an image from a Dockerfile.
///
/// # Arguments
/// * `context_path` - Path to build context directory
/// * `tag` - Optional tag for the image (e.g., "myapp:latest")
/// * `dockerfile` - Path to Dockerfile (relative to context)
/// * `build_args` - Build arguments as key-value pairs
/// * `target` - Optional target build stage
/// * `no_cache` - Disable build cache
pub async fn build(
    context_path: &str,
    tag: Option<&str>,
    dockerfile: &str,
    build_args: Vec<(String, String)>,
    target: Option<&str>,
    no_cache: bool,
) -> Result<()> {
    let start_time = Instant::now();

    // Resolve paths
    let context_dir = PathBuf::from(context_path);
    if !context_dir.exists() {
        anyhow::bail!("Build context not found: {}", context_path);
    }

    let dockerfile_path = context_dir.join(dockerfile);
    if !dockerfile_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile_path.display());
    }

    // Parse tag (use directory name if not provided)
    let default_name = context_dir.file_name().and_then(|n| n.to_str()).unwrap_or("image");
    let (image_name, image_tag) = parse_tag(tag, default_name)?;

    println!(
        "{} Building image {}:{}",
        "[1/4]".bold().blue(),
        image_name.green(),
        image_tag.cyan()
    );

    // Read and parse Dockerfile
    let dockerfile_content = fs::read_to_string(&dockerfile_path)
        .with_context(|| format!("Failed to read Dockerfile: {}", dockerfile_path.display()))?;

    let parsed_dockerfile =
        parse_dockerfile(&dockerfile_content).with_context(|| "Failed to parse Dockerfile")?;

    let num_stages = parsed_dockerfile.stages.len();
    let total_instructions: usize =
        parsed_dockerfile.stages.iter().map(|s| s.instructions.len()).sum();

    println!(
        "  {} stages, {} instructions",
        num_stages.to_string().yellow(),
        total_instructions.to_string().yellow()
    );

    // Build graph
    println!("{} Constructing build graph", "[2/4]".bold().blue());
    let graph = BuildGraph::from_dockerfile(&parsed_dockerfile)
        .with_context(|| "Failed to construct build graph")?;

    let execution_order = graph.topological_sort().with_context(|| "Failed to sort build graph")?;

    println!("  {} steps in execution order", execution_order.len().to_string().yellow());

    // Initialize cache
    println!("{} Initializing cache", "[3/4]".bold().blue());
    let mut cache = CacheManager::new().with_context(|| "Failed to initialize cache manager")?;

    if no_cache {
        println!("  {}", "Cache disabled".yellow());
    } else {
        println!("  {}", "Cache enabled".green());
    }

    // Build context
    let mut build_args_map = HashMap::new();
    for (key, value) in build_args {
        build_args_map.insert(key, value);
    }

    let context = BuildContext {
        context_path: context_dir.clone(),
        dockerfile_path: PathBuf::from(dockerfile),
        build_args: build_args_map,
        target: target.map(String::from),
        no_cache,
    };

    // Execute build
    println!("{} Executing build", "[4/4]".bold().blue());

    let pb = ProgressBar::new(execution_order.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );

    let mut builder = create_builder().with_context(|| "Failed to create builder")?;

    // Note: Currently the executor is a stub, so we simulate progress
    for (i, node_id) in execution_order.iter().enumerate() {
        let node = graph.get_node(*node_id).unwrap();
        pb.set_message(format!("Step {}: {:?}", i + 1, node.instruction));
        pb.inc(1);

        // Simulate some work (remove this when executor is implemented)
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    // Execute the actual build
    let output =
        builder.execute(&graph, &context, &mut cache).await.with_context(|| "Build failed")?;

    pb.finish_with_message("Build complete");

    // Print results
    let duration = start_time.elapsed();
    let duration_str = format_duration(duration.as_secs_f64());

    println!();
    println!("{}", "Build completed successfully!".green().bold());
    println!();
    println!("  Image ID:    {}", output.image_id.cyan());
    println!("  Name:        {}:{}", image_name.green(), image_tag.cyan());
    println!("  Rootfs:      {}", output.rootfs_path.display().to_string().yellow());
    println!("  Layers:      {} ({} cached)", output.stats.layer_count, output.stats.cached_layers);
    println!("  Total size:  {:.1} MB", output.stats.total_size as f64 / 1024.0 / 1024.0);
    println!("  Duration:    {}", duration_str.yellow());

    if output.stats.cached_layers > 0 {
        let cache_pct =
            (output.stats.cached_layers as f64 / output.stats.layer_count as f64) * 100.0;
        println!("  Cache hit:   {:.0}%", cache_pct);
    }

    println!();
    println!("{} Registering image", "»".bold().blue());

    // Move rootfs to permanent location
    let images_dir = if cfg!(target_os = "linux") {
        PathBuf::from("/var/lib/hypr/images")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(format!("{}/.hypr/images", home))
    };
    let image_dir = images_dir.join(&output.image_id);

    // Create image directory
    fs::create_dir_all(&image_dir)
        .with_context(|| format!("Failed to create image directory: {}", image_dir.display()))?;

    let permanent_rootfs = image_dir.join("rootfs.squashfs");

    // Move rootfs from temp location to permanent location
    fs::rename(&output.rootfs_path, &permanent_rootfs).with_context(|| {
        format!(
            "Failed to move rootfs from {} to {}",
            output.rootfs_path.display(),
            permanent_rootfs.display()
        )
    })?;

    println!("  Moved rootfs to {}", permanent_rootfs.display().to_string().yellow());

    // Register image in database
    let state_db_path = PathBuf::from("/var/lib/hypr/hypr.db");
    let state = StateManager::new(state_db_path.to_str().unwrap())
        .await
        .with_context(|| "Failed to connect to state database")?;

    // Convert builder manifest to types manifest
    use hypr_core::types::image::{RestartPolicy, RuntimeConfig};
    use hypr_core::types::ImageManifest;
    let manifest = ImageManifest {
        version: "1".to_string(),
        name: output.manifest.name.clone(),
        tag: output.manifest.tag.clone(),
        architecture: output.manifest.architecture.clone(),
        os: output.manifest.os.clone(),
        entrypoint: output.manifest.config.entrypoint.unwrap_or_default(),
        cmd: output.manifest.config.cmd.unwrap_or_default(),
        env: output.manifest.config.env.clone(),
        workdir: output.manifest.config.workdir.unwrap_or_else(|| "/".to_string()),
        exposed_ports: output
            .manifest
            .config
            .exposed_ports
            .iter()
            .filter_map(|p| p.parse::<u16>().ok())
            .collect(),
        runtime: RuntimeConfig {
            default_memory_mb: 512,
            default_cpus: 2,
            kernel_channel: "stable".to_string(),
            rootfs_type: "squashfs".to_string(),
            restart_policy: RestartPolicy::Always,
        },
        health: None, // TODO: Extract health check from Dockerfile
    };

    let image = Image {
        id: output.image_id.clone(),
        name: image_name.clone(),
        tag: image_tag.clone(),
        manifest,
        rootfs_path: permanent_rootfs.clone(),
        size_bytes: output.stats.total_size,
        created_at: SystemTime::now(),
    };

    state.insert_image(&image).await.with_context(|| "Failed to register image in database")?;

    println!("  Registered image: {}:{}", image_name.green(), image_tag.cyan());
    println!();
    println!("{}", "✓ Image ready to use!".green().bold());
    println!("  Run with: {}", format!("hypr run {}:{}", image_name, image_tag).cyan());

    Ok(())
}

/// Parses an image tag into (name, tag) components.
///
/// Examples:
/// - None -> ("myimage", "latest")
/// - "myapp" -> ("myapp", "latest")
/// - "myapp:v1.0" -> ("myapp", "v1.0")
fn parse_tag(tag: Option<&str>, default_name: &str) -> Result<(String, String)> {
    match tag {
        None => Ok((default_name.to_string(), "latest".to_string())),
        Some(t) => {
            let parts: Vec<&str> = t.splitn(2, ':').collect();
            match parts.len() {
                1 => Ok((parts[0].to_string(), "latest".to_string())),
                2 => Ok((parts[0].to_string(), parts[1].to_string())),
                _ => anyhow::bail!("Invalid tag format: {}", t),
            }
        }
    }
}

/// Formats a duration in seconds to a human-readable string.
fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining_secs = secs - (mins * 60.0);
        format!("{:.0}m{:.0}s", mins, remaining_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tag_none() {
        let (name, tag) = parse_tag(None, "myimage").unwrap();
        assert_eq!(name, "myimage");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_tag_name_only() {
        let (name, tag) = parse_tag(Some("myapp"), "default").unwrap();
        assert_eq!(name, "myapp");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_tag_with_version() {
        let (name, tag) = parse_tag(Some("myapp:v1.0"), "default").unwrap();
        assert_eq!(name, "myapp");
        assert_eq!(tag, "v1.0");
    }

    #[test]
    fn test_parse_tag_with_registry() {
        let (name, tag) = parse_tag(Some("registry.io/myapp:latest"), "default").unwrap();
        assert_eq!(name, "registry.io/myapp");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_format_duration_milliseconds() {
        assert_eq!(format_duration(0.123), "123ms");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(5.7), "5.7s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(125.0), "2m5s");
    }
}
