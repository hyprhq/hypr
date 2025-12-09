//! Build command implementation for HYPR CLI.
//!
//! Builds HYPR images from Dockerfiles with a premium progress UI.

use anyhow::{Context, Result};
use console::style;
use hypr_core::builder::parser::parse_dockerfile;
use hypr_core::builder::{create_builder, BuildContext, BuildGraph, CacheManager};
use hypr_core::state::StateManager;
use hypr_core::types::Image;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;

use std::path::{Path, PathBuf};
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

    // Resolve paths - handle case where user passes Dockerfile as context path
    let (context_dir, dockerfile_name) = resolve_build_paths(context_path, dockerfile)?;

    // Canonicalize to get absolute path
    let context_dir_abs = context_dir
        .canonicalize()
        .with_context(|| format!("Failed to resolve build context path: {}", context_dir.display()))?;

    let dockerfile_path = context_dir.join(&dockerfile_name);
    if !dockerfile_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile_path.display());
    }

    // Parse tag
    let default_name = context_dir_abs.file_name().and_then(|n| n.to_str()).unwrap_or("image");
    let (image_name, image_tag) = parse_tag(tag, default_name)?;

    // ═══════════════════════════════════════════════════════════════════════
    // PREMIUM BUILD UI - Header
    // ═══════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", style("━".repeat(60)).cyan());
    println!(
        "  {} Building {}:{}",
        style("🚀").bold(),
        style(&image_name).green().bold(),
        style(&image_tag).cyan()
    );
    println!("{}", style("━".repeat(60)).cyan());
    println!();

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 1: Parse Dockerfile
    // ═══════════════════════════════════════════════════════════════════════
    let spinner = create_spinner("Parsing Dockerfile...");

    let dockerfile_content = fs::read_to_string(&dockerfile_path)
        .with_context(|| format!("Failed to read Dockerfile: {}", dockerfile_path.display()))?;

    let parsed_dockerfile =
        parse_dockerfile(&dockerfile_content).with_context(|| "Failed to parse Dockerfile")?;

    let num_stages = parsed_dockerfile.stages.len();
    let total_instructions: usize =
        parsed_dockerfile.stages.iter().map(|s| s.instructions.len()).sum();

    spinner.finish_with_message(format!(
        "{} Parsed {} stages, {} instructions",
        style("✓").green(),
        style(num_stages).yellow(),
        style(total_instructions).yellow()
    ));

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 2: Build graph
    // ═══════════════════════════════════════════════════════════════════════
    let spinner = create_spinner("Constructing build graph...");

    let graph = BuildGraph::from_dockerfile(&parsed_dockerfile)
        .with_context(|| "Failed to construct build graph")?;

    let execution_order = graph.topological_sort().with_context(|| "Failed to sort build graph")?;

    spinner.finish_with_message(format!(
        "{} Build graph ready ({} steps)",
        style("✓").green(),
        style(execution_order.len()).yellow()
    ));

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 3: Initialize cache
    // ═══════════════════════════════════════════════════════════════════════
    let spinner = create_spinner("Initializing cache...");

    let mut cache = CacheManager::new().with_context(|| "Failed to initialize cache manager")?;

    let cache_status = if no_cache {
        format!("{} Cache disabled", style("⚠").yellow())
    } else {
        format!("{} Cache enabled", style("✓").green())
    };
    spinner.finish_with_message(cache_status);

    println!();

    // Build context
    let mut build_args_map = HashMap::new();
    for (key, value) in build_args {
        build_args_map.insert(key, value);
    }

    let context = BuildContext {
        context_path: context_dir_abs.clone(),
        dockerfile_path: PathBuf::from(&dockerfile_name),
        build_args: build_args_map,
        target: target.map(String::from),
        no_cache,
    };

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 4: Execute build
    // ═══════════════════════════════════════════════════════════════════════
    println!("  {} {}", style("▶").cyan().bold(), style("Executing build").bold());
    println!();

    let mut builder = create_builder().with_context(|| "Failed to create builder")?;

    // Execute the actual build (streaming happens inside execute)
    let output =
        builder.execute(&graph, &context, &mut cache).await.with_context(|| "Build failed")?;

    // ═══════════════════════════════════════════════════════════════════════
    // Build Complete - Premium Results Display
    // ═══════════════════════════════════════════════════════════════════════
    let duration = start_time.elapsed();
    let duration_str = format_duration(duration.as_secs_f64());
    let size_mb = output.stats.total_size as f64 / 1024.0 / 1024.0;

    println!();
    println!("{}", style("━".repeat(60)).green());
    println!("  {} {}", style("✅").bold(), style("Build completed successfully!").green().bold());
    println!("{}", style("━".repeat(60)).green());
    println!();
    println!("  {}  {}", style("📦").bold(), style("Image Details").bold());
    println!("  {} ID:       {}", style("│").dim(), style(&output.image_id).cyan().bold());
    println!(
        "  {} Name:     {}:{}",
        style("│").dim(),
        style(&image_name).green(),
        style(&image_tag).cyan()
    );
    println!("  {} Size:     {} MB", style("│").dim(), style(format!("{:.1}", size_mb)).yellow());
    println!();
    println!("  {}  {}", style("⏱️").bold(), style("Performance").bold());
    println!("  {} Duration: {}", style("│").dim(), style(&duration_str).yellow());
    println!(
        "  {} Layers:   {} total, {} cached",
        style("│").dim(),
        output.stats.layer_count,
        output.stats.cached_layers
    );

    if output.stats.cached_layers > 0 {
        let cache_pct =
            (output.stats.cached_layers as f64 / output.stats.layer_count as f64) * 100.0;
        println!(
            "  {} Cache:    {:.0}% hit rate",
            style("│").dim(),
            style(format!("{:.0}%", cache_pct)).green()
        );
    }

    println!();

    // Registering image with spinner
    let spinner = create_spinner("Registering image...");

    // Move rootfs to permanent location (uses centralized paths)
    let images_dir = hypr_core::paths::images_dir();
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

    // Rootfs moved silently - spinner will show success

    // Register image in database (uses centralized paths)
    let state_db_path = hypr_core::paths::db_path();
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

    // Try to delete existing image with same name:tag first (Docker overwrites by default)
    if state.delete_image_by_name_tag(&image_name, &image_tag).await.is_err() {
        // Image didn't exist, that's fine
    }

    state.insert_image(&image).await.with_context(|| "Failed to register image in database")?;

    spinner.finish_with_message(format!("{} Image registered", style("✓").green()));

    // Final success message
    println!();
    println!(
        "  {} Run with: {}",
        style("➜").cyan().bold(),
        style(format!("hypr run {}:{}", image_name, image_tag)).cyan()
    );
    println!();

    Ok(())
}

/// Resolves build context and dockerfile paths.
///
/// Handles various input patterns:
/// - `hypr build` -> context=".", dockerfile="Dockerfile"
/// - `hypr build .` -> context=".", dockerfile="Dockerfile"
/// - `hypr build ./Dockerfile` -> context=".", dockerfile="Dockerfile"
/// - `hypr build -f custom.Dockerfile .` -> context=".", dockerfile="custom.Dockerfile"
fn resolve_build_paths(context_path: &str, dockerfile: &str) -> Result<(PathBuf, String)> {
    let path = PathBuf::from(context_path);

    // Check if context_path is actually a Dockerfile
    if path.is_file() {
        // User passed a Dockerfile path, extract directory and filename
        let parent = path.parent().unwrap_or(Path::new("."));
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Dockerfile");
        return Ok((parent.to_path_buf(), filename.to_string()));
    }

    // Check if it looks like a Dockerfile path (ends with Dockerfile or .dockerfile)
    let path_str = context_path.to_lowercase();
    if path_str.ends_with("dockerfile") || path_str.contains(".dockerfile") {
        // It might be a Dockerfile path that doesn't exist yet
        let path = PathBuf::from(context_path);
        if let Some(parent) = path.parent() {
            if parent.exists() || parent == Path::new("") || parent == Path::new(".") {
                let parent_dir = if parent == Path::new("") { PathBuf::from(".") } else { parent.to_path_buf() };
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Dockerfile");
                return Ok((parent_dir, filename.to_string()));
            }
        }
    }

    // Normal case: context_path is a directory
    if !path.exists() {
        anyhow::bail!("Build context not found: {}", context_path);
    }

    Ok((path, dockerfile.to_string()))
}

/// Create a premium spinner with consistent styling.
fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("  {spinner:.cyan} {msg}").unwrap().tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));
    spinner
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

    #[test]
    fn test_parse_tag_uses_default_name() {
        // When no tag provided, should use default name with "latest" tag
        let (name, tag) = parse_tag(None, "frontend").unwrap();
        assert_eq!(name, "frontend");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_tag_ignores_default_when_tag_provided() {
        // When tag is provided, default name should be ignored
        let (name, tag) = parse_tag(Some("myapp:v1.0"), "ignored").unwrap();
        assert_eq!(name, "myapp");
        assert_eq!(tag, "v1.0");
    }
}
