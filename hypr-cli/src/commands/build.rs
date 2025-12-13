//! Build command implementation for HYPR CLI.
//!
//! Thin gRPC client that delegates build execution to the daemon.
//! Displays premium progress UI for streamed build events.

use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::client::{ensure_daemon, BuildEventKind, HyprClient};

/// Builds an image from a Dockerfile via the daemon.
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
    let context_dir_abs = context_dir.canonicalize().with_context(|| {
        format!("Failed to resolve build context path: {}", context_dir.display())
    })?;

    let dockerfile_path = context_dir.join(&dockerfile_name);
    if !dockerfile_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile_path.display());
    }

    // Parse tag
    let default_name = context_dir_abs.file_name().and_then(|n| n.to_str()).unwrap_or("image");
    let (image_name, image_tag) = parse_tag(tag, default_name)?;
    let full_tag = format!("{}:{}", image_name, image_tag);

    // Convert build args to HashMap
    let build_args_map: HashMap<String, String> = build_args.into_iter().collect();

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
    // Connect to daemon (or spawn ephemeral)
    // ═══════════════════════════════════════════════════════════════════════
    let spinner = create_spinner("Connecting to daemon...");

    let socket_path = ensure_daemon().await?;
    let mut client = HyprClient::connect_at(&socket_path).await?;

    spinner.finish_with_message(format!("{} Connected to daemon", style("✓").green()));

    // ═══════════════════════════════════════════════════════════════════════
    // Execute build via gRPC
    // ═══════════════════════════════════════════════════════════════════════
    println!();
    println!("  {} {}", style("▶").cyan().bold(), style("Executing build").bold());
    println!();

    let mut current_spinner: Option<ProgressBar> = None;
    let mut cached_layers = 0u32;
    let mut total_layers = 0u32;

    let image = client
        .build_image(
            context_dir_abs.to_str().unwrap_or("."),
            &dockerfile_name,
            &full_tag,
            build_args_map,
            target.map(String::from),
            no_cache,
            vec![], // cache_from (could be added as CLI arg later)
            |event| match event {
                BuildEventKind::Step { step_number, total_steps, instruction, cached } => {
                    // Finish previous spinner if any
                    if let Some(sp) = current_spinner.take() {
                        let status = if cached {
                            format!("{} CACHED", style("✓").green())
                        } else {
                            format!("{} done", style("✓").green())
                        };
                        sp.finish_with_message(status);
                    }

                    total_layers = total_steps;
                    if cached {
                        cached_layers += 1;
                    }

                    // Truncate instruction for display
                    let display_instr = if instruction.len() > 50 {
                        format!("{}...", &instruction[..47])
                    } else {
                        instruction.clone()
                    };

                    let msg = format!(
                        "[{}/{}] {}",
                        style(step_number).yellow(),
                        style(total_steps).dim(),
                        display_instr
                    );

                    current_spinner = Some(create_spinner(&msg));
                }
                BuildEventKind::Output { line, stream: _ } => {
                    // Show build output (trimmed)
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && trimmed.len() < 100 {
                        println!("  {} {}", style("│").dim(), style(trimmed).dim());
                    }
                }
            },
        )
        .await?;

    // Finish last spinner
    if let Some(sp) = current_spinner.take() {
        sp.finish_with_message(format!("{} done", style("✓").green()));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Build Complete - Premium Results Display
    // ═══════════════════════════════════════════════════════════════════════
    let duration = start_time.elapsed();
    let duration_str = format_duration(duration.as_secs_f64());
    let size_mb = image.size_bytes as f64 / 1024.0 / 1024.0;

    println!();
    println!("{}", style("━".repeat(60)).green());
    println!("  {} {}", style("✅").bold(), style("Build completed successfully!").green().bold());
    println!("{}", style("━".repeat(60)).green());
    println!();
    println!("  {}  {}", style("📦").bold(), style("Image Details").bold());
    println!("  {} ID:       {}", style("│").dim(), style(&image.id).cyan().bold());
    println!(
        "  {} Name:     {}:{}",
        style("│").dim(),
        style(&image.name).green(),
        style(&image.tag).cyan()
    );
    println!("  {} Size:     {} MB", style("│").dim(), style(format!("{:.1}", size_mb)).yellow());
    println!();
    println!("  {}  {}", style("⏱️").bold(), style("Performance").bold());
    println!("  {} Duration: {}", style("│").dim(), style(&duration_str).yellow());
    println!(
        "  {} Layers:   {} total, {} cached",
        style("│").dim(),
        total_layers,
        cached_layers
    );

    if cached_layers > 0 && total_layers > 0 {
        let cache_pct = (cached_layers as f64 / total_layers as f64) * 100.0;
        println!(
            "  {} Cache:    {:.0}% hit rate",
            style("│").dim(),
            style(format!("{:.0}%", cache_pct)).green()
        );
    }

    println!();
    println!(
        "  {} Run with: {}",
        style("➜").cyan().bold(),
        style(format!("hypr run {}:{}", image.name, image.tag)).cyan()
    );
    println!();

    Ok(())
}

/// Resolves build context and dockerfile paths.
fn resolve_build_paths(context_path: &str, dockerfile: &str) -> Result<(PathBuf, String)> {
    let path = PathBuf::from(context_path);

    // Check if context_path is actually a Dockerfile
    if path.is_file() {
        let parent = path.parent().unwrap_or(Path::new("."));
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("Dockerfile");
        return Ok((parent.to_path_buf(), filename.to_string()));
    }

    // Check if it looks like a Dockerfile path
    let path_str = context_path.to_lowercase();
    if path_str.ends_with("dockerfile") || path_str.contains(".dockerfile") {
        let path = PathBuf::from(context_path);
        if let Some(parent) = path.parent() {
            if parent.exists() || parent == Path::new("") || parent == Path::new(".") {
                let parent_dir =
                    if parent == Path::new("") { PathBuf::from(".") } else { parent.to_path_buf() };
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("Dockerfile");
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
