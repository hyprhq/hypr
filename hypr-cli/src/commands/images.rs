//! Images command implementation for HYPR CLI.
//!
//! Lists all images stored in the HYPR image registry.

use anyhow::{Context, Result};
use colored::Colorize;
use hypr_core::state::StateManager;
use std::path::PathBuf;
use tabled::{Table, Tabled};

/// Lists all images in the HYPR image registry.
pub async fn images() -> Result<()> {
    let state_db_path = PathBuf::from("/var/lib/hypr/hypr.db");
    let state = StateManager::new(state_db_path.to_str().unwrap())
        .await
        .with_context(|| "Failed to connect to state database")?;

    let images = state.list_images().await.with_context(|| "Failed to list images")?;

    if images.is_empty() {
        println!("No images found.");
        println!();
        println!("Build your first image with: {}", "hypr build".cyan());
        return Ok(());
    }

    #[derive(Tabled)]
    struct ImageRow {
        #[tabled(rename = "REPOSITORY")]
        repository: String,
        #[tabled(rename = "TAG")]
        tag: String,
        #[tabled(rename = "IMAGE ID")]
        image_id: String,
        #[tabled(rename = "SIZE")]
        size: String,
        #[tabled(rename = "CREATED")]
        created: String,
    }

    let rows: Vec<ImageRow> = images
        .iter()
        .map(|img| ImageRow {
            repository: img.name.clone(),
            tag: img.tag.clone(),
            image_id: format_image_id(&img.id),
            size: format_size(img.size_bytes),
            created: format_created(img.created_at),
        })
        .collect();

    let table = Table::new(rows).to_string();
    println!("{}", table);

    Ok(())
}

/// Formats an image ID to short form (first 12 characters).
fn format_image_id(id: &str) -> String {
    if id.starts_with("sha256:") {
        id[7..19].to_string()
    } else if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}

/// Formats size in bytes to human-readable form.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Formats creation time relative to now.
fn format_created(created_at: std::time::SystemTime) -> String {
    use std::time::SystemTime;

    let elapsed = SystemTime::now().duration_since(created_at).unwrap_or_default();

    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{} seconds ago", secs)
    } else if secs < 3600 {
        format!("{} minutes ago", secs / 60)
    } else if secs < 86400 {
        format!("{} hours ago", secs / 3600)
    } else if secs < 604800 {
        format!("{} days ago", secs / 86400)
    } else {
        format!("{} weeks ago", secs / 604800)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_image_id_sha256() {
        let id = "sha256:abcdef1234567890abcdef1234567890";
        assert_eq!(format_image_id(id), "abcdef123456");
    }

    #[test]
    fn test_format_image_id_short() {
        let id = "abc123";
        assert_eq!(format_image_id(id), "abc123");
    }

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(format_size(500), "500B");
    }

    #[test]
    fn test_format_size_kb() {
        assert_eq!(format_size(5 * 1024), "5.0KB");
    }

    #[test]
    fn test_format_size_mb() {
        assert_eq!(format_size(50 * 1024 * 1024), "50.0MB");
    }

    #[test]
    fn test_format_size_gb() {
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.00GB");
    }
}
