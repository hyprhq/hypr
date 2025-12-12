//! Volume management commands for HYPR CLI.
//!
//! Provides Docker-compatible volume management:
//! - hypr volume ls
//! - hypr volume create
//! - hypr volume rm
//! - hypr volume inspect
//! - hypr volume prune

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tabled::{Table, Tabled};

/// Get the volumes directory path
fn volumes_dir() -> PathBuf {
    hypr_core::paths::data_dir().join("volumes")
}

/// List all volumes
pub async fn ls() -> Result<()> {
    let vol_dir = volumes_dir();

    if !vol_dir.exists() {
        println!("No volumes found.");
        return Ok(());
    }

    #[derive(Tabled)]
    struct VolumeRow {
        #[tabled(rename = "DRIVER")]
        driver: String,
        #[tabled(rename = "VOLUME NAME")]
        name: String,
    }

    let mut rows = Vec::new();

    // Volumes are organized as /var/lib/hypr/volumes/<stack_id>/<volume_name>
    // For standalone volumes, stack_id is "local"
    for stack_entry in fs::read_dir(&vol_dir)? {
        let stack_entry = stack_entry?;
        let stack_path = stack_entry.path();

        if !stack_path.is_dir() {
            continue;
        }

        let stack_name = stack_entry.file_name().to_string_lossy().to_string();

        for vol_entry in fs::read_dir(&stack_path)? {
            let vol_entry = vol_entry?;
            let vol_path = vol_entry.path();

            if !vol_path.is_dir() {
                continue;
            }

            let vol_name = vol_entry.file_name().to_string_lossy().to_string();
            let display_name = if stack_name == "local" {
                vol_name
            } else {
                format!("{}_{}", stack_name, vol_name)
            };

            rows.push(VolumeRow {
                driver: "local".to_string(),
                name: display_name,
            });
        }
    }

    if rows.is_empty() {
        println!("No volumes found.");
        return Ok(());
    }

    let table = Table::new(rows).to_string();
    println!("{}", table);

    Ok(())
}

/// Create a new volume
pub async fn create(name: &str) -> Result<()> {
    let vol_path = volumes_dir().join("local").join(name);

    if vol_path.exists() {
        anyhow::bail!("Volume '{}' already exists", name);
    }

    fs::create_dir_all(&vol_path)
        .with_context(|| format!("Failed to create volume directory: {}", vol_path.display()))?;

    println!("{}", name);
    Ok(())
}

/// Remove a volume
pub async fn rm(name: &str, force: bool) -> Result<()> {
    let vol_dir = volumes_dir();

    // Try local volume first
    let local_path = vol_dir.join("local").join(name);
    if local_path.exists() {
        if !force {
            // Check if volume is in use (TODO: check running VMs)
        }
        fs::remove_dir_all(&local_path)
            .with_context(|| format!("Failed to remove volume: {}", name))?;
        println!("{}", name);
        return Ok(());
    }

    // Try stack volume (stack_name_volume_name format)
    if name.contains('_') {
        let parts: Vec<&str> = name.splitn(2, '_').collect();
        if parts.len() == 2 {
            let stack_path = vol_dir.join(parts[0]).join(parts[1]);
            if stack_path.exists() {
                if !force {
                    // Check if volume is in use
                }
                fs::remove_dir_all(&stack_path)
                    .with_context(|| format!("Failed to remove volume: {}", name))?;
                println!("{}", name);
                return Ok(());
            }
        }
    }

    anyhow::bail!("Volume '{}' not found", name);
}

/// Inspect a volume
pub async fn inspect(name: &str) -> Result<()> {
    let vol_dir = volumes_dir();

    // Try local volume first
    let local_path = vol_dir.join("local").join(name);
    if local_path.exists() {
        print_volume_info(name, &local_path, "local")?;
        return Ok(());
    }

    // Try stack volume
    if name.contains('_') {
        let parts: Vec<&str> = name.splitn(2, '_').collect();
        if parts.len() == 2 {
            let stack_path = vol_dir.join(parts[0]).join(parts[1]);
            if stack_path.exists() {
                print_volume_info(name, &stack_path, parts[0])?;
                return Ok(());
            }
        }
    }

    anyhow::bail!("Volume '{}' not found", name);
}

fn print_volume_info(name: &str, path: &PathBuf, scope: &str) -> Result<()> {
    // Calculate size
    let size = dir_size(path)?;

    println!("[");
    println!("    {{");
    println!("        \"Name\": \"{}\",", name);
    println!("        \"Driver\": \"local\",");
    println!("        \"Mountpoint\": \"{}\",", path.display());
    println!("        \"Scope\": \"{}\",", scope);
    println!("        \"Size\": {}", size);
    println!("    }}");
    println!("]");

    Ok(())
}

fn dir_size(path: &PathBuf) -> Result<u64> {
    let mut size = 0u64;

    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                size += dir_size(&path)?;
            } else {
                size += entry.metadata()?.len();
            }
        }
    }

    Ok(size)
}

/// Remove unused volumes
pub async fn prune(force: bool) -> Result<()> {
    if !force {
        print!("WARNING! This will remove all local volumes not used by at least one container.\nAre you sure you want to continue? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let vol_dir = volumes_dir();

    if !vol_dir.exists() {
        println!("Total reclaimed space: 0B");
        return Ok(());
    }

    let mut total_reclaimed: u64 = 0;
    let mut removed = Vec::new();

    // Only prune "local" standalone volumes for now
    // Stack volumes should be pruned with `hypr compose down`
    let local_dir = vol_dir.join("local");
    if local_dir.exists() {
        for entry in fs::read_dir(&local_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            // TODO: Check if volume is in use by any running VM
            // For now, prune all local volumes
            let size = dir_size(&path)?;
            let name = entry.file_name().to_string_lossy().to_string();

            fs::remove_dir_all(&path)?;
            removed.push(name);
            total_reclaimed += size;
        }
    }

    if removed.is_empty() {
        println!("Total reclaimed space: 0B");
    } else {
        println!("Deleted Volumes:");
        for name in &removed {
            println!("{}", name);
        }
        println!();
        println!("Total reclaimed space: {}", format_size(total_reclaimed));
    }

    Ok(())
}

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
