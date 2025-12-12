//! Volume management commands for HYPR CLI.
//!
//! Provides Docker-compatible volume management:
//! - hypr volume ls
//! - hypr volume create
//! - hypr volume rm
//! - hypr volume inspect
//! - hypr volume prune

use crate::client::HyprClient;
use anyhow::{Context, Result};
use hypr_core::types::VmStatus;
use std::fs;
use std::path::PathBuf;
use tabled::{Table, Tabled};

/// Get the volumes directory path
fn volumes_dir() -> PathBuf {
    hypr_core::paths::data_dir().join("volumes")
}

/// Check if a volume is in use by any running VM.
///
/// Returns the list of VM names using this volume.
async fn check_volume_in_use(volume_name: &str) -> Result<Vec<String>> {
    // Try to connect to daemon - if daemon isn't running, assume volume is not in use
    let client = match HyprClient::connect().await {
        Ok(c) => c,
        Err(_) => return Ok(vec![]), // Daemon not running, can't check
    };

    let mut client = client;
    let vms = match client.list_vms().await {
        Ok(v) => v,
        Err(_) => return Ok(vec![]), // Can't list VMs, assume not in use
    };

    let mut using_vms = Vec::new();

    // Get the full path for volume name resolution
    let vol_dir = volumes_dir();
    let local_vol_path = vol_dir.join("local").join(volume_name);

    // Check stack volume path too (stack_name_volume_name format)
    let stack_vol_path = if volume_name.contains('_') {
        let parts: Vec<&str> = volume_name.splitn(2, '_').collect();
        if parts.len() == 2 {
            Some(vol_dir.join(parts[0]).join(parts[1]))
        } else {
            None
        }
    } else {
        None
    };

    for vm in vms {
        // Only check running VMs
        if vm.status != VmStatus::Running {
            continue;
        }

        for vol in &vm.config.volumes {
            // Check if source matches the volume name or path
            let source = &vol.source;

            // Direct name match
            if source == volume_name {
                using_vms.push(vm.name.clone());
                break;
            }

            // Path-based match (for local volumes)
            if local_vol_path.exists() {
                let local_str = local_vol_path.to_string_lossy();
                if source == local_str.as_ref() || source.starts_with(local_str.as_ref()) {
                    using_vms.push(vm.name.clone());
                    break;
                }
            }

            // Stack volume path match
            if let Some(ref stack_path) = stack_vol_path {
                if stack_path.exists() {
                    let stack_str = stack_path.to_string_lossy();
                    if source == stack_str.as_ref() || source.starts_with(stack_str.as_ref()) {
                        using_vms.push(vm.name.clone());
                        break;
                    }
                }
            }
        }
    }

    Ok(using_vms)
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

            rows.push(VolumeRow { driver: "local".to_string(), name: display_name });
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

    // Check if volume is in use (unless --force)
    if !force {
        let using_vms = check_volume_in_use(name).await?;
        if !using_vms.is_empty() {
            anyhow::bail!(
                "Volume '{}' is in use by: {}. Use --force to remove anyway.",
                name,
                using_vms.join(", ")
            );
        }
    }

    // Try local volume first
    let local_path = vol_dir.join("local").join(name);
    if local_path.exists() {
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

            let name = entry.file_name().to_string_lossy().to_string();

            // Check if volume is in use by any running VM
            let using_vms = check_volume_in_use(&name).await?;
            if !using_vms.is_empty() {
                // Skip volumes in use
                continue;
            }

            let size = dir_size(&path)?;
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
