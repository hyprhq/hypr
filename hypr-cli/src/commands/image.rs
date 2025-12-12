//! Image management commands for HYPR CLI.

use crate::client::HyprClient;
use anyhow::Result;

/// Display detailed information on an image
pub async fn inspect(image: &str) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Parse image name and tag
    let (name, tag) = if image.contains(':') {
        let parts: Vec<&str> = image.splitn(2, ':').collect();
        (parts[0], parts[1])
    } else {
        (image, "latest")
    };

    let img = client.get_image(name, tag).await?;

    // Output JSON-like format similar to Docker
    println!("[");
    println!("    {{");
    println!("        \"Id\": \"{}\",", img.id);
    println!("        \"Name\": \"{}\",", img.name);
    println!("        \"Tag\": \"{}\",", img.tag);
    println!("        \"Architecture\": \"{}\",", img.manifest.architecture);
    println!("        \"Os\": \"{}\",", img.manifest.os);
    println!("        \"RootfsPath\": \"{}\",", img.rootfs_path.display());
    println!("        \"Size\": {},", img.size_bytes);
    println!("        \"Created\": \"{}\"", format_timestamp(img.created_at));
    println!("    }}");
    println!("]");

    Ok(())
}

/// Remove unused images
pub async fn prune(all: bool, force: bool) -> Result<()> {
    if !force {
        if all {
            print!("WARNING! This will remove all unused images.\nAre you sure you want to continue? [y/N] ");
        } else {
            print!("WARNING! This will remove all dangling images.\nAre you sure you want to continue? [y/N] ");
        }
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut client = HyprClient::connect().await?;
    let images = client.list_images().await?;

    // Get list of images in use by VMs
    let vms = client.list_vms().await?;
    let images_in_use: std::collections::HashSet<String> = vms
        .iter()
        .filter_map(|vm| vm.config.disks.first().map(|d| d.path.to_string_lossy().to_string()))
        .collect();

    let mut removed = Vec::new();
    let total_reclaimed: u64 = 0;

    for img in images {
        // Skip if in use
        if images_in_use.iter().any(|p| p.contains(&img.id)) {
            continue;
        }

        // If not --all, only remove dangling images (no name)
        if !all && !img.name.is_empty() {
            continue;
        }

        // Try to delete
        match client.delete_image(&img.id, false).await {
            Ok(_) => {
                removed.push(img.id);
            }
            Err(_) => {
                // Image might be in use, skip
            }
        }
    }

    if removed.is_empty() {
        println!("Total reclaimed space: 0B");
    } else {
        println!("Deleted Images:");
        for id in &removed {
            println!("{}", id);
        }
        println!("\nTotal reclaimed space: {}B", total_reclaimed);
    }

    Ok(())
}

fn format_timestamp(ts: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let secs = ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if secs == 0 {
        return "N/A".to_string();
    }
    format!("{}", secs)
}
