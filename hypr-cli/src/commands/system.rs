//! `hypr system` commands for garbage collection and maintenance.

use anyhow::Result;
use hypr_core::VmStatus;
use std::path::Path;

/// Run system prune to clean up unused resources.
///
/// # Arguments
/// * `all` - Remove all stopped VMs and unused images
/// * `force` - Skip confirmation prompt
/// * `volumes` - Also remove unused volumes
pub async fn prune(all: bool, force: bool, volumes: bool) -> Result<()> {
    if !force {
        println!("WARNING! This will remove:");
        println!("  - All dangling images (images not used by any VM)");
        if all {
            println!("  - All stopped VMs");
            println!("  - All unused images");
        }
        if volumes {
            println!("  - All unused volumes");
        }
        #[cfg(target_os = "linux")]
        {
            println!("  - Orphaned TAP devices");
            println!("  - Orphaned VFIO bindings");
        }
        println!();

        print!("Are you sure you want to continue? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("Pruning system resources...\n");

    let mut total_reclaimed: u64 = 0;

    // 1. Clean up dangling images
    let (images_removed, images_space) = prune_dangling_images(all).await?;
    if images_removed > 0 {
        println!(
            "Removed {} image(s), reclaimed {} MB",
            images_removed,
            images_space / (1024 * 1024)
        );
        total_reclaimed += images_space;
    }

    // 2. Clean up stopped VMs (if --all)
    if all {
        let vms_removed = prune_stopped_vms().await?;
        if vms_removed > 0 {
            println!("Removed {} stopped VM(s)", vms_removed);
        }
    }

    // 3. Clean up build cache
    let (cache_entries, cache_space) = prune_build_cache().await?;
    if cache_entries > 0 {
        println!(
            "Removed {} cache entries, reclaimed {} MB",
            cache_entries,
            cache_space / (1024 * 1024)
        );
        total_reclaimed += cache_space;
    }

    // 4. Clean up log files for deleted VMs
    let (logs_removed, logs_space) = prune_orphaned_logs().await?;
    if logs_removed > 0 {
        println!(
            "Removed {} orphaned log file(s), reclaimed {} MB",
            logs_removed,
            logs_space / (1024 * 1024)
        );
        total_reclaimed += logs_space;
    }

    // 5. Platform-specific cleanup
    #[cfg(target_os = "linux")]
    {
        let taps = prune_orphaned_taps().await?;
        if taps > 0 {
            println!("Removed {} orphaned TAP device(s)", taps);
        }

        let vfio = prune_orphaned_vfio().await?;
        if vfio > 0 {
            println!("Restored {} VFIO-bound GPU(s) to host", vfio);
        }
    }

    // 6. Clean up volumes (if --volumes)
    if volumes {
        let volumes_removed = prune_unused_volumes().await?;
        if volumes_removed > 0 {
            println!("Removed {} unused volume(s)", volumes_removed);
        }
    }

    println!(
        "\nTotal reclaimed space: {} MB",
        total_reclaimed / (1024 * 1024)
    );
    Ok(())
}

/// Prune dangling images not referenced by any VM.
async fn prune_dangling_images(all: bool) -> Result<(usize, u64)> {
    use crate::client::HyprClient;

    let mut client = HyprClient::connect().await?;

    // Get all images
    let images = client.list_images().await?;

    // Get all VMs to check which images are in use
    let vms = client.list_vms().await?;
    let used_images: std::collections::HashSet<_> = vms.iter().map(|vm| &vm.image_id).collect();

    let mut removed = 0;
    let mut reclaimed: u64 = 0;

    // Get images directory
    let images_dir = hypr_core::paths::images_dir();

    for image in images {
        let image_ref = format!("{}:{}", image.name, image.tag);

        // Skip if image is in use
        if used_images.contains(&image_ref) && !all {
            continue;
        }

        // Skip if not dangling (has a name/tag) and not --all
        if !all && !image.name.is_empty() {
            continue;
        }

        // Get image file size before deletion
        let rootfs_path = images_dir.join(format!("{}_{}.squashfs", image.name, image.tag));
        let size = std::fs::metadata(&rootfs_path).map(|m| m.len()).unwrap_or(0);

        // Delete image via API
        if client.delete_image(&image.id, true).await.is_ok() {
            removed += 1;
            reclaimed += size;

            // Also delete the squashfs file
            let _ = std::fs::remove_file(&rootfs_path);
        }
    }

    Ok((removed, reclaimed))
}

/// Prune stopped VMs.
async fn prune_stopped_vms() -> Result<usize> {
    use crate::client::HyprClient;

    let mut client = HyprClient::connect().await?;

    let vms = client.list_vms().await?;
    let mut removed = 0;

    for vm in vms {
        if (vm.status == VmStatus::Stopped || vm.status == VmStatus::Failed)
            && client.delete_vm(&vm.id, true).await.is_ok()
        {
            removed += 1;
        }
    }

    Ok(removed)
}

/// Prune build cache.
async fn prune_build_cache() -> Result<(usize, u64)> {
    let cache_dir = hypr_core::paths::data_dir().join("cache");

    if !cache_dir.exists() {
        return Ok((0, 0));
    }

    let mut removed = 0;
    let mut reclaimed: u64 = 0;

    // Walk cache directory
    if let Ok(entries) = std::fs::read_dir(&cache_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if std::fs::remove_file(&path).is_ok() {
                    removed += 1;
                    reclaimed += size;
                }
            }
        }
    }

    Ok((removed, reclaimed))
}

/// Prune orphaned log files for deleted VMs.
async fn prune_orphaned_logs() -> Result<(usize, u64)> {
    use crate::client::HyprClient;

    let logs_dir = hypr_core::paths::logs_dir();

    if !logs_dir.exists() {
        return Ok((0, 0));
    }

    // Get list of existing VM IDs
    let mut client = HyprClient::connect().await?;
    let vms = client.list_vms().await?;
    let vm_ids: std::collections::HashSet<_> = vms.iter().map(|vm| vm.id.as_str()).collect();

    let mut removed = 0;
    let mut reclaimed: u64 = 0;

    // Check each log file
    if let Ok(entries) = std::fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "log").unwrap_or(false) {
                // Extract VM ID from filename (vm-id.log)
                if let Some(filename) = path.file_stem() {
                    let vm_id = filename.to_string_lossy();
                    if !vm_ids.contains(vm_id.as_ref()) {
                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        if std::fs::remove_file(&path).is_ok() {
                            removed += 1;
                            reclaimed += size;
                        }
                    }
                }
            }
        }
    }

    Ok((removed, reclaimed))
}

/// Prune orphaned TAP devices (Linux only).
#[cfg(target_os = "linux")]
async fn prune_orphaned_taps() -> Result<usize> {
    use crate::client::HyprClient;
    use std::process::Command;

    // Get running VMs to know how many TAPs we should have
    let mut client = HyprClient::connect().await?;
    let vms = client.list_vms().await?;
    let running_count = vms.iter().filter(|vm| vm.status == VmStatus::Running).count();

    let mut cleaned = 0;

    // List TAP devices attached to vbr0
    let output = Command::new("ip")
        .args(["link", "show", "master", "vbr0"])
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if let Some(name) = line.split(':').nth(1) {
                let name = name.trim().split('@').next().unwrap_or("").trim();
                if name.starts_with("tap") {
                    if let Ok(tap_num) = name[3..].parse::<usize>() {
                        if tap_num >= running_count {
                            let _ = Command::new("ip").args(["link", "del", name]).status();
                            cleaned += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Prune orphaned VFIO bindings (Linux only).
#[cfg(target_os = "linux")]
async fn prune_orphaned_vfio() -> Result<usize> {
    use crate::client::HyprClient;
    use std::collections::HashSet;
    use std::path::Path as StdPath;

    // Get GPUs used by running VMs
    let mut client = HyprClient::connect().await?;
    let vms = client.list_vms().await?;

    let running_gpu_addresses: HashSet<String> = vms
        .iter()
        .filter(|vm| vm.status == VmStatus::Running)
        .filter_map(|vm| vm.config.gpu.as_ref())
        .filter_map(|gpu| gpu.pci_address.clone())
        .collect();

    let mut cleaned = 0;
    let vfio_pci_path = StdPath::new("/sys/bus/pci/drivers/vfio-pci");

    if !vfio_pci_path.exists() {
        return Ok(0);
    }

    if let Ok(entries) = std::fs::read_dir(vfio_pci_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip non-device entries
            if name_str == "bind"
                || name_str == "unbind"
                || name_str == "new_id"
                || name_str == "remove_id"
                || name_str == "module"
                || name_str == "uevent"
            {
                continue;
            }

            // Check if this is a PCI address format
            if name_str.contains(':') && name_str.contains('.') {
                if !running_gpu_addresses.contains(name_str.as_ref()) {
                    let unbind_path = vfio_pci_path.join("unbind");
                    if std::fs::write(&unbind_path, name_str.as_ref()).is_ok() {
                        cleaned += 1;
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

/// Prune unused volumes.
async fn prune_unused_volumes() -> Result<usize> {
    // Placeholder - volumes feature not fully implemented yet
    Ok(0)
}

/// Show system disk usage.
pub async fn df() -> Result<()> {
    let data_dir = hypr_core::paths::data_dir();
    let images_dir = hypr_core::paths::images_dir();
    let logs_dir = hypr_core::paths::logs_dir();
    let cache_dir = data_dir.join("cache");

    println!("HYPR Disk Usage\n");
    println!("{:<20} {:>12} {:>8}", "COMPONENT", "SIZE", "COUNT");
    println!("{:-<42}", "");

    // Images
    let (images_size, images_count) = dir_size(&images_dir);
    println!(
        "{:<20} {:>10} MB {:>8}",
        "Images",
        images_size / (1024 * 1024),
        images_count
    );

    // Build cache
    let (cache_size, cache_count) = dir_size(&cache_dir);
    println!(
        "{:<20} {:>10} MB {:>8}",
        "Build Cache",
        cache_size / (1024 * 1024),
        cache_count
    );

    // Logs
    let (logs_size, logs_count) = dir_size(&logs_dir);
    println!(
        "{:<20} {:>10} MB {:>8}",
        "Logs",
        logs_size / (1024 * 1024),
        logs_count
    );

    // Database
    let db_path = hypr_core::paths::db_path();
    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "{:<20} {:>10} MB {:>8}",
        "Database",
        db_size / (1024 * 1024),
        1
    );

    println!("{:-<42}", "");
    let total = images_size + cache_size + logs_size + db_size;
    println!("{:<20} {:>10} MB", "TOTAL", total / (1024 * 1024));

    Ok(())
}

/// Calculate total size and file count for a directory.
fn dir_size(path: &Path) -> (u64, usize) {
    if !path.exists() {
        return (0, 0);
    }

    let mut size: u64 = 0;
    let mut count: usize = 0;

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let metadata = entry.metadata();
            if let Ok(meta) = metadata {
                if meta.is_file() {
                    size += meta.len();
                    count += 1;
                }
            }
        }
    }

    (size, count)
}
