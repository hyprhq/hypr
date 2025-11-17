// build.rs - Build embedded initramfs with kestrel + busybox for both amd64 and arm64
//
// This script creates complete initramfs.cpio archives containing:
// - kestrel binary (PID 1 init)
// - busybox (static, downloaded from Debian)
// - Basic directory structure
//
// The initramfs archives are placed in embedded/ for compile-time inclusion via include_bytes!

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // ALWAYS rebuild initramfs - no caching, no conditionals
    // The embedded binary must be fresh every build
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../guest/kestrel.c");

    let kestrel_src = PathBuf::from("../guest/kestrel.c");

    if !kestrel_src.exists() {
        println!("cargo:warning=kestrel.c not found, skipping build");
        return;
    }

    // Create embedded directory
    let embedded_dir = PathBuf::from("embedded");
    if let Err(e) = fs::create_dir_all(&embedded_dir) {
        println!("cargo:warning=Failed to create embedded/ directory: {}", e);
        return;
    }

    // Download cloud-hypervisor binary (only for target architecture)
    download_cloud_hypervisor(&embedded_dir);

    // Build initramfs ONLY for target architecture (host can only virtualize its own arch)
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    let (zig_target, arch_name) = if target_arch == "x86_64" {
        ("x86_64-linux-musl", "amd64")
    } else if target_arch == "aarch64" {
        ("aarch64-linux-musl", "arm64")
    } else {
        println!("cargo:warning=Unsupported architecture: {}", target_arch);
        println!("cargo:warning=Skipping initramfs build");
        return;
    };

    println!("cargo:warning=Building initramfs for {} (host arch: {})", arch_name, target_arch);
    build_initramfs(&kestrel_src, &embedded_dir, zig_target, arch_name);
}

/// Build complete initramfs for a specific architecture.
///
/// Steps:
/// 1. Compile kestrel for target architecture
/// 2. Download busybox-static for target architecture
/// 3. Create initramfs directory structure
/// 4. Create cpio archive
fn build_initramfs(kestrel_src: &Path, embedded_dir: &Path, zig_target: &str, arch_name: &str) {
    let initramfs_name = format!("initramfs-linux-{}.cpio", arch_name);
    let initramfs_path = embedded_dir.join(&initramfs_name);

    // Always rebuild if kestrel.c changed (cargo:rerun-if-changed ensures this)
    // Remove old initramfs to force rebuild
    if initramfs_path.exists() {
        let _ = fs::remove_file(&initramfs_path);
    }

    println!("cargo:warning=Building {} for {}", initramfs_name, arch_name);

    // Create temp directory for initramfs contents
    let temp_dir = std::env::temp_dir().join(format!("hypr-initramfs-build-{}", arch_name));
    if let Err(e) = fs::remove_dir_all(&temp_dir) {
        // Ignore error if dir doesn't exist
        let _ = e;
    }
    if let Err(e) = fs::create_dir_all(&temp_dir) {
        println!("cargo:warning=Failed to create temp dir: {}", e);
        return;
    }

    // Step 1: Compile kestrel
    let kestrel_path = temp_dir.join("init");
    if !compile_kestrel_to(kestrel_src, &kestrel_path, zig_target, arch_name) {
        panic!(
            "Failed to compile kestrel for {}. Install zig: brew install zig (macOS) or see https://ziglang.org/download/",
            arch_name
        );
    }

    // Step 2: Download busybox
    if !download_busybox(&temp_dir, arch_name) {
        panic!("Failed to download busybox for {}", arch_name);
    }

    // Step 3: No directory structure needed!
    // Kestrel creates /proc, /sys, /dev, /tmp at boot time
    // Busybox doesn't need /bin/busybox, it can live at /busybox

    // Move busybox from bin/busybox to busybox (root level)
    let busybox_src = temp_dir.join("bin/busybox");
    let busybox_dst = temp_dir.join("busybox");
    if busybox_src.exists() {
        let _ = fs::rename(&busybox_src, &busybox_dst);
        let _ = fs::remove_dir_all(temp_dir.join("bin"));
    }

    // Step 4: Create cpio archive
    if !create_cpio_archive(&temp_dir, &initramfs_path) {
        println!("cargo:warning=Failed to create cpio archive for {}", arch_name);
        return;
    }

    // Cleanup temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    if let Ok(metadata) = fs::metadata(&initramfs_path) {
        println!(
            "cargo:warning={} created successfully ({} KB)",
            initramfs_name,
            metadata.len() / 1024
        );
    }
}

/// Find zig binary in common installation locations.
fn find_zig_binary() -> Option<PathBuf> {
    // Try PATH first
    if let Ok(output) = Command::new("which").arg("zig").output() {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                let path = path.trim();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }

    // Try common installation locations
    let candidates = vec![
        "/opt/homebrew/bin/zig", // macOS Homebrew ARM64
        "/usr/local/bin/zig",    // macOS Homebrew x86_64, Linux
        "/usr/local/zig/zig",    // CI/CD custom installation
        "/usr/bin/zig",          // System package manager
    ];

    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Compile kestrel to a specific output path.
fn compile_kestrel_to(src: &Path, output_path: &Path, zig_target: &str, arch_name: &str) -> bool {
    println!("cargo:warning=  Compiling kestrel for {}...", arch_name);

    // Find zig binary
    let zig_bin = match find_zig_binary() {
        Some(path) => {
            println!("cargo:warning=  Using zig: {}", path.display());
            path
        }
        None => {
            println!("cargo:warning=  zig not found in PATH or common locations");
            println!("cargo:warning=  Searched: /opt/homebrew/bin/zig, /usr/local/bin/zig, /usr/local/zig/zig, /usr/bin/zig");
            println!("cargo:warning=  Install zig: brew install zig (macOS) or see https://ziglang.org/download/");
            return false;
        }
    };

    let status = Command::new(&zig_bin)
        .args([
            "cc",
            "-target",
            zig_target,
            "-static",
            "-Os",
            "-s",
            "-o",
            output_path.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(status) if status.success() => {
            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(output_path) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    let _ = fs::set_permissions(output_path, permissions);
                }
            }
            true
        }
        Ok(_) => {
            println!("cargo:warning=  Kestrel compilation failed (non-zero exit)");
            false
        }
        Err(e) => {
            println!("cargo:warning=  Failed to compile kestrel: {}", e);
            println!("cargo:warning=  Make sure zig is installed: brew install zig");
            false
        }
    }
}

/// Download busybox-static from Debian and extract to temp_dir/bin/busybox.
fn download_busybox(temp_dir: &Path, arch_name: &str) -> bool {
    println!("cargo:warning=  Downloading busybox for {}...", arch_name);

    let (deb_arch, deb_url) = match arch_name {
        "amd64" => (
            "amd64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_amd64.deb",
        ),
        "arm64" => (
            "arm64",
            "https://ftp.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-7_arm64.deb",
        ),
        _ => {
            println!("cargo:warning=  Unsupported architecture: {}", arch_name);
            return false;
        }
    };

    let deb_file = temp_dir.join(format!("busybox-static_{}.deb", deb_arch));
    let busybox_dst = temp_dir.join("bin/busybox");

    // Create bin directory
    if let Err(e) = fs::create_dir_all(temp_dir.join("bin")) {
        println!("cargo:warning=  Failed to create bin dir: {}", e);
        return false;
    }

    // Download .deb file
    let download_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -fsSL {} -o {} || wget -q -O {} {}",
            deb_url,
            deb_file.display(),
            deb_file.display(),
            deb_url
        ))
        .status();

    if !matches!(download_status, Ok(status) if status.success()) {
        println!("cargo:warning=  Failed to download busybox from Debian");
        return false;
    }

    // Extract .deb
    let extract_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && (ar x {} data.tar.xz 2>/dev/null || bsdtar -xf {} data.tar.xz) && \
             tar -xf data.tar.xz ./usr/bin/busybox && mv usr/bin/busybox {}",
            temp_dir.display(),
            deb_file.display(),
            deb_file.display(),
            busybox_dst.display()
        ))
        .status();

    // Cleanup
    let _ = fs::remove_file(&deb_file);
    let _ = fs::remove_dir_all(temp_dir.join("usr"));
    let _ = fs::remove_file(temp_dir.join("data.tar.xz"));

    if !matches!(extract_status, Ok(status) if status.success()) {
        println!("cargo:warning=  Failed to extract busybox from .deb");
        return false;
    }

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&busybox_dst) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755);
            let _ = fs::set_permissions(&busybox_dst, permissions);
        }
    }

    busybox_dst.exists()
}

/// Create cpio archive from directory contents.
fn create_cpio_archive(source_dir: &Path, output_path: &Path) -> bool {
    println!("cargo:warning=  Creating cpio archive...");

    // Get absolute paths
    let source_abs = source_dir.canonicalize().unwrap_or_else(|_| source_dir.to_path_buf());
    let output_abs = match output_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // If output doesn't exist yet, canonicalize parent and append filename
            let parent = output_path.parent().unwrap();
            let filename = output_path.file_name().unwrap();
            parent
                .canonicalize()
                .map(|p| p.join(filename))
                .unwrap_or_else(|_| output_path.to_path_buf())
        }
    };

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . -print0 | cpio -0 -o -H newc > {}",
            source_abs.display(),
            output_abs.display()
        ))
        .output();

    match output {
        Ok(output) if output.status.success() => output_abs.exists(),
        Ok(output) => {
            println!("cargo:warning=  cpio failed: {}", String::from_utf8_lossy(&output.stderr));
            false
        }
        Err(e) => {
            println!("cargo:warning=  Failed to run cpio: {}", e);
            false
        }
    }
}

/// Download cloud-hypervisor binary for the target architecture.
///
/// Downloads from GitHub releases (latest stable) to embedded/ directory.
/// Only downloads the binary matching the target architecture to minimize binary size.
fn download_cloud_hypervisor(embedded_dir: &Path) {
    println!("cargo:warning=Downloading cloud-hypervisor binary...");

    // Determine target architecture from environment
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());

    let binary_name = if target_arch == "x86_64" {
        "cloud-hypervisor-static"
    } else if target_arch == "aarch64" {
        "cloud-hypervisor-static-aarch64"
    } else {
        println!("cargo:warning=  Unsupported architecture: {}", target_arch);
        return;
    };

    let dest_path = embedded_dir.join(binary_name);

    // Skip if already downloaded
    if dest_path.exists() {
        println!("cargo:warning=  {} already exists, skipping download", binary_name);
        return;
    }

    let url = format!(
        "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/latest/download/{}",
        binary_name
    );

    println!("cargo:warning=  Downloading {} for {}...", binary_name, target_arch);

    // Download using curl or wget
    let download_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -fsSL {} -o {} || wget -q -O {} {}",
            url,
            dest_path.display(),
            dest_path.display(),
            url
        ))
        .status();

    match download_status {
        Ok(status) if status.success() => {
            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(&dest_path) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    let _ = fs::set_permissions(&dest_path, permissions);
                }
            }

            // Get file size
            if let Ok(metadata) = fs::metadata(&dest_path) {
                let size_mb = metadata.len() as f64 / 1024.0 / 1024.0;
                println!(
                    "cargo:warning=  {} downloaded successfully ({:.2} MB)",
                    binary_name, size_mb
                );
            }
        }
        Ok(_) => {
            println!("cargo:warning=  Failed to download {} (non-zero exit)", binary_name);
            println!("cargo:warning=  URL: {}", url);
        }
        Err(e) => {
            println!("cargo:warning=  Failed to download {}: {}", binary_name, e);
            println!("cargo:warning=  Make sure curl or wget is installed");
        }
    }
}
