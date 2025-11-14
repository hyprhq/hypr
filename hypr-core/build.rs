// build.rs - Compile kestrel.c for both amd64 and arm64 during cargo build
//
// This script cross-compiles kestrel.c into static binaries for both architectures
// and places them in embedded/ for compile-time inclusion via include_bytes!

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../guest/kestrel.c");

    let kestrel_src = PathBuf::from("../guest/kestrel.c");

    if !kestrel_src.exists() {
        println!("cargo:warning=kestrel.c not found, skipping compilation");
        return;
    }

    // Create embedded directory
    let embedded_dir = PathBuf::from("embedded");
    if let Err(e) = fs::create_dir_all(&embedded_dir) {
        println!("cargo:warning=Failed to create embedded/ directory: {}", e);
        return;
    }

    // Compile for both architectures
    let targets = [
        ("x86_64-linux-musl", "amd64"),
        ("aarch64-linux-musl", "arm64"),
    ];

    for (zig_target, arch_name) in targets {
        compile_kestrel(&kestrel_src, &embedded_dir, zig_target, arch_name);
    }
}

fn compile_kestrel(src: &PathBuf, embedded_dir: &PathBuf, zig_target: &str, arch_name: &str) {
    let output_name = format!("kestrel-linux-{}", arch_name);
    let output_path = embedded_dir.join(&output_name);

    println!("cargo:warning=Compiling {} for {}", output_name, zig_target);

    let status = Command::new("zig")
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
            if let Ok(metadata) = fs::metadata(&output_path) {
                println!(
                    "cargo:warning={} compiled successfully ({} KB)",
                    output_name,
                    metadata.len() / 1024
                );
            }

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(&output_path) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    let _ = fs::set_permissions(&output_path, permissions);
                }
            }
        }
        Ok(_) => {
            println!("cargo:warning={} compilation failed (non-zero exit)", output_name);
        }
        Err(e) => {
            println!("cargo:warning=Failed to compile {}: {}", output_name, e);
            println!("cargo:warning=Make sure zig is installed: brew install zig");
        }
    }
}
