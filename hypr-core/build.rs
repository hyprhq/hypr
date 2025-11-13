// build.rs - Compile kestrel.c guest agent during cargo build
//
// This script compiles kestrel.c into a static binary that can be
// embedded in an initramfs for VM builds.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only compile on Linux (kestrel.c uses Linux-specific headers)
    // On macOS, kestrel.c will be cross-compiled or distributed separately
    if !cfg!(target_os = "linux") {
        println!("cargo:warning=Skipping kestrel.c compilation on non-Linux platform");
        println!("cargo:warning=kestrel.c requires Linux headers (linux/vm_sockets.h)");
        println!("cargo:warning=On macOS, kestrel will run inside Linux VMs");
        return;
    }

    println!("cargo:rerun-if-changed=../guest/kestrel.c");

    // Determine output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let kestrel_bin = PathBuf::from(&out_dir).join("kestrel");

    // Source file
    let kestrel_src = PathBuf::from("../guest/kestrel.c");

    // Check if source exists
    if !kestrel_src.exists() {
        println!("cargo:warning=kestrel.c not found at {:?}, skipping compilation", kestrel_src);
        return;
    }

    println!("cargo:warning=Compiling kestrel.c to {:?}", kestrel_bin);

    // Compile kestrel.c with static linking and optimization
    // Flags:
    //   -static: Static linking (no dynamic dependencies)
    //   -Os: Optimize for size
    //   -s: Strip symbols (reduce binary size)
    //   -o: Output file
    let status = Command::new("cc")
        .args([
            "-static",
            "-Os",
            "-s",
            "-o",
            kestrel_bin.to_str().unwrap(),
            kestrel_src.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(status) if status.success() => {
            println!("cargo:warning=kestrel.c compiled successfully");

            // Check binary size
            if let Ok(metadata) = std::fs::metadata(&kestrel_bin) {
                println!("cargo:warning=kestrel binary size: {} KB", metadata.len() / 1024);
            }

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&kestrel_bin) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    let _ = std::fs::set_permissions(&kestrel_bin, permissions);
                }
            }

            // Set environment variable for runtime access
            println!("cargo:rustc-env=KESTREL_BIN_PATH={}", kestrel_bin.display());
        }
        Ok(_) => {
            println!("cargo:warning=kestrel.c compilation failed (non-zero exit code)");
            println!("cargo:warning=Build will continue, but VM-based builder may not work");
        }
        Err(e) => {
            println!("cargo:warning=Failed to execute cc: {}", e);
            println!("cargo:warning=Make sure a C compiler (gcc/clang) is installed");
            println!("cargo:warning=Build will continue, but VM-based builder may not work");
        }
    }
}
