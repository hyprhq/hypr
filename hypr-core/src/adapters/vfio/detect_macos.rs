//! GPU detection for macOS systems.
//!
//! On macOS, GPU passthrough works differently:
//! - Apple Silicon (ARM64): Metal GPU via krunkit/libkrun-efi
//! - Intel Macs: No GPU passthrough support

use crate::error::{HyprError, Result};
use crate::types::vm::GpuVendor;
use std::process::Command;
use tracing::debug;

/// Detected GPU information.
#[derive(Debug, Clone)]
pub struct DetectedGpu {
    /// No PCI address on macOS Metal
    pub pci_address: Option<String>,
    /// GPU vendor (Metal for Apple Silicon)
    pub vendor: GpuVendor,
    /// Human-readable model name (e.g., "Apple M3 Max")
    pub model: String,
    /// GPU memory in MB (unified memory on Apple Silicon)
    pub memory_mb: Option<u64>,
    /// GPU is available (always true on ARM64)
    pub available: bool,
}

/// Detect available GPUs on macOS.
///
/// - ARM64: Detects Apple Silicon GPU via system_profiler
/// - x86_64: Returns empty (no GPU support on Intel Macs)
pub fn detect_gpus() -> Result<Vec<DetectedGpu>> {
    #[cfg(target_arch = "aarch64")]
    {
        detect_apple_silicon_gpu()
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        // No GPU support on Intel Macs with krunkit
        debug!("GPU detection: Intel Mac detected, no GPU passthrough available");
        Ok(vec![])
    }
}

/// Detect Apple Silicon GPU details.
#[cfg(target_arch = "aarch64")]
fn detect_apple_silicon_gpu() -> Result<Vec<DetectedGpu>> {
    // Query system_profiler for GPU info
    let output = Command::new("system_profiler")
        .args(["SPDisplaysDataType", "-json"])
        .output()
        .map_err(|e| HyprError::Internal(format!("Failed to run system_profiler: {}", e)))?;

    if !output.status.success() {
        // Fallback to basic detection
        return Ok(vec![DetectedGpu {
            pci_address: None,
            vendor: GpuVendor::Metal,
            model: get_chip_name().unwrap_or_else(|| "Apple Silicon GPU".to_string()),
            memory_mb: get_unified_memory(),
            available: true,
        }]);
    }

    // Parse JSON output
    let json_str = String::from_utf8_lossy(&output.stdout);
    let model = parse_gpu_model(&json_str)
        .unwrap_or_else(|| get_chip_name().unwrap_or_else(|| "Apple Silicon GPU".to_string()));

    debug!(model = %model, "Detected Apple Silicon GPU");

    Ok(vec![DetectedGpu {
        pci_address: None,
        vendor: GpuVendor::Metal,
        model,
        memory_mb: get_unified_memory(),
        available: true,
    }])
}

/// Get Apple chip name (M1, M2, M3, etc.) via sysctl.
#[cfg(target_arch = "aarch64")]
fn get_chip_name() -> Option<String> {
    let output = Command::new("sysctl").args(["-n", "machdep.cpu.brand_string"]).output().ok()?;

    if output.status.success() {
        let brand = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // brand_string returns something like "Apple M3 Max"
        Some(brand)
    } else {
        None
    }
}

/// Get unified memory size in MB.
#[cfg(target_arch = "aarch64")]
fn get_unified_memory() -> Option<u64> {
    let output = Command::new("sysctl").args(["-n", "hw.memsize"]).output().ok()?;

    if output.status.success() {
        let mem_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let bytes: u64 = mem_str.parse().ok()?;
        Some(bytes / (1024 * 1024)) // Convert to MB
    } else {
        None
    }
}

/// Parse GPU model from system_profiler JSON output.
#[cfg(target_arch = "aarch64")]
fn parse_gpu_model(json_str: &str) -> Option<String> {
    // Simple JSON parsing without external dependencies
    // Look for "sppci_model" or "chipset_model" field

    // Pattern: "chipset_model" : "Apple M3 Max"
    if let Some(start) = json_str.find("\"chipset_model\"") {
        let rest = &json_str[start..];
        if let Some(colon) = rest.find(':') {
            let after_colon = &rest[colon + 1..];
            // Find the quoted value
            if let Some(quote_start) = after_colon.find('"') {
                let after_quote = &after_colon[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('"') {
                    let model = &after_quote[..quote_end];
                    if !model.is_empty() {
                        return Some(model.to_string());
                    }
                }
            }
        }
    }

    // Fallback: look for sppci_model
    if let Some(start) = json_str.find("\"sppci_model\"") {
        let rest = &json_str[start..];
        if let Some(colon) = rest.find(':') {
            let after_colon = &rest[colon + 1..];
            if let Some(quote_start) = after_colon.find('"') {
                let after_quote = &after_colon[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('"') {
                    let model = &after_quote[..quote_end];
                    if !model.is_empty() {
                        return Some(model.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_parse_gpu_model() {
        let json = r#"{"SPDisplaysDataType":[{"chipset_model":"Apple M3 Max"}]}"#;
        assert_eq!(parse_gpu_model(json), Some("Apple M3 Max".to_string()));
    }

    #[test]
    fn test_detect_gpus_runs() {
        // Should not panic
        let result = detect_gpus();
        assert!(result.is_ok());
    }
}
