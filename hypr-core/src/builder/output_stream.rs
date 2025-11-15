//! Build output streaming and prettification layer.
//!
//! This is a PURE PRESENTATION LAYER. It has zero influence on build semantics.
//!
//! Responsibilities:
//! - Read raw bytes from VM stdout
//! - Prettify them for terminal display
//! - Capture them for logging
//! - Detect and extract [HYPR-RESULT] blocks after VM exits
//!
//! Non-responsibilities (CRITICAL - DO NOT ADD):
//! - Does NOT block or delay command execution
//! - Does NOT interpret output as protocol messages
//! - Does NOT wait for ready states
//! - Does NOT coordinate with VM
//! - Does NOT send commands based on timing
//! - Does NOT write additional files
//! - Does NOT change the DAG execution order
//!
//! Equivalent mental model: `tail -f | prettier`

use colored::Colorize;
use std::io::BufRead;
use std::time::{Duration, SystemTime};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader};
use tracing::{debug, warn};

/// Result of parsing a build step execution.
#[derive(Debug, Clone)]
pub struct StepResult {
    pub step: usize,
    pub exit_code: i32,
    pub duration_ms: u64,
}

/// Prettified output streamer for build VM console.
///
/// This is a pure decorator - it reads VM stdout and makes it look nice.
/// It does NOT change build behavior or semantics.
pub struct BuildOutputStream {
    /// Current step being executed (for grouping output)
    current_step: Option<usize>,
    /// Start time for duration calculation
    start_time: SystemTime,
}

impl BuildOutputStream {
    /// Create a new output streamer.
    pub fn new() -> Self {
        Self { current_step: None, start_time: SystemTime::now() }
    }

    /// Stream and prettify output from a log file (macOS vfkit).
    ///
    /// This function:
    /// 1. Tails the log file as it's being written
    /// 2. Prettifies each line with colors and formatting
    /// 3. Extracts [HYPR-RESULT] blocks for later parsing
    /// 4. Returns all results when VM exits (file stops growing)
    pub async fn stream_from_file(
        &mut self,
        log_path: &std::path::Path,
    ) -> crate::error::Result<Vec<StepResult>> {
        let mut results = Vec::new();

        // Wait for log file to be created (VM might take a moment to start)
        for _ in 0..50 {
            if log_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !log_path.exists() {
            warn!("Log file not created after 5 seconds: {}", log_path.display());
            return Ok(results);
        }

        // Open file and tail it
        let file = File::open(log_path).await.map_err(|e| crate::error::HyprError::IoError {
            path: log_path.to_path_buf(),
            source: e,
        })?;

        let mut reader = AsyncBufReader::new(file);
        let mut line = String::new();
        let mut result_block = Vec::new();
        let mut in_result_block = false;
        let mut consecutive_eof = 0;

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF - wait a bit and retry (tail -f behavior)
                    consecutive_eof += 1;
                    if consecutive_eof > 30 {
                        // 3 seconds of no output, assume VM exited
                        debug!("No output for 3s, assuming VM exited");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(_) => {
                    consecutive_eof = 0; // Reset EOF counter
                    let trimmed = line.trim_end();

                    // Parse and prettify the line
                    if trimmed == "[HYPR-RESULT]" {
                        in_result_block = true;
                        result_block.clear();
                    } else if trimmed == "[HYPR-RESULT-END]" {
                        in_result_block = false;
                        if let Some(result) = Self::parse_result_block(&result_block) {
                            results.push(result);
                        }
                        result_block.clear();
                    } else if in_result_block {
                        result_block.push(trimmed.to_string());
                    } else {
                        // Prettify and print the line
                        self.prettify_line(trimmed);
                    }
                }
                Err(e) => {
                    warn!("Error reading log file: {}", e);
                    break;
                }
            }
        }

        Ok(results)
    }

    /// Stream and prettify output from a subprocess pipe (Linux cloud-hypervisor).
    pub fn stream_from_pipe<R: BufRead>(
        &mut self,
        reader: R,
    ) -> crate::error::Result<Vec<StepResult>> {
        let mut results = Vec::new();
        let mut result_block = Vec::new();
        let mut in_result_block = false;

        for line in reader.lines() {
            let line = line.map_err(|e| crate::error::HyprError::BuildFailed {
                reason: format!("Failed to read stdout: {}", e),
            })?;

            let trimmed = line.trim_end();

            if trimmed == "[HYPR-RESULT]" {
                in_result_block = true;
                result_block.clear();
            } else if trimmed == "[HYPR-RESULT-END]" {
                in_result_block = false;
                if let Some(result) = Self::parse_result_block(&result_block) {
                    results.push(result);
                }
                result_block.clear();
            } else if in_result_block {
                result_block.push(trimmed.to_string());
            } else {
                // Prettify and print the line
                self.prettify_line(trimmed);
            }
        }

        Ok(results)
    }

    /// Prettify a single line of output.
    ///
    /// This is where the UX magic happens - but it's ONLY presentation.
    fn prettify_line(&mut self, line: &str) {
        // Timestamp for every line
        let elapsed = self.start_time.elapsed().unwrap_or_default();
        let timestamp = format!("{:>6.2}s", elapsed.as_secs_f64()).dimmed();

        // Detect line type and colorize
        if let Some(content) = line.strip_prefix("[kestrel]") {
            // Kestrel internal logs - cyan
            let content = content.trim();

            // Special handling for step execution
            if let Some(cmd) = content.strip_prefix("EXEC:") {
                let cmd = cmd.trim();
                let step_num = self.current_step.map(|s| s + 1).unwrap_or(1);
                self.current_step = Some(step_num);

                println!(
                    "{} {} {}",
                    timestamp,
                    format!("▶ Step {}", step_num).bold().green(),
                    cmd.cyan()
                );
            } else if content == "READY" {
                println!("{} {}", timestamp, "✓ Build VM ready".green());
            } else {
                println!("{} {} {}", timestamp, "kestrel".cyan().bold(), content.dimmed());
            }
        } else if line.starts_with("[    ") {
            // Kernel logs - extra dimmed, only show if RUST_LOG=debug
            if std::env::var("RUST_LOG").unwrap_or_default().contains("debug") {
                println!("{} {} {}", timestamp, "kernel".dimmed(), line.dimmed());
            }
        } else if line.contains("error") || line.contains("ERROR") || line.contains("Error") {
            // Error output - red
            println!("{} {} {}", timestamp, "✗".red().bold(), line.red());
        } else if line.contains("warning") || line.contains("WARN") {
            // Warning output - yellow
            println!("{} {} {}", timestamp, "⚠".yellow().bold(), line.yellow());
        } else if line.trim().is_empty() {
            // Skip blank lines for cleaner output
        } else {
            // Regular command output - white
            println!("{} │ {}", timestamp, line);
        }
    }

    /// Parse a HYPR-RESULT block into a StepResult.
    fn parse_result_block(lines: &[String]) -> Option<StepResult> {
        let mut step = None;
        let mut exit_code = None;
        let mut duration_ms = None;

        for line in lines {
            if let Some(value) = line.strip_prefix("step=") {
                step = value.parse().ok();
            } else if let Some(value) = line.strip_prefix("exit=") {
                exit_code = value.parse().ok();
            } else if let Some(value) = line.strip_prefix("duration_ms=") {
                duration_ms = value.parse().ok();
            }
        }

        // exit_code is mandatory, step and duration are optional
        exit_code.map(|exit| StepResult {
            step: step.unwrap_or(0),
            exit_code: exit,
            duration_ms: duration_ms.unwrap_or(0),
        })
    }
}

impl Default for BuildOutputStream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_result_block() {
        let lines =
            vec!["step=1".to_string(), "exit=0".to_string(), "duration_ms=1234".to_string()];

        let result = BuildOutputStream::parse_result_block(&lines).unwrap();
        assert_eq!(result.step, 1);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.duration_ms, 1234);
    }

    #[test]
    fn test_parse_minimal_result_block() {
        let lines = vec!["exit=0".to_string()];

        let result = BuildOutputStream::parse_result_block(&lines).unwrap();
        assert_eq!(result.step, 0);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.duration_ms, 0);
    }

    #[test]
    fn test_parse_invalid_result_block() {
        let lines = vec!["invalid".to_string()];
        assert!(BuildOutputStream::parse_result_block(&lines).is_none());
    }
}
