//! Build output streaming with premium progress UI.
//!
//! This module provides a polished, modern build experience with:
//! - Multi-line progress bars for each build stage
//! - Real-time streaming output with beautiful formatting
//! - Step-by-step progress tracking
//! - Timing and performance metrics
//!
//! This is a PURE PRESENTATION LAYER. It has zero influence on build semantics.

use console::{style, Emoji};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::BufRead;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader};
use tracing::{debug, warn};

// Premium emoji set for build stages
static ROCKET: Emoji<'_, '_> = Emoji("🚀 ", "");
static PACKAGE: Emoji<'_, '_> = Emoji("📦 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
static CROSS: Emoji<'_, '_> = Emoji("❌ ", "[ERR] ");
static LAYER: Emoji<'_, '_> = Emoji("🔷 ", "* ");
static CLOCK: Emoji<'_, '_> = Emoji("⏱️  ", "");

/// Result of parsing a build step execution.
#[derive(Debug, Clone)]
pub struct StepResult {
    pub step: usize,
    pub exit_code: i32,
    pub duration_ms: u64,
}

/// Build event types for progress tracking
#[derive(Debug, Clone)]
pub enum BuildEvent {
    /// Build started with total number of stages
    BuildStarted { total_stages: usize },
    /// A new stage is starting
    StageStarted { stage_idx: usize, stage_name: String, base_image: String },
    /// A stage completed successfully
    StageCompleted { stage_idx: usize, duration_secs: f64 },
    /// A build step (instruction) is starting
    StepStarted { stage_idx: usize, step_idx: usize, instruction: String },
    /// A build step completed
    StepCompleted { stage_idx: usize, step_idx: usize, cached: bool, duration_secs: f64 },
    /// Command output from the build
    Output { line: String },
    /// Build completed successfully
    BuildCompleted { image_id: String, total_duration_secs: f64 },
    /// Build failed
    BuildFailed { error: String },
}

/// Premium progress UI for builds.
pub struct BuildProgressUI {
    /// Multi-progress container for multiple progress bars
    multi: MultiProgress,
    /// Overall build progress bar
    overall_bar: ProgressBar,
    /// Current stage progress bar
    stage_bar: Option<ProgressBar>,
    /// Start time
    start_time: Instant,
    /// Total stages
    total_stages: usize,
    /// Current stage index
    current_stage: usize,
    /// Output lines buffer
    output_buffer: Vec<String>,
}

impl BuildProgressUI {
    /// Create a new premium build progress UI.
    pub fn new(total_stages: usize, total_steps: usize) -> Self {
        let multi = MultiProgress::new();

        // Create the overall progress bar with a premium style
        let overall_style = ProgressStyle::with_template(
            "{prefix:.bold.dim} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("━━╸");

        let overall_bar = multi.add(ProgressBar::new(total_steps as u64));
        overall_bar.set_style(overall_style);
        overall_bar.set_prefix(format!("{ROCKET}Building"));
        overall_bar.set_message("Starting...");

        Self {
            multi,
            overall_bar,
            stage_bar: None,
            start_time: Instant::now(),
            total_stages,
            current_stage: 0,
            output_buffer: Vec::new(),
        }
    }

    /// Start a new build stage.
    pub fn start_stage(
        &mut self,
        stage_idx: usize,
        stage_name: &str,
        base_image: &str,
        steps: usize,
    ) {
        self.current_stage = stage_idx;

        // Finish previous stage bar if exists
        if let Some(bar) = self.stage_bar.take() {
            bar.finish_and_clear();
        }

        // Create new stage progress bar
        let stage_style = ProgressStyle::with_template(
            "  {prefix:.bold} [{bar:30.green/white}] {pos}/{len} {msg:.dim}",
        )
        .unwrap()
        .progress_chars("▓▒░");

        let stage_bar = self.multi.add(ProgressBar::new(steps as u64));
        stage_bar.set_style(stage_style);
        stage_bar.set_prefix(format!("{LAYER}Stage {}/{}", stage_idx + 1, self.total_stages));
        stage_bar.set_message(format!("{} (from {})", stage_name, base_image));

        self.stage_bar = Some(stage_bar);

        // Print stage header
        self.print_stage_header(stage_idx, stage_name, base_image);
    }

    /// Print a beautiful stage header.
    fn print_stage_header(&self, stage_idx: usize, stage_name: &str, base_image: &str) {
        println!();
        println!(
            "{} {} {}",
            style(format!("Stage {}/{}", stage_idx + 1, self.total_stages)).bold().cyan(),
            style("━".repeat(40)).dim(),
            style(stage_name).bold().white()
        );
        println!("  {} FROM {}", style("│").dim(), style(base_image).yellow());
    }

    /// Start a build step.
    pub fn start_step(&mut self, step_idx: usize, instruction: &str) {
        // Truncate long instructions for display
        let display_instruction = if instruction.len() > 60 {
            format!("{}...", &instruction[..57])
        } else {
            instruction.to_string()
        };

        println!(
            "  {} {} {}",
            style("│").dim(),
            style(format!("Step {}", step_idx + 1)).bold(),
            style(&display_instruction).dim()
        );
    }

    /// Complete a build step.
    pub fn complete_step(&mut self, _step_idx: usize, cached: bool, duration_secs: f64) {
        // Update progress bars
        self.overall_bar.inc(1);
        if let Some(ref bar) = self.stage_bar {
            bar.inc(1);
        }

        let status = if cached {
            format!("{} CACHED", CHECK)
        } else {
            format!("{} {:.2}s", CHECK, duration_secs)
        };

        println!("  {} {}", style("│").dim(), style(status).green());
    }

    /// Show a step failure.
    pub fn fail_step(&self, step_idx: usize, error: &str) {
        println!(
            "  {} {} Step {} failed: {}",
            style("│").dim(),
            CROSS,
            step_idx + 1,
            style(error).red()
        );
    }

    /// Complete a stage.
    pub fn complete_stage(&mut self, duration_secs: f64) {
        if let Some(bar) = self.stage_bar.take() {
            bar.finish_and_clear();
        }

        println!("  {} {} Stage completed in {:.2}s", style("└").dim(), CHECK, duration_secs);
    }

    /// Print command output.
    pub fn print_output(&mut self, line: &str) {
        // Filter and format output
        let formatted = self.format_output_line(line);
        if let Some(formatted) = formatted {
            println!("  {}   {}", style("│").dim(), formatted);
            self.output_buffer.push(line.to_string());
        }
    }

    /// Format an output line with syntax highlighting.
    fn format_output_line(&self, line: &str) -> Option<String> {
        let trimmed = line.trim();

        // Skip empty lines and certain noise
        if trimmed.is_empty() {
            return None;
        }

        // Skip kernel messages unless debug
        if trimmed.starts_with("[    ") {
            return None;
        }

        // Skip kestrel internal messages (show only EXEC)
        if trimmed.starts_with("[kestrel]") {
            if trimmed.contains("EXEC:") {
                let cmd = trimmed.split("EXEC:").nth(1).unwrap_or("").trim();
                return Some(format!("{} {}", style("$").cyan().bold(), style(cmd).white()));
            }
            return None;
        }

        // Color errors red
        if trimmed.contains("error") || trimmed.contains("ERROR") || trimmed.contains("Error") {
            return Some(style(trimmed).red().to_string());
        }

        // Color warnings yellow
        if trimmed.contains("warning") || trimmed.contains("WARNING") || trimmed.contains("Warning")
        {
            return Some(style(trimmed).yellow().to_string());
        }

        // Dim less important lines
        if trimmed.starts_with("--") || trimmed.starts_with("##") {
            return Some(style(trimmed).dim().to_string());
        }

        Some(trimmed.to_string())
    }

    /// Complete the entire build.
    pub fn complete_build(&self, image_id: &str, total_duration_secs: f64) {
        self.overall_bar.finish_and_clear();

        println!();
        println!("{}", style("━".repeat(60)).green());
        println!(
            "{} {} in {:.2}s",
            ROCKET,
            style("Build completed successfully").green().bold(),
            total_duration_secs
        );
        println!();
        println!("  {} Image ID: {}", PACKAGE, style(image_id).cyan().bold());
        println!("  {} Duration: {:.2}s", CLOCK, total_duration_secs);
        println!("{}", style("━".repeat(60)).green());
    }

    /// Fail the build.
    pub fn fail_build(&self, error: &str) {
        self.overall_bar.abandon();

        println!();
        println!("{}", style("━".repeat(60)).red());
        println!("{} {}", CROSS, style("Build failed").red().bold());
        println!("  {}", style(error).red());
        println!("{}", style("━".repeat(60)).red());
    }

    /// Get elapsed time.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Simpler output streamer for VM-based builds (file tailing).
pub struct BuildOutputStream {
    /// Current step being executed
    current_step: Option<usize>,
    /// Start time
    start_time: Instant,
}

impl BuildOutputStream {
    /// Create a new output streamer.
    pub fn new() -> Self {
        Self { current_step: None, start_time: Instant::now() }
    }

    /// Stream and prettify output from a log file.
    pub async fn stream_from_file(
        &mut self,
        log_path: &std::path::Path,
    ) -> crate::error::Result<Vec<StepResult>> {
        let mut results = Vec::new();

        // Show waiting message
        print!("\r  {} Waiting for build VM...", style("⠋").cyan());
        let _ = std::io::Write::flush(&mut std::io::stdout());

        // Wait for log file to be created
        let mut spinner_idx = 0;
        let spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

        for _ in 0..100 {
            if log_path.exists() {
                print!("\r{}\r", " ".repeat(40));
                let _ = std::io::Write::flush(&mut std::io::stdout());
                break;
            }
            spinner_idx = (spinner_idx + 1) % spinner_chars.len();
            print!("\r  {} Waiting for build VM...", style(spinner_chars[spinner_idx]).cyan());
            let _ = std::io::Write::flush(&mut std::io::stdout());
            tokio::time::sleep(Duration::from_millis(50)).await;
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
                    consecutive_eof += 1;
                    if consecutive_eof > 50 {
                        debug!("No output for 2.5s, assuming VM exited");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok(_) => {
                    consecutive_eof = 0;
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

    /// Stream from a pipe (for Linux).
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
                self.prettify_line(trimmed);
            }
        }

        Ok(results)
    }

    /// Prettify a single line.
    fn prettify_line(&mut self, line: &str) {
        let elapsed = self.start_time.elapsed();
        let timestamp = format!("{:>6.2}s", elapsed.as_secs_f64());

        // Skip empty lines
        if line.trim().is_empty() {
            return;
        }

        // Skip kernel messages
        if line.starts_with("[    ") {
            return;
        }

        // Handle kestrel messages
        if let Some(content) = line.strip_prefix("[kestrel]") {
            let content = content.trim();

            if let Some(cmd) = content.strip_prefix("EXEC:") {
                let cmd = cmd.trim();
                let step_num = self.current_step.map(|s| s + 1).unwrap_or(1);
                self.current_step = Some(step_num);

                // Truncate long commands
                let display_cmd =
                    if cmd.len() > 60 { format!("{}...", &cmd[..57]) } else { cmd.to_string() };

                println!(
                    "{} {} {}",
                    style(timestamp).dim(),
                    style(format!("▶ Step {}", step_num)).bold().green(),
                    style(display_cmd).cyan()
                );
            } else if content == "READY" {
                println!("{} {} Build VM ready", style(timestamp).dim(), style("✓").green());
            } else {
                // Print other kestrel messages for debugging
                println!("{} │ [kestrel] {}", style(timestamp).dim(), content);
            }
            return;
        }

        // Color errors/warnings
        if line.contains("error") || line.contains("ERROR") || line.contains("Error") {
            println!("{} {} {}", style(timestamp).dim(), style("✗").red(), style(line).red());
        } else if line.contains("warning") || line.contains("WARN") {
            println!("{} {} {}", style(timestamp).dim(), style("⚠").yellow(), style(line).yellow());
        } else {
            println!("{} │ {}", style(timestamp).dim(), line);
        }
    }

    /// Parse a result block.
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
