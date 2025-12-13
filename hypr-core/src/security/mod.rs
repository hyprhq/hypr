//! Security scanning module for vulnerability detection.
//!
//! This module provides image vulnerability scanning using Trivy as the backend scanner.
//! It supports:
//! - Scanning OCI images for known vulnerabilities (CVEs)
//! - Storing and retrieving security reports
//! - Filtering vulnerabilities by severity
//!
//! # Example
//!
//! ```no_run
//! use hypr_core::security::{SecurityScanner, ScanOptions};
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let scanner = SecurityScanner::new()?;
//!
//!     let options = ScanOptions::default();
//!     let report = scanner.scan_image("nginx:latest", &options).await?;
//!
//!     println!("Found {} vulnerabilities", report.summary.total);
//!     Ok(())
//! }
//! ```

mod scanner;
mod trivy;

pub use scanner::{
    RiskLevel, ScanOptions, ScanProgress, ScanStage, SecurityReport, SecurityScanner,
    Vulnerability, VulnerabilitySeverity, VulnerabilitySummary,
};
pub use trivy::TrivyScanner;
