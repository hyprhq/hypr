//! Core security scanner types and traits.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::error::{HyprError, Result};
use crate::state::StateManager;

use super::trivy::TrivyScanner;

/// Overall risk level for an image based on vulnerability severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Critical vulnerabilities found - immediate action required.
    Critical,
    /// High severity vulnerabilities present.
    High,
    /// Medium severity vulnerabilities present.
    Medium,
    /// Low severity vulnerabilities only.
    Low,
    /// No vulnerabilities detected.
    #[default]
    None,
}

impl RiskLevel {
    /// Parse risk level from string.
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => RiskLevel::Critical,
            "HIGH" => RiskLevel::High,
            "MEDIUM" => RiskLevel::Medium,
            "LOW" => RiskLevel::Low,
            _ => RiskLevel::None,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "CRITICAL",
            RiskLevel::High => "HIGH",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::Low => "LOW",
            RiskLevel::None => "NONE",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Vulnerability severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum VulnerabilitySeverity {
    /// Critical severity - CVSS 9.0-10.0.
    Critical,
    /// High severity - CVSS 7.0-8.9.
    High,
    /// Medium severity - CVSS 4.0-6.9.
    Medium,
    /// Low severity - CVSS 0.1-3.9.
    Low,
    /// Unknown severity.
    #[default]
    Unknown,
}

impl VulnerabilitySeverity {
    /// Parse severity from string.
    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "CRITICAL" => VulnerabilitySeverity::Critical,
            "HIGH" => VulnerabilitySeverity::High,
            "MEDIUM" => VulnerabilitySeverity::Medium,
            "LOW" => VulnerabilitySeverity::Low,
            _ => VulnerabilitySeverity::Unknown,
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnerabilitySeverity::Critical => "CRITICAL",
            VulnerabilitySeverity::High => "HIGH",
            VulnerabilitySeverity::Medium => "MEDIUM",
            VulnerabilitySeverity::Low => "LOW",
            VulnerabilitySeverity::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Summary of vulnerabilities by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    /// Number of critical vulnerabilities.
    pub critical: u32,
    /// Number of high severity vulnerabilities.
    pub high: u32,
    /// Number of medium severity vulnerabilities.
    pub medium: u32,
    /// Number of low severity vulnerabilities.
    pub low: u32,
    /// Number of unknown severity vulnerabilities.
    pub unknown: u32,
    /// Total number of vulnerabilities.
    pub total: u32,
}

impl VulnerabilitySummary {
    /// Create a new summary from a list of vulnerabilities.
    pub fn from_vulnerabilities(vulns: &[Vulnerability]) -> Self {
        let mut summary = VulnerabilitySummary::default();
        for vuln in vulns {
            match vuln.severity {
                VulnerabilitySeverity::Critical => summary.critical += 1,
                VulnerabilitySeverity::High => summary.high += 1,
                VulnerabilitySeverity::Medium => summary.medium += 1,
                VulnerabilitySeverity::Low => summary.low += 1,
                VulnerabilitySeverity::Unknown => summary.unknown += 1,
            }
            summary.total += 1;
        }
        summary
    }

    /// Determine overall risk level from the summary.
    pub fn risk_level(&self) -> RiskLevel {
        if self.critical > 0 {
            RiskLevel::Critical
        } else if self.high > 0 {
            RiskLevel::High
        } else if self.medium > 0 {
            RiskLevel::Medium
        } else if self.low > 0 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        }
    }
}

/// A single vulnerability found in an image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE ID (e.g., "CVE-2024-12345").
    pub id: String,
    /// Vulnerability severity.
    pub severity: VulnerabilitySeverity,
    /// Affected package name.
    pub package_name: String,
    /// Currently installed version.
    pub installed_version: String,
    /// Version that fixes the vulnerability (empty if none).
    pub fixed_version: String,
    /// Short title/summary.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// URLs for more information.
    pub references: Vec<String>,
    /// CVSS score (0.0-10.0).
    pub cvss_score: f64,
    /// CVSS vector string.
    pub cvss_vector: String,
    /// When vulnerability was published (Unix timestamp).
    pub published_date: i64,
    /// When vulnerability was last updated (Unix timestamp).
    pub last_modified: i64,
}

impl Default for Vulnerability {
    fn default() -> Self {
        Self {
            id: String::new(),
            severity: VulnerabilitySeverity::Unknown,
            package_name: String::new(),
            installed_version: String::new(),
            fixed_version: String::new(),
            title: String::new(),
            description: String::new(),
            references: Vec::new(),
            cvss_score: 0.0,
            cvss_vector: String::new(),
            published_date: 0,
            last_modified: 0,
        }
    }
}

/// Security report for a scanned image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Unique report ID.
    pub id: String,
    /// Scanned image ID.
    pub image_id: String,
    /// Image name:tag.
    pub image_name: String,
    /// Unix timestamp when scanned.
    pub scanned_at: i64,
    /// Version of the scanner used.
    pub scanner_version: String,
    /// Overall risk assessment.
    pub risk_level: RiskLevel,
    /// Vulnerability counts by severity.
    pub summary: VulnerabilitySummary,
    /// Detailed vulnerability list.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl Default for SecurityReport {
    fn default() -> Self {
        Self {
            id: String::new(),
            image_id: String::new(),
            image_name: String::new(),
            scanned_at: 0,
            scanner_version: String::new(),
            risk_level: RiskLevel::None,
            summary: VulnerabilitySummary::default(),
            vulnerabilities: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

/// Scanning stage for progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStage {
    /// Initializing the scanner.
    Initializing,
    /// Updating vulnerability database.
    UpdatingDatabase,
    /// Scanning the image.
    Scanning,
    /// Analyzing results.
    Analyzing,
    /// Scan complete.
    Complete,
}

impl ScanStage {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStage::Initializing => "initializing",
            ScanStage::UpdatingDatabase => "updating_db",
            ScanStage::Scanning => "scanning",
            ScanStage::Analyzing => "analyzing",
            ScanStage::Complete => "complete",
        }
    }
}

impl fmt::Display for ScanStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Progress update during scanning.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current scanning stage.
    pub stage: ScanStage,
    /// Human-readable progress message.
    pub message: String,
    /// Progress percentage (0-100).
    pub percent: u32,
}

impl ScanProgress {
    /// Create a new progress update.
    pub fn new(stage: ScanStage, message: impl Into<String>, percent: u32) -> Self {
        Self {
            stage,
            message: message.into(),
            percent: percent.min(100),
        }
    }
}

/// Options for image scanning.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Skip vulnerability database update.
    pub skip_db_update: bool,
    /// Filter vulnerabilities by severity (empty = all).
    pub severity_filter: Vec<VulnerabilitySeverity>,
    /// Timeout for scanning in seconds (default: 300).
    pub timeout_secs: Option<u64>,
}

impl ScanOptions {
    /// Create options with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to skip database update.
    pub fn skip_db_update(mut self, skip: bool) -> Self {
        self.skip_db_update = skip;
        self
    }

    /// Filter by severity levels.
    pub fn filter_severity(mut self, severities: Vec<VulnerabilitySeverity>) -> Self {
        self.severity_filter = severities;
        self
    }

    /// Set scan timeout in seconds.
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }
}

/// Security scanner for detecting vulnerabilities in images.
pub struct SecurityScanner {
    /// The underlying Trivy scanner.
    trivy: TrivyScanner,
    /// State manager for persisting reports.
    state: Option<Arc<StateManager>>,
}

impl SecurityScanner {
    /// Create a new security scanner.
    pub fn new() -> Result<Self> {
        let trivy = TrivyScanner::new()?;
        Ok(Self { trivy, state: None })
    }

    /// Create a new security scanner with state persistence.
    pub fn with_state(state: Arc<StateManager>) -> Result<Self> {
        let trivy = TrivyScanner::new()?;
        Ok(Self {
            trivy,
            state: Some(state),
        })
    }

    /// Create a new security scanner with custom Trivy binary path.
    pub fn with_trivy_path(trivy_path: PathBuf) -> Result<Self> {
        let trivy = TrivyScanner::with_path(trivy_path)?;
        Ok(Self { trivy, state: None })
    }

    /// Check if Trivy is available and properly configured.
    pub async fn is_available(&self) -> bool {
        self.trivy.is_available().await
    }

    /// Get the Trivy version.
    pub async fn scanner_version(&self) -> Result<String> {
        self.trivy.version().await
    }

    /// Scan an image for vulnerabilities.
    ///
    /// Returns a channel that receives progress updates and eventually the final report.
    pub async fn scan_image(
        &self,
        image: &str,
        options: &ScanOptions,
    ) -> Result<SecurityReport> {
        self.trivy.scan_image(image, options).await
    }

    /// Scan an image with progress reporting.
    ///
    /// Returns a channel that receives progress updates.
    pub async fn scan_image_with_progress(
        &self,
        image: &str,
        options: &ScanOptions,
    ) -> Result<(mpsc::Receiver<ScanProgress>, tokio::task::JoinHandle<Result<SecurityReport>>)>
    {
        let (tx, rx) = mpsc::channel(32);
        let trivy = self.trivy.clone();
        let image = image.to_string();
        let options = options.clone();

        let handle = tokio::spawn(async move {
            trivy.scan_image_with_progress(&image, &options, tx).await
        });

        Ok((rx, handle))
    }

    /// Get a security report by ID.
    pub async fn get_report(&self, report_id: &str) -> Result<SecurityReport> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| HyprError::Internal("State manager not configured".into()))?;

        state.get_security_report(report_id).await
    }

    /// List security reports with optional filters.
    pub async fn list_reports(
        &self,
        image_id: Option<&str>,
        image_name: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<SecurityReport>> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| HyprError::Internal("State manager not configured".into()))?;

        state
            .list_security_reports(image_id, image_name, limit)
            .await
    }

    /// Save a security report.
    pub async fn save_report(&self, report: &SecurityReport) -> Result<()> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| HyprError::Internal("State manager not configured".into()))?;

        state.insert_security_report(report).await
    }

    /// Delete a security report.
    pub async fn delete_report(&self, report_id: &str) -> Result<()> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| HyprError::Internal("State manager not configured".into()))?;

        state.delete_security_report(report_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_parse() {
        assert_eq!(RiskLevel::parse("CRITICAL"), RiskLevel::Critical);
        assert_eq!(RiskLevel::parse("high"), RiskLevel::High);
        assert_eq!(RiskLevel::parse("Medium"), RiskLevel::Medium);
        assert_eq!(RiskLevel::parse("LOW"), RiskLevel::Low);
        assert_eq!(RiskLevel::parse("unknown"), RiskLevel::None);
    }

    #[test]
    fn test_vulnerability_severity_parse() {
        assert_eq!(
            VulnerabilitySeverity::parse("CRITICAL"),
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            VulnerabilitySeverity::parse("high"),
            VulnerabilitySeverity::High
        );
        assert_eq!(
            VulnerabilitySeverity::parse("invalid"),
            VulnerabilitySeverity::Unknown
        );
    }

    #[test]
    fn test_vulnerability_summary() {
        let vulns = vec![
            Vulnerability {
                severity: VulnerabilitySeverity::Critical,
                ..Default::default()
            },
            Vulnerability {
                severity: VulnerabilitySeverity::Critical,
                ..Default::default()
            },
            Vulnerability {
                severity: VulnerabilitySeverity::High,
                ..Default::default()
            },
            Vulnerability {
                severity: VulnerabilitySeverity::Medium,
                ..Default::default()
            },
            Vulnerability {
                severity: VulnerabilitySeverity::Low,
                ..Default::default()
            },
        ];

        let summary = VulnerabilitySummary::from_vulnerabilities(&vulns);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.risk_level(), RiskLevel::Critical);
    }

    #[test]
    fn test_scan_options_builder() {
        let options = ScanOptions::new()
            .skip_db_update(true)
            .filter_severity(vec![
                VulnerabilitySeverity::Critical,
                VulnerabilitySeverity::High,
            ])
            .timeout(600);

        assert!(options.skip_db_update);
        assert_eq!(options.severity_filter.len(), 2);
        assert_eq!(options.timeout_secs, Some(600));
    }
}
