//! Trivy vulnerability scanner integration.
//!
//! This module provides integration with Aqua Security's Trivy scanner for
//! detecting vulnerabilities in container images.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;
use uuid::Uuid;

use crate::error::{HyprError, Result};

use super::scanner::{
    RiskLevel, ScanOptions, ScanProgress, ScanStage, SecurityReport, Vulnerability,
    VulnerabilitySeverity, VulnerabilitySummary,
};

/// Default timeout for scanning operations (5 minutes).
const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 300;

/// Trivy vulnerability scanner.
#[derive(Clone)]
pub struct TrivyScanner {
    /// Path to the Trivy binary.
    binary_path: PathBuf,
    /// Path to store Trivy cache/database.
    cache_dir: PathBuf,
}

impl TrivyScanner {
    /// Create a new Trivy scanner, auto-detecting binary location.
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_trivy_binary()?;
        let cache_dir = Self::default_cache_dir()?;

        Ok(Self { binary_path, cache_dir })
    }

    /// Create a scanner with a specific Trivy binary path.
    pub fn with_path(binary_path: PathBuf) -> Result<Self> {
        if !binary_path.exists() {
            return Err(HyprError::FileNotFound {
                path: binary_path,
                hint: "Please install Trivy: https://aquasecurity.github.io/trivy/".into(),
            });
        }

        let cache_dir = Self::default_cache_dir()?;

        Ok(Self { binary_path, cache_dir })
    }

    /// Find the Trivy binary in common locations.
    fn find_trivy_binary() -> Result<PathBuf> {
        // Check PATH first using `which`
        if let Ok(output) = std::process::Command::new("which").arg("trivy").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }

        // Check common installation locations
        let common_paths = [
            "/usr/local/bin/trivy",
            "/usr/bin/trivy",
            "/opt/homebrew/bin/trivy",
            "/opt/trivy/trivy",
        ];

        for path in common_paths {
            let path = PathBuf::from(path);
            if path.exists() {
                return Ok(path);
            }
        }

        Err(HyprError::FileNotFound {
            path: PathBuf::from("trivy"),
            hint: "Please install Trivy: https://aquasecurity.github.io/trivy/".into(),
        })
    }

    /// Get the default cache directory for Trivy.
    fn default_cache_dir() -> Result<PathBuf> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| HyprError::Internal("Could not determine cache directory".into()))?
            .join("hypr")
            .join("trivy");

        // Ensure directory exists
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            HyprError::Internal(format!("Failed to create Trivy cache directory: {}", e))
        })?;

        Ok(cache_dir)
    }

    /// Check if Trivy is available and working.
    pub async fn is_available(&self) -> bool {
        self.version().await.is_ok()
    }

    /// Get the Trivy version.
    pub async fn version(&self) -> Result<String> {
        let output = Command::new(&self.binary_path)
            .arg("version")
            .arg("--format")
            .arg("json")
            .output()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to run Trivy: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HyprError::Internal(format!("Trivy version check failed: {}", stderr)));
        }

        // Parse JSON output to get version
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| HyprError::Internal(format!("Failed to parse Trivy version: {}", e)))?;

        let version = json.get("Version").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        Ok(version)
    }

    /// Scan an image for vulnerabilities.
    pub async fn scan_image(&self, image: &str, options: &ScanOptions) -> Result<SecurityReport> {
        let timeout_secs = options.timeout_secs.unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS);

        let scan_future = self.run_scan(image, options);
        let result = timeout(Duration::from_secs(timeout_secs), scan_future)
            .await
            .map_err(|_| HyprError::Internal(format!("Scan timed out after {}s", timeout_secs)))?;

        result
    }

    /// Scan an image with progress reporting.
    pub async fn scan_image_with_progress(
        &self,
        image: &str,
        options: &ScanOptions,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<SecurityReport> {
        // Send initializing progress
        let _ = progress_tx
            .send(ScanProgress::new(
                ScanStage::Initializing,
                "Initializing vulnerability scanner",
                5,
            ))
            .await;

        // Update database if not skipped
        if !options.skip_db_update {
            let _ = progress_tx
                .send(ScanProgress::new(
                    ScanStage::UpdatingDatabase,
                    "Updating vulnerability database",
                    10,
                ))
                .await;

            // The database update happens automatically during scan
        }

        // Send scanning progress
        let _ = progress_tx
            .send(ScanProgress::new(ScanStage::Scanning, format!("Scanning image: {}", image), 30))
            .await;

        // Run the actual scan
        let report = self.run_scan_with_progress(image, options, &progress_tx).await?;

        // Send complete progress
        let _ = progress_tx
            .send(ScanProgress::new(
                ScanStage::Complete,
                format!("Scan complete: found {} vulnerabilities", report.summary.total),
                100,
            ))
            .await;

        Ok(report)
    }

    /// Run the actual Trivy scan.
    async fn run_scan(&self, image: &str, options: &ScanOptions) -> Result<SecurityReport> {
        let mut cmd = Command::new(&self.binary_path);

        cmd.arg("image")
            .arg("--format")
            .arg("json")
            .arg("--cache-dir")
            .arg(&self.cache_dir)
            .arg("--quiet");

        // Add severity filter if specified
        if !options.severity_filter.is_empty() {
            let severities: Vec<&str> =
                options.severity_filter.iter().map(|s| s.as_str()).collect();
            cmd.arg("--severity").arg(severities.join(","));
        }

        // Skip database update if requested
        if options.skip_db_update {
            cmd.arg("--skip-db-update");
        }

        cmd.arg(image);

        let output = cmd
            .output()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to run Trivy: {}", e)))?;

        // Parse the output
        self.parse_scan_output(image, &output.stdout).await
    }

    /// Run scan with progress updates.
    async fn run_scan_with_progress(
        &self,
        image: &str,
        options: &ScanOptions,
        progress_tx: &mpsc::Sender<ScanProgress>,
    ) -> Result<SecurityReport> {
        let mut cmd = Command::new(&self.binary_path);

        cmd.arg("image").arg("--format").arg("json").arg("--cache-dir").arg(&self.cache_dir);

        // Add severity filter if specified
        if !options.severity_filter.is_empty() {
            let severities: Vec<&str> =
                options.severity_filter.iter().map(|s| s.as_str()).collect();
            cmd.arg("--severity").arg(severities.join(","));
        }

        // Skip database update if requested
        if options.skip_db_update {
            cmd.arg("--skip-db-update");
        }

        cmd.arg(image);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| HyprError::Internal(format!("Failed to spawn Trivy: {}", e)))?;

        // Read stderr for progress updates
        let stderr = child.stderr.take();
        if let Some(stderr) = stderr {
            let progress_tx = progress_tx.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut progress = 30;

                while let Ok(Some(line)) = lines.next_line().await {
                    // Increment progress based on stderr output
                    progress = (progress + 5).min(90);

                    let message = if line.contains("Downloading") {
                        "Downloading vulnerability database"
                    } else if line.contains("Analyzing") {
                        "Analyzing image layers"
                    } else if line.contains("Detecting") {
                        "Detecting vulnerabilities"
                    } else {
                        continue;
                    };

                    let _ = progress_tx
                        .send(ScanProgress::new(ScanStage::Scanning, message, progress))
                        .await;
                }
            });
        }

        // Wait for the scan to complete
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to wait for Trivy: {}", e)))?;

        // Send analyzing progress
        let _ = progress_tx
            .send(ScanProgress::new(ScanStage::Analyzing, "Analyzing scan results", 95))
            .await;

        // Parse the output
        self.parse_scan_output(image, &output.stdout).await
    }

    /// Parse Trivy JSON output into a security report.
    async fn parse_scan_output(&self, image: &str, output: &[u8]) -> Result<SecurityReport> {
        // Get scanner version once (cached for the report)
        // Don't fail if we can't get the version - this is a non-critical field
        let scanner_version = self.version().await.unwrap_or_else(|_| "unknown".into());

        self.parse_scan_output_with_version(image, output, &scanner_version)
    }

    /// Parse Trivy JSON output into a security report with a pre-fetched version.
    /// This is useful for testing where Trivy might not be available.
    fn parse_scan_output_with_version(
        &self,
        image: &str,
        output: &[u8],
        scanner_version: &str,
    ) -> Result<SecurityReport> {
        // Handle empty output (no vulnerabilities found)
        if output.is_empty() {
            return Ok(SecurityReport {
                id: Uuid::new_v4().to_string(),
                image_id: String::new(),
                image_name: image.to_string(),
                scanned_at: Utc::now().timestamp(),
                scanner_version: scanner_version.to_string(),
                risk_level: RiskLevel::None,
                summary: VulnerabilitySummary::default(),
                vulnerabilities: Vec::new(),
                metadata: HashMap::new(),
            });
        }

        let trivy_output: TrivyOutput = serde_json::from_slice(output).map_err(|e| {
            tracing::error!("Trivy output: {}", String::from_utf8_lossy(output));
            HyprError::Internal(format!("Failed to parse Trivy output: {}", e))
        })?;

        // Convert to our format
        let mut vulnerabilities = Vec::new();

        for result in &trivy_output.results {
            if let Some(vulns) = &result.vulnerabilities {
                for vuln in vulns {
                    vulnerabilities.push(self.convert_vulnerability(vuln));
                }
            }
        }

        let summary = VulnerabilitySummary::from_vulnerabilities(&vulnerabilities);
        let risk_level = summary.risk_level();

        let mut metadata = HashMap::new();
        if let Some(artifact) = &trivy_output.artifact_name {
            metadata.insert("artifact_name".to_string(), artifact.clone());
        }
        if let Some(artifact_type) = &trivy_output.artifact_type {
            metadata.insert("artifact_type".to_string(), artifact_type.clone());
        }

        Ok(SecurityReport {
            id: Uuid::new_v4().to_string(),
            image_id: trivy_output
                .metadata
                .as_ref()
                .and_then(|m| m.image_id.clone())
                .unwrap_or_default(),
            image_name: image.to_string(),
            scanned_at: Utc::now().timestamp(),
            scanner_version: scanner_version.to_string(),
            risk_level,
            summary,
            vulnerabilities,
            metadata,
        })
    }

    /// Convert a Trivy vulnerability to our format.
    fn convert_vulnerability(&self, vuln: &TrivyVulnerability) -> Vulnerability {
        Vulnerability {
            id: vuln.vulnerability_id.clone(),
            severity: VulnerabilitySeverity::parse(&vuln.severity),
            package_name: vuln.pkg_name.clone(),
            installed_version: vuln.installed_version.clone(),
            fixed_version: vuln.fixed_version.clone().unwrap_or_default(),
            title: vuln.title.clone().unwrap_or_default(),
            description: vuln.description.clone().unwrap_or_default(),
            references: vuln.references.clone().unwrap_or_default(),
            cvss_score: vuln
                .cvss
                .as_ref()
                .and_then(|c| c.nvd.as_ref())
                .map(|n| n.v3_score.unwrap_or(0.0))
                .unwrap_or(0.0),
            cvss_vector: vuln
                .cvss
                .as_ref()
                .and_then(|c| c.nvd.as_ref())
                .and_then(|n| n.v3_vector.clone())
                .unwrap_or_default(),
            published_date: vuln
                .published_date
                .as_ref()
                .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                .map(|d| d.timestamp())
                .unwrap_or(0),
            last_modified: vuln
                .last_modified_date
                .as_ref()
                .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                .map(|d| d.timestamp())
                .unwrap_or(0),
        }
    }
}

// Trivy JSON output structures

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyOutput {
    artifact_name: Option<String>,
    artifact_type: Option<String>,
    metadata: Option<TrivyMetadata>,
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyMetadata {
    #[serde(rename = "ImageID")]
    image_id: Option<String>,
    #[serde(rename = "RepoDigests")]
    _repo_digests: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    #[serde(rename = "Target")]
    _target: Option<String>,
    #[serde(rename = "Class")]
    _class: Option<String>,
    #[serde(rename = "Type")]
    _type: Option<String>,
    vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    pkg_name: String,
    installed_version: String,
    fixed_version: Option<String>,
    severity: String,
    title: Option<String>,
    description: Option<String>,
    references: Option<Vec<String>>,
    published_date: Option<String>,
    last_modified_date: Option<String>,
    #[serde(rename = "CVSS")]
    cvss: Option<TrivyCvss>,
}

#[derive(Debug, Deserialize)]
struct TrivyCvss {
    nvd: Option<TrivyNvdCvss>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyNvdCvss {
    v3_vector: Option<String>,
    v3_score: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_output() {
        let scanner = TrivyScanner {
            binary_path: PathBuf::from("/usr/bin/trivy"),
            cache_dir: PathBuf::from("/tmp/trivy"),
        };

        let report = scanner.parse_scan_output_with_version("test:latest", b"", "0.50.0");
        assert!(report.is_ok());

        let report = report.unwrap();
        assert_eq!(report.image_name, "test:latest");
        assert_eq!(report.summary.total, 0);
        assert_eq!(report.risk_level, RiskLevel::None);
    }

    #[test]
    fn test_parse_trivy_output() {
        let scanner = TrivyScanner {
            binary_path: PathBuf::from("/usr/bin/trivy"),
            cache_dir: PathBuf::from("/tmp/trivy"),
        };

        let output = r#"{
            "ArtifactName": "nginx:latest",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:abc123"
            },
            "Results": [
                {
                    "Target": "nginx:latest (alpine 3.18.0)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "Severity": "CRITICAL",
                            "Title": "Test vulnerability",
                            "Description": "A test vulnerability"
                        },
                        {
                            "VulnerabilityID": "CVE-2024-67890",
                            "PkgName": "curl",
                            "InstalledVersion": "7.80.0",
                            "Severity": "HIGH"
                        }
                    ]
                }
            ]
        }"#;

        let report =
            scanner.parse_scan_output_with_version("nginx:latest", output.as_bytes(), "0.50.0");
        assert!(report.is_ok(), "Parse failed: {:?}", report.err());

        let report = report.unwrap();
        assert_eq!(report.image_name, "nginx:latest");
        assert_eq!(report.image_id, "sha256:abc123");
        assert_eq!(report.summary.total, 2);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.high, 1);
        assert_eq!(report.risk_level, RiskLevel::Critical);
        assert_eq!(report.vulnerabilities.len(), 2);
        assert_eq!(report.vulnerabilities[0].id, "CVE-2024-12345");
        assert_eq!(report.vulnerabilities[0].package_name, "openssl");
        assert_eq!(report.vulnerabilities[0].fixed_version, "1.1.2");
    }
}
