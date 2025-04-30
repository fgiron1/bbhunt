use std::path::PathBuf;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Complete report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub target: String,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, String>,
}

/// Report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_hosts_scanned: usize,
    pub total_findings: usize,
    pub severity_counts: HashMap<Severity, usize>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cve_ids: Vec<String>,
    pub affected_targets: Vec<String>,
    pub evidence: Evidence,
    pub remediation: Option<String>,
    pub references: Vec<Reference>,
    pub tags: Vec<String>,
    pub discovered_by: String, // Plugin/tool name
    pub discovered_at: DateTime<Utc>,
}

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub data: serde_json::Value,
    pub screenshots: Vec<PathBuf>,
    pub request_response: Option<RequestResponse>,
}

/// HTTP request/response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponse {
    pub request: String,
    pub response: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}

/// Finding severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
    pub source_type: ReferenceType,
}

/// Reference source type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferenceType {
    CVE,
    CWE,
    OWASP,
    ExploitDB,
    Blog,
    Paper,
    Other,
}

impl Report {
    /// Create a new report
    pub fn new(id: String, title: String, target: String) -> Self {
        let now = Utc::now();
        
        Self {
            id,
            title,
            created_at: now,
            target,
            summary: ReportSummary {
                total_hosts_scanned: 0,
                total_findings: 0,
                severity_counts: HashMap::new(),
                start_time: now,
                end_time: now,
                duration_seconds: 0,
            },
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add a finding to the report
    pub fn add_finding(&mut self, finding: Finding) {
        // Update severity counts
        *self.summary.severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        
        // Update total findings
        self.summary.total_findings += 1;
        
        // Add the finding
        self.findings.push(finding);
    }
    
    /// Set the report duration
    pub fn set_duration(&mut self, start_time: DateTime<Utc>, end_time: DateTime<Utc>) {
        self.summary.start_time = start_time;
        self.summary.end_time = end_time;
        self.summary.duration_seconds = (end_time - start_time).num_seconds() as u64;
    }
    
    /// Set the total hosts scanned
    pub fn set_total_hosts_scanned(&mut self, count: usize) {
        self.summary.total_hosts_scanned = count;
    }
    
    /// Add metadata to the report
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }
}

/// Helper functions for working with severity levels
pub mod severity {
    use super::Severity;
    
    /// Convert severity to string
    pub fn to_string(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium", 
            Severity::Low => "Low",
            Severity::Info => "Informational",
        }
    }
    
    /// Parse severity from string
    pub fn from_string(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" | "informational" => Some(Severity::Info),
            _ => None,
        }
    }
    
    /// Get sort order for severity (higher severity = lower index)
    pub fn sort_order(severity: &Severity) -> usize {
        match severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}