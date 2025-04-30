// src/core/report.rs
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// Report data structure
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_hosts_scanned: usize,
    pub total_findings: usize,
    pub severity_counts: HashMap<Severity, usize>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub data: serde_json::Value,
    pub screenshots: Vec<PathBuf>,
    pub request_response: Option<RequestResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponse {
    pub request: String,
    pub response: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
    pub source_type: ReferenceType,
}

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

// Report generator traits and implementations
#[async_trait::async_trait]
pub trait ReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()>;
    fn supported_format(&self) -> ReportFormat;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    JSON,
    HTML,
    Markdown,
    PDF,
    CSV,
    XML,
}

// JSON Report Generator implementation
pub struct JsonReportGenerator;

#[async_trait::async_trait]
impl ReportGenerator for JsonReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        tokio::fs::write(output_path, json).await?;
        Ok(())
    }
    
    fn supported_format(&self) -> ReportFormat {
        ReportFormat::JSON
    }
}

// Markdown Report Generator implementation
pub struct MarkdownReportGenerator;

#[async_trait::async_trait]
impl ReportGenerator for MarkdownReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()> {
        let mut content = String::new();
        
        // Title and metadata
        content.push_str(&format!("# {}\n\n", report.title));
        content.push_str(&format!("**Generated:** {}\n", report.created_at));
        content.push_str(&format!("**Target:** {}\n\n", report.target));
        
        // Summary
        content.push_str("## Summary\n\n");
        content.push_str(&format!("- **Total Hosts Scanned:** {}\n", report.summary.total_hosts_scanned));
        content.push_str(&format!("- **Total Findings:** {}\n", report.summary.total_findings));
        content.push_str("- **Severity Breakdown:**\n");
        
        for (severity, count) in &report.summary.severity_counts {
            content.push_str(&format!("  - {}: {}\n", severity_to_string(severity), count));
        }
        
        content.push_str(&format!("\n**Scan Duration:** {} seconds\n\n", report.summary.duration_seconds));
        
        // Findings
        content.push_str("## Findings\n\n");
        
        for finding in &report.findings {
            content.push_str(&format!("### {}\n\n", finding.title));
            content.push_str(&format!("**Severity:** {}\n", severity_to_string(&finding.severity)));
            
            if let Some(cvss) = finding.cvss_score {
                content.push_str(&format!("**CVSS Score:** {:.1}\n", cvss));
            }
            
            content.push_str("\n**Description:**\n\n");
            content.push_str(&format!("{}\n\n", finding.description));
            
            content.push_str("**Affected Targets:**\n\n");
            for target in &finding.affected_targets {
                content.push_str(&format!("- {}\n", target));
            }
            content.push_str("\n");
            
            content.push_str("**Evidence:**\n\n");
            content.push_str(&format!("{}\n\n", finding.evidence.description));
            
            if let Some(req_resp) = &finding.evidence.request_response {
                content.push_str("**Request/Response:**\n\n");
                content.push_str("```http\n");
                content.push_str(&req_resp.request);
                content.push_str("\n```\n\n");
                content.push_str("```http\n");
                content.push_str(&req_resp.response);
                content.push_str("\n```\n\n");
            }
            
            if let Some(remediation) = &finding.remediation {
                content.push_str("**Remediation:**\n\n");
                content.push_str(&format!("{}\n\n", remediation));
            }
            
            if !finding.references.is_empty() {
                content.push_str("**References:**\n\n");
                for reference in &finding.references {
                    content.push_str(&format!("- [{}]({})\n", reference.title, reference.url));
                }
                content.push_str("\n");
            }
            
            content.push_str(&format!("*Discovered by:* {} on {}\n\n", 
                finding.discovered_by, finding.discovered_at));
            
            content.push_str("---\n\n");
        }
        
        tokio::fs::write(output_path, content).await?;
        Ok(())
    }
    
    fn supported_format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }
}

// HTML report generator would be implemented similarly

// Report Manager to coordinate report generation
pub struct ReportManager {
    generators: HashMap<ReportFormat, Box<dyn ReportGenerator + Send + Sync>>,
    report_dir: PathBuf,
}

impl ReportManager {
    pub fn new(report_dir: PathBuf) -> Self {
        let mut generators = HashMap::new();
        
        // Register default generators
        generators.insert(ReportFormat::JSON, Box::new(JsonReportGenerator) as Box<dyn ReportGenerator + Send + Sync>);
        generators.insert(ReportFormat::Markdown, Box::new(MarkdownReportGenerator) as Box<dyn ReportGenerator + Send + Sync>);
        
        Self {
            generators,
            report_dir,
        }
    }
    
    pub fn register_generator(&mut self, generator: Box<dyn ReportGenerator + Send + Sync>) {
        self.generators.insert(generator.supported_format(), generator);
    }
    
    pub async fn generate_report(&self, report: &Report, format: ReportFormat) -> Result<PathBuf> {
        if !self.report_dir.exists() {
            tokio::fs::create_dir_all(&self.report_dir).await?;
        }
        
        let generator = self.generators.get(&format)
            .ok_or_else(|| anyhow::anyhow!("No generator found for format {:?}", format))?;
        
        let filename = format!("{}-{}.{}", 
            report.id,
            report.created_at.format("%Y%m%d-%H%M%S"),
            format_to_extension(&format));
        
        let output_path = self.report_dir.join(filename);
        generator.generate(report, &output_path).await?;
        
        Ok(output_path)
    }
    
    pub async fn generate_multi_format(&self, report: &Report, formats: &[ReportFormat]) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        
        for format in formats {
            let path = self.generate_report(report, format.clone()).await?;
            paths.push(path);
        }
        
        Ok(paths)
    }
}

// Helper functions
fn severity_to_string(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Informational",
    }
}

fn format_to_extension(format: &ReportFormat) -> &'static str {
    match format {
        ReportFormat::JSON => "json",
        ReportFormat::HTML => "html",
        ReportFormat::Markdown => "md",
        ReportFormat::PDF => "pdf",
        ReportFormat::CSV => "csv",
        ReportFormat::XML => "xml",
    }
}
