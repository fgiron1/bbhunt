// src/report.rs
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use tracing::{info, debug, error};
use tokio::fs;
use uuid::Uuid;

use crate::config::AppConfig;
use crate::target::TargetData;
use crate::template::TemplateEngine;

/// Manager for generating reports
pub struct ReportManager {
    config: AppConfig,
    template_engine: Arc<tokio::sync::Mutex<TemplateEngine>>,
}

impl ReportManager {
    /// Create a new report manager
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: config.clone(),
            template_engine: Arc::new(tokio::sync::Mutex::new(
                TemplateEngine::new(PathBuf::new()) // Will be initialized later
            )),
        }
    }

    /// Initialize the report manager
    pub async fn initialize(&self) -> Result<()> {
        // Get data directory from config
        let config_dir = self.config.config_dir().await;
        let template_dir = config_dir.join("templates");
        
        // Create reports directory if it doesn't exist
        let data_dir = self.config.data_dir().await;
        let reports_dir = data_dir.join("reports");
        
        if !reports_dir.exists() {
            fs::create_dir_all(&reports_dir).await
                .context(format!("Failed to create reports directory: {}", reports_dir.display()))?;
        }
        
        // Initialize template engine
        let mut template_engine = self.template_engine.lock().await;
        *template_engine = TemplateEngine::new(template_dir);
        template_engine.initialize().await?;
        
        info!("Report manager initialized successfully");
        Ok(())
    }
    
    /// Generate a report for a target
    pub async fn generate_report(
        &self,
        target: &TargetData,
        formats: &[String],
        output_dir: Option<&Path>,
        title: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        let report_title_str = format!("Security Scan Report for {}", target.name);
        let report_title = title.unwrap_or(&report_title_str);
        let report_id = Uuid::new_v4().to_string();
        
        // Create report structure
        let mut report = Report {
            id: report_id,
            title: report_title.to_string(),
            created_at: Utc::now(),
            target: target.name.clone(),
            summary: ReportSummary {
                total_hosts_scanned: 1 + target.subdomains.len(),
                total_findings: 0,
                severity_counts: HashMap::new(),
                start_time: Utc::now(),
                end_time: Utc::now(),
                duration_seconds: 0,
            },
            findings: Vec::new(),
            metadata: HashMap::new(),
        };
        
        // Add metadata
        report.metadata.insert("Generator".to_string(), format!("BBHunt v{}", env!("CARGO_PKG_VERSION")));
        if let Some(domain) = &target.primary_domain {
            report.metadata.insert("Primary Domain".to_string(), domain.clone());
        }
        
        // Get report output directory
        let output_dir = if let Some(dir) = output_dir {
            dir.to_path_buf()
        } else {
            self.config.data_dir().await.join("reports")
        };
        
        // Ensure output directory exists
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir).await
                .context(format!("Failed to create output directory: {}", output_dir.display()))?;
        }
        
        // Parse formats
        let formats: Vec<ReportFormat> = formats.iter()
            .map(|fmt| match fmt.to_lowercase().as_str() {
                "json" => ReportFormat::JSON,
                "md" | "markdown" => ReportFormat::Markdown,
                "html" => ReportFormat::HTML,
                "pdf" => ReportFormat::PDF,
                "csv" => ReportFormat::CSV,
                "xml" => ReportFormat::XML,
                _ => ReportFormat::JSON,
            })
            .collect();
        
        if formats.is_empty() {
            return Err(anyhow::anyhow!("No valid report formats specified"));
        }
        
        // Generate report in each format
        let mut output_paths = Vec::new();
        
        for format in formats {
            let output_path = output_dir.join(format!("{}-{}.{}", 
                target.name,
                report.created_at.format("%Y%m%d-%H%M%S"),
                format_to_extension(&format)));
            
            match self.generate_report_in_format(&report, &format, &output_path).await {
                Ok(_) => {
                    info!("Generated {} report: {}", format_to_extension(&format), output_path.display());
                    output_paths.push(output_path);
                },
                Err(e) => {
                    error!("Failed to generate {} report: {}", format_to_extension(&format), e);
                }
            }
        }
        
        if output_paths.is_empty() {
            return Err(anyhow::anyhow!("Failed to generate any reports"));
        }
        
        Ok(output_paths)
    }
    
    /// Generate a report in a specific format
    async fn generate_report_in_format(
        &self,
        report: &Report,
        format: &ReportFormat,
        output_path: &Path,
    ) -> Result<()> {
        match format {
            ReportFormat::JSON => self.generate_json_report(report, output_path).await,
            ReportFormat::Markdown => self.generate_markdown_report(report, output_path).await,
            ReportFormat::HTML => self.generate_html_report(report, output_path).await,
            ReportFormat::PDF => Err(anyhow::anyhow!("PDF format not yet implemented")),
            ReportFormat::CSV => Err(anyhow::anyhow!("CSV format not yet implemented")),
            ReportFormat::XML => Err(anyhow::anyhow!("XML format not yet implemented")),
        }
    }
    
    /// Generate a JSON report
    async fn generate_json_report(&self, report: &Report, output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(report)
            .context("Failed to serialize report to JSON")?;
            
        fs::write(output_path, json).await
            .context(format!("Failed to write JSON report to {}", output_path.display()))?;
            
        Ok(())
    }
    
    /// Generate a Markdown report
    async fn generate_markdown_report(&self, report: &Report, output_path: &Path) -> Result<()> {
        let template_engine = self.template_engine.lock().await;
        
        // Create a map of variables for the template
        let mut variables = HashMap::new();
        
        // Add basic information
        variables.insert("title".to_string(), report.title.clone());
        variables.insert("generated_date".to_string(), report.created_at.format("%Y-%m-%d %H:%M:%S").to_string());
        variables.insert("target".to_string(), report.target.clone());
        variables.insert("total_hosts".to_string(), report.summary.total_hosts_scanned.to_string());
        variables.insert("total_findings".to_string(), report.summary.total_findings.to_string());
        variables.insert("duration_seconds".to_string(), report.summary.duration_seconds.to_string());
        
        // Add severity counts
        let critical_count = report.summary.severity_counts.get(&Severity::Critical).unwrap_or(&0);
        let high_count = report.summary.severity_counts.get(&Severity::High).unwrap_or(&0);
        let medium_count = report.summary.severity_counts.get(&Severity::Medium).unwrap_or(&0);
        let low_count = report.summary.severity_counts.get(&Severity::Low).unwrap_or(&0);
        let info_count = report.summary.severity_counts.get(&Severity::Info).unwrap_or(&0);
        
        variables.insert("critical_count".to_string(), critical_count.to_string());
        variables.insert("high_count".to_string(), high_count.to_string());
        variables.insert("medium_count".to_string(), medium_count.to_string());
        variables.insert("low_count".to_string(), low_count.to_string());
        variables.insert("info_count".to_string(), info_count.to_string());
        
        // Process findings
        let mut findings_vars = Vec::new();
        
        // Sort findings by severity
        let mut findings = report.findings.clone();
        findings.sort_by(|a, b| severity_to_order(&a.severity).cmp(&severity_to_order(&b.severity)));
        
        for finding in findings {
            let mut finding_vars = HashMap::new();
            
            // Set finding variables
            finding_vars.insert("title".to_string(), finding.title);
            finding_vars.insert("severity".to_string(), severity_to_string(&finding.severity).to_string());
            
            if let Some(cvss) = finding.cvss_score {
                finding_vars.insert("cvss_score".to_string(), format!("{:.1}", cvss));
            }
            
            finding_vars.insert("description".to_string(), finding.description);
            
            // Format affected targets
            let affected_targets = finding.affected_targets.iter()
                .map(|t| format!("- {}", t))
                .collect::<Vec<String>>()
                .join("\n");
            finding_vars.insert("affected_targets".to_string(), affected_targets);
            
            finding_vars.insert("evidence".to_string(), finding.evidence);
            
            if let Some(remediation) = finding.remediation {
                finding_vars.insert("remediation".to_string(), remediation);
                finding_vars.insert("has_remediation".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_remediation".to_string(), "false".to_string());
            }
            
            // Format references
            if !finding.references.is_empty() {
                let references = finding.references.iter()
                    .map(|r| format!("- [{}]({})", r.title, r.url))
                    .collect::<Vec<String>>()
                    .join("\n");
                finding_vars.insert("references".to_string(), references);
                finding_vars.insert("has_references".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_references".to_string(), "false".to_string());
            }
            
            // Format tags
            if !finding.tags.is_empty() {
                finding_vars.insert("tags".to_string(), finding.tags.join(", "));
                finding_vars.insert("has_tags".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_tags".to_string(), "false".to_string());
            }
            
            findings_vars.push(finding_vars);
        }
        
        // Render findings if any
        let findings_md = if !findings_vars.is_empty() {
            template_engine.render_section("finding_md", &findings_vars)?
        } else {
            "No findings were identified.".to_string()
        };
        
        variables.insert("findings".to_string(), findings_md);
        
        // Format metadata
        let metadata_md = report.metadata.iter()
            .map(|(k, v)| format!("- **{}:** {}", k, v))
            .collect::<Vec<String>>()
            .join("\n");
        variables.insert("metadata".to_string(), metadata_md);
        
        // Render the template
        let markdown = template_engine.render("report_md", &variables)?;
        
        // Write to file
        fs::write(output_path, markdown).await
            .context(format!("Failed to write Markdown report to {}", output_path.display()))?;
            
        Ok(())
    }
    
    /// Generate an HTML report
    async fn generate_html_report(&self, report: &Report, output_path: &Path) -> Result<()> {
        let template_engine = self.template_engine.lock().await;
        
        // Create a map of variables for the template
        let mut variables = HashMap::new();
        
        // Add basic information
        variables.insert("title".to_string(), report.title.clone());
        variables.insert("generated_date".to_string(), report.created_at.format("%Y-%m-%d %H:%M:%S").to_string());
        variables.insert("target".to_string(), report.target.clone());
        variables.insert("total_hosts".to_string(), report.summary.total_hosts_scanned.to_string());
        variables.insert("total_findings".to_string(), report.summary.total_findings.to_string());
        variables.insert("duration_seconds".to_string(), report.summary.duration_seconds.to_string());
        
        // Add severity counts
        let critical_count = report.summary.severity_counts.get(&Severity::Critical).unwrap_or(&0);
        let high_count = report.summary.severity_counts.get(&Severity::High).unwrap_or(&0);
        let medium_count = report.summary.severity_counts.get(&Severity::Medium).unwrap_or(&0);
        let low_count = report.summary.severity_counts.get(&Severity::Low).unwrap_or(&0);
        let info_count = report.summary.severity_counts.get(&Severity::Info).unwrap_or(&0);
        
        variables.insert("critical_count".to_string(), critical_count.to_string());
        variables.insert("high_count".to_string(), high_count.to_string());
        variables.insert("medium_count".to_string(), medium_count.to_string());
        variables.insert("low_count".to_string(), low_count.to_string());
        variables.insert("info_count".to_string(), info_count.to_string());
        
        // Process findings
        let mut findings_vars = Vec::new();
        
        // Sort findings by severity
        let mut findings = report.findings.clone();
        findings.sort_by(|a, b| severity_to_order(&a.severity).cmp(&severity_to_order(&b.severity)));
        
        for finding in findings {
            let mut finding_vars = HashMap::new();
            
            // Set finding variables
            finding_vars.insert("title".to_string(), finding.title);
            finding_vars.insert("severity".to_string(), severity_to_string(&finding.severity).to_string());
            
            // Set severity class
            let severity_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            finding_vars.insert("severity_class".to_string(), severity_class.to_string());
            
            if let Some(cvss) = finding.cvss_score {
                finding_vars.insert("cvss_score".to_string(), format!("{:.1}", cvss));
                finding_vars.insert("has_cvss".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_cvss".to_string(), "false".to_string());
            }
            
            finding_vars.insert("description".to_string(), finding.description);
            
            // Format affected targets
            let affected_targets = finding.affected_targets.iter()
                .map(|t| format!("<li>{}</li>", t))
                .collect::<Vec<String>>()
                .join("\n");
            finding_vars.insert("affected_targets".to_string(), affected_targets);
            
            finding_vars.insert("evidence".to_string(), html_encode(&finding.evidence));
            
            if let Some(remediation) = finding.remediation {
                finding_vars.insert("remediation".to_string(), remediation);
                finding_vars.insert("has_remediation".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_remediation".to_string(), "false".to_string());
            }
            
            // Format references
            if !finding.references.is_empty() {
                let references = finding.references.iter()
                    .map(|r| format!("<li><a href=\"{}\" target=\"_blank\">{}</a></li>", r.url, r.title))
                    .collect::<Vec<String>>()
                    .join("\n");
                finding_vars.insert("references".to_string(), references);
                finding_vars.insert("has_references".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_references".to_string(), "false".to_string());
            }
            
            // Format tags
            if !finding.tags.is_empty() {
                finding_vars.insert("tags".to_string(), finding.tags.join(", "));
                finding_vars.insert("has_tags".to_string(), "true".to_string());
            } else {
                finding_vars.insert("has_tags".to_string(), "false".to_string());
            }
            
            findings_vars.push(finding_vars);
        }
        
        // Render findings if any
        let findings_html = if !findings_vars.is_empty() {
            template_engine.render_section("finding", &findings_vars)?
        } else {
            "<p>No findings were identified.</p>".to_string()
        };
        
        variables.insert("findings".to_string(), findings_html);
        
        // Format metadata
        let metadata_html = report.metadata.iter()
            .map(|(k, v)| format!("<dt>{}</dt>\n<dd>{}</dd>", k, v))
            .collect::<Vec<String>>()
            .join("\n");
        variables.insert("metadata".to_string(), metadata_html);
        
        // Render the template
        let html = template_engine.render("report", &variables)?;
        
        // Write to file
        fs::write(output_path, html).await
            .context(format!("Failed to write HTML report to {}", output_path.display()))?;
            
        Ok(())
    }
}

/// Report structure
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

/// Finding information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cve_ids: Vec<String>,
    pub affected_targets: Vec<String>,
    pub evidence: String,
    pub remediation: Option<String>,
    pub references: Vec<Reference>,
    pub tags: Vec<String>,
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

/// Finding reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: String,
    pub url: String,
    pub source_type: ReferenceType,
}

/// Reference type
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

/// Vulnerability structure for plugin results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub url: String,
    pub cvss_score: Option<f32>,
    pub cve_ids: Vec<String>,
    pub evidence: String,
    pub remediation: Option<String>,
    pub references: Vec<Reference>,
    pub tags: Vec<String>,
}

/// Report format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormat {
    JSON,
    Markdown,
    HTML,
    PDF,
    CSV,
    XML,
}

/// Convert severity to string
fn severity_to_string(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Informational",
    }
}

/// Convert severity to order (for sorting)
fn severity_to_order(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// Convert report format to file extension
fn format_to_extension(format: &ReportFormat) -> &'static str {
    match format {
        ReportFormat::JSON => "json",
        ReportFormat::Markdown => "md",
        ReportFormat::HTML => "html",
        ReportFormat::PDF => "pdf",
        ReportFormat::CSV => "csv",
        ReportFormat::XML => "xml",
    }
}

/// Encode HTML special characters
fn html_encode(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}