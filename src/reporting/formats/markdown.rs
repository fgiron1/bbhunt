use std::path::Path;
use async_trait::async_trait;
use anyhow::Result;

use crate::reporting::model::{Report, severity};
use crate::reporting::formats::{ReportFormat, ReportGenerator};

/// Markdown report generator
pub struct MarkdownReportGenerator;

impl MarkdownReportGenerator {
    /// Create a new Markdown report generator
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ReportGenerator for MarkdownReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()> {
        let mut content = String::new();
        
        // Title and metadata
        content.push_str(&format!("# {}\n\n", report.title));
        content.push_str(&format!("**Generated:** {}\n", report.created_at.format("%Y-%m-%d %H:%M:%S")));
        content.push_str(&format!("**Target:** {}\n\n", report.target));
        
        // Summary
        content.push_str("## Summary\n\n");
        content.push_str(&format!("- **Total Hosts Scanned:** {}\n", report.summary.total_hosts_scanned));
        content.push_str(&format!("- **Total Findings:** {}\n", report.summary.total_findings));
        content.push_str("- **Severity Breakdown:**\n");
        
        // Sort severities by criticality
        let mut severities: Vec<_> = report.summary.severity_counts.iter().collect();
        severities.sort_by_key(|(s, _)| severity::sort_order(s));
        
        for (severity, count) in severities {
            content.push_str(&format!("  - {}: {}\n", severity::to_string(severity), count));
        }
        
        content.push_str(&format!("\n**Scan Duration:** {} seconds\n\n", report.summary.duration_seconds));
        
        // Findings
        content.push_str("## Findings\n\n");
        
        // Sort findings by severity
        let mut findings = report.findings.clone();
        findings.sort_by_key(|f| severity::sort_order(&f.severity));
        
        for finding in &findings {
            content.push_str(&format!("### {}\n\n", finding.title));
            content.push_str(&format!("**Severity:** {}\n", severity::to_string(&finding.severity)));
            
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
                finding.discovered_by, finding.discovered_at.format("%Y-%m-%d %H:%M:%S")));
            
            content.push_str("---\n\n");
        }
        
        // Metadata
        if !report.metadata.is_empty() {
            content.push_str("## Metadata\n\n");
            for (key, value) in &report.metadata {
                content.push_str(&format!("- **{}:** {}\n", key, value));
            }
            content.push_str("\n");
        }
        
        tokio::fs::write(output_path, content).await?;
        Ok(())
    }
    
    fn supported_format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }
}