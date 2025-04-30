use std::path::Path;
use async_trait::async_trait;
use anyhow::Result;

use crate::reporting::model::{Report, severity};
use crate::reporting::formats::{ReportFormat, ReportGenerator};

/// HTML report generator
pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    /// Create a new HTML report generator
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ReportGenerator for HtmlReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()> {
        let mut html = String::new();
        
        // HTML header
        html.push_str("<!DOCTYPE html>\n");
        html.push_str("<html lang=\"en\">\n");
        html.push_str("<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("  <title>{}</title>\n", report.title));
        html.push_str("  <style>\n");
        html.push_str("    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }\n");
        html.push_str("    h1 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }\n");
        html.push_str("    h2 { color: #444; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 5px; }\n");
        html.push_str("    h3 { color: #555; }\n");
        html.push_str("    .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }\n");
        html.push_str("    .finding { background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 20px 0; }\n");
        html.push_str("    .critical { border-left: 5px solid #d9534f; }\n");
        html.push_str("    .high { border-left: 5px solid #f0ad4e; }\n");
        html.push_str("    .medium { border-left: 5px solid #5bc0de; }\n");
        html.push_str("    .low { border-left: 5px solid #5cb85c; }\n");
        html.push_str("    .info { border-left: 5px solid #777; }\n");
        html.push_str("    .severity-badge { display: inline-block; padding: 5px 10px; color: white; border-radius: 3px; font-weight: bold; }\n");
        html.push_str("    .severity-critical { background-color: #d9534f; }\n");
        html.push_str("    .severity-high { background-color: #f0ad4e; }\n");
        html.push_str("    .severity-medium { background-color: #5bc0de; }\n");
        html.push_str("    .severity-low { background-color: #5cb85c; }\n");
        html.push_str("    .severity-info { background-color: #777; }\n");
        html.push_str("    .http-request { background: #f8f8f8; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }\n");
        html.push_str("    .metadata { color: #777; font-style: italic; }\n");
        html.push_str("  </style>\n");
        html.push_str("</head>\n");
        html.push_str("<body>\n");
        
        // Report header
        html.push_str(&format!("  <h1>{}</h1>\n", report.title));
        html.push_str("  <div class=\"metadata\">\n");
        html.push_str(&format!("    <p><strong>Generated:</strong> {}</p>\n", report.created_at.format("%Y-%m-%d %H:%M:%S")));
        html.push_str(&format!("    <p><strong>Target:</strong> {}</p>\n", report.target));
        html.push_str("  </div>\n");
        
        // Summary section
        html.push_str("  <h2>Summary</h2>\n");
        html.push_str("  <div class=\"summary\">\n");
        html.push_str(&format!("    <p><strong>Total Hosts Scanned:</strong> {}</p>\n", report.summary.total_hosts_scanned));
        html.push_str(&format!("    <p><strong>Total Findings:</strong> {}</p>\n", report.summary.total_findings));
        html.push_str("    <p><strong>Severity Breakdown:</strong></p>\n");
        html.push_str("    <ul>\n");
        
        // Sort severities by criticality
        let mut severities: Vec<_> = report.summary.severity_counts.iter().collect();
        severities.sort_by_key(|(s, _)| severity::sort_order(s));
        
        for (severity, count) in severities {
            let severity_class = match severity {
                crate::reporting::model::Severity::Critical => "severity-critical",
                crate::reporting::model::Severity::High => "severity-high",
                crate::reporting::model::Severity::Medium => "severity-medium",
                crate::reporting::model::Severity::Low => "severity-low",
                crate::reporting::model::Severity::Info => "severity-info",
            };
            
            html.push_str(&format!("      <li><span class=\"severity-badge {}\">{}</span>: {}</li>\n", 
                severity_class, severity::to_string(severity), count));
        }
        
        html.push_str("    </ul>\n");
        html.push_str(&format!("    <p><strong>Scan Duration:</strong> {} seconds</p>\n", report.summary.duration_seconds));
        html.push_str("  </div>\n");
        
        // Findings section
        html.push_str("  <h2>Findings</h2>\n");
        
        // Sort findings by severity
        let mut findings = report.findings.clone();
        findings.sort_by_key(|f| severity::sort_order(&f.severity));
        
        for finding in &findings {
            let severity_class = match finding.severity {
                crate::reporting::model::Severity::Critical => "critical",
                crate::reporting::model::Severity::High => "high",
                crate::reporting::model::Severity::Medium => "medium",
                crate::reporting::model::Severity::Low => "low",
                crate::reporting::model::Severity::Info => "info",
            };
            
            let severity_badge_class = match finding.severity {
                crate::reporting::model::Severity::Critical => "severity-critical",
                crate::reporting::model::Severity::High => "severity-high",
                crate::reporting::model::Severity::Medium => "severity-medium",
                crate::reporting::model::Severity::Low => "severity-low",
                crate::reporting::model::Severity::Info => "severity-info",
            };
            
            html.push_str(&format!("  <div class=\"finding {}\">\n", severity_class));
            html.push_str(&format!("    <h3>{}</h3>\n", finding.title));
            html.push_str(&format!("    <p><span class=\"severity-badge {}\">Severity: {}</span></p>\n", 
                severity_badge_class, severity::to_string(&finding.severity)));
            
            if let Some(cvss) = finding.cvss_score {
                html.push_str(&format!("    <p><strong>CVSS Score:</strong> {:.1}</p>\n", cvss));
            }
            
            html.push_str("    <div class=\"description\">\n");
            html.push_str("      <h4>Description:</h4>\n");
            html.push_str(&format!("      <p>{}</p>\n", finding.description));
            html.push_str("    </div>\n");
            
            html.push_str("    <div class=\"affected-targets\">\n");
            html.push_str("      <h4>Affected Targets:</h4>\n");
            html.push_str("      <ul>\n");
            for target in &finding.affected_targets {
                html.push_str(&format!("        <li>{}</li>\n", target));
            }
            html.push_str("      </ul>\n");
            html.push_str("    </div>\n");
            
            html.push_str("    <div class=\"evidence\">\n");
            html.push_str("      <h4>Evidence:</h4>\n");
            html.push_str(&format!("      <p>{}</p>\n", finding.evidence.description));
            
            if let Some(req_resp) = &finding.evidence.request_response {
                html.push_str("      <h5>Request:</h5>\n");
                html.push_str("      <pre class=\"http-request\">");
                html.push_str(&html_encode(&req_resp.request));
                html.push_str("</pre>\n");
                
                html.push_str("      <h5>Response:</h5>\n");
                html.push_str("      <pre class=\"http-request\">");
                html.push_str(&html_encode(&req_resp.response));
                html.push_str("</pre>\n");
            }
            html.push_str("    </div>\n");
            
            if let Some(remediation) = &finding.remediation {
                html.push_str("    <div class=\"remediation\">\n");
                html.push_str("      <h4>Remediation:</h4>\n");
                html.push_str(&format!("      <p>{}</p>\n", remediation));
                html.push_str("    </div>\n");
            }
            
            if !finding.references.is_empty() {
                html.push_str("    <div class=\"references\">\n");
                html.push_str("      <h4>References:</h4>\n");
                html.push_str("      <ul>\n");
                for reference in &finding.references {
                    html.push_str(&format!("        <li><a href=\"{}\" target=\"_blank\">{}</a></li>\n", 
                        reference.url, reference.title));
                }
                html.push_str("      </ul>\n");
                html.push_str("    </div>\n");
            }
            
            html.push_str("    <div class=\"metadata\">\n");
            html.push_str(&format!("      <p>Discovered by: {} on {}</p>\n", 
                finding.discovered_by, finding.discovered_at.format("%Y-%m-%d %H:%M:%S")));
            html.push_str("    </div>\n");
            
            html.push_str("  </div>\n");
        }
        
        // Metadata section
        if !report.metadata.is_empty() {
            html.push_str("  <h2>Metadata</h2>\n");
            html.push_str("  <dl>\n");
            for (key, value) in &report.metadata {
                html.push_str(&format!("    <dt>{}</dt>\n", key));
                html.push_str(&format!("    <dd>{}</dd>\n", value));
            }
            html.push_str("  </dl>\n");
        }
        
        // HTML footer
        html.push_str("</body>\n");
        html.push_str("</html>\n");
        
        tokio::fs::write(output_path, html).await?;
        Ok(())
    }
    
    fn supported_format(&self) -> ReportFormat {
        ReportFormat::HTML
    }
}

// Helper function to encode HTML special characters
fn html_encode(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}