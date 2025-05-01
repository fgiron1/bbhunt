// src/reporting/formats/html.rs
use std::path::Path;
use std::sync::Arc;
use async_trait::async_trait;

use crate::context::Context;
use crate::error::{BBHuntResult, BBHuntError};
use crate::reporting::model::{Report, severity};
use crate::reporting::formats::{ReportFormat, ReportGenerator};
use crate::reporting::template::TemplateEngine;

/// HTML report generator
pub struct HtmlReportGenerator {
    context: Option<Arc<Context>>,
    template_engine: Option<TemplateEngine>,
}

impl HtmlReportGenerator {
    /// Create a new HTML report generator
    pub fn new() -> Self {
        Self {
            context: None,
            template_engine: None,
        }
    }
    
    /// Create a new HTML report generator with context
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            context: Some(context),
            template_engine: None,
        }
    }
    
    /// Create a new HTML report generator with template engine
    pub fn new_with_template(template_engine: TemplateEngine) -> Self {
        Self {
            context: None,
            template_engine: Some(template_engine),
        }
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    /// Set the template engine
    pub fn set_template_engine(&mut self, template_engine: TemplateEngine) {
        self.template_engine = Some(template_engine);
    }
}

#[async_trait]
impl ReportGenerator for HtmlReportGenerator {
    async fn generate(&self, report: &Report, output_path: &Path) -> BBHuntResult<()> {
        // Use template engine if available
        if let Some(template_engine) = &self.template_engine {
            let mut variables = HashMap::new();
            
            // Add report variables
            variables.insert("title".to_string(), report.title.clone());
            variables.insert("generated_date".to_string(), report.created_at.format("%Y-%m-%d %H:%M:%S").to_string());
            variables.insert("target".to_string(), report.target.clone());
            variables.insert("total_hosts".to_string(), report.summary.total_hosts_scanned.to_string());
            variables.insert("total_findings".to_string(), report.summary.total_findings.to_string());
            variables.insert("duration_seconds".to_string(), report.summary.duration_seconds.to_string());
            
            // Add severity counts
            variables.insert("critical_count".to_string(), 
                report.summary.severity_counts.get(&crate::reporting::model::Severity::Critical).unwrap_or(&0).to_string());
            variables.insert("high_count".to_string(), 
                report.summary.severity_counts.get(&crate::reporting::model::Severity::High).unwrap_or(&0).to_string());
            variables.insert("medium_count".to_string(), 
                report.summary.severity_counts.get(&crate::reporting::model::Severity::Medium).unwrap_or(&0).to_string());
            variables.insert("low_count".to_string(), 
                report.summary.severity_counts.get(&crate::reporting::model::Severity::Low).unwrap_or(&0).to_string());
            variables.insert("info_count".to_string(), 
                report.summary.severity_counts.get(&crate::reporting::model::Severity::Info).unwrap_or(&0).to_string());
            
            // Generate findings section
            let mut findings_html = String::new();
            
            // Sort findings by severity
            let mut findings = report.findings.clone();
            findings.sort_by_key(|f| severity::sort_order(&f.severity));
            
            for finding in &findings {
                let mut finding_vars = HashMap::new();
                
                // Set finding variables
                finding_vars.insert("title".to_string(), finding.title.clone());
                finding_vars.insert("severity".to_string(), severity::to_string(&finding.severity).to_string());
                finding_vars.insert("severity_class".to_string(), match finding.severity {
                    crate::reporting::model::Severity::Critical => "critical",
                    crate::reporting::model::Severity::High => "high",
                    crate::reporting::model::Severity::Medium => "medium",
                    crate::reporting::model::Severity::Low => "low",
                    crate::reporting::model::Severity::Info => "info",
                }.to_string());
                
                if let Some(cvss) = finding.cvss_score {
                    finding_vars.insert("cvss_score".to_string(), format!("{:.1}", cvss));
                }
                
                finding_vars.insert("description".to_string(), finding.description.clone());
                
                let affected_targets_html = finding.affected_targets.iter()
                    .map(|t| format!("<li>{}</li>", t))
                    .collect::<Vec<String>>()
                    .join("\n");
                finding_vars.insert("affected_targets".to_string(), affected_targets_html);
                
                finding_vars.insert("evidence_description".to_string(), finding.evidence.description.clone());
                
                if let Some(req_resp) = &finding.evidence.request_response {
                    finding_vars.insert("has_request_response".to_string(), "true".to_string());
                    finding_vars.insert("request".to_string(), html_encode(&req_resp.request));
                    finding_vars.insert("response".to_string(), html_encode(&req_resp.response));
                } else {
                    finding_vars.insert("has_request_response".to_string(), "false".to_string());
                }
                
                if let Some(remediation) = &finding.remediation {
                    finding_vars.insert("remediation".to_string(), remediation.clone());
                }
                
                if !finding.references.is_empty() {
                    finding_vars.insert("has_references".to_string(), "true".to_string());
                    let references_html = finding.references.iter()
                        .map(|r| format!("<li><a href=\"{}\" target=\"_blank\">{}</a></li>", r.url, r.title))
                        .collect::<Vec<String>>()
                        .join("\n");
                    finding_vars.insert("references".to_string(), references_html);
                } else {
                    finding_vars.insert("has_references".to_string(), "false".to_string());
                }
                
                finding_vars.insert("discovered_by".to_string(), finding.discovered_by.clone());
                finding_vars.insert("discovered_at".to_string(), 
                    finding.discovered_at.format("%Y-%m-%d %H:%M:%S").to_string());
                
                // Render finding template
                match template_engine.render("html_finding", &finding_vars) {
                    Ok(finding_html) => findings_html.push_str(&finding_html),
                    Err(e) => return Err(BBHuntError::SerializationError(
                        format!("Failed to render finding template: {}", e))),
                }
            }
            
            // Add findings HTML to variables
            variables.insert("findings".to_string(), findings_html);
            
            // Add metadata
            let metadata_html = report.metadata.iter()
                .map(|(k, v)| format!("<dt>{}</dt>\n<dd>{}</dd>", k, v))
                .collect::<Vec<String>>()
                .join("\n");
            variables.insert("metadata".to_string(), metadata_html);
            
            // Render main report template
            let html = template_engine.render("html_report", &variables)
                .map_err(|e| BBHuntError::SerializationError(
                    format!("Failed to render HTML report template: {}", e)))?;
            
            // Write to file
            tokio::fs::write(output_path, html).await
                .map_err(|e| BBHuntError::FileError {
                    path: output_path.to_path_buf(),
                    message: format!("Failed to write HTML report: {}", e),
                })?;
            
            return Ok(());
        }
        
        // Fallback to hardcoded HTML generation if no template engine is available
        warn!("No template engine available, using hardcoded HTML generation");
        
        // ... [fallback HTML generation code, which would be the original implementation] ...
        
        Err(BBHuntError::UnexpectedError("HTML generation without template engine is not implemented".to_string()))
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