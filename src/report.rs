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
        let report_title = title.unwrap_or(&format!("Security Scan Report for {}", target.name));
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
            ReportFormat::PDF => Err(anyhow::anyhow!("PDF format not yet