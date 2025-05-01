// src/reporting/generator.rs
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, debug, warn};

use crate::context::Context;
use crate::error::{BBHuntResult, BBHuntError};
use super::model::Report;
use super::formats::{ReportFormat, ReportGenerator, format_to_extension};
use super::formats::json::JsonReportGenerator;
use super::formats::markdown::MarkdownReportGenerator;
use super::formats::html::HtmlReportGenerator;
use super::template::TemplateEngine;

/// Report generation manager
pub struct ReportManager {
    generators: HashMap<ReportFormat, Box<dyn ReportGenerator + Send + Sync>>,
    report_dir: PathBuf,
    context: Option<Arc<Context>>,
    template_engine: TemplateEngine,
}

impl ReportManager {
    /// Create a new report manager
    pub fn new(report_dir: PathBuf) -> Self {
        let mut generators = HashMap::new();
        let template_engine = TemplateEngine::new();
        
        // Register default generators
        generators.insert(
            ReportFormat::JSON, 
            Box::new(JsonReportGenerator::new()) as Box<dyn ReportGenerator + Send + Sync>
        );
        generators.insert(
            ReportFormat::Markdown, 
            Box::new(MarkdownReportGenerator::new_with_template(template_engine.clone())) as Box<dyn ReportGenerator + Send + Sync>
        );
        generators.insert(
            ReportFormat::HTML, 
            Box::new(HtmlReportGenerator::new_with_template(template_engine.clone())) as Box<dyn ReportGenerator + Send + Sync>
        );
        
        Self {
            generators,
            report_dir,
            context: None,
            template_engine,
        }
    }
    
    /// Create a new report manager with context
    pub fn new_with_context(report_dir: PathBuf, context: Arc<Context>) -> Self {
        let mut manager = Self::new(report_dir);
        manager.context = Some(context);
        manager
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    /// Initialize template engine with default templates
    pub async fn init_templates(&mut self) -> BBHuntResult<()> {
        // Register default templates
        self.template_engine.register_template("html_report", 
            super::template::get_default_html_template())?;
        self.template_engine.register_template("markdown_report", 
            super::template::get_default_markdown_template())?;
        self.template_engine.register_template("html_finding", 
            super::template::get_default_finding_html_template())?;
        self.template_engine.register_template("markdown_finding", 
            super::template::get_default_finding_markdown_template())?;
        
        // Attempt to load custom templates from config directory if context is available
        if let Some(context) = &self.context {
            let config_dir = {
                let config = context.config.lock().await;
                config.global.config_dir.clone()
            };
            
            let template_dir = config_dir.join("templates");
            if template_dir.exists() {
                debug!("Looking for custom templates in {}", template_dir.display());
                
                // Try to load HTML report template
                let html_template_path = template_dir.join("report_template.html");
                if html_template_path.exists() {
                    match self.template_engine.load_template("html_report", &html_template_path).await {
                        Ok(_) => info!("Loaded custom HTML report template"),
                        Err(e) => warn!("Failed to load custom HTML template: {}", e),
                    }
                }
                
                // Try to load Markdown report template
                let md_template_path = template_dir.join("report_template.md");
                if md_template_path.exists() {
                    match self.template_engine.load_template("markdown_report", &md_template_path).await {
                        Ok(_) => info!("Loaded custom Markdown report template"),
                        Err(e) => warn!("Failed to load custom Markdown template: {}", e),
                    }
                }
                
                // Try to load HTML finding template
                let html_finding_path = template_dir.join("finding_template.html");
                if html_finding_path.exists() {
                    match self.template_engine.load_template("html_finding", &html_finding_path).await {
                        Ok(_) => info!("Loaded custom HTML finding template"),
                        Err(e) => warn!("Failed to load custom HTML finding template: {}", e),
                    }
                }
                
                // Try to load Markdown finding template
                let md_finding_path = template_dir.join("finding_template.md");
                if md_finding_path.exists() {
                    match self.template_engine.load_template("markdown_finding", &md_finding_path).await {
                        Ok(_) => info!("Loaded custom Markdown finding template"),
                        Err(e) => warn!("Failed to load custom Markdown finding template: {}", e),
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Register a new report generator
    pub fn register_generator(&mut self, generator: Box<dyn ReportGenerator + Send + Sync>) {
        let format = generator.supported_format();
        debug!("Registering report generator for format: {:?}", format);
        self.generators.insert(format, generator);
    }
    
    /// Get the template engine
    pub fn template_engine(&self) -> &TemplateEngine {
        &self.template_engine
    }
    
    /// Generate a report in a specific format
    pub async fn generate_report(&self, report: &Report, format: ReportFormat) -> BBHuntResult<PathBuf> {
        // Ensure report directory exists
        if !self.report_dir.exists() {
            debug!("Creating report directory: {}", self.report_dir.display());
            tokio::fs::create_dir_all(&self.report_dir).await
                .map_err(|e| BBHuntError::FileError {
                    path: self.report_dir.clone(),
                    message: format!("Failed to create directory: {}", e),
                })?;
        }
        
        // Get the generator
        let generator = self.generators.get(&format)
            .ok_or_else(|| BBHuntError::InvalidInput(format!("No generator found for format {:?}", format)))?;
        
        // Generate output filename
        let filename = format!("{}-{}.{}", 
            report.id,
            report.created_at.format("%Y%m%d-%H%M%S"),
            format_to_extension(&format));
        
        let output_path = self.report_dir.join(filename);
        
        info!("Generating report in format {:?} at {}", format, output_path.display());
        
        // Generate the report
        generator.generate(report, &output_path).await
            .map_err(|e| BBHuntError::UnexpectedError(format!("Failed to generate report: {}", e)))?;
        
        Ok(output_path)
    }
    
    /// Generate a report in multiple formats
    pub async fn generate_multi_format(&self, report: &Report, formats: &[ReportFormat]) -> BBHuntResult<Vec<PathBuf>> {
        let mut paths = Vec::new();
        
        for format in formats {
            match self.generate_report(report, format.clone()).await {
                Ok(path) => {
                    paths.push(path);
                }
                Err(e) => {
                    warn!("Failed to generate report in format {:?}: {}", format, e);
                }
            }
        }
        
        if paths.is_empty() {
            return Err(BBHuntError::UnexpectedError("Failed to generate any reports".to_string()));
        }
        
        Ok(paths)
    }
    
    /// Get the report directory
    pub fn report_dir(&self) -> &PathBuf {
        &self.report_dir
    }
}