use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;
use tracing::{info, debug, warn};

use super::model::Report;
use super::formats::{ReportFormat, ReportGenerator, format_to_extension};
use super::formats::json::JsonReportGenerator;
use super::formats::markdown::MarkdownReportGenerator;
use super::formats::html::HtmlReportGenerator;

/// Report generation manager
pub struct ReportManager {
    generators: HashMap<ReportFormat, Box<dyn ReportGenerator + Send + Sync>>,
    report_dir: PathBuf,
}

impl ReportManager {
    /// Create a new report manager
    pub fn new(report_dir: PathBuf) -> Self {
        let mut generators = HashMap::new();
        
        // Register default generators
        generators.insert(
            ReportFormat::JSON, 
            Box::new(JsonReportGenerator::new()) as Box<dyn ReportGenerator + Send + Sync>
        );
        generators.insert(
            ReportFormat::Markdown, 
            Box::new(MarkdownReportGenerator::new()) as Box<dyn ReportGenerator + Send + Sync>
        );
        generators.insert(
            ReportFormat::HTML, 
            Box::new(HtmlReportGenerator::new()) as Box<dyn ReportGenerator + Send + Sync>
        );
        
        Self {
            generators,
            report_dir,
        }
    }

    /// Register a new report generator
    pub fn register_generator(&mut self, generator: Box<dyn ReportGenerator + Send + Sync>) {
        let format = generator.supported_format();
        debug!("Registering report generator for format: {:?}", format);
        self.generators.insert(format, generator);
    }
    
    /// Generate a report in a specific format
    pub async fn generate_report(&self, report: &Report, format: ReportFormat) -> Result<PathBuf> {
        // Ensure report directory exists
        if !self.report_dir.exists() {
            debug!("Creating report directory: {}", self.report_dir.display());
            tokio::fs::create_dir_all(&self.report_dir).await?;
        }
        
        // Get the generator
        let generator = self.generators.get(&format)
            .ok_or_else(|| anyhow::anyhow!("No generator found for format {:?}", format))?;
        
        // Generate output filename
        let filename = format!("{}-{}.{}", 
            report.id,
            report.created_at.format("%Y%m%d-%H%M%S"),
            format_to_extension(&format));
        
        let output_path = self.report_dir.join(filename);
        
        info!("Generating report in format {:?} at {}", format, output_path.display());
        
        // Generate the report
        generator.generate(report, &output_path).await?;
        
        Ok(output_path)
    }
    
    /// Generate a report in multiple formats
    pub async fn generate_multi_format(&self, report: &Report, formats: &[ReportFormat]) -> Result<Vec<PathBuf>> {
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
            return Err(anyhow::anyhow!("Failed to generate any reports"));
        }
        
        Ok(paths)
    }
}