use std::path::Path;
use async_trait::async_trait;
use anyhow::Result;
use serde::{Serialize, Deserialize};

use super::model::Report;

/// Report format enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportFormat {
    JSON,
    HTML,
    Markdown,
    PDF,
    CSV,
    XML,
}

/// Report generator trait
#[async_trait]
pub trait ReportGenerator: Send + Sync {
    /// Generate a report in a specific format
    async fn generate(&self, report: &Report, output_path: &Path) -> Result<()>;
    
    /// Get the supported format
    fn supported_format(&self) -> ReportFormat;
}

/// Convert report format to file extension
pub fn format_to_extension(format: &ReportFormat) -> &'static str {
    match format {
        ReportFormat::JSON => "json",
        ReportFormat::HTML => "html",
        ReportFormat::Markdown => "md",
        ReportFormat::PDF => "pdf",
        ReportFormat::CSV => "csv",
        ReportFormat::XML => "xml",
    }
}

/// Convert file extension to report format
pub fn extension_to_format(extension: &str) -> Option<ReportFormat> {
    match extension.to_lowercase().as_str() {
        "json" => Some(ReportFormat::JSON),
        "html" | "htm" => Some(ReportFormat::HTML),
        "md" | "markdown" => Some(ReportFormat::Markdown),
        "pdf" => Some(ReportFormat::PDF),
        "csv" => Some(ReportFormat::CSV),
        "xml" => Some(ReportFormat::XML),
        _ => None,
    }
}