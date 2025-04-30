use std::path::Path;
use async_trait::async_trait;
use anyhow::Result;

use crate::reporting::model::Report;
use crate::reporting::formats::{ReportFormat, ReportGenerator};

/// JSON report generator
pub struct JsonReportGenerator;

impl JsonReportGenerator {
    /// Create a new JSON report generator
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
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