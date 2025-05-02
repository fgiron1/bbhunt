// src/template.rs - Refactored to use templates from ./templates directory
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context, bail};
use tokio::fs;
use tracing::{debug, warn};

/// Simple template engine for reports
pub struct TemplateEngine {
    templates: HashMap<String, String>,
    template_dir: PathBuf,
}

impl TemplateEngine {
    /// Create a new template engine
    pub fn new() -> Self {
        // Use templates from ./templates directory (sibling of ./src)
        let template_dir = PathBuf::from("./templates");
        Self {
            templates: HashMap::new(),
            template_dir,
        }
    }
    
    /// Create with explicit template directory
    pub fn with_template_dir(template_dir: PathBuf) -> Self {
        Self {
            templates: HashMap::new(),
            template_dir,
        }
    }
    
    /// Initialize template engine (load default templates)
    pub async fn initialize(&mut self) -> Result<()> {
        // Ensure the template directory exists
        if !self.template_dir.exists() {
            fs::create_dir_all(&self.template_dir).await
                .context(format!("Failed to create template directory: {}", self.template_dir.display()))?;
            
            // If directory was just created, write default templates
            self.write_default_templates().await?;
        } else {
            // Try to load templates from directory, fall back to defaults if needed
            if let Err(e) = self.load_templates().await {
                warn!("Failed to load templates: {}, writing defaults", e);
                self.write_default_templates().await?;
            }
        }
        
        debug!("Template engine initialized with {} templates", self.templates.len());
        Ok(())
    }
    
    /// Load templates from template directory
    async fn load_templates(&mut self) -> Result<()> {
        let mut entries = fs::read_dir(&self.template_dir).await
            .context(format!("Failed to read template directory: {}", self.template_dir.display()))?;
            
        let mut found_templates = false;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() {
                let file_name = path.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
                    
                if file_name.ends_with(".html") || file_name.ends_with(".md") {
                    let template_name = file_name.rsplit_once('.')
                        .map(|(name, _)| name.to_string())
                        .unwrap_or_else(|| file_name.to_string());
                        
                    let content = fs::read_to_string(&path).await
                        .context(format!("Failed to read template file: {}", path.display()))?;
                        
                    self.templates.insert(template_name.clone(), content);
                    found_templates = true;
                    debug!("Loaded template: {}", template_name);
                }
            }
        }
        
        if !found_templates {
            bail!("No template files found in directory");
        }
        
        Ok(())
    }
    
    /// Write default templates to the template directory
    async fn write_default_templates(&mut self) -> Result<()> {
        // Write HTML report template
        let html_report_path = self.template_dir.join("report.html");
        fs::write(&html_report_path, Self::get_default_html_report_template()).await
            .context(format!("Failed to write HTML report template to {}", html_report_path.display()))?;
            
        // Write HTML finding template
        let html_finding_path = self.template_dir.join("finding.html");
        fs::write(&html_finding_path, Self::get_default_html_finding_template()).await
            .context(format!("Failed to write HTML finding template to {}", html_finding_path.display()))?;
            
        // Write Markdown report template
        let md_report_path = self.template_dir.join("report.md");
        fs::write(&md_report_path, Self::get_default_md_report_template()).await
            .context(format!("Failed to write Markdown report template to {}", md_report_path.display()))?;
            
        // Write Markdown finding template
        let md_finding_path = self.template_dir.join("finding.md");
        fs::write(&md_finding_path, Self::get_default_md_finding_template()).await
            .context(format!("Failed to write Markdown finding template to {}", md_finding_path.display()))?;
        
        // Load the templates into memory
        self.templates.insert("report".to_string(), Self::get_default_html_report_template().to_string());
        self.templates.insert("finding".to_string(), Self::get_default_html_finding_template().to_string());
        self.templates.insert("report_md".to_string(), Self::get_default_md_report_template().to_string());
        self.templates.insert("finding_md".to_string(), Self::get_default_md_finding_template().to_string());
        
        debug!("Wrote default templates to {}", self.template_dir.display());
        Ok(())
    }
    
    /// Register a template
    pub fn register_template(&mut self, name: &str, content: &str) {
        self.templates.insert(name.to_string(), content.to_string());
    }
    
    /// Get a template by name
    pub fn get_template(&self, name: &str) -> Option<&str> {
        self.templates.get(name).map(|s| s.as_str())
    }
    
    /// Render a template with variables
    pub fn render(&self, template_name: &str, variables: &HashMap<String, String>) -> Result<String> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| anyhow::anyhow!("Template not found: {}", template_name))?;
            
        let mut result = template.clone();
        
        // Replace variables
        for (key, value) in variables {
            let placeholder = format!("{{{{ {} }}}}", key);
            result = result.replace(&placeholder, value);
        }
        
        Ok(result)
    }
    
    /// Render a section template for each item in a collection
    pub fn render_section(&self, section_template_name: &str, items: &[HashMap<String, String>]) -> Result<String> {
        let section_template = self.templates.get(section_template_name)
            .ok_or_else(|| anyhow::anyhow!("Section template not found: {}", section_template_name))?;
            
        let mut result = String::new();
        
        for item in items {
            let mut section = section_template.clone();
            
            for (key, value) in item {
                let placeholder = format!("{{{{ {} }}}}", key);
                section = section.replace(&placeholder, value);
            }
            
            result.push_str(&section);
        }
        
        Ok(result)
    }
    
    // Default template content - these could be moved to separate files in a real implementation
    fn get_default_html_report_template() -> &'static str {
        include_str!("../templates/report.html")
    }
    
    fn get_default_html_finding_template() -> &'static str {
        include_str!("../templates/finding.html")
    }
    
    fn get_default_md_report_template() -> &'static str {
        include_str!("../templates/report.md")
    }
    
    fn get_default_md_finding_template() -> &'static str {
        include_str!("../templates/finding.md")
    }
}