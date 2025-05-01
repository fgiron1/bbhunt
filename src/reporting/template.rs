// src/reporting/template.rs
use std::collections::HashMap;
use anyhow::{Context, Result};
use tracing::debug;

/// A simple templating engine for reports
pub struct TemplateEngine {
    templates: HashMap<String, String>,
}

impl TemplateEngine {
    /// Create a new template engine
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }
    
    /// Register a template with a name
    pub fn register_template(&mut self, name: &str, template: &str) -> Result<()> {
        self.templates.insert(name.to_string(), template.to_string());
        debug!("Registered template: {}", name);
        Ok(())
    }
    
    /// Load a template from a file
    pub async fn load_template(&mut self, name: &str, path: &std::path::Path) -> Result<()> {
        let content = tokio::fs::read_to_string(path)
            .await
            .context(format!("Failed to read template file: {}", path.display()))?;
            
        self.register_template(name, &content)?;
        Ok(())
    }
    
    /// Render a template with the provided variables
    pub fn render(&self, template_name: &str, variables: &HashMap<String, String>) -> Result<String> {
        let template = self.templates.get(template_name)
            .context(format!("Template not found: {}", template_name))?;
            
        let mut result = template.clone();
        
        // Simple variable substitution
        for (key, value) in variables {
            let placeholder = format!("{{{{ {} }}}}", key);
            result = result.replace(&placeholder, value);
        }
        
        Ok(result)
    }
    
    /// Render a section of a template for each item in a collection
    pub fn render_section(&self, section_template: &str, items: &[HashMap<String, String>]) -> Result<String> {
        let mut result = String::new();
        
        for item in items {
            let mut section = section_template.to_string();
            
            for (key, value) in item {
                let placeholder = format!("{{{{ {} }}}}", key);
                section = section.replace(&placeholder, value);
            }
            
            result.push_str(&section);
        }
        
        Ok(result)
    }
}

// Predefined templates for HTML, Markdown, and JSON reports
pub fn get_default_html_template() -> &'static str {
    include_str!("../../templates/report_template.html")
}

pub fn get_default_markdown_template() -> &'static str {
    include_str!("../../templates/report_template.md")
}

pub fn get_default_finding_html_template() -> &'static str {
    include_str!("../../templates/finding_template.html")
}

pub fn get_default_finding_markdown_template() -> &'static str {
    include_str!("../../templates/finding_template.md")
}