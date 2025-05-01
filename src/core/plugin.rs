// src/core/plugin.rs
use std::collections::HashMap;
use std::path::Path;
use async_trait::async_trait;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCategory {
    Recon,
    Scan,
    Exploit,
    Utility,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: PluginCategory,
    pub author: String,
    pub required_tools: Vec<String>,
}

impl Default for PluginMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            version: String::new(),
            category: PluginCategory::Utility,
            author: String::new(),
            required_tools: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub status: PluginStatus,
    pub message: String,
    pub data: HashMap<String, Value>,
    pub execution_time: std::time::Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginStatus {
    Success,
    Error,
    Partial,
}

/// Plugin trait that all plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;
    
    /// Initialize the plugin (called once at startup)
    async fn init(&mut self, config: &crate::config::Config) -> Result<()> {
        Ok(())
    }
    
    /// Set up plugin for execution (called before each execution)
    async fn setup(&mut self) -> Result<()>;
    
    /// Execute the plugin with the given target and options
    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult>;
    
    /// Clean up after execution (called after each execution)
    async fn cleanup(&mut self) -> Result<()>;
    
    /// Get resource requirements
    fn resource_requirements(&self) -> crate::core::resource::ResourceRequirements {
        crate::core::resource::ResourceRequirements {
            memory_mb: 256,
            cpu_cores: 0.5,
            disk_mb: 100,
            network_required: true,
        }
    }
    
    /// Whether this plugin can run in parallel with itself
    fn supports_self_parallelism(&self) -> bool {
        true
    }
    
    /// Whether this plugin can run in parallel with other plugins
    fn supports_concurrent_plugins(&self) -> bool {
        true
    }
    
    /// Returns a list of plugin names that this plugin should not run alongside
    fn incompatible_plugins(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Manager for loading and running plugins
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn Plugin>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Load plugins from a directory
    pub async fn load_plugins(&mut self, plugin_dir: &Path) -> Result<()> {
        info!("Loading plugins from {}", plugin_dir.display());
        
        // This is a simplified implementation
        // In a real application, you would dynamically load plugins
        // from shared libraries or use a plugin registry
        
        // Register built-in plugins
        self.register_plugin("subdomain_enum", crate::plugins::recon::subdomain_enum::create())?;
        self.register_plugin("web_scan", crate::plugins::scan::web_scan::create())?;
        
        info!("Loaded {} plugins", self.plugins.len());
        
        Ok(())
    }
    
    /// Register a new plugin
    pub fn register_plugin(&mut self, name: &str, plugin: Box<dyn Plugin>) -> Result<()> {
        if self.plugins.contains_key(name) {
            warn!("Plugin '{}' is already registered, overriding", name);
        }
        
        self.plugins.insert(name.to_string(), plugin);
        Ok(())
    }

    /// Run a specific plugin
    pub async fn run_plugin(
        &mut self, 
        plugin_name: &str, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        let plugin = self.plugins.get_mut(plugin_name)
            .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", plugin_name))?;
        
        info!("Running plugin '{}' on target '{}'", plugin_name, target);
        
        let start_time = std::time::Instant::now();
        
        // Setup, execute, and cleanup
        plugin.setup().await
            .context(format!("Failed to set up plugin '{}'", plugin_name))?;
        
        let mut result = plugin.execute(target, options).await
            .context(format!("Failed to execute plugin '{}'", plugin_name))?;
        
        plugin.cleanup().await
            .context(format!("Failed to clean up plugin '{}'", plugin_name))?;
        
        // Add execution time to the result
        result.execution_time = start_time.elapsed();
        
        info!("Plugin '{}' completed in {:?}", plugin_name, result.execution_time);
        
        Ok(result)
    }
    
    /// Get metadata for all loaded plugins
    pub fn get_plugins(&self) -> Vec<&PluginMetadata> {
        self.plugins.values()
            .map(|plugin| plugin.metadata())
            .collect()
    }
    
    /// Get plugins filtered by category
    pub fn get_plugins_by_category(&self, category: &PluginCategory) -> Vec<&PluginMetadata> {
        self.plugins.values()
            .filter(|plugin| plugin.metadata().category == *category)
            .map(|plugin| plugin.metadata())
            .collect()
    }
}

// Minimal implementation of a subdomain enumeration plugin
#[derive(Default)]
pub struct SimpleSubdomainEnumPlugin {
    metadata: PluginMetadata,
}

impl SimpleSubdomainEnumPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "subdomain_enum".to_string(),
                description: "Simple subdomain enumeration".to_string(),
                version: "0.1.0".to_string(),
                category: PluginCategory::Recon,
                author: "BBHunt Team".to_string(),
                required_tools: vec![],
            },
        }
    }
}

#[async_trait]
impl Plugin for SimpleSubdomainEnumPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn setup(&mut self) -> Result<()> {
        Ok(())
    }
    
    async fn execute(
        &mut self, 
        target: &str, 
        _options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        // Simulated results
        let mut data = HashMap::new();
        data.insert(
            "subdomains".to_string(), 
            Value::Array(vec![
                Value::String(format!("www.{}", target)),
                Value::String(format!("api.{}", target)),
                Value::String(format!("blog.{}", target)),
            ])
        );
        
        Ok(PluginResult {
            status: PluginStatus::Success,
            message: format!("Found 3 subdomains for {}", target),
            data,
            execution_time: std::time::Duration::from_millis(100),
        })
    }
    
    async fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

// Provide a simple function to create the plugin
pub fn create_simple_subdomain_enum() -> Box<dyn Plugin> {
    Box::new(SimpleSubdomainEnumPlugin::new())
}