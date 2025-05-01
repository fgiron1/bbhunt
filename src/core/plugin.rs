// src/core/plugin.rs
use std::collections::HashMap;
use std::path::Path;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use tracing::{info, warn, error, debug};

use crate::error::{BBHuntResult, BBHuntError, util::log_error};
use crate::config::Config;

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
    async fn init(&mut self, _config: &Config) -> BBHuntResult<()> {
        Ok(())
    }
    
    /// Set up plugin for execution (called before each execution)
    async fn setup(&mut self) -> BBHuntResult<()>;
    
    /// Execute the plugin with the given target and options
    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> BBHuntResult<PluginResult>;
    
    /// Clean up after execution (called after each execution)
    async fn cleanup(&mut self) -> BBHuntResult<()>;
    
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
    config: Option<Config>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            config: None,
        }
    }

    /// Set the configuration for the plugin manager
    pub fn set_config(&mut self, config: Config) {
        self.config = Some(config);
    }

    /// Load plugins from a directory
    pub async fn load_plugins(&mut self, plugin_dir: &Path) -> BBHuntResult<()> {
        info!("Loading plugins from {}", plugin_dir.display());
        
        // This is a simplified implementation
        // In a real application, you would dynamically load plugins
        // from shared libraries or use a plugin registry
        
        // Register built-in plugins
        self.register_plugin("subdomain_enum", crate::plugins::recon::subdomain_enum::create())?;
        self.register_plugin("web_scan", crate::plugins::scan::web_scan::create())?;
        
        info!("Loaded {} plugins", self.plugins.len());
        
        // Initialize plugins with config if available
        if let Some(ref config) = self.config {
            for (name, plugin) in &mut self.plugins {
                match plugin.init(config).await {
                    Ok(_) => debug!("Initialized plugin: {}", name),
                    Err(e) => {
                        // Don't fail on plugin initialization error, just log it
                        warn!("Failed to initialize plugin '{}': {}", name, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Register a new plugin
    pub fn register_plugin(&mut self, name: &str, plugin: Box<dyn Plugin>) -> BBHuntResult<()> {
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
    ) -> BBHuntResult<PluginResult> {
        // Get the plugin but don't fail if not found - return a Plugin Not Found result instead
        let plugin = match self.plugins.get_mut(plugin_name) {
            Some(plugin) => plugin,
            None => {
                error!("Plugin '{}' not found", plugin_name);
                return Err(BBHuntError::PluginNotFound(plugin_name.to_string()));
            }
        };
        
        info!("Running plugin '{}' on target '{}'", plugin_name, target);
        
        let start_time = std::time::Instant::now();
        
        // Setup, execute, and cleanup with safe error handling
        // If any step fails, we don't want to crash the whole framework
        
        // Setup phase
        if let Err(e) = plugin.setup().await {
            warn!("Failed to set up plugin '{}': {}", plugin_name, e);
            return Ok(PluginResult {
                status: PluginStatus::Error,
                message: format!("Setup failed: {}", e),
                data: HashMap::new(),
                execution_time: start_time.elapsed(),
            });
        }
        
        // Execute phase
        let result = match plugin.execute(target, options).await {
            Ok(result) => result,
            Err(e) => {
                warn!("Failed to execute plugin '{}': {}", plugin_name, e);
                
                // Try to cleanup even if execution failed
                if let Err(cleanup_err) = plugin.cleanup().await {
                    warn!("Failed to clean up plugin '{}' after execution error: {}", plugin_name, cleanup_err);
                }
                
                return Ok(PluginResult {
                    status: PluginStatus::Error,
                    message: format!("Execution failed: {}", e),
                    data: HashMap::new(),
                    execution_time: start_time.elapsed(),
                });
            }
        };
        
        // Cleanup phase
        if let Err(e) = plugin.cleanup().await {
            warn!("Failed to clean up plugin '{}': {}", plugin_name, e);
            // We got results but cleanup failed - mark as partial success
            return Ok(PluginResult {
                status: PluginStatus::Partial,
                message: format!("Execution succeeded but cleanup failed: {}", e),
                data: result.data,
                execution_time: start_time.elapsed(),
            });
        }
        
        info!("Plugin '{}' completed in {:?}", plugin_name, start_time.elapsed());
        
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
    
    /// Check if a plugin exists
    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }
    
    /// Get the number of loaded plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
    
    /// Get plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }
}