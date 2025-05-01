// src/context.rs
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;

use crate::config::Config;
use crate::core::plugin::PluginManager;
use crate::core::resource::ResourceManager;
use crate::core::target::TargetManager;
use crate::reporting::ReportManager;
use crate::osint::OsintCollector;
use crate::error::{BBHuntResult, BBHuntError};

/// Application context containing all shared resources
/// This allows for easier dependency injection and access to shared state
pub struct Context {
    pub config: Arc<Mutex<Config>>,
    pub plugin_manager: Arc<Mutex<PluginManager>>,
    pub resource_manager: Arc<ResourceManager>,
    pub target_manager: Arc<Mutex<TargetManager>>,
    pub report_manager: Arc<ReportManager>,
    pub osint_collector: Arc<Mutex<OsintCollector>>,
}

impl Context {
    /// Create a new application context
    pub async fn new() -> BBHuntResult<Self> {
        // Load the global configuration first
        let config = Config::load(None).map_err(|e| BBHuntError::ConfigError(e.to_string()))?;
        let config = Arc::new(Mutex::new(config));
        
        // Get data directory from config
        let data_dir = {
            let config_guard = config.lock().await;
            config_guard.global.data_dir.clone()
        };
        
        // Initialize the plugin manager
        let plugin_manager = Arc::new(Mutex::new(PluginManager::new()));
        
        // Initialize the resource manager
        let resource_manager = Arc::new(ResourceManager::new());
        
        // Initialize the target manager
        let target_manager = Arc::new(Mutex::new(TargetManager::new(data_dir.join("targets"))));
        
        // Initialize the target manager
        target_manager.lock().await.init().await
            .map_err(|e| BBHuntError::ConfigError(format!("Failed to initialize target manager: {}", e)))?;
        
        // Initialize the report manager
        let report_manager = Arc::new(Mutex::new(ReportManager::new(data_dir.join("reports"))));
        
        // Initialize the OSINT collector
        let osint_collector = Arc::new(Mutex::new(OsintCollector::new()));
        
        // Create the context
        let context = Self {
            config,
            plugin_manager,
            resource_manager,
            target_manager,
            report_manager,
            osint_collector,
        };
        
        // Return the context
        Ok(context)
    }

    /// Initialize context and ensure all required directories exist
    pub async fn initialize(&self) -> BBHuntResult<()> {
        // Create necessary directories
        let data_dir = {
            let config_guard = self.config.lock().await;
            config_guard.global.data_dir.clone()
        };
        
        // Create data directory
        Self::ensure_directory(&data_dir).await?;
        
        // Create targets directory
        Self::ensure_directory(&data_dir.join("targets")).await?;
        
        // Create reports directory
        Self::ensure_directory(&data_dir.join("reports")).await?;
        
        // Initialize templates for report manager
        self.report_manager.lock().await.init_templates().await?;
        
        Ok(())
    }

    /// Ensure a directory exists, creating it if necessary
    async fn ensure_directory(path: &PathBuf) -> BBHuntResult<()> {
        if !path.exists() {
            tokio::fs::create_dir_all(path).await
                .map_err(|e| BBHuntError::FileError {
                    path: path.clone(),
                    message: format!("Failed to create directory: {}", e)
                })?;
        }
        Ok(())
    }
}