use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use crate::config::Config;
use crate::core::plugin::PluginManager;
use crate::core::resource::ResourceManager;

use super::commands::{self, Args, Commands};
use super::interactive::InteractiveShell;

/// The main application struct
pub struct App {
    config: Config,
    plugin_manager: PluginManager,
    resource_manager: ResourceManager,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Result<Self> {
        // Load configuration
        let config = Config::load(None)?;
        
        // Initialize plugin and resource managers
        let plugin_manager = PluginManager::new();
        let resource_manager = ResourceManager::new();
        
        Ok(Self {
            config,
            plugin_manager,
            resource_manager,
        })
    }
    
    /// Run the application
    pub async fn run(&mut self) -> Result<()> {
        // Parse command line arguments
        let args = Args::parse();
        
        info!("Starting BBHunt v{}", env!("CARGO_PKG_VERSION"));
        
        // Load plugins
        let plugin_dir = self.config.global.config_dir.join("plugins");
        self.plugin_manager.load_plugins(&plugin_dir).await
            .context("Failed to load plugins")?;
        
        if args.verbose {
            info!("Verbose mode enabled");
        }
        
        match &args.command {
            Some(command) => {
                commands::execute_command(
                    command, 
                    &mut self.config, 
                    &mut self.plugin_manager, 
                    &self.resource_manager
                ).await?;
            }
            None => {
                // Start interactive shell if no command provided
                let mut shell = InteractiveShell::new(
                    &mut self.config,
                    &mut self.plugin_manager,
                    &self.resource_manager,
                );
                shell.run().await?;
            }
        }
        
        Ok(())
    }
}