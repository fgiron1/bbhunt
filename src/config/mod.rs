// src/config/mod.rs
mod schema;

use std::path::{Path, PathBuf};
use config::{Config as ConfigLoader, FileFormat};
use tracing::{info, warn};

pub use schema::{
    Config, GlobalConfig, PluginConfig, ToolConfig, 
    ProfileConfig, TargetConfig
};

use crate::error::{BBHuntResult, BBHuntError};

/// Centralized configuration handling
impl Config {
    /// Load configuration from a file or create default if not found
    pub fn load(config_path: Option<&Path>) -> BBHuntResult<Self> {
        info!("Loading configuration");
        
        let mut config_builder = ConfigLoader::builder();

        // Default configuration
        config_builder = config_builder.add_source(
            config::File::from_str(
                include_str!("../../config/default.toml"), 
                FileFormat::Toml
            )
        );

        // User-provided configuration
        if let Some(path) = config_path {
            if path.exists() {
                config_builder = config_builder.add_source(config::File::from(path));
                info!("Loading user configuration from: {}", path.display());
            } else {
                warn!("Specified configuration file not found: {}", path.display());
            }
        } else {
            // Try to load from default location
            let default_path = Self::get_default_config_path();
            if default_path.exists() {
                config_builder = config_builder.add_source(config::File::from(default_path.as_path()));
                info!("Loading default configuration from: {}", default_path.display());
            } else {
                info!("No existing configuration found, using built-in defaults");
            }
        }

        // Environment variables
        config_builder = config_builder.add_source(
            config::Environment::with_prefix("BBHUNT").separator("_")
        );
        info!("Environment variables with BBHUNT_ prefix will override configuration settings");

        // Build and parse configuration
        let config: Config = match config_builder.build() {
            Ok(c) => match c.try_deserialize() {
                Ok(config) => config,
                Err(e) => return Err(BBHuntError::ConfigError(format!("Failed to parse configuration: {}", e))),
            },
            Err(e) => return Err(BBHuntError::ConfigError(format!("Failed to build configuration: {}", e))),
        };

        Ok(config)
    }

    /// Get the default configuration path
    pub fn get_default_config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".bbhunt/config/config.toml")
    }

    /// Initialize a new configuration
    pub fn init(force: bool) -> BBHuntResult<PathBuf> {
        let config_path = Self::get_default_config_path();
        
        // Create parent directories
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BBHuntError::FileError {
                    path: parent.to_path_buf(),
                    message: format!("Failed to create directory: {}", e),
                })?;
        }
        
        // Check if config already exists
        if config_path.exists() && !force {
            return Err(BBHuntError::ConfigError(
                format!("Configuration already exists at {}. Use --force to overwrite.", config_path.display())
            ));
        }
        
        // Create default configuration
        let config = Config::default();
        
        // Save configuration
        config.save(&config_path)?;
        
        Ok(config_path)
    }
    
    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> BBHuntResult<()> {
        let config_str = toml::to_string_pretty(self)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize configuration: {}", e)))?;
            
        std::fs::write(path, config_str)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to write configuration: {}", e),
            })?;
            
        info!("Configuration saved to {}", path.display());
        
        Ok(())
    }
    
    /// Get a plugin configuration by name
    pub fn get_plugin_config(&self, name: &str) -> Option<&PluginConfig> {
        self.plugins.get(name)
    }
    
    /// Get a tool configuration by name
    pub fn get_tool_config(&self, name: &str) -> Option<&ToolConfig> {
        self.tools.get(name)
    }
    
    /// Get a profile configuration by name
    pub fn get_profile_config(&self, name: &str) -> Option<&ProfileConfig> {
        self.profiles.get(name)
    }
    
    /// Get the active profile configuration
    pub fn get_active_profile(&self) -> &ProfileConfig {
        self.profiles.get(&self.global.default_profile)
            .unwrap_or_else(|| {
                // Fallback to the first profile or create a default one
                self.profiles.values().next()
                    .unwrap_or_else(|| panic!("No profiles defined in configuration"))
            })
    }
}