use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use config::{Config as ConfigLoader, FileFormat};

use super::schema::Config;

/// Load configuration from a file
pub fn load_config(config_path: Option<&Path>) -> Result<Config> {
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
        config_builder = config_builder.add_source(config::File::from(path));
    } else {
        // Try to load from default location
        let default_path = get_default_config_path();
        if default_path.exists() {
            config_builder = config_builder.add_source(config::File::from(default_path.as_path()));
        }
    }

    // Environment variables
    config_builder = config_builder.add_source(
        config::Environment::with_prefix("BBHUNT")
    );

    // Build and parse configuration
    let config: Config = config_builder
        .build()?
        .try_deserialize()
        .context("Failed to load configuration")?;

    Ok(config)
}

/// Get the default configuration path
fn get_default_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".bbhunt/config/config.toml")
}

/// Initialize a new configuration
pub fn init_config(force: bool) -> Result<PathBuf> {
    let config_path = get_default_config_path();
    
    // Create parent directories
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    // Check if config already exists
    if config_path.exists() && !force {
        return Err(anyhow::anyhow!(
            "Configuration already exists at {}. Use --force to overwrite.",
            config_path.display()
        ));
    }
    
    // Create default configuration
    let config = Config::default();
    
    // Save configuration
    config.save(&config_path)?;
    
    Ok(config_path)
}