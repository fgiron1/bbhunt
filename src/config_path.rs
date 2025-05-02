// src/config_path.rs - Path utilities for finding configuration files and templates
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};

/// Get the base directory of the application
pub fn get_base_dir() -> PathBuf {
    // Get the current executable path
    if let Ok(exe_path) = std::env::current_exe() {
        // Navigate up to find the base directory
        if let Some(parent) = exe_path.parent() {
            if let Some(grandparent) = parent.parent() {
                return grandparent.to_path_buf();
            }
            return parent.to_path_buf();
        }
    }
    
    // Fallback to current directory
    match std::env::current_dir() {
        Ok(current_dir) => current_dir,
        Err(_) => PathBuf::from("."),
    }
}

/// Get the profiles directory (./profiles)
pub fn get_profiles_dir() -> PathBuf {
    let mut base_dir = get_base_dir();
    base_dir.push("profiles");
    base_dir
}

/// Get the templates directory (./templates)
pub fn get_templates_dir() -> PathBuf {
    let mut base_dir = get_base_dir();
    base_dir.push("templates");
    base_dir
}

/// Get the path to a specific profile file
pub fn get_profile_path(profile_name: &str) -> PathBuf {
    let mut profiles_dir = get_profiles_dir();
    profiles_dir.push(format!("{}.toml", profile_name));
    profiles_dir
}

/// Get the path to a specific template file
pub fn get_template_path(template_name: &str) -> PathBuf {
    let mut templates_dir = get_templates_dir();
    templates_dir.push(template_name);
    templates_dir
}

/// Ensure all required directories exist
pub async fn ensure_directories_exist() -> Result<()> {
    // Create profiles directory if it doesn't exist
    let profiles_dir = get_profiles_dir();
    if !profiles_dir.exists() {
        tokio::fs::create_dir_all(&profiles_dir).await
            .context(format!("Failed to create profiles directory: {}", profiles_dir.display()))?;
    }
    
    // Create templates directory if it doesn't exist
    let templates_dir = get_templates_dir();
    if !templates_dir.exists() {
        tokio::fs::create_dir_all(&templates_dir).await
            .context(format!("Failed to create templates directory: {}", templates_dir.display()))?;
    }
    
    Ok(())
}

/// List available profiles
pub async fn list_available_profiles() -> Result<Vec<String>> {
    let profiles_dir = get_profiles_dir();
    
    if !profiles_dir.exists() {
        return Ok(Vec::new());
    }
    
    let mut profiles = Vec::new();
    let mut entries = tokio::fs::read_dir(&profiles_dir).await
        .context(format!("Failed to read profiles directory: {}", profiles_dir.display()))?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "toml") {
            if let Some(stem) = path.file_stem() {
                if let Some(name) = stem.to_str() {
                    profiles.push(name.to_string());
                }
            }
        }
    }
    
    Ok(profiles)
}

/// Read a profile file
pub async fn read_profile_file(profile_name: &str) -> Result<String> {
    let profile_path = get_profile_path(profile_name);
    
    if !profile_path.exists() {
        anyhow::bail!("Profile file not found: {}", profile_path.display());
    }
    
    tokio::fs::read_to_string(&profile_path).await
        .context(format!("Failed to read profile file: {}", profile_path.display()))
}

/// Write a profile file
pub async fn write_profile_file(profile_name: &str, content: &str) -> Result<()> {
    let profile_path = get_profile_path(profile_name);
    
    // Create parent directories if needed
    if let Some(parent) = profile_path.parent() {
        if !parent.exists() {
            tokio::fs::create_dir_all(parent).await
                .context(format!("Failed to create directory: {}", parent.display()))?;
        }
    }
    
    tokio::fs::write(&profile_path, content).await
        .context(format!("Failed to write profile file: {}", profile_path.display()))
}

/// Check if a profile exists
pub async fn profile_exists(profile_name: &str) -> bool {
    get_profile_path(profile_name).exists()
}