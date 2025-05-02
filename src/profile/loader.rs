// src/profile/loader.rs - Profile loading functionality
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, debug, warn, error};

use crate::config_path;
use super::{Profile, ProfileManager};

impl ProfileManager {
    /// Load profile from filesystem based on name
    pub async fn load_profile(&self, name: &str) -> Result<Profile> {
        // Get the profile path
        let profile_path = config_path::get_profile_path(name);
        
        if !profile_path.exists() {
            bail!("Profile file not found: {}", profile_path.display());
        }
        
        // Read the profile file
        let content = fs::read_to_string(&profile_path).await
            .context(format!("Failed to read profile file: {}", profile_path.display()))?;
        
        // Parse the profile based on file extension
        let profile = if profile_path.extension().map_or(false, |ext| ext == "toml") {
            toml::from_str(&content)
                .context(format!("Failed to parse TOML profile: {}", profile_path.display()))?
        } else if profile_path.extension().map_or(false, |ext| ext == "json") {
            serde_json::from_str(&content)
                .context(format!("Failed to parse JSON profile: {}", profile_path.display()))?
        } else {
            bail!("Unsupported profile file format: {}", profile_path.display());
        };
        
        debug!("Loaded profile '{}'", name);
        Ok(profile)
    }
    
    /// Save profile to filesystem
    pub async fn save_profile(&self, profile: &Profile) -> Result<()> {
        // Get the profile path
        let profile_path = config_path::get_profile_path(&profile.name);
        
        // Create parent directories if they don't exist
        if let Some(parent) = profile_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await
                    .context(format!("Failed to create profile directory: {}", parent.display()))?;
            }
        }
        
        // Serialize the profile
        let content = toml::to_string_pretty(profile)
            .context("Failed to serialize profile to TOML")?;
        
        // Write to file
        fs::write(&profile_path, content).await
            .context(format!("Failed to write profile file: {}", profile_path.display()))?;
        
        debug!("Saved profile '{}' to {}", profile.name, profile_path.display());
        Ok(())
    }
    
    /// List all available profiles
    pub async fn list_available_profiles(&self) -> Result<Vec<String>> {
        config_path::list_available_profiles().await
    }
    
    /// Initialize default profiles
    pub async fn init_default_profiles(&self) -> Result<()> {
        // Ensure the profiles directory exists
        config_path::ensure_directories_exist().await?;
        
        // Check if we need to create default profiles
        let profiles = self.list_available_profiles().await?;
        if !profiles.is_empty() {
            // Already have profiles, nothing to do
            return Ok(());
        }
        
        info!("No profiles found, creating defaults");
        
        // Create default profile
        let default_profile = Profile::default();
        self.save_profile(&default_profile).await?;
        
        // Create Audible profile
        let audible_profile = Profile::audible_profile();
        self.save_profile(&audible_profile).await?;
        
        // Create safe profile
        let safe_profile = Profile::safe_profile();
        self.save_profile(&safe_profile).await?;
        
        info!("Created default profiles");
        Ok(())
    }

    pub async fn list_available_profiles(&self) -> Result<Vec<String>> {
        Ok(self.list_profiles().await)
    }
    
    // Renamed method to match what's called in app.rs
    pub async fn get_active_profile_name(&self) -> Result<String> {
        let active_profile = self.get_active_profile().await?;
        Ok(active_profile.name)
    }
    
    // Add method to delete a profile
    pub async fn delete_profile(&self, name: &str) -> Result<()> {
        // First check if this is the active profile
        let active_profile = self.get_active_profile().await?;
        if active_profile.name == name {
            bail!("Cannot delete the active profile. Set another profile as active first.");
        }
        
        // Get the profile path
        let profile_path = self.config_dir.join("profiles").join(format!("{}.json", name));
        
        if !profile_path.exists() {
            bail!("Profile file not found: {}", profile_path.display());
        }
        
        // Delete the file
        fs::remove_file(&profile_path).await
            .context(format!("Failed to delete profile file: {}", profile_path.display()))?;
        
        // Remove from in-memory cache
        let mut profiles = self.profiles.write().await;
        profiles.remove(name);
        
        info!("Profile '{}' deleted successfully", name);
        Ok(())
    }
    
    // Add method to import a profile from a file
    pub async fn import_profile_from_file(&self, path: &Path) -> Result<()> {
        // Read profile file
        let content = fs::read_to_string(path).await
            .context(format!("Failed to read profile file: {}", path.display()))?;
        
        // Parse profile based on file extension
        let profile: Profile = if path.extension().map_or(false, |ext| ext == "json") {
            serde_json::from_str(&content)
                .context(format!("Failed to parse JSON profile: {}", path.display()))?
        } else if path.extension().map_or(false, |ext| ext == "toml") {
            toml::from_str(&content)
                .context(format!("Failed to parse TOML profile: {}", path.display()))?
        } else {
            bail!("Unsupported profile file format. Use .json or .toml");
        };
        
        // Save the profile
        self.save_profile(&profile).await?;
        
        info!("Profile '{}' imported successfully", profile.name);
        Ok(())
    }
    
    // Add method to export a profile to a file
    pub async fn export_profile_to_file(&self, name: &str, path: &Path, format: &str) -> Result<()> {
        // Get the profile
        let profile = self.get_profile(name).await?;
        
        // Serialize profile based on format
        let content = match format {
            "json" => serde_json::to_string_pretty(&profile)
                .context("Failed to serialize profile to JSON")?,
            "toml" => toml::to_string(&profile)
                .context("Failed to serialize profile to TOML")?,
            _ => bail!("Unsupported format: {}. Use 'json' or 'toml'", format),
        };
        
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await
                    .context(format!("Failed to create directory: {}", parent.display()))?;
            }
        }
        
        // Write to file
        fs::write(path, content).await
            .context(format!("Failed to write profile to {}", path.display()))?;
        
        info!("Profile '{}' exported to {}", name, path.display());
        Ok(())
    }
}

impl Profile {
    /// Create a default Audible profile
    pub fn audible_profile() -> Self {
        // Implementation would have the same structure as the .toml file we created
        // This is a placeholder for the actual implementation
        let mut profile = Self::default();
        profile.name = "audible".to_string();
        profile.description = Some("Profile for Audible bug bounty program".to_string());
        profile.tags = vec!["audible".to_string(), "bug-bounty".to_string()];
        
        // Set resource limits
        profile.resource_limits.max_concurrent_tasks = 2;
        profile.resource_limits.max_requests_per_second = 5;
        profile.resource_limits.timeout_seconds = 600;
        profile.resource_limits.scan_mode = "standard".to_string();
        profile.resource_limits.risk_level = "medium".to_string();
        
        // Set scope
        profile.scope.include_domains = vec!["*.audible.*".to_string()];
        profile.scope.exclude_domains = vec![
            "help.audible.com".to_string(),
            "newsletters.audible.com".to_string(),
            "www.audiblecareers.com".to_string(),
            "www.audible.com/ep/podcast-development-program".to_string(),
            "www.audiblehub.com/submit".to_string(),
            "www.audible.ca/blog/en".to_string(),
        ];
        profile.scope.exclude_paths = vec![
            "/careers".to_string(),
            "/jobs".to_string(),
            "/podcast-development-program".to_string(),
        ];
        
        // HTTP settings
        profile.http.user_agent = Some("audibleresearcher_yourh1username".to_string());
        profile.http.headers.insert("User-Agent".to_string(), "audibleresearcher_yourh1username".to_string());
        profile.http.headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
        profile.http.headers.insert("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".to_string());
        
        profile
    }
    
    /// Create a safe profile with minimal impact
    pub fn safe_profile() -> Self {
        let mut profile = Self::default();
        profile.name = "safe".to_string();
        profile.description = Some("Safe profile with minimal resource usage and impact".to_string());
        profile.tags = vec!["safe".to_string(), "minimal".to_string()];
        
        // Set resource limits
        profile.resource_limits.max_concurrent_tasks = 1;
        profile.resource_limits.max_requests_per_second = 2;
        profile.resource_limits.timeout_seconds = 120;
        profile.resource_limits.scan_mode = "basic".to_string();
        profile.resource_limits.risk_level = "low".to_string();
        
        profile
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: Some("Default profile with standard settings".to_string()),
            tags: vec!["default".to_string()],
            resource_limits: Default::default(),
            scope: Default::default(),
            tools: HashMap::new(),
            http: Default::default(),
            authentication: HashMap::new(),
            environment: HashMap::new(),
            default_options: HashMap::new(),
            enabled: true,
            program_configs: HashMap::new(),
        }
    }
}