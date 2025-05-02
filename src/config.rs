// src/config.rs - Refactored to use profile system
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context, bail};
use tracing::{info, debug, warn};

use crate::profile::{Profile, ProfileManager};

/// Central configuration structure for BBHunt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Global settings
    #[serde(default)]
    pub global: GlobalConfig,
    
    // Plugin-specific configurations
    #[serde(default)]
    pub plugins: HashMap<String, PluginConfig>,
    
    // External tool configurations
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
    
    // Target configurations
    #[serde(default)]
    pub targets: HashMap<String, TargetConfig>,
}

/// Global application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    // Directories
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    
    // Resource limits
    pub max_memory: usize,
    pub max_cpu: usize,
    
    // HTTP settings
    pub user_agent: String,
    
    // Default profile to use
    pub default_profile: String,
}

/// Default implementation for GlobalConfig
impl Default for GlobalConfig {
    fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir: home_dir.join(".bbhunt/data"),
            config_dir: home_dir.join(".bbhunt/config"),
            max_memory: 4096, // 4GB
            max_cpu: num_cpus::get(),
            user_agent: format!("bbhunt/{}", env!("CARGO_PKG_VERSION")),
            default_profile: "default".to_string(),
        }
    }
}

/// Plugin-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tools: Vec<String>,
    pub wordlist: Option<String>,
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
}

/// External tool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub path: PathBuf,
    pub config_file: Option<PathBuf>,
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
}

/// Default implementation for ToolConfig
impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(""),
            config_file: None,
            options: HashMap::new(),
        }
    }
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub domain: String,
    #[serde(default)]
    pub scope: Vec<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    pub added_at: String,
}

/// Default implementation for TargetConfig
impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            scope: Vec::new(),
            notes: None,
            tags: HashMap::new(),
            added_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Configuration singleton that can be shared across the application
#[derive(Clone)]
pub struct AppConfig {
    inner: Arc<Mutex<Config>>,
    profile_manager: Arc<ProfileManager>,
}

impl AppConfig {
    /// Create a new AppConfig instance with default configuration
    pub fn new() -> Self {
        let profile_manager = Arc::new(ProfileManager::new(PathBuf::from("./profiles")));
        
        Self {
            inner: Arc::new(Mutex::new(Config::default())),
            profile_manager,
        }
    }
    
    /// Load configuration from file or use defaults
    pub async fn load(&self, config_path: Option<&Path>) -> Result<()> {
        let mut config = if let Some(path) = config_path {
            if path.exists() {
                debug!("Loading config from: {}", path.display());
                let content = fs::read_to_string(path)
                    .context(format!("Failed to read config file: {}", path.display()))?;
                
                toml::from_str(&content)
                    .context(format!("Failed to parse config file: {}", path.display()))?
            } else {
                warn!("Config file not found: {}", path.display());
                Config::default()
            }
        } else {
            // Try to load from default location
            let default_path = Self::get_default_config_path();
            if default_path.exists() {
                debug!("Loading config from default path: {}", default_path.display());
                let content = fs::read_to_string(&default_path)
                    .context(format!("Failed to read config file: {}", default_path.display()))?;
                
                toml::from_str(&content)
                    .context(format!("Failed to parse config file: {}", default_path.display()))?
            } else {
                debug!("No config file found, using defaults");
                Config::default()
            }
        };
        
        // Merge with environment variables
        self.apply_environment_vars(&mut config);
        
        // Update the stored configuration
        let mut inner = self.inner.lock().await;
        *inner = config;
        
        // Initialize directories
        self.initialize_directories().await?;
        
        // Initialize profile system
        self.profile_manager.initialize().await?;
        
        // Set default profile from config
        let config = self.inner.lock().await;
        // Only set if the profile exists
        let profiles = self.profile_manager.list_profiles().await;
        if profiles.contains(&config.global.default_profile) {
            self.profile_manager.set_active_profile(&config.global.default_profile).await?;
        }
        
        info!("Configuration loaded successfully");
        Ok(())
    }
    
    /// Apply environment variables to override configuration
    fn apply_environment_vars(&self, config: &mut Config) {
        // Example environment variable processing:
        // BBHUNT_GLOBAL_DATA_DIR -> config.global.data_dir
        
        if let Ok(data_dir) = std::env::var("BBHUNT_GLOBAL_DATA_DIR") {
            config.global.data_dir = PathBuf::from(data_dir);
            debug!("Set data_dir from environment: {:?}", config.global.data_dir);
        }
        
        if let Ok(config_dir) = std::env::var("BBHUNT_GLOBAL_CONFIG_DIR") {
            config.global.config_dir = PathBuf::from(config_dir);
            debug!("Set config_dir from environment: {:?}", config.global.config_dir);
        }
        
        if let Ok(user_agent) = std::env::var("BBHUNT_GLOBAL_USER_AGENT") {
            config.global.user_agent = user_agent;
            debug!("Set user_agent from environment: {}", config.global.user_agent);
        }
        
        if let Ok(profile) = std::env::var("BBHUNT_GLOBAL_PROFILE") {
            config.global.default_profile = profile;
            debug!("Set default_profile from environment: {}", config.global.default_profile);
        }
    }
    
    /// Get the default configuration path
    pub fn get_default_config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".bbhunt/config/config.toml")
    }
    
    /// Save the current configuration to a file
    pub async fn save(&self, path: Option<&Path>) -> Result<PathBuf> {
        let config = self.inner.lock().await;
        let default_path = Self::get_default_config_path();
        let path = path.unwrap_or(&default_path);
        
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context(format!("Failed to create directory: {}", parent.display()))?;
        }
        
        // Serialize and save
        let content = toml::to_string_pretty(&*config)
            .context("Failed to serialize configuration")?;
        
        fs::write(path, content)
            .context(format!("Failed to write config to {}", path.display()))?;
        
        info!("Configuration saved to {}", path.display());
        Ok(path.to_path_buf())
    }
    
    /// Initialize required directories
    async fn initialize_directories(&self) -> Result<()> {
        let config = self.inner.lock().await;
        
        // Create data directory
        if !config.global.data_dir.exists() {
            debug!("Creating data directory: {}", config.global.data_dir.display());
            fs::create_dir_all(&config.global.data_dir)
                .context(format!("Failed to create data directory: {}", config.global.data_dir.display()))?;
        }
        
        // Create config directory
        if !config.global.config_dir.exists() {
            debug!("Creating config directory: {}", config.global.config_dir.display());
            fs::create_dir_all(&config.global.config_dir)
                .context(format!("Failed to create config directory: {}", config.global.config_dir.display()))?;
        }
        
        // Create subdirectories
        let targets_dir = config.global.data_dir.join("targets");
        if !targets_dir.exists() {
            fs::create_dir_all(&targets_dir)
                .context(format!("Failed to create targets directory: {}", targets_dir.display()))?;
        }
        
        let reports_dir = config.global.data_dir.join("reports");
        if !reports_dir.exists() {
            fs::create_dir_all(&reports_dir)
                .context(format!("Failed to create reports directory: {}", reports_dir.display()))?;
        }
        
        // Create profiles directory
        let profiles_dir = PathBuf::from("./profiles");
        if !profiles_dir.exists() {
            debug!("Creating profiles directory: {}", profiles_dir.display());
            fs::create_dir_all(&profiles_dir)
                .context(format!("Failed to create profiles directory: {}", profiles_dir.display()))?;
        }
        
        // Create templates directory
        let templates_dir = PathBuf::from("./templates");
        if !templates_dir.exists() {
            debug!("Creating templates directory: {}", templates_dir.display());
            fs::create_dir_all(&templates_dir)
                .context(format!("Failed to create templates directory: {}", templates_dir.display()))?;
        }
        
        Ok(())
    }
    
    /// Get a reference to the configuration
    pub async fn get(&self) -> Config {
        self.inner.lock().await.clone()
    }
    
    /// Update the configuration
    pub async fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Config) -> Result<()>,
    {
        let mut config = self.inner.lock().await;
        f(&mut config)
    }
    
    /// Get the active profile
    pub async fn get_active_profile(&self) -> Result<Profile> {
        self.profile_manager.get_active_profile().await
    }
    
    /// Set the active profile
    pub async fn set_active_profile(&self, name: &str) -> Result<()> {
        self.profile_manager.set_active_profile(name).await
    }
    
    /// Get a profile by name
    pub async fn get_profile(&self, name: &str) -> Result<Profile> {
        self.profile_manager.get_profile(name).await
    }
    
    /// List available profiles
    pub async fn list_profiles(&self) -> Result<Vec<String>> {
        Ok(self.profile_manager.list_profiles().await)
    }
    
    /// Get the profile manager
    pub fn profile_manager(&self) -> Arc<ProfileManager> {
        self.profile_manager.clone()
    }
    
    /// Get plugin configuration
    pub async fn get_plugin_config(&self, name: &str) -> Option<PluginConfig> {
        let config = self.inner.lock().await;
        config.plugins.get(name).cloned()
    }
    
    /// Get data directory path
    pub async fn data_dir(&self) -> PathBuf {
        self.inner.lock().await.global.data_dir.clone()
    }
    
    /// Get config directory path
    pub async fn config_dir(&self) -> PathBuf {
        self.inner.lock().await.global.config_dir.clone()
    }
}

impl Default for Config {
    fn default() -> Self {
        // Set up some default plugin configurations
        let mut plugins = HashMap::new();
        
        let mut subdomain_enum = PluginConfig::default();
        subdomain_enum.enabled = true;
        subdomain_enum.tools = vec!["subfinder".to_string(), "amass".to_string()];
        plugins.insert("subdomain_enum".to_string(), subdomain_enum);
        
        let mut web_scan = PluginConfig::default();
        web_scan.enabled = true;
        web_scan.tools = vec!["nuclei".to_string(), "nikto".to_string()];
        plugins.insert("web_scan".to_string(), web_scan);
        
        // Set up some default tool configurations
        let mut tools = HashMap::new();
        
        let mut subfinder = ToolConfig::default();
        subfinder.path = PathBuf::from("subfinder");
        tools.insert("subfinder".to_string(), subfinder);
        
        let mut amass = ToolConfig::default();
        amass.path = PathBuf::from("amass");
        tools.insert("amass".to_string(), amass);
        
        let mut nuclei = ToolConfig::default();
        nuclei.path = PathBuf::from("nuclei");
        tools.insert("nuclei".to_string(), nuclei);
        
        let mut nikto = ToolConfig::default();
        nikto.path = PathBuf::from("nikto");
        tools.insert("nikto".to_string(), nikto);
        
        Self {
            global: GlobalConfig::default(),
            plugins,
            tools,
            targets: HashMap::new(),
        }
    }
}

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