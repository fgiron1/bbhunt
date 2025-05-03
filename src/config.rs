// src/config.rs - Refactored to use true singleton pattern
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, Context};
use tracing::{info, debug};
use once_cell::sync::OnceCell;

use crate::profile::{Profile, ProfileManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    
    #[serde(default)]
    pub plugins: HashMap<String, PluginConfig>,
    
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
    
    #[serde(default)]
    pub targets: HashMap<String, TargetConfig>,
}

/// Global application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
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
            default_profile: "base".to_string(),
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub path: PathBuf,
    pub config_file: Option<PathBuf>,
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(""),
            config_file: None,
            options: HashMap::new(),
        }
    }
}

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

// Singleton implementation for AppConfig
pub struct AppConfig {
    inner: Arc<Mutex<Config>>,
    profile_manager: Arc<ProfileManager>,
    // Track the config file path
    config_path: Arc<Mutex<Option<PathBuf>>>,
}

// Static instance of AppConfig
static APP_CONFIG_INSTANCE: OnceCell<AppConfig> = OnceCell::new();

impl AppConfig {
    // Get or initialize the AppConfig singleton
    pub fn instance() -> &'static AppConfig {
        APP_CONFIG_INSTANCE.get_or_init(|| {
            let config = Config::default();
            let profile_manager = Arc::new(ProfileManager::new(PathBuf::from("./profiles")));
            
            AppConfig {
                inner: Arc::new(Mutex::new(config)),
                profile_manager,
                config_path: Arc::new(Mutex::new(None)),
            }
        })
    }
    
    // Constructor now private to enforce singleton pattern
    fn new() -> Self {
        let profile_manager = Arc::new(ProfileManager::new(PathBuf::from("./profiles")));
        
        Self {
            inner: Arc::new(Mutex::new(Config::default())),
            profile_manager,
            config_path: Arc::new(Mutex::new(None)),
        }
    }
    
    pub async fn load(&self, config_path: Option<&Path>) -> Result<()> {
        // Determine config path
        let config_file_path = if let Some(path) = config_path {
            path.to_path_buf()
        } else {
            // Try to load from default location
            Self::get_default_config_path()
        };
        
        // Store the config path for later use
        let mut path_storage = self.config_path.lock().await;
        *path_storage = Some(config_file_path.clone());
        drop(path_storage);
        
        // Load config from file if it exists
        let mut config = if config_file_path.exists() {
            debug!("Loading config from: {}", config_file_path.display());
            let content = fs::read_to_string(&config_file_path)
                .context(format!("Failed to read config file: {}", config_file_path.display()))?;
            
            toml::from_str(&content)
                .context(format!("Failed to parse config file: {}", config_file_path.display()))?
        } else {
            // Use default config
            debug!("Config file not found, using defaults");
            Config::default()
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
        // Load environment variables with a consistent prefix
        const ENV_PREFIX: &str = "BBHUNT_";
        
        for (key, value) in std::env::vars() {
            if key.starts_with(ENV_PREFIX) {
                // Remove prefix
                let config_key = key.strip_prefix(ENV_PREFIX).unwrap();
                
                // Handle nested configuration keys (using _ as separator)
                let parts: Vec<&str> = config_key.split('_').collect();
                
                match parts.as_slice() {
                    // Global config settings
                    ["GLOBAL", "DATA_DIR"] => {
                        config.global.data_dir = PathBuf::from(value);
                        debug!("Set data_dir from environment: {:?}", config.global.data_dir);
                    },
                    ["GLOBAL", "CONFIG_DIR"] => {
                        config.global.config_dir = PathBuf::from(value);
                        debug!("Set config_dir from environment: {:?}", config.global.config_dir);
                    },
                    ["GLOBAL", "USER_AGENT"] => {
                        config.global.user_agent = value;
                        debug!("Set user_agent from environment: {}", config.global.user_agent);
                    },
                    ["GLOBAL", "PROFILE"] => {
                        config.global.default_profile = value;
                        debug!("Set default_profile from environment: {}", config.global.default_profile);
                    },
                    ["GLOBAL", "MAX_MEMORY"] => {
                        if let Ok(mem) = value.parse::<usize>() {
                            config.global.max_memory = mem;
                            debug!("Set max_memory from environment: {}", config.global.max_memory);
                        }
                    },
                    ["GLOBAL", "MAX_CPU"] => {
                        if let Ok(cpu) = value.parse::<usize>() {
                            config.global.max_cpu = cpu;
                            debug!("Set max_cpu from environment: {}", config.global.max_cpu);
                        }
                    },
                    
                    // Plugin-specific settings
                    ["PLUGIN", plugin_name, option_name] => {
                        let plugin = config.plugins.entry(plugin_name.to_string())
                            .or_insert_with(PluginConfig::default);
                        
                        match *option_name {
                            "ENABLED" => {
                                if let Ok(enabled) = value.parse::<bool>() {
                                    plugin.enabled = enabled;
                                    debug!("Set plugin.{}.enabled from environment: {}", plugin_name, enabled);
                                }
                            },
                            "WORDLIST" => {
                                plugin.wordlist = Some(value.clone());
                                debug!("Set plugin.{}.wordlist from environment: {}", plugin_name, value);
                            },
                            _ => {
                                // Generic option handling
                                let json_value = serde_json::Value::String(value.clone());
                                plugin.options.insert(option_name.to_lowercase(), json_value);
                                debug!("Set plugin.{}.options.{} from environment", plugin_name, option_name);
                            },
                        }
                    },
                    
                    // Tool-specific settings
                    ["TOOL", tool_name, option_name] => {
                        let tool = config.tools.entry(tool_name.to_string())
                            .or_insert_with(ToolConfig::default);
                        
                        match *option_name {
                            "PATH" => {
                                tool.path = PathBuf::from(value.clone());
                                debug!("Set tool.{}.path from environment: {}", tool_name, value);
                            },
                            "CONFIG_FILE" => {
                                tool.path = PathBuf::from(value.clone());
                                debug!("Set tool.{}.path from environment: {}", tool_name, value);
                            },
                            _ => {
                                // Generic option handling
                                let json_value = serde_json::Value::String(value.clone());
                                tool.options.insert(option_name.to_lowercase(), json_value);
                                debug!("Set tool.{}.options.{} from environment", tool_name, option_name);
                            },
                        }
                    },
                    
                    // Worker-specific settings
                    ["WORKER_TYPE"] => {
                        debug!("Set worker_type from environment: {}", value);
                        // This would be used for distributed execution
                    },
                    
                    // Unhandled keys
                    _ => {
                        debug!("Unhandled environment variable: {}={}", key, value);
                    },
                }
            }
        }
    }
    
    /// Get the default configuration path
    pub fn get_default_config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".bbhunt/config/default.toml")
    }
    
    /// Save the current configuration to a file
    pub async fn save(&self, path: Option<&Path>) -> Result<PathBuf> {
        let config = self.inner.lock().await;
        
        // Determine save path
        let save_path = if let Some(p) = path {
            p.to_path_buf()
        } else {
            // Use the path from load() or default
            let path_storage = self.config_path.lock().await;
            path_storage.clone().unwrap_or_else(|| Self::get_default_config_path())
        };
        
        // Create parent directories if they don't exist
        if let Some(parent) = save_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .context(format!("Failed to create directory: {}", parent.display()))?;
            }
        }
        
        // Serialize and save
        let content = toml::to_string_pretty(&*config)
            .context("Failed to serialize configuration")?;
        
        fs::write(&save_path, content)
            .context(format!("Failed to write config to {}", save_path.display()))?;
        
        info!("Configuration saved to {}", save_path.display());
        Ok(save_path)
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
        let profiles_dir = config.global.config_dir.join("profiles");
        if !profiles_dir.exists() {
            debug!("Creating profiles directory: {}", profiles_dir.display());
            fs::create_dir_all(&profiles_dir)
                .context(format!("Failed to create profiles directory: {}", profiles_dir.display()))?;
        }
        
        // Create templates directory
        let templates_dir = config.global.config_dir.join("templates");
        if !templates_dir.exists() {
            debug!("Creating templates directory: {}", templates_dir.display());
            fs::create_dir_all(&templates_dir)
                .context(format!("Failed to create templates directory: {}", templates_dir.display()))?;
        }
        
        Ok(())
    }
    
    // Get a reference to the configuration - use this method instead of clone()
    pub async fn get(&self) -> Config {
        self.inner.lock().await.clone()
    }
    
    // Update the configuration
    pub async fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Config) -> Result<()>,
    {
        let mut config = self.inner.lock().await;
        f(&mut config)
    }
    
    // Get the active profile - no need to clone the result
    pub async fn get_active_profile(&self) -> Result<Profile> {
        self.profile_manager.get_active_profile().await
    }
    
    // Set the active profile
    pub async fn set_active_profile(&self, name: &str) -> Result<()> {
        self.profile_manager.set_active_profile(name).await
    }
    
    // Get a profile by name
    pub async fn get_profile(&self, name: &str) -> Result<Profile> {
        self.profile_manager.get_profile(name).await
    }
    
    // List available profiles
    pub async fn list_profiles(&self) -> Result<Vec<String>> {
        Ok(self.profile_manager.list_profiles().await)
    }
    
    // Get the profile manager - return a reference to avoid clone
    pub fn profile_manager(&self) -> &Arc<ProfileManager> {
        &self.profile_manager
    }
    
    // Get plugin configuration - avoid returning Option<PluginConfig> which could be cloned
    pub async fn get_plugin_config(&self, name: &str) -> Option<PluginConfig> {
        let config = self.inner.lock().await;
        config.plugins.get(name).cloned()
    }
    
    // Get data directory path
    pub async fn data_dir(&self) -> PathBuf {
        self.inner.lock().await.global.data_dir.clone()
    }
    
    // Get config directory path
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