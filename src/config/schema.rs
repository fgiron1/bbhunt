use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub plugins: HashMap<String, PluginConfig>,
    pub tools: HashMap<String, ToolConfig>,
    pub profiles: HashMap<String, ProfileConfig>,
    pub targets: HashMap<String, TargetConfig>,
}

/// Global configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub max_memory: usize,
    pub max_cpu: usize,
    pub user_agent: String,
    pub default_profile: String,
}

/// Plugin-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub tools: Vec<String>,
    pub wordlist: Option<String>,
    pub options: HashMap<String, serde_json::Value>,
}

/// Tool-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub path: PathBuf,
    pub config_file: Option<PathBuf>,
    pub options: HashMap<String, serde_json::Value>,
}

/// Configuration profiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub max_concurrent_tasks: usize,
    pub scan_mode: String,
    pub risk_level: Option<String>,
    pub timeout_seconds: Option<u64>,
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub domain: String,
    pub scope: Vec<String>,
    pub notes: Option<String>,
    pub tags: HashMap<String, String>,
    pub added_at: String,
}

impl Config {
    /// Create a new default configuration
    pub fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        Self {
            global: GlobalConfig {
                data_dir: home_dir.join(".bbhunt/data"),
                config_dir: home_dir.join(".bbhunt/config"),
                max_memory: 4096,  // 4GB
                max_cpu: num_cpus::get(),
                user_agent: format!("bbhunt/{}", env!("CARGO_PKG_VERSION")),
                default_profile: "standard".to_string(),
            },
            plugins: HashMap::new(),
            tools: HashMap::new(),
            profiles: HashMap::from([
                ("quick".to_string(), ProfileConfig {
                    max_concurrent_tasks: 8,
                    scan_mode: "basic".to_string(),
                    risk_level: Some("low".to_string()),
                    timeout_seconds: Some(300),
                }),
                ("standard".to_string(), ProfileConfig {
                    max_concurrent_tasks: 4,
                    scan_mode: "standard".to_string(),
                    risk_level: Some("medium".to_string()),
                    timeout_seconds: Some(600),
                }),
                ("thorough".to_string(), ProfileConfig {
                    max_concurrent_tasks: 2,
                    scan_mode: "thorough".to_string(),
                    risk_level: Some("high".to_string()),
                    timeout_seconds: Some(1800),
                }),
            ]),
            targets: HashMap::new(),
        }
    }
    
    /// Load configuration from a file or create default
    pub fn load(config_path: Option<&Path>) -> anyhow::Result<Self> {
        crate::config::loader::load_config(config_path)
    }
    
    /// Save configuration to a file
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let config_str = toml::to_string_pretty(self)?;
        std::fs::write(path, config_str)?;
        Ok(())
    }
}