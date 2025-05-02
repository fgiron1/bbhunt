// src/profile/mod.rs - Global profile system implementation
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use tokio::fs;
use tracing::{info, debug};

/// Profile manager for handling tool and global profiles
pub struct ProfileManager {
    config_dir: PathBuf,
    profiles: Arc<tokio::sync::RwLock<HashMap<String, Profile>>>,
    active_profile: Arc<tokio::sync::RwLock<String>>,
}

/// Complete profile configuration that can apply globally or be overridden per-tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    // Basic information
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    
    // Resource limits
    #[serde(default)]
    pub resource_limits: ResourceLimits,
    
    // Scope configuration
    #[serde(default)]
    pub scope: ScopeConfig,
    
    // Tool configurations - tool_name -> tool_profile
    #[serde(default)]
    pub tools: HashMap<String, ToolProfile>,
    
    // HTTP settings
    #[serde(default)]
    pub http: HttpConfig,
    
    // Authentication configuration
    #[serde(default)]
    pub authentication: HashMap<String, AuthConfig>,
    
    // Custom environment variables
    #[serde(default)]
    pub environment: HashMap<String, String>,
    
    // Default options for all tools if not specified
    #[serde(default)]
    pub default_options: HashMap<String, serde_json::Value>,
    
    // Whether this profile is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    // Program-specific configurations
    #[serde(default)]
    pub program_configs: HashMap<String, ProgramConfig>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: Some("Default profile with standard settings".to_string()),
            tags: vec!["default".to_string()],
            resource_limits: ResourceLimits::default(),
            scope: ScopeConfig::default(),
            tools: HashMap::new(),
            http: HttpConfig::default(),
            authentication: HashMap::new(),
            environment: HashMap::new(),
            default_options: HashMap::new(),
            enabled: true,
            program_configs: HashMap::new(),
        }
    }
}

fn default_true() -> bool { true }

/// Resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    // Maximum concurrent tasks
    #[serde(default = "default_concurrent_tasks")]
    pub max_concurrent_tasks: usize,
    
    // Maximum requests per second (rate limiting)
    #[serde(default = "default_max_rps")]
    pub max_requests_per_second: u32,
    
    // Timeout in seconds for each task
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    
    // Maximum memory usage in MB
    #[serde(default = "default_memory")]
    pub max_memory_mb: usize,
    
    // Maximum CPU usage (percentage 0-100)
    #[serde(default = "default_cpu")]
    pub max_cpu_percent: usize,
    
    // Scan mode (basic, standard, thorough)
    #[serde(default = "default_scan_mode")]
    pub scan_mode: String,
    
    // Risk level (low, medium, high)
    #[serde(default = "default_risk_level")]
    pub risk_level: String,
}

// Default values
fn default_concurrent_tasks() -> usize { 4 }
fn default_max_rps() -> u32 { 10 }
fn default_timeout() -> u64 { 300 }
fn default_memory() -> usize { 1024 }
fn default_cpu() -> usize { 50 }
fn default_scan_mode() -> String { "standard".to_string() }
fn default_risk_level() -> String { "medium".to_string() }

/// Scope configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeConfig {
    // Domains to include
    #[serde(default)]
    pub include_domains: Vec<String>,
    
    // Domains to exclude (takes precedence)
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    
    // IP ranges to include
    #[serde(default)]
    pub include_ips: Vec<String>,
    
    // IP ranges to exclude
    #[serde(default)]
    pub exclude_ips: Vec<String>,
    
    // URL paths to exclude
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    
    // Whether to follow redirects outside scope
    #[serde(default)]
    pub follow_out_of_scope_redirects: bool,
    
    // Maximum crawl depth
    #[serde(default = "default_crawl_depth")]
    pub max_crawl_depth: usize,
}

fn default_crawl_depth() -> usize { 3 }

/// HTTP configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpConfig {
    // User agent string
    pub user_agent: Option<String>,
    
    // Default headers to include in all requests
    #[serde(default)]
    pub headers: HashMap<String, String>,
    
    // Cookies to include
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    
    // Proxy configuration
    pub proxy: Option<String>,
    
    // Whether to use HTTPS
    #[serde(default = "default_true")]
    pub use_https: bool,
    
    // Whether to verify SSL certificates
    #[serde(default = "default_true")]
    pub verify_ssl: bool,
    
    // Follow redirects
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    
    // Maximum redirects to follow
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
}

fn default_max_redirects() -> usize { 10 }

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    // Authentication type
    pub auth_type: AuthType,
    
    // Username if applicable
    pub username: Option<String>,
    
    // Password if applicable
    pub password: Option<String>,
    
    // Token if applicable
    pub token: Option<String>,
    
    // API key if applicable
    pub api_key: Option<String>,
    
    // Custom parameters
    #[serde(default)]
    pub parameters: HashMap<String, String>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    None,
    Basic,
    Bearer,
    ApiKey,
    OAuth,
    Cookie,
    Custom,
}

/// Tool-specific profile
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolProfile {
    // Path to tool executable
    pub path: Option<PathBuf>,
    
    // Tool-specific configuration file
    pub config_file: Option<PathBuf>,
    
    // Command line arguments
    #[serde(default)]
    pub args: Vec<String>,
    
    // Tool-specific options
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
    
    // Tool-specific environment variables
    #[serde(default)]
    pub environment: HashMap<String, String>,
    
    // Tool-specific resource limits
    pub resource_limits: Option<ResourceLimits>,
    
    // Tool-specific HTTP settings
    pub http: Option<HttpConfig>,
}

/// Program-specific configuration (for bug bounty programs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramConfig {
    // Program name
    pub name: String,
    
    // Program-specific scope
    #[serde(default)]
    pub scope: ScopeConfig,
    
    // Program-specific user agent
    pub user_agent: Option<String>,
    
    // Program rules summary
    pub rules: Option<String>,
    
    // Program-specific rate limits
    pub rate_limit: Option<u32>,
    
    // Custom HTTP headers required by the program
    #[serde(default)]
    pub required_headers: HashMap<String, String>,
}

impl ProfileManager {
    /// Create a new profile manager
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            config_dir,
            profiles: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            active_profile: Arc::new(tokio::sync::RwLock::new("default".to_string())),
        }
    }
    
    /// Initialize the profile manager
    pub async fn initialize(&self) -> Result<()> {
        // Create profiles directory if it doesn't exist
        let profiles_dir = self.config_dir.join("profiles");
        
        if !profiles_dir.exists() {
            fs::create_dir_all(&profiles_dir).await
                .context(format!("Failed to create profiles directory: {}", profiles_dir.display()))?;
                
            // Create default profiles
            self.create_default_profiles().await?;
        }
        
        // Load all profiles
        self.load_all_profiles().await?;
        
        info!("Profile manager initialized successfully");
        Ok(())
    }
    
    /// Create default profiles
    async fn create_default_profiles(&self) -> Result<()> {
        // Default profile
        let default_profile = Profile {
            name: "default".to_string(),
            description: Some("Default profile with standard settings".to_string()),
            tags: vec!["default".to_string()],
            resource_limits: ResourceLimits::default(),
            scope: ScopeConfig::default(),
            tools: HashMap::new(),
            http: HttpConfig::default(),
            authentication: HashMap::new(),
            environment: HashMap::new(),
            default_options: HashMap::new(),
            enabled: true,
            program_configs: HashMap::new(),
        };
        
        self.save_profile(&default_profile).await?;
        
        // Safe profile with minimal impact
        let safe_profile = Profile {
            name: "safe".to_string(),
            description: Some("Safe profile with minimal resource usage and impact".to_string()),
            tags: vec!["safe".to_string(), "minimal".to_string()],
            resource_limits: ResourceLimits {
                max_concurrent_tasks: 1,
                max_requests_per_second: 2,
                timeout_seconds: 120,
                max_memory_mb: 512,
                max_cpu_percent: 25,
                scan_mode: "basic".to_string(),
                risk_level: "low".to_string(),
            },
            scope: ScopeConfig::default(),
            tools: HashMap::new(),
            http: HttpConfig::default(),
            authentication: HashMap::new(),
            environment: HashMap::new(),
            default_options: HashMap::new(),
            enabled: true,
            program_configs: HashMap::new(),
        };
        
        self.save_profile(&safe_profile).await?;
        
        // Audible profile
        let mut audible_http = HttpConfig::default();
        audible_http.user_agent = Some("audibleresearcher_yourh1username".to_string());
        
        let mut audible_scope = ScopeConfig::default();
        audible_scope.include_domains = vec!["*.audible.*".to_string()];
        audible_scope.exclude_domains = vec![
            "help.audible.com".to_string(),
            "newsletters.audible.com".to_string(),
            "www.audiblecareers.com".to_string(),
            "www.audible.com/ep/podcast-development-program".to_string(),
            "www.audiblehub.com/submit".to_string(),
            "www.audible.ca/blog/en".to_string(),
        ];
        audible_scope.exclude_paths = vec![
            "/careers".to_string(),
            "/jobs".to_string(),
            "/podcast-development-program".to_string(),
        ];
        
        // Nuclei tool config for Audible
        let mut nuclei_options = HashMap::new();
        nuclei_options.insert("tags".to_string(), serde_json::json!("cve,oast,injection"));
        nuclei_options.insert("exclude-tags".to_string(), serde_json::json!("dos,fuzzing,brute-force"));
        nuclei_options.insert("rate-limit".to_string(), serde_json::json!(5));
        
        let nuclei_profile = ToolProfile {
            path: None,
            config_file: None,
            args: vec![],
            options: nuclei_options,
            environment: HashMap::new(),
            resource_limits: None,
            http: None,
        };
        
        // Subfinder tool config for Audible
        let mut subfinder_options = HashMap::new();
        subfinder_options.insert("timeout".to_string(), serde_json::json!(30));
        subfinder_options.insert("max-time".to_string(), serde_json::json!(10));
        
        let subfinder_profile = ToolProfile {
            path: None,
            config_file: None,
            args: vec![],
            options: subfinder_options,
            environment: HashMap::new(),
            resource_limits: None,
            http: None,
        };
        
        // Create tool profiles map
        let mut tools = HashMap::new();
        tools.insert("nuclei".to_string(), nuclei_profile);
        tools.insert("subfinder".to_string(), subfinder_profile);
        
        // Program config for Audible
        let audible_program = ProgramConfig {
            name: "Audible Bug Bounty".to_string(),
            scope: audible_scope.clone(),
            user_agent: Some("audibleresearcher_yourh1username".to_string()),
            rules: Some("Follow responsible disclosure. Max 5 requests per second.".to_string()),
            rate_limit: Some(5),
            required_headers: {
                let mut headers = HashMap::new();
                headers.insert("User-Agent".to_string(), "audibleresearcher_yourh1username".to_string());
                headers
            },
        };
        
        let mut program_configs = HashMap::new();
        program_configs.insert("audible".to_string(), audible_program);
        
        let audible_profile = Profile {
            name: "audible".to_string(),
            description: Some("Profile for Audible bug bounty program".to_string()),
            tags: vec!["audible".to_string(), "bug-bounty".to_string()],
            resource_limits: ResourceLimits {
                max_concurrent_tasks: 2,
                max_requests_per_second: 5,
                timeout_seconds: 600,
                max_memory_mb: 1024,
                max_cpu_percent: 50,
                scan_mode: "standard".to_string(),
                risk_level: "medium".to_string(),
            },
            scope: audible_scope,
            tools,
            http: audible_http,
            authentication: HashMap::new(),
            environment: HashMap::new(),
            default_options: HashMap::new(),
            enabled: true,
            program_configs,
        };
        
        self.save_profile(&audible_profile).await?;
        
        info!("Created default profiles");
        Ok(())
    }
    
    /// Load all profiles from disk
    async fn load_all_profiles(&self) -> Result<()> {
        let profiles_dir = self.config_dir.join("profiles");
        
        if !profiles_dir.exists() {
            return Ok(());
        }
        
        let mut entries = fs::read_dir(&profiles_dir).await
            .context(format!("Failed to read profiles directory: {}", profiles_dir.display()))?;
            
        let mut loaded_count = 0;
        let mut profiles = self.profiles.write().await;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json" || ext == "toml") {
                if let Some(stem) = path.file_stem() {
                    if let Some(name) = stem.to_str() {
                        let content = fs::read_to_string(&path).await
                            .context(format!("Failed to read profile file: {}", path.display()))?;
                            
                        let profile: Profile = if path.extension().map_or(false, |ext| ext == "json") {
                            serde_json::from_str(&content)
                                .context(format!("Failed to parse JSON profile: {}", path.display()))?
                        } else {
                            toml::from_str(&content)
                                .context(format!("Failed to parse TOML profile: {}", path.display()))?
                        };
                        
                        if profile.enabled {
                            profiles.insert(name.to_string(), profile);
                            loaded_count += 1;
                        }
                    }
                }
            }
        }
        
        info!("Loaded {} profiles", loaded_count);
        Ok(())
    }
    
    /// Save a profile to disk
    pub async fn save_profile(&self, profile: &Profile) -> Result<()> {
        let profiles_dir = self.config_dir.join("profiles");
        
        if !profiles_dir.exists() {
            fs::create_dir_all(&profiles_dir).await
                .context(format!("Failed to create profiles directory: {}", profiles_dir.display()))?;
        }
        
        let profile_path = profiles_dir.join(format!("{}.json", profile.name));
        
        let json = serde_json::to_string_pretty(profile)
            .context("Failed to serialize profile")?;
            
        fs::write(&profile_path, json).await
            .context(format!("Failed to write profile file: {}", profile_path.display()))?;
            
        debug!("Saved profile {} to {}", profile.name, profile_path.display());
        
        // Update in-memory profile
        let mut profiles = self.profiles.write().await;
        profiles.insert(profile.name.clone(), profile.clone());
        
        Ok(())
    }
    
    /// Set the active profile
    pub async fn set_active_profile(&self, name: &str) -> Result<()> {
        let profiles = self.profiles.read().await;
        
        if !profiles.contains_key(name) {
            bail!("Profile not found: {}", name);
        }
        
        let mut active_profile = self.active_profile.write().await;
        *active_profile = name.to_string();
        
        info!("Active profile set to: {}", name);
        Ok(())
    }
    
    /// Get the active profile
    pub async fn get_active_profile(&self) -> Result<Profile> {
        let profiles = self.profiles.read().await;
        let active_profile = self.active_profile.read().await;
        
        profiles.get(&*active_profile)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Active profile not found: {}", *active_profile))
    }
    
    /// Get a profile by name
    pub async fn get_profile(&self, name: &str) -> Result<Profile> {
        let profiles = self.profiles.read().await;
        
        profiles.get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Profile not found: {}", name))
    }
    
    /// List all available profiles
    pub async fn list_profiles(&self) -> Vec<String> {
        let profiles = self.profiles.read().await;
        profiles.keys().cloned().collect()
    }

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
    
    /// Create a new profile
    pub async fn create_profile(&self, profile: Profile) -> Result<()> {
        self.save_profile(&profile).await
    }
    
    /// Get tool configuration for a specific tool within the active profile
    pub async fn get_tool_config_for_active_profile(&self, tool_name: &str) -> Result<ToolProfile> {
        let profile = self.get_active_profile().await?;
        
        profile.tools.get(tool_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Tool configuration not found for {} in profile {}", tool_name, profile.name))
    }
    
    /// Get tool configuration for a specific tool within a named profile
    pub async fn get_tool_config(&self, profile_name: &str, tool_name: &str) -> Result<ToolProfile> {
        let profile = self.get_profile(profile_name).await?;
        
        profile.tools.get(tool_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Tool configuration not found for {} in profile {}", tool_name, profile_name))
    }
    
    /// Create a configuration for a specific bug bounty program
    pub async fn create_program_profile(&self, program_name: &str, profile: Profile) -> Result<()> {
        self.save_profile(&profile).await
    }
    
    /// Get scope configuration for active profile
    pub async fn get_active_scope_config(&self) -> Result<ScopeConfig> {
        let profile = self.get_active_profile().await?;
        Ok(profile.scope)
    }
}

/// Helper methods for applying profiles to command execution
pub trait ProfileApplicable {
    /// Apply profile settings to a command
    fn apply_profile(&mut self, profile: &Profile, tool_name: &str) -> Result<()>;
    
    /// Apply tool-specific settings
    fn apply_tool_profile(&mut self, tool_profile: &ToolProfile) -> Result<()>;
    
    /// Apply resource limits
    fn apply_resource_limits(&mut self, limits: &ResourceLimits) -> Result<()>;
    
    /// Apply HTTP configuration
    fn apply_http_config(&mut self, http_config: &HttpConfig) -> Result<()>;
}

/// Command with profile application capability
pub struct ProfiledCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub timeout: Option<std::time::Duration>,
    pub current_dir: Option<PathBuf>,
}

impl ProfileApplicable for ProfiledCommand {
    fn apply_profile(&mut self, profile: &Profile, tool_name: &str) -> Result<()> {
        // Apply global resource limits
        self.apply_resource_limits(&profile.resource_limits)?;
        
        // Apply tool-specific settings if available
        if let Some(tool_profile) = profile.tools.get(tool_name) {
            self.apply_tool_profile(tool_profile)?;
            
            // Tool-specific resource limits override global
            if let Some(ref limits) = tool_profile.resource_limits {
                self.apply_resource_limits(limits)?;
            }
            
            // Tool-specific HTTP config
            if let Some(ref http_config) = tool_profile.http {
                self.apply_http_config(http_config)?;
            }
        }
        
        // Apply global HTTP config (if not already set by tool)
        self.apply_http_config(&profile.http)?;
        
        // Apply environment variables
        for (key, value) in &profile.environment {
            self.env.insert(key.clone(), value.clone());
        }
        
        Ok(())
    }
    
    fn apply_tool_profile(&mut self, tool_profile: &ToolProfile) -> Result<()> {
        // Set custom path if specified
        if let Some(ref path) = tool_profile.path {
            self.program = path.to_string_lossy().to_string();
        }
        
        // Add args from tool profile
        self.args.extend(tool_profile.args.clone());
        
        // Add environment variables
        for (key, value) in &tool_profile.environment {
            self.env.insert(key.clone(), value.clone());
        }
        
        // Add config file if specified
        if let Some(ref config_file) = tool_profile.config_file {
            self.args.push("--config".to_string());
            self.args.push(config_file.to_string_lossy().to_string());
        }
        
        // Add options
        for (key, value) in &tool_profile.options {
            self.args.push(format!("--{}", key));
            
            if !value.is_null() && !value.is_boolean() {
                self.args.push(value.to_string());
            }
        }
        
        Ok(())
    }
    
    fn apply_resource_limits(&mut self, limits: &ResourceLimits) -> Result<()> {
        // Set timeout
        self.timeout = Some(std::time::Duration::from_secs(limits.timeout_seconds));
        
        // CPU and memory limits would be applied at a system level
        // For now we just set corresponding args if the tool supports them
        
        // Common args for rate limiting
        self.args.push("--rate-limit".to_string());
        self.args.push(limits.max_requests_per_second.to_string());
        
        Ok(())
    }
    
    fn apply_http_config(&mut self, http_config: &HttpConfig) -> Result<()> {
        // User agent
        if let Some(ref user_agent) = http_config.user_agent {
            self.args.push("--user-agent".to_string());
            self.args.push(user_agent.clone());
            
            // Also set environment variable for tools that support it
            self.env.insert("HTTP_USER_AGENT".to_string(), user_agent.clone());
        }
        
        // Headers
        for (name, value) in &http_config.headers {
            self.args.push("--header".to_string());
            self.args.push(format!("{}: {}", name, value));
        }
        
        // Proxy
        if let Some(ref proxy) = http_config.proxy {
            self.args.push("--proxy".to_string());
            self.args.push(proxy.clone());
            
            // Also set environment variables for tools that use them
            self.env.insert("HTTP_PROXY".to_string(), proxy.clone());
            self.env.insert("HTTPS_PROXY".to_string(), proxy.clone());
        }
        
        // SSL verification
        if !http_config.verify_ssl {
            self.args.push("--no-verify".to_string());
        }
        
        // Follow redirects
        if !http_config.follow_redirects {
            self.args.push("--no-follow-redirects".to_string());
        } else {
            self.args.push("--max-redirects".to_string());
            self.args.push(http_config.max_redirects.to_string());
        }
        
        Ok(())
    }
}

/// Example of initialization and usage
pub async fn initialize_profile_manager(config_dir: &Path) -> Result<ProfileManager> {
    let manager = ProfileManager::new(config_dir.to_path_buf());
    manager.initialize().await?;
    
    // Set active profile to "audible" for the Audible bug bounty program
    manager.set_active_profile("audible").await?;
    
    Ok(manager)
}

pub async fn create_command_with_profile(
    profile_manager: &ProfileManager,
    tool_name: &str,
    base_args: Vec<String>,
) -> Result<ProfiledCommand> {
    let profile = profile_manager.get_active_profile().await?;
    
    let mut command = ProfiledCommand {
        program: tool_name.to_string(),
        args: base_args,
        env: HashMap::new(),
        timeout: None,
        current_dir: None,
    };
    
    command.apply_profile(&profile, tool_name)?;
    
    Ok(command)
}