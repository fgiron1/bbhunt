// src/plugin.rs
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, Context, bail};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use tracing::{info, debug, error, warn};
use tokio::fs;
use tempfile::NamedTempFile;
use url::Url;

use crate::config::AppConfig;
use crate::report::{Severity, Reference, ReferenceType};
use crate::profile::{Profile, ProfileManager};
use crate::scope_filter::ScopeFilter;

/// Plugin manager for loading and executing plugins
#[derive(Clone)]
pub struct PluginManager {
    config: &'static AppConfig,
    profile_manager: Arc<ProfileManager>,
    plugins: Arc<tokio::sync::Mutex<HashMap<String, Box<dyn Plugin>>>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(config: &'static AppConfig, profile_manager: Arc<ProfileManager>) -> Self {
        Self {
            config,
            profile_manager,
            plugins: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Initialize the plugin manager
    pub async fn initialize(&self) -> Result<()> {
        // Register built-in plugins
        self.register_default_plugins().await?;
        
        info!("Plugin manager initialized successfully");
        Ok(())
    }
    
    /// Register built-in plugins
    async fn register_default_plugins(&self) -> Result<()> {
        // Create subdomain enumeration plugin
        let subdomain_plugin = SubdomainEnumPlugin::new(self.config);
        self.register_plugin("subdomain_enum", Box::new(subdomain_plugin)).await?;
        
        // Create web scanning plugin
        let web_scan_plugin = WebScanPlugin::new(self.config);
        self.register_plugin("web_scan", Box::new(web_scan_plugin)).await?;
        
        debug!("Registered default plugins");
        Ok(())
    }
    
    /// Register a plugin
    pub async fn register_plugin(&self, name: &str, plugin: Box<dyn Plugin>) -> Result<()> {
        let mut plugins = self.plugins.lock().await;
        
        if plugins.contains_key(name) {
            debug!("Plugin '{}' already exists, replacing", name);
        }
        
        plugins.insert(name.to_string(), plugin);
        debug!("Registered plugin: {}", name);
        
        Ok(())
    }
    
    /// Run a plugin with the specified target and options
    pub async fn run_plugin(
        &self, 
        plugin_name: &str, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        let mut plugins = self.plugins.lock().await;
        
        let plugin = plugins.get_mut(plugin_name)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", plugin_name))?;
        
        info!("Running plugin '{}' on target '{}'", plugin_name, target);
        
        let start_time = std::time::Instant::now();
        
        // Run the plugin
        let mut result = plugin.execute(target, options).await
            .context(format!("Failed to execute plugin: {}", plugin_name))?;
        
        // Set execution time
        result.execution_time = start_time.elapsed();
        
        info!("Plugin '{}' completed in {:?}", plugin_name, result.execution_time);
        
        Ok(result)
    }
    
    /// Run a plugin with profile-based settings
    pub async fn run_plugin_with_profile(
        &self, 
        plugin_name: &str, 
        target: &str, 
        options: Option<HashMap<String, Value>>,
        profile: Option<&Profile>
    ) -> Result<PluginResult> {
        let profile = if let Some(p) = profile {
            p.clone()
        } else {
            self.profile_manager.get_active_profile().await?
        };
        
        // Merge options from profile if available
        let merged_options = if let Some(mut opts) = options {
            // If profile has tool-specific options for this plugin, add them
            if let Some(tool_profile) = profile.tools.get(plugin_name) {
                for (key, value) in &tool_profile.options {
                    if !opts.contains_key(key) {
                        opts.insert(key.clone(), value.clone());
                    }
                }
            }
            
            // Add profile default options if not already set
            for (key, value) in &profile.default_options {
                if !opts.contains_key(key) {
                    opts.insert(key.clone(), value.clone());
                }
            }
            
            Some(opts)
        } else {
            // If no options provided, use profile options if available
            if let Some(tool_profile) = profile.tools.get(plugin_name) {
                if !tool_profile.options.is_empty() {
                    Some(tool_profile.options.clone())
                } else {
                    Some(profile.default_options.clone())
                }
            } else {
                Some(profile.default_options.clone())
            }
        };
        
        // Run the plugin with merged options
        self.run_plugin(plugin_name, target, merged_options).await
    }
    
    /// Get all available plugins
    pub async fn get_plugins(&self) -> Result<Vec<PluginMetadata>> {
        let plugins = self.plugins.lock().await;
        
        let metadata: Vec<PluginMetadata> = plugins.values()
            .map(|plugin| plugin.metadata())
            .collect();
        
        Ok(metadata)
    }
    
    /// Get plugins by category
    pub async fn get_plugins_by_category(&self, category: &str) -> Result<Vec<PluginMetadata>> {
        let plugins = self.plugins.lock().await;
        
        let category = match category.to_lowercase().as_str() {
            "recon" => PluginCategory::Recon,
            "scan" => PluginCategory::Scan,
            "exploit" => PluginCategory::Exploit,
            "utility" => PluginCategory::Utility,
            _ => bail!("Invalid category: {}", category),
        };
        
        let metadata: Vec<PluginMetadata> = plugins.values()
            .filter(|plugin| plugin.metadata().category == category)
            .map(|plugin| plugin.metadata())
            .collect();
        
        Ok(metadata)
    }
    
    /// Load task definitions from a file
    pub fn load_tasks(&self, path: &Path) -> Result<Vec<TaskDefinition>> {
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read tasks file: {}", path.display()))?;
            
        let tasks: Vec<TaskDefinition> = serde_json::from_str(&content)
            .context(format!("Failed to parse tasks JSON from {}", path.display()))?;
            
        Ok(tasks)
    }
    
    /// Load task definitions from a file and filter by scope
    pub fn load_tasks_with_scope(&self, path: &Path, profile: &Profile) -> Result<Vec<TaskDefinition>> {
        // Load tasks
        let tasks = self.load_tasks(path)?;
        let tasks_len = tasks.len();
        
        // Create scope filter from profile
        let scope_filter = ScopeFilter::new(&profile.scope)?;
        
        // Filter tasks by scope
        let filtered_tasks: Vec<TaskDefinition> = tasks.into_iter()
        .filter(|task| scope_filter.is_host_in_scope(&task.target))
        .collect();
        
        info!("Loaded {} tasks (filtered from {} by scope)", filtered_tasks.len(), tasks_len);
        
        Ok(filtered_tasks)
    }
    
    /// Save task definitions to a file
    pub async fn save_tasks(&self, tasks: &[TaskDefinition], path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(tasks)
            .context("Failed to serialize tasks")?;
            
        fs::write(path, json).await
            .context(format!("Failed to write tasks to {}", path.display()))?;
            
        Ok(())
    }
    
    /// Execute tasks in parallel
    pub async fn execute_tasks(
        &self, 
        tasks: Vec<TaskDefinition>, 
        max_concurrent: usize
    ) -> Result<Vec<TaskResult>> {
        if tasks.is_empty() {
            return Ok(Vec::new());
        }
        
        info!("Executing {} tasks with max concurrency {}", tasks.len(), max_concurrent);
        
        // Create a semaphore to limit concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        
        // Create a channel for results
        let (tx, mut rx) = tokio::sync::mpsc::channel(max_concurrent);
        
        // Track dependencies
        let mut completed_tasks = std::collections::HashSet::new();
        let mut pending_tasks: Vec<TaskDefinition> = tasks;
        let mut results = Vec::new();
        
        // Process tasks in dependency order
        while !pending_tasks.is_empty() {
            // Find tasks with satisfied dependencies
            let runnable_tasks: Vec<TaskDefinition> = pending_tasks
                .iter()
                .filter(|task| task.dependencies.iter().all(|dep| completed_tasks.contains(dep)))
                .cloned()
                .collect();
            
            if runnable_tasks.is_empty() && !pending_tasks.is_empty() {
                bail!("Circular dependency detected in tasks");
            }
            
            debug!("Found {} runnable tasks", runnable_tasks.len());
            
            // Launch tasks
            let mut handles = Vec::new();
            
            for task in runnable_tasks {
                let task_id = task.id.clone();
                let semaphore_clone = semaphore.clone();
                let tx_clone = tx.clone();
                let self_clone = self.clone();
                
                let handle = tokio::spawn(async move {
                    // Acquire a permit from the semaphore
                    let _permit = semaphore_clone.acquire().await
                        .expect("Failed to acquire semaphore permit");
                    
                    // Execute the task
                    let result = match self_clone.run_plugin(&task.plugin, &task.target, task.options).await {
                        Ok(plugin_result) => {
                            
                            let execution_time = plugin_result.execution_time;
                            TaskResult {
                                task_id: task.id.clone(),
                                plugin: task.plugin.clone(),
                                target: task.target.clone(),
                                status: TaskStatus::Completed,
                                result: Some(plugin_result), // plugin_result moved here
                                error: None,
                                execution_time, // Use the stored value
                            }
                        },
                        Err(e) => {
                            error!("Task {} failed: {}", task.id, e);
                            TaskResult {
                                task_id: task.id.clone(),
                                plugin: task.plugin.clone(),
                                target: task.target.clone(),
                                status: TaskStatus::Failed,
                                result: None,
                                error: Some(e.to_string()),
                                execution_time: Duration::from_secs(0),
                            }
                        }
                    };
                    
                    // Send the result
                    tx_clone.send(result).await
                        .expect("Failed to send task result");
                });
                
                handles.push(handle);
                
                // Mark as completed for dependency tracking
                completed_tasks.insert(task_id);
            }
            
            // Remove processed tasks from pending
            pending_tasks.retain(|task| !completed_tasks.contains(&task.id));
            
            // Wait for all spawned tasks to complete
            for handle in handles {
                if let Err(e) = handle.await {
                    error!("Task execution failed: {}", e);
                }
            }
        }
        
        // Drop the sender to close the channel
        drop(tx);
        
        // Collect all results
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Execute tasks with profile-based settings
    pub async fn execute_tasks_with_profile(
        &self,
        tasks: Vec<TaskDefinition>,
        max_concurrent: usize,
        profile: &Profile
    ) -> Result<Vec<TaskResult>> {
        // Override concurrency with profile setting if not explicitly specified
        let concurrency = if max_concurrent > 0 {
            max_concurrent
        } else {
            profile.resource_limits.max_concurrent_tasks
        };
        
        // TODO: Apply more profile settings to task execution
        
        self.execute_tasks(tasks, concurrency).await
    }
    
    /// Generate tasks from previous results
    pub async fn generate_tasks(
        &self,
        input_path: &Path,
        task_type: &str,
        plugins: Option<&str>,
        max_targets_per_task: usize,
        options_str: Option<&str>,
    ) -> Result<Vec<TaskDefinition>> {
        info!("Generating {} tasks from {}", task_type, input_path.display());
        
        // Parse task type
        let task_type = match task_type.to_lowercase().as_str() {
            "recon" => TaskType::Recon,
            "scan" => TaskType::Scan,
            "exploit" => TaskType::Exploit,
            _ => bail!("Invalid task type: {}", task_type),
        };
        
        // Load results from input file
        let content = fs::read_to_string(input_path).await
            .context(format!("Failed to read input file: {}", input_path.display()))?;
            
        let results: Vec<TaskResult> = serde_json::from_str(&content)
            .context(format!("Failed to parse results JSON from {}", input_path.display()))?;
        
        // Parse plugins
        let plugin_list = if let Some(p) = plugins {
            p.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            // Default plugins based on task type
            match task_type {
                TaskType::Recon => vec!["subdomain_enum".to_string()],
                TaskType::Scan => vec!["web_scan".to_string()],
                TaskType::Exploit => Vec::new(),
            }
        };
        
        // Parse options
        let options = if let Some(opts) = options_str {
            Some(serde_json::from_str(opts)
                .context("Invalid JSON options")?)
        } else {
            None
        };
        
        let mut targets = Vec::new();
        
        // Extract targets from results based on task type
        for result in &results {
            if let Some(plugin_result) = &result.result {
                match task_type {
                    TaskType::Recon => {
                        // For recon -> scan, extract discovered hosts/domains
                        if let Some(subdomains) = plugin_result.data.get("subdomains") {
                            if let Value::Array(subdomains) = subdomains {
                                for subdomain in subdomains {
                                    if let Value::String(domain) = subdomain {
                                        targets.push(domain.clone());
                                    }
                                }
                            }
                        }
                    },
                    TaskType::Scan => {
                        // For scan -> exploit, extract vulnerable URLs
                        if let Some(vulnerabilities) = plugin_result.data.get("vulnerabilities") {
                            if let Value::Array(vulnerabilities) = vulnerabilities {
                                for vuln in vulnerabilities {
                                    if let Some(Value::String(url)) = vuln.get("url") {
                                        targets.push(url.clone());
                                    }
                                }
                            }
                        }
                    },
                    TaskType::Exploit => {
                        // Custom logic for exploit task generation
                    }
                }
            }
        }
        
        // Remove duplicates
        targets.sort();
        targets.dedup();
        
        debug!("Found {} unique targets", targets.len());
        
        // Generate tasks
        let mut tasks = Vec::new();
        
        for plugin in &plugin_list {
            // Process targets in chunks
            for (chunk_idx, chunk) in targets.chunks(max_targets_per_task).enumerate() {
                for target in chunk {
                    let task_id = format!("{}-{}-{}", 
                        task_type.to_string().to_lowercase(), 
                        plugin, 
                        chunk_idx);
                        
                    let task = TaskDefinition {
                        id: task_id,
                        plugin: plugin.clone(),
                        target: target.clone(),
                        options: options.clone(),
                        dependencies: Vec::new(),
                    };
                    
                    tasks.push(task);
                }
            }
        }
        
        info!("Generated {} tasks", tasks.len());
        Ok(tasks)
    }
}

/// Trait that all plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> PluginMetadata;
    
    /// Execute the plugin with the given target and options
    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult>;
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: PluginCategory,
    pub author: String,
    pub required_tools: Vec<String>,
}

/// Plugin category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCategory {
    Recon,
    Scan,
    Exploit,
    Utility,
}

impl std::fmt::Display for PluginCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginCategory::Recon => write!(f, "Recon"),
            PluginCategory::Scan => write!(f, "Scan"),
            PluginCategory::Exploit => write!(f, "Exploit"),
            PluginCategory::Utility => write!(f, "Utility"),
        }
    }
}

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub status: PluginStatus,
    pub message: String,
    pub data: HashMap<String, Value>,
    pub execution_time: Duration,
}

/// Plugin status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginStatus {
    Success,
    Error,
    Partial,
}

/// Task definition for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub id: String,
    pub plugin: String,
    pub target: String,
    pub options: Option<HashMap<String, Value>>,
    pub dependencies: Vec<String>,
}

/// Task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub plugin: String,
    pub target: String,
    pub status: TaskStatus,
    pub result: Option<PluginResult>,
    pub error: Option<String>,
    pub execution_time: Duration,
}

/// Task status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Timeout,
}

/// Task type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskType {
    Recon,
    Scan,
    Exploit,
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskType::Recon => write!(f, "Recon"),
            TaskType::Scan => write!(f, "Scan"),
            TaskType::Exploit => write!(f, "Exploit"),
        }
    }
}

/// Execute shell command
async fn execute_command(cmd: &str, timeout_secs: Option<u64>) -> Result<std::process::Output> {
    debug!("Executing command{}: {}", 
           timeout_secs.map_or("".to_string(), |t| format!(" with timeout {}", t)), 
           cmd);
    
    let command_future = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    
    let output = match timeout_secs {
        Some(secs) => {
            tokio::time::timeout(std::time::Duration::from_secs(secs), command_future)
                .await
                .map_err(|_| anyhow::anyhow!("Command timed out after {} seconds: {}", secs, cmd))?
        },
        None => command_future.await,
    }.context(format!("Failed to execute command: {}", cmd))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Command failed: {}\nStderr: {}", cmd, stderr);
    } else {
        debug!("Command succeeded: {}", cmd);
    }
    
    Ok(output)
}

// ---------------------------------------------------------------------------
// PLUGIN IMPLEMENTATIONS
// ---------------------------------------------------------------------------

/// Vulnerability structure for plugin results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub url: String,
    pub cvss_score: Option<f32>,
    pub cve_ids: Vec<String>,
    pub evidence: String,
    pub remediation: Option<String>,
    pub references: Vec<Reference>,
    pub tags: Vec<String>,
}

/// Subdomain enumeration plugin
pub struct SubdomainEnumPlugin {
    config: &'static AppConfig,
    metadata: PluginMetadata,
    http_client: Option<reqwest::Client>,
}

impl SubdomainEnumPlugin {
    /// Create a new subdomain enumeration plugin
    pub fn new(config: &'static AppConfig) -> Self {
        Self {
            config,
            metadata: PluginMetadata {
                name: "subdomain_enum".to_string(),
                description: "Enumerate subdomains using various techniques".to_string(),
                version: "0.1.0".to_string(),
                category: PluginCategory::Recon,
                author: "BBHunt Team".to_string(),
                required_tools: vec!["subfinder".to_string(), "amass".to_string()],
            },
            http_client: None,
        }
    }
    
    /// Initialize HTTP client
    fn init_http_client(&mut self) -> Result<()> {
        if self.http_client.is_none() {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("Failed to create HTTP client")?;
                
            self.http_client = Some(client);
        }
        
        Ok(())
    }
    
    /// Run a subdomain enumeration tool
    async fn run_subdomain_tool(
        &self, 
        target: &str, 
        tool_name: &str, 
        command_template: &str
    ) -> Result<Vec<String>> {
        debug!("Running subdomain tool {} on target {}", tool_name, target);
        
        // Create temporary output file
        let output_file = NamedTempFile::new()
            .context("Failed to create temporary file")?;
            
        let output_path = output_file.path().to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))?;
        
        // Format command
        let command = command_template
            .replace("{target}", target)
            .replace("{output}", output_path);
        
        // Execute command
        let output = execute_command(&command, None).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Subdomain tool {} failed: {}", tool_name, stderr);
        }
        
        // Read results
        let content = tokio::fs::read_to_string(output_path).await
            .context(format!("Failed to read output from {}", output_path))?;
        
        // Parse results
        let subdomains: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();
        
        debug!("Found {} subdomains with {}", subdomains.len(), tool_name);
        Ok(subdomains)
    }
    
    /// Verify which subdomains are live
    async fn verify_live_subdomains(&self, subdomains: &[String]) -> Result<Vec<String>> {
        debug!("Verifying {} subdomains", subdomains.len());
        
        let client = self.http_client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not initialized"))?;
        
        let mut live_subdomains = Vec::new();
        
        for subdomain in subdomains {
            let https_url = format!("https://{}", subdomain);
            let http_url = format!("http://{}", subdomain);
            
            // Try HTTPS first
            match client.head(&https_url).timeout(std::time::Duration::from_secs(5)).send().await {
                Ok(_) => {
                    debug!("Subdomain {} is live (HTTPS)", subdomain);
                    live_subdomains.push(subdomain.clone());
                    continue;
                },
                Err(e) => {
                    debug!("HTTPS check for {} failed: {}", subdomain, e);
                }
            }
            
            // Then try HTTP
            match client.head(&http_url).timeout(std::time::Duration::from_secs(5)).send().await {
                Ok(_) => {
                    debug!("Subdomain {} is live (HTTP)", subdomain);
                    live_subdomains.push(subdomain.clone());
                },
                Err(e) => {
                    debug!("HTTP check for {} failed: {}", subdomain, e);
                }
            }
        }
        
        info!("Verified {} live subdomains out of {}", live_subdomains.len(), subdomains.len());
        Ok(live_subdomains)
    }
}

#[async_trait]
impl Plugin for SubdomainEnumPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }
    
    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        info!("Running subdomain enumeration on target: {}", target);
        
        // Initialize HTTP client
        self.init_http_client()?;
        
        // Parse options
        let passive_only = options
            .as_ref()
            .and_then(|opts| opts.get("passive_only"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        debug!("Passive mode: {}", passive_only);
        
        // Define tools
        let tools = vec![
            ("subfinder", "subfinder -d {target} -o {output}", false),
            ("amass", "amass enum -d {target} -o {output}", false),
        ];
        
        let mut all_subdomains = Vec::new();
        
        // Run each tool
        for (tool_name, command_template, is_passive) in tools {
            // Skip tools based on passive mode
            if passive_only && !is_passive {
                debug!("Skipping {} in passive mode", tool_name);
                continue;
            }
            
            match self.run_subdomain_tool(target, tool_name, command_template).await {
                Ok(subdomains) => {
                    info!("Found {} subdomains with {}", subdomains.len(), tool_name);
                    all_subdomains.extend(subdomains);
                },
                Err(e) => {
                    error!("Error running {}: {}", tool_name, e);
                    // Continue with other tools
                }
            }
        }
        
        // Deduplicate subdomains
        all_subdomains.sort();
        all_subdomains.dedup();
        
        // Verify live subdomains
        let live_subdomains = match self.verify_live_subdomains(&all_subdomains).await {
            Ok(live) => live,
            Err(e) => {
                error!("Error verifying live subdomains: {}", e);
                Vec::new()
            }
        };
        
        // Build result
        let mut result_data = HashMap::new();
        result_data.insert("total_subdomains".to_string(), Value::Number(all_subdomains.len().into()));
        result_data.insert("live_subdomains".to_string(), Value::Number(live_subdomains.len().into()));
        result_data.insert("subdomains".to_string(), Value::Array(
            all_subdomains.iter().map(|s| Value::String(s.clone())).collect()
        ));
        
        Ok(PluginResult {
            status: PluginStatus::Success,
            message: format!("Found {} total subdomains, {} live", all_subdomains.len(), live_subdomains.len()),
            data: result_data,
            execution_time: Duration::default(), // Will be set by plugin manager
        })
    }
}

/// Web scanning plugin
pub struct WebScanPlugin {
    config: &'static AppConfig,
    metadata: PluginMetadata,
    http_client: Option<reqwest::Client>,
}

impl WebScanPlugin {
    /// Create a new web scanning plugin
    pub fn new(config: &'static AppConfig) -> Self {
        Self {
            config,
            metadata: PluginMetadata {
                name: "web_scan".to_string(),
                description: "Scan web applications for vulnerabilities".to_string(),
                version: "0.1.0".to_string(),
                category: PluginCategory::Scan,
                author: "BBHunt Team".to_string(),
                required_tools: vec!["nuclei".to_string(), "nikto".to_string()],
            },
            http_client: None,
        }
    }
    
    /// Initialize HTTP client
    fn init_http_client(&mut self) -> Result<()> {
        if self.http_client.is_none() {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("Failed to create HTTP client")?;
                
            self.http_client = Some(client);
        }
        
        Ok(())
    }
    
    /// Run a web scan tool
    async fn run_web_scan_tool(
        &self, 
        target: &Url, 
        tool_name: &str, 
        command_template: &str
    ) -> Result<Vec<Vulnerability>> {
        debug!("Running web scan tool {} on target {}", tool_name, target);
        
        // Create temporary output file
        let output_file = NamedTempFile::new()
            .context("Failed to create temporary file")?;
            
        let output_path = output_file.path().to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))?;
        
        // Format command
        let command = command_template
            .replace("{target}", &target.to_string())
            .replace("{output}", output_path);
        
        // Execute command
        let output = execute_command(&command, Some(600)).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Web scan tool {} failed: {}", tool_name, stderr);
        }
        
        // Parse results based on tool
        let vulnerabilities = match tool_name {
            "nuclei" => self.parse_nuclei_results(output_file.path()).await?,
            "nikto" => self.parse_nikto_results(output_file.path()).await?,
            _ => Vec::new(),
        };
        
        debug!("Found {} vulnerabilities with {}", vulnerabilities.len(), tool_name);
        Ok(vulnerabilities)
    }
    
    /// Parse Nuclei results
    async fn parse_nuclei_results(&self, output_path: &Path) -> Result<Vec<Vulnerability>> {
        // Read file content
        let content = tokio::fs::read_to_string(output_path).await
            .context("Failed to read Nuclei results")?;
        
        let mut vulnerabilities = Vec::new();
        
        // Nuclei typically outputs JSON lines
        for line in content.lines() {
            // Try to parse as JSON
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                // Extract vulnerability data
                if let Some(name) = value.get("info").and_then(|i| i.get("name")).and_then(|n| n.as_str()) {
                    let severity = value.get("info").and_then(|i| i.get("severity")).and_then(|s| s.as_str())
                        .map(|s| match s.to_lowercase().as_str() {
                            "critical" => Severity::Critical,
                            "high" => Severity::High,
                            "medium" => Severity::Medium,
                            "low" => Severity::Low,
                            _ => Severity::Info,
                        })
                        .unwrap_or(Severity::Info);
                    
                    let url = value.get("host").and_then(|h| h.as_str()).unwrap_or("").to_string();
                    
                    vulnerabilities.push(Vulnerability {
                        name: name.to_string(),
                        description: value.get("info")
                            .and_then(|i| i.get("description"))
                            .and_then(|d| d.as_str())
                            .unwrap_or("No description available")
                            .to_string(),
                        severity,
                        url,
                        cvss_score: value.get("info")
                            .and_then(|i| i.get("classification"))
                            .and_then(|c| c.get("cvss-score"))
                            .and_then(|s| s.as_f64())
                            .map(|s| s as f32),
                        cve_ids: value.get("info")
                            .and_then(|i| i.get("classification"))
                            .and_then(|c| c.get("cve-id"))
                            .and_then(|c| c.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect())
                            .unwrap_or_default(),
                        evidence: value.get("matched-at")
                            .and_then(|m| m.as_str())
                            .unwrap_or("No evidence available")
                            .to_string(),
                        remediation: value.get("info")
                            .and_then(|i| i.get("remediation"))
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string()),
                        references: value.get("info")
                            .and_then(|i| i.get("reference"))
                            .and_then(|r| r.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str().map(|s| 
                                    Reference {
                                        title: s.to_string(),
                                        url: s.to_string(),
                                        source_type: ReferenceType::Other,
                                    }
                                ))
                                .collect())
                            .unwrap_or_default(),
                        tags: value.get("info")
                            .and_then(|i| i.get("tags"))
                            .and_then(|t| t.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect())
                            .unwrap_or_default(),
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Parse Nikto results
    async fn parse_nikto_results(&self, output_path: &Path) -> Result<Vec<Vulnerability>> {
        // Read file content
        let content = tokio::fs::read_to_string(output_path).await
            .context("Failed to read Nikto results")?;
        
        let mut vulnerabilities = Vec::new();
        
        // Nikto typically outputs in a specific format
        for line in content.lines() {
            if line.contains("+ ") {
                // Example: "+ OSVDB-3092: /admin/: This might be interesting..."
                let parts: Vec<&str> = line.splitn(2, ": ").collect();
                
                if parts.len() == 2 {
                    let id_part = parts[0];
                    let description = parts[1].to_string();
                    
                    // Extract ID
                    let id = id_part.trim_start_matches("+ ").to_string();
                    
                    // Determine severity (simplified)
                    let severity = if description.to_lowercase().contains("critical") {
                        Severity::Critical
                    } else if description.to_lowercase().contains("high") {
                        Severity::High
                    } else if description.to_lowercase().contains("medium") {
                        Severity::Medium
                    } else if description.to_lowercase().contains("low") {
                        Severity::Low
                    } else {
                        Severity::Info
                    };
                    
                    vulnerabilities.push(Vulnerability {
                        name: id.clone(),
                        description,
                        severity,
                        url: "".to_string(), // We would need to extract this from the result
                        cvss_score: None,
                        cve_ids: Vec::new(),
                        evidence: line.to_string(),
                        remediation: None,
                        references: Vec::new(),
                        tags: vec![id],
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    /// Categorize vulnerabilities by severity
    fn categorize_vulnerabilities(&self, vulnerabilities: &[Vulnerability]) -> HashMap<String, usize> {
        let mut severity_counts = HashMap::new();
        
        for vuln in vulnerabilities {
            let severity_key = match vuln.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            
            *severity_counts.entry(severity_key.to_string()).or_insert(0) += 1;
        }
        
        severity_counts
    }
}

#[async_trait]
impl Plugin for WebScanPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }
    
    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        info!("Running web scan on target: {}", target);
        
        // Initialize HTTP client
        self.init_http_client()?;
        
        // Parse options
        let scan_mode = options
            .as_ref()
            .and_then(|opts| opts.get("mode"))
            .and_then(|v| v.as_str())
            .unwrap_or("standard");
        
        debug!("Scan mode: {}", scan_mode);

        // Validate and parse URL
        let parsed_url = Url::parse(target)
            .or_else(|_| Url::parse(&format!("https://{}", target)))
            .context("Invalid target URL")?;

        // Define tools
        let tools = vec![
            ("nuclei", "nuclei -target {target} -output {output} -json", "medium"),
            ("nikto", "nikto -h {target} -output {output} -Format txt", "low"),
        ];
        
        let mut vulnerabilities = Vec::new();
        
        // Run each tool based on scan mode
        for (tool_name, command_template, risk_level) in tools {
            // Filter tools based on scan mode and risk level
            let should_run = match (scan_mode, risk_level) {
                ("basic", "low") => true,
                ("standard", "low") | ("standard", "medium") => true,
                ("thorough", _) => true,
                _ => false,
            };
            
            if should_run {
                debug!("Running scan tool: {}", tool_name);
                
                match self.run_web_scan_tool(&parsed_url, tool_name, command_template).await {
                    Ok(found_vulns) => {
                        info!("Found {} vulnerabilities with {}", found_vulns.len(), tool_name);
                        vulnerabilities.extend(found_vulns);
                    },
                    Err(e) => {
                        error!("Error running {}: {}", tool_name, e);
                        // Continue with other tools
                    }
                }
            } else {
                debug!("Skipping scan tool {} for mode {}", tool_name, scan_mode);
            }
        }
        
        // Analyze and categorize vulnerabilities
        let severity_counts = self.categorize_vulnerabilities(&vulnerabilities);
        
        // Build result data
        let mut result_data = HashMap::new();
        result_data.insert("total_vulnerabilities".to_string(), Value::Number(vulnerabilities.len().into()));
        result_data.insert("severity_counts".to_string(), serde_json::to_value(severity_counts)?);
        
        // Add vulnerabilities to result data
        result_data.insert("vulnerabilities".to_string(), serde_json::to_value(&vulnerabilities)?);
        
        Ok(PluginResult {
            status: PluginStatus::Success,
            message: format!("Found {} vulnerabilities", vulnerabilities.len()),
            data: result_data,
            execution_time: Duration::default(), // Will be set by plugin manager
        })
    }
}