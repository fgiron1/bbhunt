// src/app.rs
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::{Result, Context};
use tracing::{info, debug, error};

use crate::config::AppConfig;
use crate::plugin::PluginManager;
use crate::target::TargetManager;
use crate::report::ReportManager;

/// Main application struct that holds all components and state
pub struct App {
    config: AppConfig,
    plugin_manager: Arc<PluginManager>,
    target_manager: Arc<TargetManager>,
    report_manager: Arc<ReportManager>,
    initialized: bool,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Self {
        let config = AppConfig::new();
        
        Self {
            config: config.clone(),
            plugin_manager: Arc::new(PluginManager::new(config.clone())),
            target_manager: Arc::new(TargetManager::new(config.clone())),
            report_manager: Arc::new(ReportManager::new(config.clone())),
            initialized: false,
        }
    }
    
    /// Initialize the application with a specific config file
    pub async fn initialize_with_config(&mut self, config_path: Option<&Path>) -> Result<()> {
        // Load configuration
        self.config.load(config_path).await?;
        
        // Initialize all managers
        self.plugin_manager.initialize().await?;
        self.target_manager.initialize().await?;
        self.report_manager.initialize().await?;
        
        self.initialized = true;
        info!("Application initialized successfully");
        Ok(())
    }
    
    /// Initialize with default configuration
    pub async fn initialize(&mut self) -> Result<()> {
        self.initialize_with_config(None).await
    }
    
    /// Run a specific command
    pub async fn run_command(&self, command: &Command) -> Result<()> {
        if !self.initialized {
            return Err(anyhow::anyhow!("Application not initialized"));
        }
        
        match command {
            Command::Target(target_cmd) => self.handle_target_command(target_cmd).await,
            Command::Scan(scan_cmd) => self.handle_scan_command(scan_cmd).await,
            Command::Report(report_cmd) => self.handle_report_command(report_cmd).await,
            Command::Plugin(plugin_cmd) => self.handle_plugin_command(plugin_cmd).await,
            Command::Parallel(parallel_cmd) => self.handle_parallel_command(parallel_cmd).await,
        }
    }
    
    /// Handle target-related commands
    async fn handle_target_command(&self, command: &TargetCommand) -> Result<()> {
        match command {
            TargetCommand::Add { name, domain, ip, cidr } => {
                info!("Adding target: {}", name);
                let target_id = self.target_manager.create_target(name, None).await?;
                
                // Add domains if specified
                if let Some(domains) = domain {
                    for d in domains {
                        self.target_manager.add_domain(&target_id, d).await?;
                    }
                }
                
                // Add IP addresses if specified
                if let Some(ips) = ip {
                    for ip_str in ips {
                        self.target_manager.add_ip_address(&target_id, ip_str).await?;
                    }
                }
                
                // Add CIDR ranges if specified
                if let Some(cidrs) = cidr {
                    for cidr_str in cidrs {
                        self.target_manager.add_ip_range(&target_id, cidr_str).await?;
                    }
                }
                
                info!("Target added successfully with ID: {}", target_id);
                Ok(())
            },
            TargetCommand::List => {
                println!("Available targets:");
                
                let targets = self.target_manager.list_targets().await?;
                for target in targets {
                    println!("- {} ({})", target.name, target.id);
                }
                
                Ok(())
            },
            TargetCommand::Show { name } => {
                // Find target by name or ID
                let target = self.target_manager.get_target_by_name_or_id(name).await?;
                
                println!("Target: {} (ID: {})", target.name, target.id);
                
                if let Some(desc) = &target.description {
                    println!("Description: {}", desc);
                }
                
                if let Some(domain) = &target.primary_domain {
                    println!("Primary Domain: {}", domain);
                }
                
                if !target.domains.is_empty() {
                    println!("Domains:");
                    for domain in &target.domains {
                        println!("  - {}", domain);
                    }
                }
                
                if !target.subdomains.is_empty() {
                    println!("Subdomains ({})", target.subdomains.len());
                    for (i, subdomain) in target.subdomains.iter().enumerate().take(10) {
                        println!("  - {}", subdomain);
                    }
                    
                    if target.subdomains.len() > 10 {
                        println!("  ... and {} more", target.subdomains.len() - 10);
                    }
                }
                
                if !target.ip_addresses.is_empty() {
                    println!("IP Addresses:");
                    for ip in &target.ip_addresses {
                        println!("  - {}", ip);
                    }
                }
                
                Ok(())
            },
            TargetCommand::Delete { name } => {
                self.target_manager.delete_target_by_name_or_id(name).await?;
                println!("Target deleted successfully");
                Ok(())
            },
        }
    }
    
    /// Handle scan-related commands
    async fn handle_scan_command(&self, command: &ScanCommand) -> Result<()> {
        match command {
            ScanCommand::Run { plugin, target, options } => {
                info!("Running scan with plugin '{}' on target '{}'", plugin, target);
                
                // Parse options if provided
                let parsed_options = if let Some(opts_str) = options {
                    Some(serde_json::from_str(opts_str)
                        .context("Invalid JSON options")?)
                } else {
                    None
                };
                
                // Run the plugin
                let result = self.plugin_manager.run_plugin(plugin, target, parsed_options).await?;
                
                // Display results
                println!("Status: {:?}", result.status);
                println!("Message: {}", result.message);
                println!("Execution time: {:?}", result.execution_time);
                
                if !result.data.is_empty() {
                    println!("Results:");
                    let json = serde_json::to_string_pretty(&result.data)
                        .context("Failed to format results")?;
                    println!("{}", json);
                }
                
                Ok(())
            }
        }
    }
    
    /// Handle report-related commands
    async fn handle_report_command(&self, command: &ReportCommand) -> Result<()> {
        match command {
            ReportCommand::Generate { target, format, output, title } => {
                info!("Generating report for target: {}", target);
                
                // Get the target data
                let target_data = self.target_manager.get_target_by_name_or_id(target).await?;
                
                // Generate the report
                let report_paths = self.report_manager
                    .generate_report(&target_data, format, output.as_deref(), title.as_deref())
                    .await?;
                
                for path in report_paths {
                    println!("Report generated: {}", path.display());
                }
                
                Ok(())
            }
        }
    }
    
    /// Handle plugin-related commands
    async fn handle_plugin_command(&self, command: &PluginCommand) -> Result<()> {
        match command {
            PluginCommand::List { category } => {
                if let Some(cat_str) = category {
                    // Filter by category if specified
                    let plugins = self.plugin_manager.get_plugins_by_category(cat_str).await?;
                    
                    println!("{} plugins in category {}:", plugins.len(), cat_str);
                    
                    for plugin in plugins {
                        println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
                    }
                } else {
                    // Show all plugins
                    let plugins = self.plugin_manager.get_plugins().await?;
                    
                    println!("{} plugins available:", plugins.len());
                    
                    for plugin in plugins {
                        println!("- {} (v{}, {:?}): {}", 
                            plugin.name, plugin.version, plugin.category, plugin.description);
                    }
                }
                
                Ok(())
            }
        }
    }
    
    /// Handle parallel execution commands
    async fn handle_parallel_command(&self, command: &ParallelCommand) -> Result<()> {
        match command {
            ParallelCommand::Run { tasks, output, concurrent } => {
                info!("Running tasks from {} with concurrency {}", tasks.display(), concurrent);
                
                // Load tasks
                let task_definitions = self.plugin_manager.load_tasks(tasks)
                    .context(format!("Failed to load tasks from {}", tasks.display()))?;
                
                println!("Loaded {} tasks", task_definitions.len());
                
                // Execute tasks
                let results = self.plugin_manager.execute_tasks(task_definitions, *concurrent).await?;
                
                println!("Completed {} tasks", results.len());
                
                // Save results
                let json = serde_json::to_string_pretty(&results)
                    .context("Failed to serialize results")?;
                
                std::fs::write(output, json)
                    .context(format!("Failed to write results to {}", output.display()))?;
                
                println!("Results saved to {}", output.display());
                
                Ok(())
            },
            ParallelCommand::GenerateTasks { input, output, r#type, plugins, max_targets, options } => {
                info!("Generating {} tasks from {}", r#type, input.display());
                
                // Generate tasks
                let tasks = self.plugin_manager.generate_tasks(
                    input,
                    r#type,
                    plugins.as_deref(),
                    *max_targets,
                    options.as_deref(),
                ).await?;
                
                println!("Generated {} tasks", tasks.len());
                
                // Save tasks
                self.plugin_manager.save_tasks(&tasks, output).await?;
                
                println!("Tasks saved to {}", output.display());
                
                Ok(())
            }
        }
    }
    
    /// Get a reference to the config
    pub fn config(&self) -> &AppConfig {
        &self.config
    }
    
    /// Get a reference to the plugin manager
    pub fn plugin_manager(&self) -> &Arc<PluginManager> {
        &self.plugin_manager
    }
    
    /// Get a reference to the target manager
    pub fn target_manager(&self) -> &Arc<TargetManager> {
        &self.target_manager
    }
    
    /// Get a reference to the report manager
    pub fn report_manager(&self) -> &Arc<ReportManager> {
        &self.report_manager
    }
}

/// Command enum representing all possible CLI commands
#[derive(Debug, Clone)]
pub enum Command {
    Target(TargetCommand),
    Scan(ScanCommand),
    Report(ReportCommand),
    Plugin(PluginCommand),
    Parallel(ParallelCommand),
}

/// Target management commands
#[derive(Debug, Clone)]
pub enum TargetCommand {
    Add {
        name: String,
        domain: Option<Vec<String>>,
        ip: Option<Vec<String>>,
        cidr: Option<Vec<String>>,
    },
    List,
    Show {
        name: String,
    },
    Delete {
        name: String,
    },
}

/// Scan execution commands
#[derive(Debug, Clone)]
pub enum ScanCommand {
    Run {
        plugin: String,
        target: String,
        options: Option<String>,
    },
}

/// Report generation commands
#[derive(Debug, Clone)]
pub enum ReportCommand {
    Generate {
        target: String,
        format: Vec<String>,
        output: Option<PathBuf>,
        title: Option<String>,
    },
}

/// Plugin management commands
#[derive(Debug, Clone)]
pub enum PluginCommand {
    List {
        category: Option<String>,
    },
}

/// Parallel execution commands
#[derive(Debug, Clone)]
pub enum ParallelCommand {
    Run {
        tasks: PathBuf,
        output: PathBuf,
        concurrent: usize,
    },
    GenerateTasks {
        input: PathBuf,
        output: PathBuf,
        r#type: String,
        plugins: Option<String>,
        max_targets: usize,
        options: Option<String>,
    },
}