// src/app.rs - Complete implementation with profile system integration
use std::path::{Path, PathBuf};
use std::sync::Arc;
use anyhow::{Result, Context, bail};
use tracing::info;

use crate::config::AppConfig;
use crate::plugin::PluginManager;
use crate::target::TargetManager;
use crate::report::ReportManager;
use crate::osint::OsintCollector;
use crate::profile::{Profile, ProfileManager};
use crate::scope_filter::ScopeFilter;

/// Main application struct that holds all components and state
pub struct App {
    config: AppConfig,
    plugin_manager: Arc<PluginManager>,
    target_manager: Arc<TargetManager>,
    report_manager: Arc<ReportManager>,
    osint_collector: Arc<OsintCollector>,
    profile_manager: Arc<ProfileManager>,
    initialized: bool,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Self {
        let config = AppConfig::new();
        let profile_manager = config.profile_manager();
        
        Self {
            config: config.clone(),
            plugin_manager: Arc::new(PluginManager::new(config.clone(), profile_manager.clone())),
            target_manager: Arc::new(TargetManager::new(config.clone())),
            report_manager: Arc::new(ReportManager::new(config.clone())),
            osint_collector: Arc::new(OsintCollector::new(config.clone())),
            profile_manager,
            initialized: false,
        }
    }

    // Required helper function for configuration
    pub async fn config_dir(&self) -> Result<PathBuf> {
        Ok(self.config.config_dir().await.clone())
    }
    
    // Required helper function for data directory
    pub async fn data_dir(&self) -> Result<PathBuf> {
        Ok(self.config.data_dir().await.clone())
    }
    
    // Required helper function for workflow manager
    pub fn workflow_manager(&self) -> &Arc<WorkflowManager> {
        // This is a placeholder - you'll need to add the actual WorkflowManager to your App struct
        // For now, we just need this to compile
        panic!("WorkflowManager not implemented yet");
    }
    
    
    /// Initialize the application with a specific config file
    pub async fn initialize_with_config(&mut self, config_path: Option<&Path>) -> Result<()> {
        // Load configuration
        self.config.load(config_path).await?;
        
        // Initialize all managers
        self.plugin_manager.initialize().await?;
        self.target_manager.initialize().await?;
        self.report_manager.initialize().await?;
        // Note: OSINT collector uses lazy initialization
        
        // Initialize profile manager (already initialized in config.load)
        
        self.initialized = true;
        info!("Application initialized successfully");
        Ok(())
    }
    
    /// Initialize with default configuration
    pub async fn initialize(&mut self) -> Result<()> {
        self.initialize_with_config(None).await
    }
    
    /// Run a specific command
    pub async fn run_command(&self, command: &Command, profile_name: Option<&str>) -> Result<()> {
        if !self.initialized {
            return Err(anyhow::anyhow!("Application not initialized"));
        }
        
        // Get profile
        let profile = if let Some(name) = profile_name {
            self.config.set_active_profile(name).await?;
            self.config.get_profile(name).await?
        } else {
            self.config.get_active_profile().await?
        };
        
        match command {
            Command::Target(target_cmd) => self.handle_target_command(target_cmd, &profile).await,
            Command::Scan(scan_cmd) => self.handle_scan_command(scan_cmd, &profile).await,
            Command::Report(report_cmd) => self.handle_report_command(report_cmd, &profile).await,
            Command::Plugin(plugin_cmd) => self.handle_plugin_command(plugin_cmd, &profile).await,
            Command::Parallel(parallel_cmd) => self.handle_parallel_command(parallel_cmd, &profile).await,
            Command::Osint(osint_cmd) => self.handle_osint_command(osint_cmd, &profile).await,
            Command::Profile(profile_cmd) => self.handle_profile_command(profile_cmd).await,
            Command::FilterScope(filter_cmd) => self.handle_filter_scope_command(filter_cmd, &profile).await,
        }
    }
    
    /// Handle target-related commands
    async fn handle_target_command(&self, command: &TargetCommand, profile: &Profile) -> Result<()> {
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
                    for subdomain in target.subdomains.iter().take(10) {
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
                
                // Show OSINT data if available
                if !target.osint_data.discovered_subdomains.is_empty() {
                    println!("\nOSINT Discovered Subdomains ({})", target.osint_data.discovered_subdomains.len());
                    for subdomain in target.osint_data.discovered_subdomains.iter().take(10) {
                        println!("  - {}", subdomain);
                    }
                    
                    if target.osint_data.discovered_subdomains.len() > 10 {
                        println!("  ... and {} more", target.osint_data.discovered_subdomains.len() - 10);
                    }
                }
                
                if target.osint_data.whois_data.is_some() {
                    println!("\nWHOIS Information Available");
                }
                
                if !target.osint_data.certificates.is_empty() {
                    println!("\nSSL Certificates: {}", target.osint_data.certificates.len());
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
    async fn handle_scan_command(&self, command: &ScanCommand, profile: &Profile) -> Result<()> {
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
                
                // Run the plugin with profile support
                let result = self.plugin_manager.run_plugin_with_profile(plugin, target, parsed_options, Some(profile)).await?;
                
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
    async fn handle_report_command(&self, command: &ReportCommand, profile: &Profile) -> Result<()> {
        match command {
            ReportCommand::Generate { target, format, output, title } => {
                info!("Generating report for target: {}", target);
                
                // Get the target data
                let target_data = self.target_manager.get_target_by_name_or_id(target).await?;
                
                // Generate the report using profile settings
                let report_paths = self.report_manager
                    .generate_report_with_profile(&target_data, format, output.as_deref(), title.as_deref(), profile)
                    .await?;
                
                for path in report_paths {
                    println!("Report generated: {}", path.display());
                }
                
                Ok(())
            }
        }
    }
    
    /// Handle plugin-related commands
    async fn handle_plugin_command(&self, command: &PluginCommand, profile: &Profile) -> Result<()> {
        match command {
            PluginCommand::List { category } => {
                if let Some(cat_str) = category {
                    // Filter by category
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
    
    /// Handle OSINT-related commands
    async fn handle_osint_command(&self, command: &OsintCommand, profile: &Profile) -> Result<()> {
        match command {
            OsintCommand::Collect { target, source } => {
                // Get target
                let mut target_data = self.target_manager.get_target_by_name_or_id(target).await?;
                
                if let Some(source_name) = source {
                    // Run specific OSINT source
                    info!("Running OSINT source {} on target '{}'", source_name, target);
                    self.osint_collector.collect_from_source(&mut target_data, source_name).await?;
                } else {
                    // Run all OSINT sources
                    info!("Running all OSINT sources on target '{}'", target);
                    self.osint_collector.collect_all(&mut target_data).await?;
                }
                
                // Save updated target data
                self.target_manager.save_target(&target_data).await?;
                
                // Display summary of collected data
                println!("OSINT collection completed for target '{}'", target);
                
                if !target_data.osint_data.discovered_subdomains.is_empty() {
                    println!("- Discovered {} subdomains", target_data.osint_data.discovered_subdomains.len());
                }
                
                if target_data.osint_data.whois_data.is_some() {
                    println!("- WHOIS information collected");
                }
                
                if !target_data.osint_data.certificates.is_empty() {
                    println!("- Collected {} SSL certificates", target_data.osint_data.certificates.len());
                }
                
                if !target_data.osint_data.dns_records.is_empty() {
                    let count: usize = target_data.osint_data.dns_records.values().map(|v| v.len()).sum();
                    println!("- Collected {} DNS records", count);
                }
                
                println!("\nUse 'target show {}' to see more details", target);
                
                Ok(())
            },
            OsintCommand::Sources => {
                // List available OSINT sources
                let sources = self.osint_collector.list_sources().await?;
                
                println!("{} OSINT sources available:", sources.len());
                for source in sources {
                    println!("- {}", source);
                }
                
                Ok(())
            }
        }
    }
    
    /// Handle parallel execution commands
    async fn handle_parallel_command(&self, command: &ParallelCommand, profile: &Profile) -> Result<()> {
        match command {
            ParallelCommand::Run { tasks, output, concurrent } => {
                // Override profile's concurrency if provided in command
                let concurrency = concurrent.unwrap_or(profile.resource_limits.max_concurrent_tasks);
                
                info!("Running tasks from {} with concurrency {}", tasks.display(), concurrency);
                
                // Load tasks and filter by scope
                let task_definitions = self.plugin_manager.load_tasks_with_scope(tasks, profile)?;
                
                println!("Loaded {} tasks (filtered by scope)", task_definitions.len());
                
                // Execute tasks with profile settings
                let results = self.plugin_manager.execute_tasks_with_profile(task_definitions, concurrency, profile).await?;
                
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
                
                // Generate tasks (uses profile's scope settings internally)
                let tasks = self.plugin_manager.generate_tasks(
                    input,
                    r#type,
                    plugins.as_deref(),
                    max_targets.unwrap_or(10),
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
    
    /// Handle profile-related commands
    async fn handle_profile_command(&self, command: &ProfileCommand) -> Result<()> {
        match command {
            ProfileCommand::List => {
                // Get a reference to the inner ProfileManager
                let profile_manager = self.profile_manager.as_ref();
                let profiles = profile_manager.list_profiles().await;
                let active_profile = profile_manager.get_active_profile().await?;
                
                println!("Available profiles:");
                for profile in profiles {
                    if profile == active_profile.name {
                        println!("- {} (active)", profile);
                    } else {
                        println!("- {}", profile);
                    }
                }
                
                Ok(())
            },
            ProfileCommand::Show { name } => {
                let profile = self.profile_manager.get_profile(name).await?;
                
                println!("Profile: {}", profile.name);
                if let Some(desc) = &profile.description {
                    println!("Description: {}", desc);
                }
                
                // Print resource limits
                println!("\nResource Limits:");
                println!("  Max Concurrent Tasks: {}", profile.resource_limits.max_concurrent_tasks);
                println!("  Max Requests Per Second: {}", profile.resource_limits.max_requests_per_second);
                println!("  Timeout: {} seconds", profile.resource_limits.timeout_seconds);
                println!("  Scan Mode: {}", profile.resource_limits.scan_mode);
                println!("  Risk Level: {}", profile.resource_limits.risk_level);
                
                // Print scope
                println!("\nScope:");
                println!("  Include Domains: {}", profile.scope.include_domains.join(", "));
                if !profile.scope.exclude_domains.is_empty() {
                    println!("  Exclude Domains: {}", profile.scope.exclude_domains.join(", "));
                }
                if !profile.scope.exclude_paths.is_empty() {
                    println!("  Exclude Paths: {}", profile.scope.exclude_paths.join(", "));
                }
                
                // Print HTTP settings
                println!("\nHTTP Settings:");
                if let Some(ref user_agent) = profile.http.user_agent {
                    println!("  User Agent: {}", user_agent);
                }
                if !profile.http.headers.is_empty() {
                    println!("  Headers:");
                    for (name, value) in &profile.http.headers {
                        println!("    {}: {}", name, value);
                    }
                }
                
                // Print tools configuration
                if !profile.tools.is_empty() {
                    println!("\nTool Configurations:");
                    for (name, _) in &profile.tools {
                        println!("  - {}", name);
                    }
                }
                
                Ok(())
            },
            ProfileCommand::Set { name } => {
                self.profile_manager.set_active_profile(name).await?;
                println!("Active profile set to: {}", name);
                Ok(())
            },
            ProfileCommand::Create { name, base, description } => {
                // Create a new profile based on an existing one or default
                let mut profile = if let Some(base_name) = base {
                    self.profile_manager.get_profile(base_name).await?
                } else {
                    Profile::default()
                };
                
                // Update the name and description
                profile.name = name.clone();
                profile.description = description.clone();
                
                // Save the profile
                self.profile_manager.save_profile(&profile).await?;
                
                println!("Profile '{}' created successfully", name);
                Ok(())
            },
            ProfileCommand::Delete { name } => {
                 // Get a reference to the inner ProfileManager
                let profile_manager = self.profile_manager.as_ref();
                
                // Check if this is the active profile
                let active_profile = profile_manager.get_active_profile().await?;
                if active_profile.name == *name {
                    bail!("Cannot delete the active profile. Set another profile as active first.");
                }
                
                // Delete the profile
                profile_manager.delete_profile(name).await?;
                
                println!("Profile '{}' deleted successfully", name);
                Ok(())
            },
            ProfileCommand::Import { path } => {
                // Get a reference to the inner ProfileManager
                let profile_manager = self.profile_manager.as_ref();
                
                // Import a profile from a file
                profile_manager.import_profile_from_file(path).await?;
                
                println!("Profile imported successfully");
                Ok(())
            },
            ProfileCommand::Export { name, path, format } => {
                // Get a reference to the inner ProfileManager
                let profile_manager = self.profile_manager.as_ref();
                
                // Export a profile to a file
                let format_str = format.as_deref().unwrap_or("toml");
                profile_manager.export_profile_to_file(name, path, format_str).await?;
                
                println!("Profile '{}' exported to {}", name, path.display());
                Ok(())
            },
        }
    }
    
    /// Handle scope filtering commands
    async fn handle_filter_scope_command(&self, command: &FilterScopeCommand, profile: &Profile) -> Result<()> {
        match command {
            FilterScopeCommand::Filter { input, output } => {
                info!("Filtering items from {} by scope", input.display());
                
                // Create a scope filter from the profile
                let scope_filter = ScopeFilter::new(&profile.scope)?;
                
                // Read input file
                let content = tokio::fs::read_to_string(input).await
                    .context(format!("Failed to read input file: {}", input.display()))?;
                
                // Parse items
                let items: Vec<String> = content.lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
                
                println!("Read {} items from input file", items.len());
                
                // Filter items based on scope
                let in_scope_items = scope_filter.filter_hosts(&items);
                
                println!("Filtered to {} in-scope items", in_scope_items.len());
                
                // Write output file
                let output_content = in_scope_items.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join("\n");
                tokio::fs::write(output, output_content).await
                    .context(format!("Failed to write output file: {}", output.display()))?;
                
                println!("In-scope items written to {}", output.display());
                
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
    
    /// Get a reference to the OSINT collector
    pub fn osint_collector(&self) -> &Arc<OsintCollector> {
        &self.osint_collector
    }
    
    /// Get a reference to the profile manager
    pub fn profile_manager(&self) -> &Arc<ProfileManager> {
        &self.profile_manager
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
    Osint(OsintCommand),
    Profile(ProfileCommand),
    FilterScope(FilterScopeCommand),
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

/// OSINT collection commands
#[derive(Debug, Clone)]
pub enum OsintCommand {
    Collect {
        target: String,
        source: Option<String>,
    },
    Sources,
}

/// Parallel execution commands
#[derive(Debug, Clone)]
pub enum ParallelCommand {
    Run {
        tasks: PathBuf,
        output: PathBuf,
        concurrent: Option<usize>,
    },
    GenerateTasks {
        input: PathBuf,
        output: PathBuf,
        r#type: String,
        plugins: Option<String>,
        max_targets: Option<usize>,
        options: Option<String>,
    },
}

/// Profile management commands
#[derive(Debug, Clone)]
pub enum ProfileCommand {
    List,
    Show {
        name: String,
    },
    Set {
        name: String,
    },
    Create {
        name: String,
        base: Option<String>,
        description: Option<String>,
    },
    Delete {
        name: String,
    },
    Import {
        path: PathBuf,
    },
    Export {
        name: String,
        path: PathBuf,
        format: Option<String>,
    },
}

/// Scope filtering commands
#[derive(Debug, Clone)]
pub enum FilterScopeCommand {
    Filter {
        input: PathBuf,
        output: PathBuf,
    },
}

pub struct WorkflowManager;

impl WorkflowManager {
pub async fn list_workflows(&self) -> Result<Vec<Workflow>> {
    // Placeholder implementation
    Ok(Vec::new())
    }
}

pub struct Workflow {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<WorkflowStep>,
}

pub struct WorkflowStep {
    pub name: String,
    pub description: Option<String>,
    pub tool: String,
    pub args: Vec<String>,
    pub depends_on: Vec<String>,
}