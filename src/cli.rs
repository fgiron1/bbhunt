// src/cli.rs - Profile-based CLI implementation

use std::path::PathBuf;
use anyhow::{Result, Context, bail};
use clap::{Parser, Subcommand};
use tracing::{info, debug, warn, error};

use crate::profile::{ProfileManager, Profile, create_command_with_profile, ProfiledCommand};
use crate::scope_filter::ScopeFilter;
use crate::app::App;

#[derive(Parser)]
#[command(name = "bbhunt")]
#[command(about = "A modular bug bounty hunting framework with profile-based configuration")]
struct Args {
    #[command(subcommand)]
    command: Option<Cli>,

    #[arg(long, global = true)]
    verbose: bool,
    
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,
    
    #[arg(long, short = 'p', global = true, default_value = "default")]
    profile: String,
}

#[derive(Subcommand)]
enum Cli {
    /// Manage targets for reconnaissance
    Target {
        #[command(subcommand)]
        command: TargetCli,
    },

    /// Run a specific plugin with profile-based configuration
    Run {
        #[arg(help = "Plugin name to run")]
        plugin: String,

        #[arg(help = "Target domain or URL")]
        target: String,

        #[arg(long, help = "JSON-formatted options to override profile settings")]
        options: Option<String>,
    },
    
    /// Generate reports
    Report {
        #[arg(short, long, help = "Target name")]
        target: String,
        
        #[arg(short, long, help = "Report format (json, md, html)")]
        format: Vec<String>,
        
        #[arg(short, long, help = "Output directory")]
        output: Option<PathBuf>,
        
        #[arg(short, long, help = "Report title")]
        title: Option<String>,
    },

    /// List available plugins
    Plugins {
        #[arg(long, help = "Filter by category")]
        category: Option<String>,
    },
    
    /// OSINT data collection with profile-based configuration
    Osint {
        #[command(subcommand)]
        command: OsintCli,
    },

    /// Run parallel tasks with profile-based resource management
    Parallel {
        #[arg(short, long, help = "Path to task definition file")]
        tasks: PathBuf,
        
        #[arg(short, long, help = "Path to output results")]
        output: PathBuf,
        
        #[arg(short, long, help = "Maximum concurrent tasks (overrides profile setting)")]
        concurrent: Option<usize>,
    },
    
    /// Generate tasks from previous results
    GenerateTasks {
        #[arg(short, long, help = "Input results file")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output tasks file")]
        output: PathBuf,
        
        #[arg(short, long, help = "Task type (recon, scan, exploit)")]
        r#type: String,
        
        #[arg(long, help = "Plugins to use (comma-separated)")]
        plugins: Option<String>,
        
        #[arg(long, help = "Maximum targets per task")]
        max_targets: Option<usize>,
        
        #[arg(long, help = "JSON-formatted options")]
        options: Option<String>,
    },
    
    /// Initialize config with default profiles
    Init {
        #[arg(short, long, help = "Force overwrite existing configuration")]
        force: bool,
    },
    
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCli,
    },
    
    /// Run a workflow from the active profile
    Workflow {
        #[arg(help = "Workflow name")]
        name: String,
        
        #[arg(short, long, help = "Target domain or URL")]
        target: String,
        
        #[arg(short, long, help = "Output directory")]
        output: Option<PathBuf>,
    },
    
    /// Filter targets based on scope configuration
    FilterScope {
        #[arg(short, long, help = "Input file with domains/URLs")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output file for in-scope items")]
        output: PathBuf,
        
        #[arg(short, long, help = "Profile to use for scope filtering")]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum TargetCli {
    /// Add a new target
    Add {
        #[arg(help = "Target name")]
        name: String,
        
        #[arg(long, help = "Domain to include")]
        domain: Option<Vec<String>>,
        
        #[arg(long, help = "IP address to include")]
        ip: Option<Vec<String>>,
        
        #[arg(long, help = "CIDR range to include")]
        cidr: Option<Vec<String>>,
    },
    
    /// List targets
    List,
    
    /// Show target details
    Show {
        #[arg(help = "Target name")]
        name: String,
    },
    
    /// Delete a target
    Delete {
        #[arg(help = "Target name")]
        name: String,
    },
}

#[derive(Subcommand)]
enum OsintCli {
    /// Collect OSINT data for a target
    Collect {
        #[arg(help = "Target name or ID")]
        target: String,
        
        #[arg(short, long, help = "Specific source to use (optional)")]
        source: Option<String>,
    },
    
    /// List available OSINT sources
    Sources,
}

#[derive(Subcommand)]
enum ProfileCli {
    /// List available profiles
    List,
    
    /// Show profile details
    Show {
        #[arg(help = "Profile name")]
        name: String,
    },
    
    /// Set the active profile
    Set {
        #[arg(help = "Profile name")]
        name: String,
    },
    
    /// Create a new profile
    Create {
        #[arg(help = "Profile name")]
        name: String,
        
        #[arg(long, help = "Base on existing profile")]
        base: Option<String>,
        
        #[arg(long, help = "Profile description")]
        description: Option<String>,
    },
    
    /// Delete a profile
    Delete {
        #[arg(help = "Profile name")]
        name: String,
    },
    
    /// Import a profile from JSON/TOML file
    Import {
        #[arg(help = "Profile file path")]
        path: PathBuf,
    },
    
    /// Export a profile to JSON/TOML file
    Export {
        #[arg(help = "Profile name")]
        name: String,
        
        #[arg(help = "Output file path")]
        path: PathBuf,
        
        #[arg(long, help = "Export format (json or toml)")]
        format: Option<String>,
    },
}

pub async fn run_cli() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();
    
    // Set log level based on verbosity
    if args.verbose {
        // This would normally set a more verbose log level
        info!("Verbose mode enabled");
    }

    // Create the application
    let mut app = App::new();
    
    // Initialize the application with custom profile if specified
    match app.initialize_with_config(args.config.as_deref()).await {
        Ok(_) => {
            info!("Application initialized successfully");
            
            // Set the active profile
            if app.profile_manager().set_active_profile(&args.profile).await.is_err() {
                warn!("Profile '{}' not found, using default", args.profile);
            } else {
                info!("Using profile: {}", args.profile);
            }
        },
        Err(e) => {
            error!("Failed to initialize application: {}", e);
            std::process::exit(1);
        }
    }
    
    // Process commands
    match args.command {
        Some(cmd) => {
            // Process command using the profile system
            process_command(cmd, &app).await
        },
        None => {
            println!("No command specified. Use --help for available commands.");
            Ok(())
        }
    }
}

async fn process_command(cmd: Cli, app: &App) -> Result<()> {
    match cmd {
        Cli::Target { command } => process_target_command(command, app).await,
        Cli::Run { plugin, target, options } => process_run_command(plugin, target, options, app).await,
        Cli::Report { target, format, output, title } => process_report_command(target, format, output, title, app).await,
        Cli::Plugins { category } => process_plugins_command(category, app).await,
        Cli::Osint { command } => process_osint_command(command, app).await,
        Cli::Parallel { tasks, output, concurrent } => process_parallel_command(tasks, output, concurrent, app).await,
        Cli::GenerateTasks { input, output, r#type, plugins, max_targets, options } => 
            process_generate_tasks_command(input, output, r#type, plugins, max_targets, options, app).await,
        Cli::Init { force } => process_init_command(force, app).await,
        Cli::Profile { command } => process_profile_command(command, app).await,
        Cli::Workflow { name, target, output } => process_workflow_command(name, target, output, app).await,
        Cli::FilterScope { input, output, profile } => process_filter_scope_command(input, output, profile, app).await,
    }
}

async fn process_target_command(cmd: TargetCli, app: &App) -> Result<()> {
    match cmd {
        TargetCli::Add { name, domain, ip, cidr } => {
            info!("Adding target: {}", name);
            
            // Create target
            let target_id = app.target_manager().create_target(&name, None).await?;
            
            // Add domains
            if let Some(domains) = domain {
                for d in domains {
                    app.target_manager().add_domain(&target_id, &d).await?;
                }
            }
            
            // Add IPs
            if let Some(ips) = ip {
                for ip_str in ips {
                    app.target_manager().add_ip_address(&target_id, &ip_str).await?;
                }
            }
            
            // Add CIDRs
            if let Some(cidrs) = cidr {
                for cidr_str in cidrs {
                    app.target_manager().add_ip_range(&target_id, &cidr_str).await?;
                }
            }
            
            println!("Target added successfully with ID: {}", target_id);
            Ok(())
        },
        TargetCli::List => {
            println!("Available targets:");
            
            let targets = app.target_manager().list_targets().await?;
            for target in targets {
                println!("- {} ({})", target.name, target.id);
            }
            
            Ok(())
        },
        TargetCli::Show { name } => {
            let target = app.target_manager().get_target_by_name_or_id(&name).await?;
            
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
            
            // Show more details...
            
            Ok(())
        },
        TargetCli::Delete { name } => {
            app.target_manager().delete_target_by_name_or_id(&name).await?;
            println!("Target deleted successfully");
            Ok(())
        },
    }
}

async fn process_run_command(plugin: String, target: String, options: Option<String>, app: &App) -> Result<()> {
    info!("Running plugin '{}' on target '{}' with profile configuration", plugin, target);
    
    // Get active profile
    let profile = app.profile_manager().get_active_profile().await?;
    
    // Parse additional options if provided
    let mut options_map = if let Some(opts_str) = options {
        serde_json::from_str(&opts_str)
            .context("Invalid JSON options")?
    } else {
        std::collections::HashMap::new()
    };
    
    // Add profile-specific options for this plugin if they exist
    if let Some(tool_profile) = profile.tools.get(&plugin) {
        for (key, value) in &tool_profile.options {
            if !options_map.contains_key(key) {
                options_map.insert(key.clone(), value.clone());
            }
        }
    }
    
    // Run the plugin with profile-based configuration
    let result = app.plugin_manager().run_plugin(&plugin, &target, Some(options_map)).await?;
    
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

async fn process_report_command(target: String, format: Vec<String>, output: Option<PathBuf>, title: Option<String>, app: &App) -> Result<()> {
    info!("Generating report for target: {}", target);
    
    // Get the target data
    let target_data = app.target_manager().get_target_by_name_or_id(&target).await?;
    
    // Generate the report
    let report_paths = app.report_manager()
        .generate_report(&target_data, &format, output.as_deref(), title.as_deref())
        .await?;
    
    for path in report_paths {
        println!("Report generated: {}", path.display());
    }
    
    Ok(())
}

async fn process_plugins_command(category: Option<String>, app: &App) -> Result<()> {
    if let Some(cat_str) = category {
        // Filter by category
        let plugins = app.plugin_manager().get_plugins_by_category(&cat_str).await?;
        
        println!("{} plugins in category {}:", plugins.len(), cat_str);
        
        for plugin in plugins {
            println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
        }
    } else {
        // Show all plugins
        let plugins = app.plugin_manager().get_plugins().await?;
        
        println!("{} plugins available:", plugins.len());
        
        for plugin in plugins {
            println!("- {} (v{}, {:?}): {}", 
                plugin.name, plugin.version, plugin.category, plugin.description);
        }
    }
    
    Ok(())
}

async fn process_osint_command(cmd: OsintCli, app: &App) -> Result<()> {
    match cmd {
        OsintCli::Collect { target, source } => {
            // Get target
            let mut target_data = app.target_manager().get_target_by_name_or_id(&target).await?;
            
            // Get active profile for OSINT configuration
            let profile = app.profile_manager().get_active_profile().await?;
            
            if let Some(source_name) = source {
                // Run specific OSINT source
                info!("Running OSINT source {} on target '{}'", source_name, target);
                app.osint_collector().collect_from_source(&mut target_data, &source_name).await?;
            } else {
                // Run all OSINT sources
                info!("Running all OSINT sources on target '{}'", target);
                app.osint_collector().collect_all(&mut target_data).await?;
            }
            
            // Save updated target data
            app.target_manager().save_target(&target_data).await?;
            
            // Display summary
            println!("OSINT collection completed for target '{}'", target);
            // Display more details...
            
            Ok(())
        },
        OsintCli::Sources => {
            // List available OSINT sources
            let sources = app.osint_collector().list_sources().await?;
            
            println!("{} OSINT sources available:", sources.len());
            for source in sources {
                println!("- {}", source);
            }
            
            Ok(())
        }
    }
}

async fn process_parallel_command(tasks: PathBuf, output: PathBuf, concurrent: Option<usize>, app: &App) -> Result<()> {
    info!("Running tasks from {} with profile-based concurrency", tasks.display());
    
    // Get profile resource limits
    let profile = app.profile_manager().get_active_profile().await?;
    let concurrency = concurrent.unwrap_or(profile.resource_limits.max_concurrent_tasks);
    
    // Load tasks
    let task_definitions = app.plugin_manager().load_tasks(&tasks)
        .context(format!("Failed to load tasks from {}", tasks.display()))?;
    
    println!("Loaded {} tasks", task_definitions.len());
    
    // Apply scope filtering if configured
    let filtered_tasks = filter_tasks_by_scope(&task_definitions, &profile).context("Failed to filter tasks by scope")?;
    
    if filtered_tasks.len() < task_definitions.len() {
        println!("Filtered to {} in-scope tasks", filtered_tasks.len());
    }
    
    // Execute tasks
    let results = app.plugin_manager().execute_tasks(filtered_tasks, concurrency).await?;
    
    println!("Completed {} tasks", results.len());
    
    // Save results
    let json = serde_json::to_string_pretty(&results)
        .context("Failed to serialize results")?;
    
    tokio::fs::write(&output, json).await
        .context(format!("Failed to write results to {}", output.display()))?;
    
    println!("Results saved to {}", output.display());
    
    Ok(())
}

async fn process_generate_tasks_command(
    input: PathBuf, 
    output: PathBuf, 
    r#type: String, 
    plugins: Option<String>, 
    max_targets: Option<usize>, 
    options: Option<String>, 
    app: &App
) -> Result<()> {
    info!("Generating {} tasks from {}", r#type, input.display());
    
    // Get profile for configuration
    let profile = app.profile_manager().get_active_profile().await?;
    
    // Generate tasks
    let tasks = app.plugin_manager().generate_tasks(
        &input,
        &r#type,
        plugins.as_deref(),
        max_targets.unwrap_or(10),
        options.as_deref(),
    ).await?;
    
    println!("Generated {} tasks", tasks.len());
    
    // Save tasks
    app.plugin_manager().save_tasks(&tasks, &output).await?;
    
    println!("Tasks saved to {}", output.display());
    
    Ok(())
}

async fn process_init_command(force: bool, app: &App) -> Result<()> {
    // Initialize configuration
    let config_path = app.config().save(None).await?;
    
    println!("Configuration initialized at {}", config_path.display());
    
    // Initialize profile system
    app.profile_manager().initialize().await?;
    
    println!("Profile system initialized");
    
    Ok(())
}

async fn process_profile_command(cmd: ProfileCli, app: &App) -> Result<()> {
    match cmd {
        ProfileCli::List => {
            let profiles = app.profile_manager().list_profiles().await;
            let active_profile = app.profile_manager().get_active_profile().await?;
            
            println!("Available profiles:");
            for profile_name in profiles {
                if profile_name == active_profile.name {
                    println!("- {} (active)", profile_name);
                } else {
                    println!("- {}", profile_name);
                }
            }
            
            Ok(())
        },
        ProfileCli::Show { name } => {
            let profile = app.profile_manager().get_profile(&name).await?;
            
            println!("Profile: {}", profile.name);
            
            if let Some(desc) = &profile.description {
                println!("Description: {}", desc);
            }
            
            println!("Tags: {}", profile.tags.join(", "));
            println!("Enabled: {}", profile.enabled);
            
            println!("\nResource Limits:");
            println!("  Max Concurrent Tasks: {}", profile.resource_limits.max_concurrent_tasks);
            println!("  Max Requests Per Second: {}", profile.resource_limits.max_requests_per_second);
            println!("  Timeout: {} seconds", profile.resource_limits.timeout_seconds);
            println!("  Scan Mode: {}", profile.resource_limits.scan_mode);
            println!("  Risk Level: {}", profile.resource_limits.risk_level);
            
            println!("\nScope Configuration:");
            println!("  Include Domains: {}", profile.scope.include_domains.join(", "));
            println!("  Exclude Domains: {}", profile.scope.exclude_domains.join(", "));
            
            println!("\nConfigured Tools:");
            for (tool_name, _) in &profile.tools {
                println!("  - {}", tool_name);
            }
            
            Ok(())
        },
        ProfileCli::Set { name } => {
            app.profile_manager().set_active_profile(&name).await?;
            println!("Active profile set to: {}", name);
            Ok(())
        },
        ProfileCli::Create { name, base, description, .. } => {
            // Create new profile
            let mut profile = if let Some(base_name) = base {
                // Base on existing profile
                app.profile_manager().get_profile(&base_name).await?
            } else {
                // Create from default template
                Profile {
                    name: name.clone(),
                    description: description,
                    tags: vec![],
                    resource_limits: Default::default(),
                    scope: Default::default(),
                    tools: Default::default(),
                    http: Default::default(),
                    authentication: Default::default(),
                    environment: Default::default(),
                    default_options: Default::default(),
                    enabled: true,
                    program_configs: Default::default(),
                }
            };
            
            // Update name
            profile.name = name.clone();
            
            // Update description if provided
            if let Some(desc) = description {
                profile.description = Some(desc);
            }
            
            // Save profile
            app.profile_manager().create_profile(profile).await?;
            
            println!("Profile '{}' created successfully", name);
            Ok(())
        },
        ProfileCli::Delete { name } => {
            // Check if this is the active profile
            let active_profile = app.profile_manager().get_active_profile().await?;
            if active_profile.name == name {
                bail!("Cannot delete the active profile. Please set another profile as active first.");
            }
            
            // Delete profile file
            let profile_path = app.config_dir().join("profiles").join(format!("{}.json", name));
            if profile_path.exists() {
                tokio::fs::remove_file(&profile_path).await
                    .context(format!("Failed to delete profile file: {}", profile_path.display()))?;
                
                println!("Profile '{}' deleted successfully", name);
            } else {
                bail!("Profile file not found: {}", profile_path.display());
            }
            
            Ok(())
        },
        ProfileCli::Import { path } => {
            // Read profile file
            let content = tokio::fs::read_to_string(&path).await
                .context(format!("Failed to read profile file: {}", path.display()))?;
            
            // Parse profile
            let profile: Profile = if path.extension().map_or(false, |ext| ext == "json") {
                serde_json::from_str(&content)
                    .context(format!("Failed to parse JSON profile: {}", path.display()))?
            } else if path.extension().map_or(false, |ext| ext == "toml") {
                toml::from_str(&content)
                    .context(format!("Failed to parse TOML profile: {}", path.display()))?
            } else {
                bail!("Unsupported profile file format. Use .json or .toml");
            };
            
            // Save profile
            app.profile_manager().create_profile(profile.clone()).await?;
            
            println!("Profile '{}' imported successfully", profile.name);
            Ok(())
        },
        ProfileCli::Export { name, path, format } => {
            // Get profile
            let profile = app.profile_manager().get_profile(&name).await?;
            
            // Determine format
            let format = format.unwrap_or_else(|| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("json")
                    .to_string()
            });
            
            // Serialize profile
            let content = match format.as_str() {
                "json" => serde_json::to_string_pretty(&profile)
                    .context("Failed to serialize profile to JSON")?,
                "toml" => toml::to_string(&profile)
                    .context("Failed to serialize profile to TOML")?,
                _ => bail!("Unsupported format: {}. Use 'json' or 'toml'", format),
            };
            
            // Write to file
            tokio::fs::write(&path, content).await
                .context(format!("Failed to write profile to {}", path.display()))?;
            
            println!("Profile '{}' exported to {}", name, path.display());
            Ok(())
        },
    }
}

async fn process_workflow_command(name: String, target: String, output: Option<PathBuf>, app: &App) -> Result<()> {
    info!("Running workflow '{}' on target '{}'", name, target);
    
    // Get active profile
    let profile = app.profile_manager().get_active_profile().await?;
    
    // Get workflow from profile
    let workflows = app.workflow_manager().list_workflows().await?;
    let workflow = workflows.iter()
        .find(|w| w.name == name)
        .ok_or_else(|| anyhow::anyhow!("Workflow not found: {}", name))?;
    
    println!("Running workflow: {}", workflow.name);
    if let Some(desc) = &workflow.description {
        println!("Description: {}", desc);
    }
    println!("Steps: {}", workflow.steps.len());
    
    // Determine output directory
    let output_dir = if let Some(dir) = output {
        dir
    } else {
        app.data_dir().join("workflows").join(format!("{}-{}", name, chrono::Local::now().format("%Y%m%d-%H%M%S")))
    };
    
    // Create output directory
    tokio::fs::create_dir_all(&output_dir).await
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;
    
    println!("Output directory: {}", output_dir.display());
    
    // Execute workflow steps
    let mut completed_steps = std::collections::HashSet::new();
    let mut step_results = std::collections::HashMap::new();
    
    for step in &workflow.steps {
        // Check dependencies
        for dep in &step.depends_on {
            if !completed_steps.contains(dep) {
                bail!("Dependency '{}' for step '{}' not satisfied", dep, step.name);
            }
        }
        
        println!("\nExecuting step: {}", step.name);
        if let Some(desc) = &step.description {
            println!("Description: {}", desc);
        }
        
        // Prepare command with profile settings
        let mut command = ProfiledCommand {
            program: step.tool.clone(),
            args: step.args.clone(),
            env: std::collections::HashMap::new(),
            timeout: None,
            current_dir: None,
        };
        
        // Apply profile settings
        command.apply_profile(&profile, &step.tool)?;
        
        // Replace variables in args
        let mut processed_args = Vec::new();
        for arg in &command.args {
            let arg = arg.replace("${TARGET}", &target)
                .replace("${OUTPUT_DIR}", &output_dir.to_string_lossy());
            processed_args.push(arg);
        }
        command.args = processed_args;
        
        // Execute command
        println!("Running: {} {}", command.program, command.args.join(" "));
        
        let start_time = std::time::Instant::now();
        
        // Create tokio Command
        let mut cmd = tokio::process::Command::new(&command.program);
        cmd.args(&command.args);
        cmd.envs(&command.env);
        
        if let Some(timeout) = command.timeout {
            // Execute with timeout
            match tokio::time::timeout(timeout, cmd.output()).await {
                Ok(result) => {
                    match result {
                        Ok(output) => {
                            let duration = start_time.elapsed();
                            
                            println!("Step completed in {:?}", duration);
                            
                            if !output.status.success() {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                println!("WARNING: Step exited with non-zero status: {}", output.status);
                                println!("Error output: {}", stderr);
                            }
                            
                            // Store result
                            step_results.insert(step.name.clone(), output);
                        },
                        Err(e) => {
                            bail!("Failed to execute step '{}': {}", step.name, e);
                        }
                    }
                },
                Err(_) => {
                    bail!("Step '{}' timed out after {:?}", step.name, timeout);
                }
            }
        } else {
            // Execute without timeout
            match cmd.output().await {
                Ok(output) => {
                    let duration = start_time.elapsed();
                    
                    println!("Step completed in {:?}", duration);
                    
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("WARNING: Step exited with non-zero status: {}", output.status);
                        println!("Error output: {}", stderr);
                    }
                    
                    // Store result
                    step_results.insert(step.name.clone(), output);
                },
                Err(e) => {
                    bail!("Failed to execute step '{}': {}", step.name, e);
                }
            }
        }
        
        // Mark as completed
        completed_steps.insert(step.name.clone());
    }
    
    println!("\nWorkflow '{}' completed successfully", name);
    println!("Output directory: {}", output_dir.display());
    
    Ok(())
}

async fn process_filter_scope_command(input: PathBuf, output: PathBuf, profile: Option<String>, app: &App) -> Result<()> {
    info!("Filtering items by scope from {}", input.display());
    
    // Get profile for scope configuration
    let profile_name = profile.unwrap_or_else(|| {
        let active_profile = app.profile_manager().get_active_profile_name().await.unwrap_or_else(|_| "default".to_string());
        active_profile
    });
    
    println!("Using profile: {}", profile_name);
    
    let profile = app.profile_manager().get_profile(&profile_name).await?;
    
    // Create scope filter
    let scope_filter = ScopeFilter::new(&profile.scope)?;
    
    // Read input file
    let content = tokio::fs::read_to_string(&input).await
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
    let output_content = in_scope_items.join("\n");
    tokio::fs::write(&output, output_content).await
        .context(format!("Failed to write output file: {}", output.display()))?;
    
    println!("In-scope items written to {}", output.display());
    
    Ok(())
}

// Helper function to filter tasks by scope
fn filter_tasks_by_scope(tasks: &[TaskDefinition], profile: &Profile) -> Result<Vec<TaskDefinition>> {
    let scope_filter = ScopeFilter::new(&profile.scope)?;
    
    let filtered_tasks = tasks.iter()
        .filter(|task| {
            // Check if target is in scope
            scope_filter.is_host_in_scope(&task.target)
        })
        .cloned()
        .collect();
    
    Ok(filtered_tasks)
}