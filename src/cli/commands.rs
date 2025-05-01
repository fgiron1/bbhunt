use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

use crate::context::Context;
use crate::error::{BBHuntResult, BBHuntError};
use crate::core::target::TargetManager;

#[derive(Parser)]
#[command(name = "bbhunt")]
#[command(about = "A modular bug bounty hunting framework")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long, global = true)]
    pub verbose: bool,
    
    #[arg(long, short, global = true)]
    pub interactive: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage targets for reconnaissance
    Target {
        #[command(subcommand)]
        subcommand: TargetSubcommand,
    },

    /// Run parallel tasks
    Parallel {
        #[arg(short, long, help = "Path to task definition file")]
        tasks: PathBuf,
        
        #[arg(short, long, help = "Path to output results")]
        output: PathBuf,
        
        #[arg(short, long, default_value = "4", help = "Maximum concurrent tasks")]
        concurrent: usize,
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

    /// Run a specific plugin
    Run {
        #[arg(help = "Plugin name to run")]
        plugin: String,

        #[arg(help = "Target domain")]
        target: String,

        #[arg(long, help = "JSON-formatted options")]
        options: Option<String>,
    },

    /// List available plugins
    Plugins {
        #[arg(long, help = "Filter by category")]
        category: Option<String>,
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
        
        #[arg(long, default_value = "10", help = "Maximum targets per task")]
        max_targets: usize,
        
        #[arg(long, help = "JSON-formatted options")]
        options: Option<String>,
    },

    /// Show system resource usage
    Resources,
    
    /// Initialize the configuration
    Init {
        #[arg(short, long, help = "Force overwrite existing configuration")]
        force: bool,
    },
    
    /// Collect OSINT information
    Osint {
        #[arg(help = "Target ID")]
        target_id: String,
        
        #[arg(short, long, help = "OSINT source to use (default: all)")]
        source: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TargetSubcommand {
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

pub async fn execute_command(
    command: &Commands,
    context: Arc<Context>,
) -> BBHuntResult<()> {
    match command {
        Commands::Target { subcommand } => {
            handle_target_command(subcommand, context).await
        },
        Commands::Parallel { tasks, output, concurrent } => {
            handle_parallel_command(tasks, output, *concurrent, context).await
        },
        Commands::Report { target, format, output, title } => {
            handle_report_command(target, format, output, title, context).await
        },
        Commands::Run { plugin, target, options } => {
            handle_run_command(plugin, target, options, context).await
        },
        Commands::Plugins { category } => {
            handle_plugins_command(category, context).await
        },
        Commands::GenerateTasks { input, output, r#type, plugins, max_targets, options } => {
            handle_generate_tasks_command(input, output, r#type, plugins, *max_targets, options, context).await
        },
        Commands::Resources => {
            handle_resources_command(context).await
        },
        Commands::Init { force } => {
            handle_init_command(*force, context).await
        },
        Commands::Osint { target_id, source } => {
            handle_osint_command(target_id, source, context).await
        },
    }
}

// Handler implementations
async fn handle_target_command(subcommand: &TargetSubcommand, context: Arc<Context>) -> BBHuntResult<()> {
    let mut target_manager = context.target_manager.lock().await;
    
    match subcommand {
        TargetSubcommand::Add { name, domain, ip, cidr } => {
            println!("Adding target: {}", name);
            
            // Create the target
            let target_id = target_manager.create_target(name.clone(), None).await?;
            
            // Add domains if specified
            if let Some(domains) = domain {
                let mut target = target_manager.get_target_mut(&target_id)
                    .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?;
                    
                for d in domains {
                    target.add_domain(d.clone());
                }
            }
            
            // Add IP addresses if specified
            if let Some(ips) = ip {
                let mut target = target_manager.get_target_mut(&target_id)
                    .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?;
                    
                for ip_str in ips {
                    match ip_str.parse() {
                        Ok(ip) => target.add_ip_address(ip),
                        Err(e) => return Err(BBHuntError::InvalidInput(format!("Invalid IP address {}: {}", ip_str, e))),
                    }
                }
            }
            
            // Add CIDR ranges if specified
            if let Some(cidrs) = cidr {
                let mut target = target_manager.get_target_mut(&target_id)
                    .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?;
                    
                for cidr_str in cidrs {
                    match cidr_str.parse() {
                        Ok(range) => target.add_ip_range(range),
                        Err(e) => return Err(BBHuntError::InvalidInput(format!("Invalid CIDR range {}: {}", cidr_str, e))),
                    }
                }
            }
            
            // Save the target
            target_manager.save_target(
                target_manager.get_target(&target_id)
                    .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?
            ).await?;
            
            println!("Target added successfully with ID: {}", target_id);
            Ok(())
        },
        TargetSubcommand::List => {
            println!("Available targets:");
            
            for target in target_manager.list_targets() {
                println!("- {} ({})", target.name, target.id);
            }
            
            Ok(())
        },
        TargetSubcommand::Show { name } => {
            // Find target by name or ID
            let targets = target_manager.list_targets();
            let target = targets.iter()
                .find(|t| t.name == *name || t.id == *name)
                .ok_or_else(|| BBHuntError::TargetNotFound(name.clone()))?;
            
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
        TargetSubcommand::Delete { name } => {
            // Find target by name or ID
            let targets = target_manager.list_targets();
            let target_id = targets.iter()
                .find(|t| t.name == *name || t.id == *name)
                .map(|t| t.id.clone())
                .ok_or_else(|| BBHuntError::TargetNotFound(name.clone()))?;
            
            target_manager.delete_target(&target_id).await?;
            
            println!("Target deleted successfully");
            Ok(())
        },
    }
}

async fn handle_parallel_command(
    tasks: &PathBuf, 
    output: &PathBuf, 
    concurrent: usize, 
    context: Arc<Context>
) -> BBHuntResult<()> {
    use crate::engine::parallel::ParallelExecutor;
    
    println!("Running tasks from {} with concurrency {}", tasks.display(), concurrent);
    
    // Load tasks
    let task_definitions = ParallelExecutor::load_tasks(tasks)
        .map_err(|e| BBHuntError::FileError {
            path: tasks.clone(),
            message: format!("Failed to load tasks: {}", e),
        })?;
    
    println!("Loaded {} tasks", task_definitions.len());
    
    // Create executor
    let plugin_manager = context.plugin_manager.lock().await;
    let executor = ParallelExecutor::new(concurrent, plugin_manager.clone());
    
    // Execute tasks
    let results = executor.execute_tasks(task_definitions).await
        .map_err(|e| BBHuntError::TaskExecutionError {
            task_id: "parallel".to_string(),
            message: format!("Task execution failed: {}", e),
        })?;
    
    println!("Completed {} tasks", results.len());
    
    // Save results
    let json = serde_json::to_string_pretty(&results)
        .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize results: {}", e)))?;
    
    std::fs::write(output, json)
        .map_err(|e| BBHuntError::FileError {
            path: output.clone(),
            message: format!("Failed to write results: {}", e),
        })?;
    
    println!("Results saved to {}", output.display());
    
    Ok(())
}

async fn handle_report_command(
    target: &str, 
    format: &[String], 
    output: &Option<PathBuf>, 
    title: &Option<String>, 
    context: Arc<Context>
) -> BBHuntResult<()> {
    use crate::reporting::{ReportFormat, format_to_extension};
    use uuid::Uuid;
    
    println!("Generating report for target: {}", target);
    
    // Parse formats
    let formats: Vec<ReportFormat> = format.iter()
        .map(|f| match f.to_lowercase().as_str() {
            "json" => Ok(ReportFormat::JSON),
            "md" | "markdown" => Ok(ReportFormat::Markdown),
            "html" => Ok(ReportFormat::HTML),
            "pdf" => Ok(ReportFormat::PDF),
            "csv" => Ok(ReportFormat::CSV),
            "xml" => Ok(ReportFormat::XML),
            _ => Err(BBHuntError::InvalidInput(format!("Invalid report format: {}", f))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    
    if formats.is_empty() {
        return Err(BBHuntError::InvalidInput("No valid report formats specified".to_string()));
    }
    
    // Find target by name or ID
    let target_manager = context.target_manager.lock().await;
    let targets = target_manager.list_targets();
    let target_data = targets.iter()
        .find(|t| t.name == *target || t.id == *target)
        .ok_or_else(|| BBHuntError::TargetNotFound(target.to_string()))?;
    
    // Create report
    use crate::reporting::model::{Report, Finding};
    
    let report_id = Uuid::new_v4().to_string();
    let report_title = title.clone().unwrap_or_else(|| format!("Security Scan Report for {}", target_data.name));
    
    let mut report = Report::new(report_id, report_title, target_data.name.clone());
    
    // Set scan info
    report.set_total_hosts_scanned(1 + target_data.subdomains.len());
    
    // Generate report in each format
    let report_manager = &context.report_manager;
    let mut output_paths = Vec::new();
    
    for format in &formats {
        match report_manager.generate_report(&report, format.clone()).await {
            Ok(path) => {
                println!("Generated {} report: {}", format_to_extension(format), path.display());
                output_paths.push(path);
            },
            Err(e) => {
                println!("Failed to generate {} report: {}", format_to_extension(format), e);
            }
        }
    }
    
    if output_paths.is_empty() {
        return Err(BBHuntError::UnexpectedError("Failed to generate any reports".to_string()));
    }
    
    Ok(())
}

async fn handle_run_command(
    plugin: &str, 
    target: &str, 
    options: &Option<String>, 
    context: Arc<Context>
) -> BBHuntResult<()> {
    println!("Running plugin '{}' on target '{}'", plugin, target);
    
    // Parse options if provided
    let parsed_options = match options {
        Some(opts_str) => {
            Some(serde_json::from_str(opts_str)
                .map_err(|e| BBHuntError::InvalidInput(format!("Invalid JSON options: {}", e)))?)
        },
        None => None,
    };
    
    // Run the plugin
    let mut plugin_manager = context.plugin_manager.lock().await;
    let result = plugin_manager.run_plugin(plugin, target, parsed_options).await?;
    
    // Display results
    println!("Status: {:?}", result.status);
    println!("Message: {}", result.message);
    println!("Execution time: {:?}", result.execution_time);
    
    if !result.data.is_empty() {
        println!("Results:");
        let json = serde_json::to_string_pretty(&result.data)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to format results: {}", e)))?;
        println!("{}", json);
    }
    
    Ok(())
}

async fn handle_plugins_command(
    category: &Option<String>, 
    context: Arc<Context>
) -> BBHuntResult<()> {
    let plugin_manager = context.plugin_manager.lock().await;
    
    if let Some(cat_str) = category {
        // Filter by category if specified
        let category = match cat_str.to_lowercase().as_str() {
            "recon" => crate::core::plugin::PluginCategory::Recon,
            "scan" => crate::core::plugin::PluginCategory::Scan,
            "exploit" => crate::core::plugin::PluginCategory::Exploit,
            "utility" => crate::core::plugin::PluginCategory::Utility,
            _ => return Err(BBHuntError::InvalidInput(format!("Invalid category: {}", cat_str))),
        };
        
        let plugins = plugin_manager.get_plugins_by_category(&category);
        
        println!("{} plugins in category {:?}:", plugins.len(), category);
        
        for plugin in plugins {
            println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
        }
    } else {
        // Show all plugins
        let plugins = plugin_manager.get_plugins();
        
        println!("{} plugins available:", plugins.len());
        
        for plugin in plugins {
            println!("- {} (v{}, {:?}): {}", 
                plugin.name, plugin.version, plugin.category, plugin.description);
        }
    }
    
    Ok(())
}

async fn handle_generate_tasks_command(
    input: &PathBuf, 
    output: &PathBuf, 
    type_str: &str, 
    plugins: &Option<String>, 
    max_targets: usize, 
    options: &Option<String>,
    context: Arc<Context>
) -> BBHuntResult<()> {
    use crate::engine::task::{TaskGenerator, TaskGeneratorConfig, TaskType};
    
    println!("Generating {} tasks from {}", type_str, input.display());
    
    // Parse task type
    let task_type = match type_str.to_lowercase().as_str() {
        "recon" => TaskType::Recon,
        "scan" => TaskType::Scan,
        "exploit" => TaskType::Exploit,
        _ => return Err(BBHuntError::InvalidInput(format!("Invalid task type: {}", type_str))),
    };
    
    // Parse plugins
    let plugin_list = if let Some(p) = plugins {
        p.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        // Default plugins based on type
        match task_type {
            TaskType::Recon => vec!["subdomain_enum".to_string()],
            TaskType::Scan => vec!["web_scan".to_string()],
            TaskType::Exploit => Vec::new(),
        }
    };
    
    // Parse options
    let option_map = if let Some(opt_str) = options {
        serde_json::from_str(opt_str)
            .map_err(|e| BBHuntError::InvalidInput(format!("Invalid JSON options: {}", e)))?
    } else {
        std::collections::HashMap::new()
    };
    
    // Create config
    let config = TaskGeneratorConfig {
        task_type,
        plugins: plugin_list,
        max_targets_per_task: max_targets,
        options: option_map,
    };
    
    // Create task generator
    let generator = TaskGenerator::new(config);
    
    // Generate tasks
    let tasks = generator.generate_from_results(input.as_path())
        .map_err(|e| BBHuntError::FileError {
            path: input.clone(),
            message: format!("Failed to generate tasks: {}", e),
        })?;
    
    println!("Generated {} tasks", tasks.len());
    
    // Save tasks
    generator.save_tasks(&tasks, output.as_path())
        .map_err(|e| BBHuntError::FileError {
            path: output.clone(),
            message: format!("Failed to save tasks: {}", e),
        })?;
    
    println!("Tasks saved to {}", output.display());
    
    Ok(())
}

async fn handle_resources_command(context: Arc<Context>) -> BBHuntResult<()> {
    println!("System Resource Usage:");
    
    let resource_manager = &context.resource_manager;
    let usage = resource_manager.get_resource_usage().await
        .map_err(|e| BBHuntError::ResourceError(format!("Failed to get resource usage: {}", e)))?;
    
    println!("Memory:");
    println!("  Total: {} MB", usage.memory.total);
    println!("  Used: {} MB ({}%)", usage.memory.used, usage.memory.percent);
    println!("  Available: {} MB", usage.memory.available);
    
    println!("CPU:");
    println!("  Cores: {}", usage.cpu.cores);
    println!("  Usage: {}%", usage.cpu.total_usage);
    
    println!("Disk:");
    println!("  Total: {} MB", usage.disk.total);
    println!("  Used: {} MB ({}%)", usage.disk.used, usage.disk.percent);
    println!("  Free: {} MB", usage.disk.free);
    
    if !usage.active_processes.is_empty() {
        println!("Active Processes:");
        for process in &usage.active_processes {
            println!("  {} (PID {}): Memory: {} MB, CPU: {}%", 
                process.name, process.pid, process.memory_usage, process.cpu_usage);
        }
    }
    
    Ok(())
}

async fn handle_init_command(force: bool, context: Arc<Context>) -> BBHuntResult<()> {
    let config = Config::init(force)?;
    println!("Configuration initialized at {}", config.display());
    Ok(())
}

async fn handle_osint_command(
    target_id: &str, 
    source: &Option<String>,
    context: Arc<Context>
) -> BBHuntResult<()> {
    println!("Running OSINT collection for target: {}", target_id);
    
    let mut target_manager = context.target_manager.lock().await;
    
    // Load target
    let target = target_manager.load_target(target_id).await
        .map_err(|e| BBHuntError::TargetNotFound(format!("Failed to load target {}: {}", target_id, e)))?;
    
    println!("Target loaded: {}", target.name);
    
    // Get OSINT collector
    let mut osint_collector = context.osint_collector.lock().await;
    
    // Register OSINT sources if not already done
    if osint_collector.list_sources().is_empty() {
        osint_collector.register_source(Box::new(crate::osint::sources::DnsOsintSource::new()))?;
        osint_collector.register_source(Box::new(crate::osint::sources::WhoisOsintSource::new()))?;
        osint_collector.register_source(Box::new(crate::osint::sources::SslCertificateOsintSource::new()))?;
        osint_collector.register_source(Box::new(crate::osint::sources::CtLogOsintSource::new()))?;
    }
    
    // Run OSINT collection
    let mut target_data = target_manager.get_target_mut(target_id)
        .ok_or_else(|| BBHuntError::TargetNotFound(target_id.to_string()))?;
    
    if let Some(source_name) = source {
        println!("Running OSINT source: {}", source_name);
        osint_collector.collect_from_source(target_data, source_name).await?;
    } else {
        println!("Running all OSINT sources");
        osint_collector.collect_all(target_data).await?;
    }
    
    // Save target with updated OSINT data
    target_manager.save_target(
        target_manager.get_target(target_id)
            .ok_or_else(|| BBHuntError::TargetNotFound(target_id.to_string()))?
    ).await?;
    
    println!("OSINT collection completed");
    Ok(())
}