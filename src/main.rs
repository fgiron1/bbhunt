// src/main.rs - Updated with OSINT commands
use std::path::PathBuf;
use std::process::exit;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber;
use tracing::{info, error};

mod config;
mod plugin;
mod target;
mod report;
mod template;
mod osint;
mod app;

use config::AppConfig;
use app::{App, Command, TargetCommand, ScanCommand, ReportCommand, PluginCommand, ParallelCommand, OsintCommand};

#[derive(Parser)]
#[command(name = "bbhunt")]
#[command(about = "A modular bug bounty hunting framework")]
struct Args {
    #[command(subcommand)]
    command: Option<Cli>,

    #[arg(long, global = true)]
    verbose: bool,
    
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,
    
    #[arg(long, short, global = true)]
    interactive: bool,
}

#[derive(Subcommand)]
enum Cli {
    /// Manage targets for reconnaissance
    Target {
        #[command(subcommand)]
        command: TargetCli,
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
    
    /// OSINT data collection
    Osint {
        #[command(subcommand)]
        command: OsintCli,
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
    
    /// Initialize config
    Init {
        #[arg(short, long, help = "Force overwrite existing configuration")]
        force: bool,
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

#[tokio::main]
async fn main() -> Result<()> {
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
    
    // Initialize the application
    match app.initialize_with_config(args.config.as_deref()).await {
        Ok(_) => {
            info!("Application initialized successfully");
        },
        Err(e) => {
            error!("Failed to initialize application: {}", e);
            exit(1);
        }
    }
    
    // Process commands
    match args.command {
        Some(cmd) => {
            // Convert clap command to app command
            let command = match cmd {
                Cli::Target { command } => {
                    match command {
                        TargetCli::Add { name, domain, ip, cidr } => {
                            Command::Target(TargetCommand::Add { name, domain, ip, cidr })
                        },
                        TargetCli::List => {
                            Command::Target(TargetCommand::List)
                        },
                        TargetCli::Show { name } => {
                            Command::Target(TargetCommand::Show { name })
                        },
                        TargetCli::Delete { name } => {
                            Command::Target(TargetCommand::Delete { name })
                        },
                    }
                },
                Cli::Run { plugin, target, options } => {
                    Command::Scan(ScanCommand::Run { plugin, target, options })
                },
                Cli::Report { target, format, output, title } => {
                    Command::Report(ReportCommand::Generate { target, format, output, title })
                },
                Cli::Plugins { category } => {
                    Command::Plugin(PluginCommand::List { category })
                },
                Cli::Osint { command } => {
                    match command {
                        OsintCli::Collect { target, source } => {
                            Command::Osint(OsintCommand::Collect { target, source })
                        },
                        OsintCli::Sources => {
                            Command::Osint(OsintCommand::Sources)
                        },
                    }
                },
                Cli::Parallel { tasks, output, concurrent } => {
                    Command::Parallel(ParallelCommand::Run { tasks, output, concurrent })
                },
                Cli::GenerateTasks { input, output, r#type, plugins, max_targets, options } => {
                    Command::Parallel(ParallelCommand::GenerateTasks { 
                        input, 
                        output, 
                        r#type, 
                        plugins, 
                        max_targets, 
                        options 
                    })
                },
                Cli::Init { force } => {
                    // Initialize configuration
                    let config_path = match app.config().save(None).await {
                        Ok(path) => path,
                        Err(e) => {
                            error!("Failed to initialize configuration: {}", e);
                            exit(1);
                        }
                    };
                    
                    println!("Configuration initialized at {}", config_path.display());
                    return Ok(());
                }
            };
            
            // Execute the command
            if let Err(e) = app.run_command(&command).await {
                error!("Command execution failed: {}", e);
                exit(1);
            }
        },
        None => {
            if args.interactive {
                println!("Interactive mode not yet implemented");
                // TODO: Implement interactive shell
            } else {
                println!("No command specified. Use --help for available commands.");
                Args::parse_from(&["bbhunt", "--help"]);
            }
        }
    }
    
    Ok(())
}