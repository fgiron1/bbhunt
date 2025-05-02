// src/main.rs - Refactored to use the profile system
use std::path::PathBuf;
use std::process::exit;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber;
use tracing::{info, error};

mod config;
mod profile;
mod plugin;
mod target;
mod report;
mod template;
mod osint;
mod app;
mod scope_filter;

use config::AppConfig;
use app::{App, Command, TargetCommand, ScanCommand, ReportCommand, PluginCommand, 
         ParallelCommand, OsintCommand, ProfileCommand, FilterScopeCommand};

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
    
    #[arg(long, short = 'p', global = true)]
    profile: Option<String>,
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
        
        #[arg(short, long, help = "Maximum concurrent tasks")]
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
    
    /// Initialize config
    Init {
        #[arg(short, long, help = "Force overwrite existing configuration")]
        force: bool,
    },
    
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCli,
    },
    
    /// Filter items by scope
    FilterScope {
        #[arg(short, long, help = "Input file with items to filter")]
        input: PathBuf,
        
        #[arg(short, long, help = "Output file for in-scope items")]
        output: PathBuf,
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
    
    /// Set active profile
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
    
    /// Import a profile from a file
    Import {
        #[arg(help = "Path to profile file")]
        path: PathBuf,
    },
    
    /// Export a profile to a file
    Export {
        #[arg(help = "Profile name")]
        name: String,
        
        #[arg(help = "Output file path")]
        path: PathBuf,
        
        #[arg(long, help = "Export format (json or toml)")]
        format: Option<String>,
    },
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
            
            // Set active profile if specified
            if let Some(profile_name) = &args.profile {
                match app.config().set_active_profile(profile_name).await {
                    Ok(_) => info!("Using profile: {}", profile_name),
                    Err(e) => {
                        error!("Failed to set profile {}: {}", profile_name, e);
                        exit(1);
                    }
                }
            }
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
                    // Initialize configuration and profiles
                    let config_path = app.config().save(None).await?;
                    
                    println!("Configuration initialized at {}", config_path.display());
                    
                    // Initialize profile system
                    app.profile_manager().initialize().await?;
                    
                    println!("Profile system initialized");
                    
                    return Ok(());
                },
                Cli::Profile { command } => {
                    match command {
                        ProfileCli::List => {
                            Command::Profile(ProfileCommand::List)
                        },
                        ProfileCli::Show { name } => {
                            Command::Profile(ProfileCommand::Show { name })
                        },
                        ProfileCli::Set { name } => {
                            Command::Profile(ProfileCommand::Set { name })
                        },
                        ProfileCli::Create { name, base, description } => {
                            Command::Profile(ProfileCommand::Create { name, base, description })
                        },
                        ProfileCli::Delete { name } => {
                            Command::Profile(ProfileCommand::Delete { name })
                        },
                        ProfileCli::Import { path } => {
                            Command::Profile(ProfileCommand::Import { path })
                        },
                        ProfileCli::Export { name, path, format } => {
                            Command::Profile(ProfileCommand::Export { name, path, format })
                        },
                    }
                },
                Cli::FilterScope { input, output } => {
                    Command::FilterScope(FilterScopeCommand::Filter { input, output })
                },
            };
            
            // Execute the command with the active profile (or the one specified in args)
            if let Err(e) = app.run_command(&command, args.profile.as_deref()).await {
                error!("Command execution failed: {}", e);
                exit(1);
            }
        },
        None => {
            println!("No command specified. Use --help for available commands.");
            Args::parse_from(&["bbhunt", "--help"]);
        }
    }
    
    Ok(())
}