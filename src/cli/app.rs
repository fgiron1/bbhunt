use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, debug, error};

use crate::config::Config;
use crate::context::Context;
use crate::error::{BBHuntResult, BBHuntError};

use super::commands::{self, Args};
use super::interactive::InteractiveShell;

/// The main application struct
pub struct App {
    context: Option<Arc<Context>>,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Self {
        Self {
            context: None,
        }
    }
    
    /// Initialize the application
    pub async fn initialize(&mut self) -> BBHuntResult<()> {
        // Initialize context
        let context = Context::new().await?;
        let context = Arc::new(context);
        
        // Initialize directories and resources
        context.initialize().await?;
        
        self.context = Some(context);
        
        Ok(())
    }
    
    /// Run the application
    pub async fn run(&mut self) -> BBHuntResult<()> {
        // Ensure we have context
        let context = match &self.context {
            Some(ctx) => ctx.clone(),
            None => {
                // Initialize if not already done
                self.initialize().await?;
                self.context.as_ref().unwrap().clone()
            }
        };
        
        // Parse command line arguments
        let args = Args::parse();
        
        info!("Starting BBHunt v{}", env!("CARGO_PKG_VERSION"));
        
        if args.verbose {
            info!("Verbose mode enabled");
        }
        
        // Handle commands or start interactive shell
        match &args.command {
            Some(command) => {
                commands::execute_command(command, context).await?;
            }
            None => {
                // Check if we should use interactive mode
                if cfg!(windows) || args.interactive {
                    info!("Starting interactive shell");
                    let mut shell = InteractiveShell::new(context);
                    shell.run().await?;
                } else {
                    // On non-Windows platforms without explicit interactive flag, show help
                    println!("No command specified. Use --help for available commands or --interactive for interactive mode.");
                    Args::parse_from(&["bbhunt", "--help"]);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get context
    pub fn context(&self) -> BBHuntResult<Arc<Context>> {
        self.context.clone().ok_or_else(|| BBHuntError::ContextError("Application context not initialized".to_string()))
    }
}