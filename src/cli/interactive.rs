// src/cli/interactive.rs
use std::sync::Arc;
use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input, Select, Confirm};
use tracing::{info, debug, error};

use crate::context::Context;
use crate::error::{BBHuntResult, BBHuntError};

pub struct InteractiveShell {
    context: Arc<Context>,
    theme: ColorfulTheme,
}

impl InteractiveShell {
    pub fn new(context: Arc<Context>) -> Self {
        Self {
            context,
            theme: ColorfulTheme::default(),
        }
    }
    
    pub async fn run(&mut self) -> BBHuntResult<()> {
        println!("BBHunt Interactive Shell");
        println!("Type 'help' for assistance or 'exit' to quit");
        
        loop {
            let action: String = Input::with_theme(&self.theme)
                .with_prompt("bbhunt")
                .interact_text()
                .map_err(|e| BBHuntError::UnexpectedError(format!("Input error: {}", e)))?;
            
            match action.trim() {
                "exit" | "quit" => break,
                "help" => self.show_help(),
                "menu" => self.show_menu().await?,
                cmd if cmd.starts_with("run ") => {
                    self.handle_run_command(&cmd[4..]).await?;
                },
                cmd if cmd.starts_with("target ") => {
                    self.handle_target_command(&cmd[7..]).await?;
                },
                cmd if cmd.starts_with("plugins") => {
                    self.list_plugins().await?;
                },
                cmd if cmd.starts_with("resources") => {
                    self.show_resources().await?;
                },
                cmd if cmd.starts_with("osint ") => {
                    self.handle_osint_command(&cmd[6..]).await?;
                },
                _ => {
                    println!("Unknown command. Type 'help' for assistance or 'menu' for interactive menu.");
                }
            }
        }
        
        Ok(())
    }
    
    fn show_help(&self) {
        println!("BBHunt - Bug Bounty Hunting Framework");
        println!("Available commands:");
        println!("  target <command>    Manage targets");
        println!("  run <plugin> <target>  Run a specific plugin");
        println!("  plugins             List available plugins");
        println!("  resources           Show system resource usage");
        println!("  osint <target-id>   Collect OSINT data for a target");
        println!("  menu                Show interactive menu");
        println!("  help                Show this help message");
        println!("  exit                Exit the interactive shell");
    }
    
    async fn show_menu(&mut self) -> BBHuntResult<()> {
        loop {
            println!();
            let choices = &[
                "Target Management", 
                "Run Plugin", 
                "List Plugins", 
                "System Resources", 
                "OSINT Collection",
                "Exit Menu"
            ];
            
            let selection = Select::with_theme(&self.theme)
                .with_prompt("Select an option")
                .default(0)
                .items(choices)
                .interact()
                .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
            
            match selection {
                0 => self.target_management_menu().await?,
                1 => self.run_plugin_menu().await?,
                2 => self.list_plugins().await?,
                3 => self.show_resources().await?,
                4 => self.osint_menu().await?,
                5 => break,
                _ => println!("Invalid selection"),
            }
        }
        
        Ok(())
    }
    
    async fn target_management_menu(&mut self) -> BBHuntResult<()> {
        let choices = &[
            "List Targets", 
            "Add Target", 
            "Show Target Details", 
            "Delete Target", 
            "Back"
        ];
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Target Management")
            .default(0)
            .items(choices)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        match selection {
            0 => self.list_targets().await?,
            1 => self.add_target().await?,
            2 => self.show_target().await?,
            3 => self.delete_target().await?,
            4 => return Ok(()),
            _ => println!("Invalid selection"),
        }
        
        Ok(())
    }
    
    async fn list_targets(&mut self) -> BBHuntResult<()> {
        let target_manager = self.context.target_manager.lock().await;
        let targets = target_manager.list_targets();
        
        if targets.is_empty() {
            println!("No targets found");
            return Ok(());
        }
        
        println!("Available targets:");
        for target in targets {
            println!("- {} ({})", target.name, target.id);
            
            if let Some(domain) = &target.primary_domain {
                println!("  Primary Domain: {}", domain);
            }
            
            println!("  Domains: {}", target.domains.len());
            println!("  Subdomains: {}", target.subdomains.len());
        }
        
        Ok(())
    }
    
    async fn add_target(&mut self) -> BBHuntResult<()> {
        let name: String = Input::with_theme(&self.theme)
            .with_prompt("Target name")
            .interact_text()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Input error: {}", e)))?;
        
        let description: String = Input::with_theme(&self.theme)
            .with_prompt("Description (optional)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Input error: {}", e)))?;
        
        let description = if description.is_empty() { None } else { Some(description) };
        
        let domain: String = Input::with_theme(&self.theme)
            .with_prompt("Primary domain (optional)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Input error: {}", e)))?;
        
        let mut target_manager = self.context.target_manager.lock().await;
        
        // Create target
        let target_id = target_manager.create_target(name.clone(), description).await?;
        
        // Add domain if provided
        if !domain.is_empty() {
            if let Some(target) = target_manager.get_target_mut(&target_id) {
                target.primary_domain = Some(domain.clone());
                target.add_domain(domain);
            }
        }
        
        // Save target
        if let Some(target) = target_manager.get_target(&target_id) {
            target_manager.save_target(target).await?;
        }
        
        println!("Target created successfully with ID: {}", target_id);
        
        Ok(())
    }
    
    async fn show_target(&mut self) -> BBHuntResult<()> {
        let mut target_manager = self.context.target_manager.lock().await;
        let targets = target_manager.list_targets();
        
        if targets.is_empty() {
            println!("No targets found");
            return Ok(());
        }
        
        // Create a list of target names for selection
        let target_names: Vec<String> = targets.iter()
            .map(|t| format!("{} ({})", t.name, t.id))
            .collect();
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select a target")
            .default(0)
            .items(&target_names)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        let target = &targets[selection];
        
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
        
        if !target.osint.subdomains.is_empty() {
            println!("OSINT Subdomains ({})", target.osint.subdomains.len());
            for (i, subdomain) in target.osint.subdomains.iter().enumerate().take(5) {
                println!("  - {}", subdomain);
            }
            
            if target.osint.subdomains.len() > 5 {
                println!("  ... and {} more", target.osint.subdomains.len() - 5);
            }
        }
        
        Ok(())
    }
    
    async fn delete_target(&mut self) -> BBHuntResult<()> {
        let mut target_manager = self.context.target_manager.lock().await;
        let targets = target_manager.list_targets();
        
        if targets.is_empty() {
            println!("No targets found");
            return Ok(());
        }
        
        // Create a list of target names for selection
        let target_names: Vec<String> = targets.iter()
            .map(|t| format!("{} ({})", t.name, t.id))
            .collect();
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select a target to delete")
            .default(0)
            .items(&target_names)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        let target = &targets[selection];
        
        let confirm = Confirm::with_theme(&self.theme)
            .with_prompt(format!("Are you sure you want to delete target '{}'?", target.name))
            .default(false)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Confirmation error: {}", e)))?;
        
        if confirm {
            target_manager.delete_target(&target.id).await?;
            println!("Target deleted successfully");
        } else {
            println!("Deletion cancelled");
        }
        
        Ok(())
    }
    
    async fn run_plugin_menu(&mut self) -> BBHuntResult<()> {
        // Get available plugins
        let plugin_manager = self.context.plugin_manager.lock().await;
        let plugins = plugin_manager.get_plugins();
        
        if plugins.is_empty() {
            println!("No plugins available");
            return Ok(());
        }
        
        // Create a list of plugin names for selection
        let plugin_names: Vec<String> = plugins.iter()
            .map(|p| format!("{} - {}", p.name, p.description))
            .collect();
        
        let plugin_selection = Select::with_theme(&self.theme)
            .with_prompt("Select a plugin")
            .default(0)
            .items(&plugin_names)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        let plugin_name = &plugins[plugin_selection].name;
        
        // Get target
        let target_manager = self.context.target_manager.lock().await;
        let targets = target_manager.list_targets();
        
        if targets.is_empty() {
            println!("No targets available. Please create a target first.");
            return Ok(());
        }
        
        // Create a list of target names for selection
        let target_names: Vec<String> = targets.iter()
            .map(|t| format!("{} ({})", t.name, t.id))
            .collect();
        
        let target_selection = Select::with_theme(&self.theme)
            .with_prompt("Select a target")
            .default(0)
            .items(&target_names)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        let target_id = &targets[target_selection].id;
        
        // Ask for options
        let options_str: String = Input::with_theme(&self.theme)
            .with_prompt("Plugin options (JSON, optional)")
            .allow_empty(true)
            .interact_text()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Input error: {}", e)))?;
        
        let options = if options_str.is_empty() {
            None
        } else {
            match serde_json::from_str(&options_str) {
                Ok(opts) => Some(opts),
                Err(e) => {
                    println!("Invalid JSON options: {}", e);
                    return Ok(());
                }
            }
        };
        
        // Run the plugin
        drop(plugin_manager);
        drop(target_manager);
        
        println!("Running plugin '{}' on target '{}'...", plugin_name, target_id);
        
        let mut plugin_manager = self.context.plugin_manager.lock().await;
        match plugin_manager.run_plugin(plugin_name, target_id, options).await {
            Ok(result) => {
                println!("Status: {:?}", result.status);
                println!("Message: {}", result.message);
                println!("Execution time: {:?}", result.execution_time);
                
                if !result.data.is_empty() {
                    println!("Results:");
                    match serde_json::to_string_pretty(&result.data) {
                        Ok(json) => println!("{}", json),
                        Err(e) => println!("Error formatting results: {}", e),
                    }
                }
            },
            Err(e) => {
                println!("Error running plugin: {}", e);
            }
        }
        
        Ok(())
    }
    
    async fn list_plugins(&mut self) -> BBHuntResult<()> {
        let plugin_manager = self.context.plugin_manager.lock().await;
        let plugins = plugin_manager.get_plugins();
        
        if plugins.is_empty() {
            println!("No plugins available");
            return Ok(());
        }
        
        println!("{} plugins available:", plugins.len());
        
        // Group plugins by category
        let mut recon_plugins = Vec::new();
        let mut scan_plugins = Vec::new();
        let mut exploit_plugins = Vec::new();
        let mut utility_plugins = Vec::new();
        
        for plugin in plugins {
            match plugin.category {
                crate::core::plugin::PluginCategory::Recon => recon_plugins.push(plugin),
                crate::core::plugin::PluginCategory::Scan => scan_plugins.push(plugin),
                crate::core::plugin::PluginCategory::Exploit => exploit_plugins.push(plugin),
                crate::core::plugin::PluginCategory::Utility => utility_plugins.push(plugin),
            }
        }
        
        if !recon_plugins.is_empty() {
            println!("\nReconnaissance Plugins:");
            for plugin in recon_plugins {
                println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
            }
        }
        
        if !scan_plugins.is_empty() {
            println!("\nScanning Plugins:");
            for plugin in scan_plugins {
                println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
            }
        }
        
        if !exploit_plugins.is_empty() {
            println!("\nExploit Plugins:");
            for plugin in exploit_plugins {
                println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
            }
        }
        
        if !utility_plugins.is_empty() {
            println!("\nUtility Plugins:");
            for plugin in utility_plugins {
                println!("- {} (v{}): {}", plugin.name, plugin.version, plugin.description);
            }
        }
        
        Ok(())
    }
    
    async fn show_resources(&mut self) -> BBHuntResult<()> {
        println!("System Resource Usage:");
        
        let resource_manager = &self.context.resource_manager;
        match resource_manager.get_resource_usage().await {
            Ok(usage) => {
                println!("Memory:");
                println!("  Total: {} MB", usage.memory.total);
                println!("  Used: {} MB ({}%)", usage.memory.used, usage.memory.percent);
                println!("  Available: {} MB", usage.memory.available);
                
                println!("\nCPU:");
                println!("  Cores: {}", usage.cpu.cores);
                println!("  Usage: {}%", usage.cpu.total_usage);
                
                println!("\nDisk:");
                println!("  Total: {} MB", usage.disk.total);
                println!("  Used: {} MB ({}%)", usage.disk.used, usage.disk.percent);
                println!("  Free: {} MB", usage.disk.free);
                
                if !usage.active_processes.is_empty() {
                    println!("\nActive Processes:");
                    for process in &usage.active_processes {
                        println!("  {} (PID {}): Memory: {} MB, CPU: {}%", 
                            process.name, process.pid, process.memory_usage, process.cpu_usage);
                    }
                }
            },
            Err(e) => {
                println!("Error getting resource usage: {}", e);
            }
        }
        
        Ok(())
    }
    
    async fn osint_menu(&mut self) -> BBHuntResult<()> {
        // Get available targets
        let target_manager = self.context.target_manager.lock().await;
        let targets = target_manager.list_targets();
        
        if targets.is_empty() {
            println!("No targets available. Please create a target first.");
            return Ok(());
        }
        
        // Create a list of target names for selection
        let target_names: Vec<String> = targets.iter()
            .map(|t| format!("{} ({})", t.name, t.id))
            .collect();
        
        let target_selection = Select::with_theme(&self.theme)
            .with_prompt("Select a target for OSINT collection")
            .default(0)
            .items(&target_names)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        let target_id = targets[target_selection].id.clone();
        
        // Get available OSINT sources
        let osint_collector = self.context.osint_collector.lock().await;
        
        // Register sources if not done yet
        if osint_collector.list_sources().is_empty() {
            drop(osint_collector);
            let mut collector = self.context.osint_collector.lock().await;
            collector.register_source(Box::new(crate::osint::sources::DnsOsintSource::new()))?;
            collector.register_source(Box::new(crate::osint::sources::WhoisOsintSource::new()))?;
            collector.register_source(Box::new(crate::osint::sources::SslCertificateOsintSource::new()))?;
            collector.register_source(Box::new(crate::osint::sources::CtLogOsintSource::new()))?;
            drop(collector);
        }
        
        // Re-acquire the lock and get sources
        let osint_collector = self.context.osint_collector.lock().await;
        let sources = osint_collector.list_sources();
        
        let source_choices = {
            let mut choices = sources.clone();
            choices.insert(0, "All Sources".to_string());
            choices
        };
        
        let source_selection = Select::with_theme(&self.theme)
            .with_prompt("Select OSINT source")
            .default(0)
            .items(&source_choices)
            .interact()
            .map_err(|e| BBHuntError::UnexpectedError(format!("Selection error: {}", e)))?;
        
        // Release locks before operation
        drop(target_manager);
        drop(osint_collector);
        
        // Run OSINT collection
        println!("Running OSINT collection...");
        
        let mut target_manager = self.context.target_manager.lock().await;
        let mut osint_collector = self.context.osint_collector.lock().await;
        
        let mut target_data = target_manager.get_target_mut(&target_id)
            .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?;
        
        if source_selection == 0 {
            // Run all sources
            osint_collector.collect_all(target_data).await?;
        } else {
            // Run specific source
            let source_name = &source_choices[source_selection];
            osint_collector.collect_from_source(target_data, source_name).await?;
        }
        
        // Save the updated target
        target_manager.save_target(
            target_manager.get_target(&target_id)
                .ok_or_else(|| BBHuntError::TargetNotFound(target_id.clone()))?
        ).await?;
        
        println!("OSINT collection completed");
        
        Ok(())
    }
    
    async fn handle_run_command(&mut self, args: &str) -> BBHuntResult<()> {
        let parts: Vec<&str> = args.splitn(3, ' ').collect();
        
        if parts.len() < 2 {
            println!("Insufficient arguments. Usage: run <plugin> <target> [options]");
            return Ok(());
        }
        
        let plugin_name = parts[0];
        let target_id = parts[1];
        let options_str = if parts.len() > 2 { Some(parts[2]) } else { None };
        
        let options = if let Some(opts) = options_str {
            match serde_json::from_str(opts) {
                Ok(parsed) => Some(parsed),
                Err(e) => {
                    println!("Invalid JSON options: {}", e);
                    return Ok(());
                }
            }
        } else {
            None
        };
        
        println!("Running plugin '{}' on target '{}'...", plugin_name, target_id);
        
        let mut plugin_manager = self.context.plugin_manager.lock().await;
        match plugin_manager.run_plugin(plugin_name, target_id, options).await {
            Ok(result) => {
                println!("Status: {:?}", result.status);
                println!("Message: {}", result.message);
                println!("Execution time: {:?}", result.execution_time);
                
                if !result.data.is_empty() {
                    println!("Results:");
                    match serde_json::to_string_pretty(&result.data) {
                        Ok(json) => println!("{}", json),
                        Err(e) => println!("Error formatting results: {}", e),
                    }
                }
            },
            Err(e) => {
                println!("Error running plugin: {}", e);
            }
        }
        
        Ok(())
    }
    
    async fn handle_target_command(&mut self, args: &str) -> BBHuntResult<()> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        
        if parts.is_empty() {
            println!("Insufficient arguments. Usage: target <list|add|show|delete> [args]");
            return Ok(());
        }
        
        match parts[0] {
            "list" => self.list_targets().await?,
            "add" => self.add_target().await?,
            "show" => {
                if parts.len() < 2 {
                    println!("Missing target name. Usage: target show <name>");
                    return Ok(());
                }
                
                let name = parts[1];
                let target_manager = self.context.target_manager.lock().await;
                let targets = target_manager.list_targets();
                
                let target = targets.iter()
                    .find(|t| t.name == name || t.id == name);
                
                match target {
                    Some(target) => {
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
                    },
                    None => {
                        println!("Target not found: {}", name);
                    }
                }
            },
            "delete" => {
                if parts.len() < 2 {
                    println!("Missing target name. Usage: target delete <name>");
                    return Ok(());
                }
                
                let name = parts[1];
                let mut target_manager = self.context.target_manager.lock().await;
                
                // Find target by name or ID
                let targets = target_manager.list_targets();
                let target_id = targets.iter()
                    .find(|t| t.name == name || t.id == name)
                    .map(|t| t.id.clone());
                
                match target_id {
                    Some(id) => {
                        let confirm = Confirm::with_theme(&self.theme)
                            .with_prompt(format!("Are you sure you want to delete target '{}'?", name))
                            .default(false)
                            .interact()
                            .map_err(|e| BBHuntError::UnexpectedError(format!("Confirmation error: {}", e)))?;
                        
                        if confirm {
                            target_manager.delete_target(&id).await?;
                            println!("Target deleted successfully");
                        } else {
                            println!("Deletion cancelled");
                        }
                    },
                    None => {
                        println!("Target not found: {}", name);
                    }
                }
            },
            _ => {
                println!("Unknown target command: {}. Available commands: list, add, show, delete", parts[0]);
            }
        }
        
        Ok(())
    }
    
    async fn handle_osint_command(&mut self, args: &str) -> BBHuntResult<()> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        
        if parts.is_empty() {
            println!("Missing target. Usage: osint <target-id> [source]");
            return Ok(());
        }
        
        let target_id = parts[0];
        let source = if parts.len() > 1 { Some(parts[1].to_string()) } else { None };
        
        println!("Running OSINT collection for target: {}", target_id);
        
        let mut target_manager = self.context.target_manager.lock().await;
        
        // Verify target exists
        if !target_manager.list_targets().iter().any(|t| t.id == target_id || t.name == target_id) {
            println!("Target not found: {}", target_id);
            return Ok(());
        }
        
        // Get OSINT collector
        let mut osint_collector = self.context.osint_collector.lock().await;
        
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
            match osint_collector.collect_from_source(target_data, &source_name).await {
                Ok(_) => println!("Successfully collected data from {}", source_name),
                Err(e) => println!("Error collecting data from {}: {}", source_name, e),
            }
        } else {
            println!("Running all OSINT sources");
            match osint_collector.collect_all(target_data).await {
                Ok(_) => println!("Successfully collected data from all sources"),
                Err(e) => println!("Error collecting data: {}", e),
            }
        }
        
        // Save target with updated OSINT data
        match target_manager.save_target(
            target_manager.get_target(target_id)
                .ok_or_else(|| BBHuntError::TargetNotFound(target_id.to_string()))?
        ).await {
            Ok(_) => println!("Target data saved successfully"),
            Err(e) => println!("Error saving target data: {}", e),
        }
        
        println!("OSINT collection completed");
        Ok(())
    }
}