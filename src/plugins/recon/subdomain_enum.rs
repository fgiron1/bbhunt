use std::collections::HashMap;
use anyhow::{Result, Context};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, debug, error};
use tempfile::NamedTempFile;

use crate::core::plugin::{Plugin, PluginMetadata, PluginCategory, PluginResult, PluginStatus};
use crate::utils::http::HttpClient;
use crate::utils::shell;

/// Subdomain enumeration plugin
pub struct SubdomainEnumPlugin {
    metadata: PluginMetadata,
    http_client: Option<HttpClient>,
    tools: Vec<SubdomainTool>,
}

#[derive(Debug)]
struct SubdomainTool {
    name: String,
    command_template: String,
    passive: bool,
}

impl SubdomainEnumPlugin {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "subdomain_enum".to_string(),
                description: "Enumerate subdomains using various techniques".to_string(),
                version: "0.1.0".to_string(),
                category: PluginCategory::Recon,
                author: "BBHunt Team".to_string(),
                required_tools: vec!["subfinder".to_string(), "amass".to_string()],
            },
            http_client: None,
            tools: Vec::new(),
        }
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
        let output_file = NamedTempFile::new()?;
        let output_path = output_file.path().to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))?;
        
        // Format command
        let command = command_template
            .replace("{target}", target)
            .replace("{output}", output_path);
        
        // Execute command
        let output = shell::execute_command(&command).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Subdomain tool {} failed: {}", tool_name, stderr);
            return Err(anyhow::anyhow!("Subdomain tool {} failed: {}", tool_name, stderr));
        }
        
        // Read results
        let content = std::fs::read_to_string(output_path)
            .context(format!("Failed to read output from {}", tool_name))?;
        
        // Parse results
        let subdomains = content
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
            let url = format!("https://{}", subdomain);
            
            if client.is_url_live(&url).await {
                debug!("Subdomain {} is live", subdomain);
                live_subdomains.push(subdomain.clone());
            } else {
                // Try HTTP if HTTPS failed
                let url = format!("http://{}", subdomain);
                if client.is_url_live(&url).await {
                    debug!("Subdomain {} is live (HTTP)", subdomain);
                    live_subdomains.push(subdomain.clone());
                }
            }
        }
        
        info!("Verified {} live subdomains out of {}", live_subdomains.len(), subdomains.len());
        Ok(live_subdomains)
    }
}

#[async_trait]
impl Plugin for SubdomainEnumPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn init(&mut self, config: &crate::config::Config) -> Result<()> {
        // Initialize HTTP client
        self.http_client = Some(HttpClient::new(
            Some(config.global.user_agent.clone()),
            None,
        )?);
        
        // Configure tools
        self.tools = vec![
            SubdomainTool {
                name: "subfinder".to_string(),
                command_template: "subfinder -d {target} -o {output}".to_string(),
                passive: false,
            },
            SubdomainTool {
                name: "amass".to_string(),
                command_template: "amass enum -d {target} -o {output}".to_string(),
                passive: true,
            },
        ];
        
        Ok(())
    }

    async fn setup(&mut self) -> Result<()> {
        // Nothing to do here
        Ok(())
    }

    async fn execute(
        &mut self, 
        target: &str, 
        options: Option<HashMap<String, Value>>
    ) -> Result<PluginResult> {
        info!("Running subdomain enumeration on target: {}", target);
        
        let start_time = std::time::Instant::now();
        
        // Parse options
        let passive_only = options
            .as_ref()
            .and_then(|opts| opts.get("passive_only"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        debug!("Passive mode: {}", passive_only);

        let mut all_subdomains = Vec::new();

        for tool in &self.tools {
            // Skip tools based on passive mode
            if passive_only && !tool.passive {
                debug!("Skipping {} in passive mode", tool.name);
                continue;
            }

            match self.run_subdomain_tool(target, &tool.name, &tool.command_template).await {
                Ok(subdomains) => {
                    info!("Found {} subdomains with {}", subdomains.len(), tool.name);
                    all_subdomains.extend(subdomains);
                }
                Err(e) => {
                    error!("Error running {}: {}", tool.name, e);
                }
            }
        }

        // Deduplicate subdomains
        let mut unique_subdomains: Vec<String> = all_subdomains
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        
        // Sort for consistent output
        unique_subdomains.sort();

        // Verify live subdomains
        let live_subdomains = self.verify_live_subdomains(&unique_subdomains).await?;

        // Build result
        let mut result_data = HashMap::new();
        result_data.insert("total_subdomains".to_string(), Value::Number(unique_subdomains.len().into()));
        result_data.insert("live_subdomains".to_string(), Value::Number(live_subdomains.len().into()));
        result_data.insert("subdomains".to_string(), Value::Array(
            unique_subdomains.into_iter().map(Value::String).collect()
        ));
        
        let execution_time = start_time.elapsed();

        info!("Subdomain enumeration completed in {:?}", execution_time);
        
        Ok(PluginResult {
            status: PluginStatus::Success,
            message: format!("Found {} total subdomains, {} live", result_data["total_subdomains"], result_data["live_subdomains"]),
            data: result_data,
            execution_time,
        })
    }

    async fn cleanup(&mut self) -> Result<()> {
        // Nothing to clean up
        Ok(())
    }
}

/// Create a new plugin instance
pub fn create() -> Box<dyn Plugin> {
    Box::new(SubdomainEnumPlugin::new())
}