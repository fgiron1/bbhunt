use std::collections::HashMap;
use anyhow::{Result, Context};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, debug, error};
use url::Url;
use tempfile::NamedTempFile;

use crate::core::plugin::{Plugin, PluginMetadata, PluginCategory, PluginResult, PluginStatus};
use crate::utils::http::HttpClient;
use crate::utils::shell;
use crate::reporting::model::Severity;

/// Web scanning plugin
pub struct WebScanPlugin {
    metadata: PluginMetadata,
    http_client: Option<HttpClient>,
    scan_tools: Vec<WebScanTool>,
}

#[derive(Debug)]
struct WebScanTool {
    name: String,
    command_template: String,
    risk_level: RiskLevel,
}

#[derive(Debug, PartialEq)]
enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Vulnerability {
    name: String,
    description: String,
    severity: Severity,
    url: String,
    cvss_score: Option<f32>,
    cve_ids: Option<Vec<String>>,
    details: Option<HashMap<String, Value>>,
    request_response: Option<RequestResponse>,
    evidence: String,
    remediation: Option<String>,
    references: Option<Vec<Reference>>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RequestResponse {
    request: String,
    response: String,
    status_code: u16,
    headers: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Reference {
    title: String,
    url: String,
    source_type: crate::reporting::model::ReferenceType,
}

impl WebScanPlugin {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "web_scan".to_string(),
                description: "Scan web applications for vulnerabilities".to_string(),
                version: "0.1.0".to_string(),
                category: PluginCategory::Scan,
                author: "BBHunt Team".to_string(),
                required_tools: vec!["nuclei".to_string(), "nikto".to_string()],
            },
            http_client: None,
            scan_tools: Vec::new(),
        }
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
        let output_file = NamedTempFile::new()?;
        let output_path = output_file.path().to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert path to string"))?;
        
        // Format command
        let command = command_template
            .replace("{target}", &target.to_string())
            .replace("{output}", output_path);
        
        // Execute command
        let output = shell::execute_command_with_timeout(&command, 600).await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Web scan tool {} failed: {}", tool_name, stderr);
            return Err(anyhow::anyhow!("Web scan tool {} failed: {}", tool_name, stderr));
        }
        
        // Parse results based on tool
        let vulnerabilities = match tool_name {
            "nuclei" => self.parse_nuclei_results(output_file.path()),
            "nikto" => self.parse_nikto_results(output_file.path()),
            _ => Ok(Vec::new()),
        }?;
        
        debug!("Found {} vulnerabilities with {}", vulnerabilities.len(), tool_name);
        Ok(vulnerabilities)
    }
    
    /// Parse Nuclei results
    fn parse_nuclei_results(&self, output_path: &std::path::Path) -> Result<Vec<Vulnerability>> {
        // This is a simplified implementation
        // In a real implementation, you would parse the actual Nuclei output format
        
        let content = std::fs::read_to_string(output_path)
            .context("Failed to read Nuclei results")?;
        
        // Example implementation - Nuclei typically outputs JSON lines
        let vulnerabilities = content
            .lines()
            .filter_map(|line| {
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
                        
                        return Some(Vulnerability {
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
                                    .collect()),
                            details: Some(HashMap::new()),
                            request_response: value.get("request").and_then(|r| r.as_str())
                                .and_then(|req| {
                                    value.get("response").and_then(|r| r.as_str()).map(|res| {
                                        RequestResponse {
                                            request: req.to_string(),
                                            response: res.to_string(),
                                            status_code: value.get("status-code")
                                                .and_then(|s| s.as_u64())
                                                .map(|s| s as u16)
                                                .unwrap_or(0),
                                            headers: HashMap::new(),
                                        }
                                    })
                                }),
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
                                            source_type: crate::reporting::model::ReferenceType::Other,
                                        }
                                    ))
                                    .collect()),
                            tags: value.get("info")
                                .and_then(|i| i.get("tags"))
                                .and_then(|t| t.as_array())
                                .map(|arr| arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()),
                        });
                    }
                }
                None
            })
            .collect();
        
        Ok(vulnerabilities)
    }
    
    /// Parse Nikto results
    fn parse_nikto_results(&self, output_path: &std::path::Path) -> Result<Vec<Vulnerability>> {
        // This is a simplified implementation
        // In a real implementation, you would parse the actual Nikto output format
        
        let content = std::fs::read_to_string(output_path)
            .context("Failed to read Nikto results")?;
        
        // Example implementation - Nikto typically outputs in a specific format
        let mut vulnerabilities = Vec::new();
        
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
                        cve_ids: None,
                        details: Some(HashMap::new()),
                        request_response: None,
                        evidence: line.to_string(),
                        remediation: None,
                        references: None,
                        tags: Some(vec![id]),
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
        self.scan_tools = vec![
            WebScanTool {
                name: "nuclei".to_string(),
                command_template: "nuclei -target {target} -output {output} -json".to_string(),
                risk_level: RiskLevel::Medium,
            },
            WebScanTool {
                name: "nikto".to_string(),
                command_template: "nikto -h {target} -output {output} -Format txt".to_string(),
                risk_level: RiskLevel::Low,
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
        info!("Running web scan on target: {}", target);
        
        let start_time = std::time::Instant::now();
        
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

        let mut vulnerabilities = Vec::new();

        // Run appropriate scan tools based on mode
        for tool in &self.scan_tools {
            // Filter tools based on scan mode and risk level
            let should_run = match (scan_mode, &tool.risk_level) {
                ("basic", RiskLevel::Low) => true,
                ("standard", RiskLevel::Low) |
                ("standard", RiskLevel::Medium) => true,
                ("thorough", _) => true,
                _ => false,
            };
            
            if should_run {
                debug!("Running scan tool: {}", tool.name);
                
                match self.run_web_scan_tool(&parsed_url, &tool.name, &tool.command_template).await {
                    Ok(mut found_vulns) => {
                        info!("Found {} vulnerabilities with {}", found_vulns.len(), tool.name);
                        vulnerabilities.append(&mut found_vulns);
                    }
                    Err(e) => {
                        error!("Error running {}: {}", tool.name, e);
                    }
                }
            } else {
                debug!("Skipping scan tool {} for mode {}", tool.name, scan_mode);
            }
        }

        // Analyze and categorize vulnerabilities
        let severity_counts = self.categorize_vulnerabilities(&vulnerabilities);
        
        // Build result
        let mut result_data = HashMap::new();
        result_data.insert("total_vulnerabilities".to_string(), Value::Number(vulnerabilities.len().into()));
        result_data.insert("severity_counts".to_string(), serde_json::to_value(severity_counts)?);
        result_data.insert("vulnerabilities".to_string(), serde_json::to_value(&vulnerabilities)?);        
        let execution_time = start_time.elapsed();
        
        info!("Web scan completed in {:?}", execution_time);
        
        Ok(PluginResult {
            status: PluginStatus::Success,
            message: format!("Scanned {} with {} vulnerabilities", target, vulnerabilities.len()),
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
    Box::new(WebScanPlugin::new())
}