use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::HashMap;
use crate::core::parallel::TaskDefinition;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGeneratorConfig {
    pub task_type: TaskType,
    pub plugins: Vec<String>,
    pub max_targets_per_task: usize,
    pub options: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskType {
    Recon,
    Scan,
    Exploit,
}

pub struct TaskGenerator {
    config: TaskGeneratorConfig,
}

impl TaskGenerator {
    pub fn new(config: TaskGeneratorConfig) -> Self {
        Self { config }
    }
    
    pub fn generate_from_results(&self, results_path: &Path) -> Result<Vec<TaskDefinition>> {
        let results_str = std::fs::read_to_string(results_path)?;
        let results: Vec<crate::core::parallel::TaskResult> = serde_json::from_str(&results_str)?;
        
        let mut tasks = Vec::new();
        let mut targets = Vec::new();
        
        // Extract targets from results
        for result in &results {
            if let Some(plugin_result) = &result.result {
                match self.config.task_type {
                    TaskType::Recon => {
                        // For recon -> scan, we want to extract discovered hosts/domains
                        if let Some(Value::Array(subdomains)) = plugin_result.data.get("subdomains") {
                            for subdomain in subdomains {
                                if let Value::String(domain) = subdomain {
                                    targets.push(domain.clone());
                                }
                            }
                        }
                    },
                    TaskType::Scan => {
                        // For scan -> exploit, we might extract vulnerable URLs
                        if let Some(Value::Array(vulnerabilities)) = plugin_result.data.get("vulnerabilities") {
                            for vuln in vulnerabilities {
                                if let Some(Value::String(url)) = vuln.get("url") {
                                    targets.push(url.clone());
                                }
                            }
                        }
                    },
                    TaskType::Exploit => {
                        // Custom logic for exploit task generation
                    }
                }
            }
        }
        
        // Deduplicate targets
        targets.sort();
        targets.dedup();
        
        // Create tasks for each plugin and target
        for plugin in &self.config.plugins {
            // Batch targets if needed
            let target_chunks = targets.chunks(self.config.max_targets_per_task);
            
            for (i, chunk) in target_chunks.enumerate() {
                for target in chunk {
                    let task_id = format!("{}-{}-{}", self.config.task_type_str(), plugin, i);
                    
                    let task = TaskDefinition {
                        id: task_id,
                        plugin: plugin.clone(),
                        target: target.clone(),
                        options: Some(self.config.options.clone().into()),
                        dependencies: Vec::new(), // Add dependency logic if needed
                    };
                    
                    tasks.push(task);
                }
            }
        }
        
        Ok(tasks)
    }
    
    fn task_type_str(&self) -> &'static str {
        match self.config.task_type {
            TaskType::Recon => "recon",
            TaskType::Scan => "scan",
            TaskType::Exploit => "exploit",
        }
    }
    
    pub fn save_tasks(&self, tasks: &[TaskDefinition], output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(tasks)?;
        std::fs::write(output_path, json)?;
        Ok(())
    }
}