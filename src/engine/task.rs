// src/engine/task.rs
use std::path::Path;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, debug};
use serde::{Serialize, Deserialize};

use crate::error::{BBHuntResult, BBHuntError};
use crate::context::Context;
use std::sync::Arc;

/// Task definition for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub id: String,
    pub plugin: String,
    pub target: String,
    pub options: Option<serde_json::Value>,
    pub dependencies: Vec<String>,
}

/// Result of task execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub plugin: String,
    pub target: String,
    pub status: TaskStatus,
    pub result: Option<crate::core::plugin::PluginResult>,
    pub error: Option<String>,
    pub execution_time: Duration,
}

/// Status of a task
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Timeout,
}

/// Type of tasks to generate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskType {
    Recon,
    Scan,
    Exploit,
}

/// Configuration for task generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGeneratorConfig {
    pub task_type: TaskType,
    pub plugins: Vec<String>,
    pub max_targets_per_task: usize,
    pub options: HashMap<String, serde_json::Value>,
}

/// Generator for creating task definitions
pub struct TaskGenerator {
    config: TaskGeneratorConfig,
    context: Option<Arc<Context>>,
}

impl TaskGenerator {
    /// Create a new task generator
    pub fn new(config: TaskGeneratorConfig) -> Self {
        Self { 
            config,
            context: None,
        }
    }
    
    /// Create a new task generator with context
    pub fn new_with_context(config: TaskGeneratorConfig, context: Arc<Context>) -> Self {
        Self {
            config,
            context: Some(context),
        }
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    /// Generate tasks from previous results
    pub fn generate_from_results(&self, results_path: &Path) -> BBHuntResult<Vec<TaskDefinition>> {
        info!("Generating tasks from results file: {}", results_path.display());
        
        let results_str = std::fs::read_to_string(results_path)
            .map_err(|e| BBHuntError::FileError {
                path: results_path.to_path_buf(),
                message: format!("Failed to read file: {}", e),
            })?;
            
        let results: Vec<TaskResult> = serde_json::from_str(&results_str)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to parse JSON: {}", e)))?;
        
        let mut tasks = Vec::new();
        let mut targets = Vec::new();
        
        // Extract targets from results
        for result in &results {
            if let Some(plugin_result) = &result.result {
                match self.config.task_type {
                    TaskType::Recon => {
                        // For recon -> scan, extract discovered hosts/domains
                        if let Some(subdomains) = plugin_result.data.get("subdomains") {
                            if let serde_json::Value::Array(subdomains) = subdomains {
                                for subdomain in subdomains {
                                    if let serde_json::Value::String(domain) = subdomain {
                                        targets.push(domain.clone());
                                    }
                                }
                            }
                        }
                    },
                    TaskType::Scan => {
                        // For scan -> exploit, extract vulnerable URLs
                        if let Some(vulnerabilities) = plugin_result.data.get("vulnerabilities") {
                            if let serde_json::Value::Array(vulnerabilities) = vulnerabilities {
                                for vuln in vulnerabilities {
                                    if let Some(serde_json::Value::String(url)) = vuln.get("url") {
                                        targets.push(url.clone());
                                    }
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
        
        debug!("Found {} unique targets", targets.len());
        
        // Create tasks for each plugin and target
        for plugin in &self.config.plugins {
            // Batch targets if needed
            let target_chunks = targets.chunks(self.config.max_targets_per_task);
            
            for (i, chunk) in target_chunks.enumerate() {
                for target in chunk {
                    let task_id = format!("{}-{}-{}", self.task_type_str(), plugin, i);
                    
                    let task = TaskDefinition {
                        id: task_id,
                        plugin: plugin.clone(),
                        target: target.clone(),
                        options: Some(serde_json::to_value(&self.config.options)
                            .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize options: {}", e)))?),
                        dependencies: Vec::new(), // Add dependency logic if needed
                    };
                    
                    tasks.push(task);
                }
            }
        }
        
        info!("Generated {} tasks", tasks.len());
        Ok(tasks)
    }
    
    /// Get string representation of task type
    fn task_type_str(&self) -> &'static str {
        match self.config.task_type {
            TaskType::Recon => "recon",
            TaskType::Scan => "scan",
            TaskType::Exploit => "exploit",
        }
    }
    
    /// Save tasks to a file
    pub fn save_tasks(&self, tasks: &[TaskDefinition], output_path: &Path) -> BBHuntResult<()> {
        info!("Saving {} tasks to {}", tasks.len(), output_path.display());
        
        let json = serde_json::to_string_pretty(tasks)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize tasks: {}", e)))?;
            
        std::fs::write(output_path, json)
            .map_err(|e| BBHuntError::FileError {
                path: output_path.to_path_buf(),
                message: format!("Failed to write file: {}", e),
            })?;
            
        Ok(())
    }
    
    /// Load tasks from a file
    pub fn load_tasks(path: &Path) -> BBHuntResult<Vec<TaskDefinition>> {
        info!("Loading tasks from {}", path.display());
        
        let json = std::fs::read_to_string(path)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to read file: {}", e),
            })?;
            
        let tasks: Vec<TaskDefinition> = serde_json::from_str(&json)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to parse JSON: {}", e)))?;
            
        Ok(tasks)
    }
}

/// Task trait for representing a task
#[async_trait::async_trait]
pub trait Task {
    /// Get the task ID
    fn id(&self) -> &str;
    
    /// Execute the task
    async fn execute(&mut self) -> BBHuntResult<TaskResult>;
    
    /// Check if the task has dependencies
    fn has_dependencies(&self) -> bool;
    
    /// Get the task dependencies
    fn dependencies(&self) -> &[String];
    
    /// Set the context
    fn set_context(&mut self, context: Arc<Context>);
}