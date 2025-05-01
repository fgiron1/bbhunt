// src/engine/workflow.rs
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, debug, warn};

use crate::error::{BBHuntResult, BBHuntError};
use crate::context::Context;
use super::task::{TaskDefinition, TaskResult, TaskStatus};
use super::parallel::ParallelExecutor;

/// Step in a workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub name: String,
    pub tasks: Vec<TaskDefinition>,
    pub depends_on: Vec<String>,
    pub max_concurrent: usize,
    pub continue_on_error: bool,
}

/// Result of a workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowResult {
    pub name: String,
    pub steps: HashMap<String, Vec<TaskResult>>,
    pub status: WorkflowStatus,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub duration_seconds: u64,
}

/// Status of a workflow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowStatus {
    Success,
    Partial,
    Failed,
}

/// Workflow for executing multiple steps
pub struct Workflow {
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    executor: ParallelExecutor,
    context: Option<Arc<Context>>,
}

impl Workflow {
    /// Create a new workflow
    pub fn new(name: String, steps: Vec<WorkflowStep>, executor: ParallelExecutor) -> Self {
        Self {
            name,
            steps,
            executor,
            context: None,
        }
    }
    
    /// Create a new workflow with context
    pub fn new_with_context(name: String, steps: Vec<WorkflowStep>, context: Arc<Context>) -> Self {
        let plugin_manager = context.plugin_manager.clone();
        let executor = ParallelExecutor::new(4, plugin_manager); // Default concurrency
        
        Self {
            name,
            steps,
            executor,
            context: Some(context),
        }
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context.clone());
        self.executor.set_context(context);
    }
    
    /// Execute the workflow
    pub async fn execute(&self) -> BBHuntResult<WorkflowResult> {
        info!("Starting workflow: {}", self.name);
        let start_time = chrono::Utc::now();
        
        let mut results = HashMap::new();
        let mut completed_steps = HashSet::new();
        let mut pending_steps: Vec<&WorkflowStep> = self.steps.iter().collect();
        
        while !pending_steps.is_empty() {
            // Find steps with satisfied dependencies
            let runnable_steps: Vec<&WorkflowStep> = pending_steps
                .iter()
                .filter(|step| step.depends_on.iter().all(|dep| completed_steps.contains(dep)))
                .cloned()
                .collect();
            
            if runnable_steps.is_empty() && !pending_steps.is_empty() {
                return Err(BBHuntError::DependencyError("Circular dependency detected in workflow steps".to_string()));
            }
            
            debug!("Found {} runnable steps", runnable_steps.len());
            
            // Execute steps
            for step in runnable_steps {
                info!("Executing workflow step: {}", step.name);
                
                // Execute tasks in parallel
                let task_results = self.executor.execute_tasks(step.tasks.clone()).await?;
                
                // Check for failures
                let failed_tasks = task_results.iter()
                    .filter(|r| r.status == TaskStatus::Failed)
                    .count();
                
                if failed_tasks > 0 && !step.continue_on_error {
                    warn!("Step {} failed with {} failed tasks", step.name, failed_tasks);
                    if !step.continue_on_error {
                        return Err(BBHuntError::TaskExecutionError {
                            task_id: step.name.clone(),
                            message: format!("Workflow step failed with {} failed tasks", failed_tasks),
                        });
                    }
                }
                
                // Store results
                results.insert(step.name.clone(), task_results);
                
                // Mark step as completed
                completed_steps.insert(step.name.clone());
                
                // Remove from pending
                pending_steps.retain(|s| s.name != step.name);
            }
        }
        
        let end_time = chrono::Utc::now();
        let duration = (end_time - start_time).num_seconds() as u64;
        
        // Determine overall status
        let status = if results.values().all(|tasks| tasks.iter().all(|t| t.status == TaskStatus::Completed)) {
            WorkflowStatus::Success
        } else if results.values().any(|tasks| tasks.iter().any(|t| t.status == TaskStatus::Failed)) {
            WorkflowStatus::Partial
        } else {
            WorkflowStatus::Failed
        };
        
        info!("Workflow {} completed with status {:?}", self.name, status);
        
        Ok(WorkflowResult {
            name: self.name.clone(),
            steps: results,
            status,
            start_time,
            end_time,
            duration_seconds: duration,
        })
    }
    
    /// Load workflow from a file
    pub fn load(path: &std::path::Path, executor: ParallelExecutor) -> BBHuntResult<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to read file: {}", e),
            })?;
            
        let workflow_data: WorkflowData = serde_json::from_str(&json)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to parse JSON: {}", e)))?;
        
        Ok(Self {
            name: workflow_data.name,
            steps: workflow_data.steps,
            executor,
            context: None,
        })
    }
    
    /// Load workflow from a file with context
    pub fn load_with_context(path: &std::path::Path, context: Arc<Context>) -> BBHuntResult<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to read file: {}", e),
            })?;
            
        let workflow_data: WorkflowData = serde_json::from_str(&json)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to parse JSON: {}", e)))?;
        
        let executor = ParallelExecutor::new_with_context(4, context.clone()); // Default concurrency
        
        Ok(Self {
            name: workflow_data.name,
            steps: workflow_data.steps,
            executor,
            context: Some(context),
        })
    }
    
    /// Save workflow to a file
    pub fn save(&self, path: &std::path::Path) -> BBHuntResult<()> {
        let workflow_data = WorkflowData {
            name: self.name.clone(),
            steps: self.steps.clone(),
        };
        
        let json = serde_json::to_string_pretty(&workflow_data)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize workflow: {}", e)))?;
            
        std::fs::write(path, json)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to write file: {}", e),
            })?;
        
        Ok(())
    }
}

/// Serializable workflow data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowData {
    pub name: String,
    pub steps: Vec<WorkflowStep>,
}