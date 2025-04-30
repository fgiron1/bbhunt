use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use tracing::{info, debug, warn, error};

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
}

impl Workflow {
    /// Create a new workflow
    pub fn new(name: String, steps: Vec<WorkflowStep>, executor: ParallelExecutor) -> Self {
        Self {
            name,
            steps,
            executor,
        }
    }
    
    /// Execute the workflow
    pub async fn execute(&self) -> Result<WorkflowResult> {
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
                return Err(anyhow::anyhow!("Circular dependency detected in workflow steps"));
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
                        return Err(anyhow::anyhow!("Workflow step {} failed", step.name));
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
    pub fn load(path: &std::path::Path, executor: ParallelExecutor) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let workflow_data: WorkflowData = serde_json::from_str(&json)?;
        
        Ok(Self {
            name: workflow_data.name,
            steps: workflow_data.steps,
            executor,
        })
    }
    
    /// Save workflow to a file
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let workflow_data = WorkflowData {
            name: self.name.clone(),
            steps: self.steps.clone(),
        };
        
        let json = serde_json::to_string_pretty(&workflow_data)?;
        std::fs::write(path, json)?;
        
        Ok(())
    }
}

/// Serializable workflow data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowData {
    pub name: String,
    pub steps: Vec<WorkflowStep>,
}