// src/core/parallel.rs
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub id: String,
    pub plugin: String,
    pub target: String,
    pub options: Option<serde_json::Value>,
    pub dependencies: Vec<String>, // IDs of tasks this depends on
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub status: TaskStatus,
    pub result: Option<crate::core::plugin::PluginResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

pub struct ParallelTaskManager {
    max_concurrent_tasks: usize,
    semaphore: Arc<Semaphore>,
    tasks: Vec<TaskDefinition>,
}

impl ParallelTaskManager {
    pub fn new(max_concurrent_tasks: usize) -> Self {
        Self {
            max_concurrent_tasks,
            semaphore: Arc::new(Semaphore::new(max_concurrent_tasks)),
            tasks: Vec::new(),
        }
    }

    pub fn add_task(&mut self, task: TaskDefinition) {
        self.tasks.push(task);
    }

    pub async fn execute_all(&self, plugin_manager: Arc<tokio::sync::Mutex<crate::core::plugin::PluginManager>>) -> Result<Vec<TaskResult>> {
        let (tx, mut rx) = mpsc::channel(self.max_concurrent_tasks);
        
        // Build dependency graph and find runnable tasks
        let mut results = Vec::new();
        let mut completed_tasks = std::collections::HashSet::new();
        let mut pending_tasks: Vec<&TaskDefinition> = self.tasks.iter().collect();
        
        while !pending_tasks.is_empty() {
            // Find tasks with satisfied dependencies
            let runnable_tasks: Vec<&TaskDefinition> = pending_tasks
                .iter()
                .filter(|task| task.dependencies.iter().all(|dep| completed_tasks.contains(dep)))
                .cloned()
                .collect();
            
            if runnable_tasks.is_empty() && !pending_tasks.is_empty() {
                return Err(anyhow::anyhow!("Circular dependency detected in tasks"));
            }
            
            // Run tasks in parallel with controlled concurrency
            let mut handles = Vec::new();
            
            for task in runnable_tasks {
                let task_clone = task.clone();
                let tx_clone = tx.clone();
                let semaphore_clone = self.semaphore.clone();
                let plugin_manager_clone = plugin_manager.clone();
                
                let handle = tokio::spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();
                    
                    let result = Self::execute_task(task_clone, plugin_manager_clone).await;
                    tx_clone.send(result).await.unwrap();
                });
                
                handles.push(handle);
                
                // Remove from pending
                pending_tasks.retain(|t| t.id != task.id);
                completed_tasks.insert(task.id.clone());
            }
            
            // Wait for batch completion
            for handle in handles {
                handle.await?;
            }
        }
        
        // Collect results
        drop(tx);
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        
        Ok(results)
    }
    
    async fn execute_task(
        task: TaskDefinition, 
        plugin_manager: Arc<tokio::sync::Mutex<crate::core::plugin::PluginManager>>
    ) -> TaskResult {
        let mut result = TaskResult {
            task_id: task.id.clone(),
            status: TaskStatus::Running,
            result: None,
            error: None,
        };
        
        let options = task.options.and_then(|opts| {
            serde_json::from_value(opts).ok()
        });
        
        match plugin_manager.lock().await.run_plugin(&task.plugin, &task.target, options).await {
            Ok(plugin_result) => {
                result.status = TaskStatus::Completed;
                result.result = Some(plugin_result);
            }
            Err(e) => {
                result.status = TaskStatus::Failed;
                result.error = Some(e.to_string());
            }
        }
        
        result
    }
    
    // Save task definitions to a file for CI integration
    pub fn export_task_definitions(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.tasks)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    // Import task definitions from a file
    pub fn import_task_definitions(&mut self, path: &std::path::Path) -> Result<()> {
        let json = std::fs::read_to_string(path)?;
        let tasks: Vec<TaskDefinition> = serde_json::from_str(&json)?;
        self.tasks = tasks;
        Ok(())
    }
}
