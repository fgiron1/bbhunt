// src/engine/parallel.rs
use std::sync::Arc;
use std::path::Path;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tracing::{info, debug, error};

use crate::core::plugin::PluginManager;
use crate::error::{BBHuntResult, BBHuntError};
use crate::context::Context;
use super::task::{TaskDefinition, TaskResult, TaskStatus};

/// Executor for running tasks in parallel
pub struct ParallelExecutor {
    max_concurrent_tasks: usize,
    semaphore: Arc<Semaphore>,
    plugin_manager: Arc<Mutex<PluginManager>>,
    context: Option<Arc<Context>>,
}

impl ParallelExecutor {
    /// Create a new parallel executor
    pub fn new(max_concurrent_tasks: usize, plugin_manager: Arc<Mutex<PluginManager>>) -> Self {
        Self {
            max_concurrent_tasks,
            semaphore: Arc::new(Semaphore::new(max_concurrent_tasks)),
            plugin_manager,
            context: None,
        }
    }
    
    /// Create a new parallel executor with context
    pub fn new_with_context(max_concurrent_tasks: usize, context: Arc<Context>) -> Self {
        Self {
            max_concurrent_tasks,
            semaphore: Arc::new(Semaphore::new(max_concurrent_tasks)),
            plugin_manager: context.plugin_manager.clone(),
            context: Some(context),
        }
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
        self.plugin_manager = context.plugin_manager.clone();
    }
    
    /// Execute a list of tasks
    pub async fn execute_tasks(&self, tasks: Vec<TaskDefinition>) -> BBHuntResult<Vec<TaskResult>> {
        if tasks.is_empty() {
            info!("No tasks to execute");
            return Ok(Vec::new());
        }
        
        info!("Executing {} tasks with max concurrency {}", tasks.len(), self.max_concurrent_tasks);
        
        let (tx, mut rx) = mpsc::channel(self.max_concurrent_tasks);
        
        // Build dependency graph
        let mut results = Vec::new();
        let mut completed_tasks = std::collections::HashSet::new();
        let mut pending_tasks: Vec<&TaskDefinition> = tasks.iter().collect();
        
        while !pending_tasks.is_empty() {
            // Find tasks with satisfied dependencies
            let runnable_tasks: Vec<&TaskDefinition> = pending_tasks
                .iter()
                .filter(|task| task.dependencies.iter().all(|dep| completed_tasks.contains(dep)))
                .cloned()
                .collect();
            
            if runnable_tasks.is_empty() && !pending_tasks.is_empty() {
                return Err(BBHuntError::DependencyError("Circular dependency detected in tasks".to_string()));
            }
            
            debug!("Found {} runnable tasks", runnable_tasks.len());
            
            // Run tasks in parallel
            let mut handles = Vec::new();
            
            for task in runnable_tasks {
                let task_clone = task.clone();
                let tx_clone = tx.clone();
                let semaphore_clone = self.semaphore.clone();
                let plugin_manager_clone = self.plugin_manager.clone();
                let context_clone = self.context.clone();
                
                let handle = tokio::spawn(async move {
                    // Acquire permit
                    let permit = semaphore_clone.acquire().await.expect("Semaphore closed");
                    
                    // Execute task
                    let result = if let Some(ctx) = context_clone {
                        Self::execute_task_with_context(task_clone, plugin_manager_clone, ctx).await
                    } else {
                        Self::execute_task(task_clone, plugin_manager_clone).await
                    };
                    
                    // Send result
                    tx_clone.send(result).await.expect("Failed to send result");
                    
                    // Drop permit
                    drop(permit);
                });
                
                handles.push(handle);
                
                // Remove from pending
                pending_tasks.retain(|t| t.id != task.id);
                completed_tasks.insert(task.id.clone());
            }
            
            // Wait for all tasks to complete before starting the next batch
            for handle in handles {
                if let Err(e) = handle.await {
                    error!("Task execution failed: {}", e);
                }
            }
        }
        
        // Collect results
        drop(tx);
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        
        info!("Completed all tasks successfully");
        Ok(results)
    }
    
    /// Execute a single task with context
    async fn execute_task_with_context(
        task: TaskDefinition,
        plugin_manager: Arc<Mutex<PluginManager>>,
        context: Arc<Context>
    ) -> TaskResult {
        debug!("Executing task {} (with context)", task.id);
        
        let start_time = std::time::Instant::now();
        let mut result = TaskResult {
            task_id: task.id.clone(),
            plugin: task.plugin.clone(),
            target: task.target.clone(),
            status: TaskStatus::Running,
            result: None,
            error: None,
            execution_time: std::time::Duration::from_secs(0),
        };
        
        // Convert options to HashMap if provided
        let options = task.options.and_then(|opts| {
            serde_json::from_value(opts).ok()
        });
        
        // Run plugin
        match plugin_manager.lock().await.run_plugin(&task.plugin, &task.target, options).await {
            Ok(plugin_result) => {
                result.status = TaskStatus::Completed;
                result.result = Some(plugin_result);
            }
            Err(e) => {
                error!("Task execution failed: {}", e);
                result.status = TaskStatus::Failed;
                result.error = Some(e.to_string());
            }
        }
        
        result.execution_time = start_time.elapsed();
        
        debug!("Task {} completed in {:?} with status {:?}", task.id, result.execution_time, result.status);
        
        result
    }
    
    /// Execute a single task (legacy method without context)
    async fn execute_task(
        task: TaskDefinition, 
        plugin_manager: Arc<Mutex<PluginManager>>
    ) -> TaskResult {
        debug!("Executing task {}", task.id);
        
        let start_time = std::time::Instant::now();
        let mut result = TaskResult {
            task_id: task.id.clone(),
            plugin: task.plugin.clone(),
            target: task.target.clone(),
            status: TaskStatus::Running,
            result: None,
            error: None,
            execution_time: std::time::Duration::from_secs(0),
        };
        
        // Convert options to HashMap if provided
        let options = task.options.and_then(|opts| {
            serde_json::from_value(opts).ok()
        });
        
        // Run plugin
        match plugin_manager.lock().await.run_plugin(&task.plugin, &task.target, options).await {
            Ok(plugin_result) => {
                result.status = TaskStatus::Completed;
                result.result = Some(plugin_result);
            }
            Err(e) => {
                error!("Task execution failed: {}", e);
                result.status = TaskStatus::Failed;
                result.error = Some(e.to_string());
            }
        }
        
        result.execution_time = start_time.elapsed();
        
        debug!("Task {} completed in {:?} with status {:?}", task.id, result.execution_time, result.status);
        
        result
    }
    
    /// Load tasks from a file
    pub fn load_tasks(path: &Path) -> BBHuntResult<Vec<TaskDefinition>> {
        debug!("Loading tasks from {}", path.display());
        let content = std::fs::read_to_string(path)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to read file: {}", e),
            })?;
            
        let tasks: Vec<TaskDefinition> = serde_json::from_str(&content)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to parse JSON: {}", e)))?;
            
        Ok(tasks)
    }
    
    /// Save tasks to a file
    pub fn save_tasks(tasks: &[TaskDefinition], path: &Path) -> BBHuntResult<()> {
        debug!("Saving {} tasks to {}", tasks.len(), path.display());
        let content = serde_json::to_string_pretty(tasks)
            .map_err(|e| BBHuntError::SerializationError(format!("Failed to serialize tasks: {}", e)))?;
            
        std::fs::write(path, content)
            .map_err(|e| BBHuntError::FileError {
                path: path.to_path_buf(),
                message: format!("Failed to write file: {}", e),
            })?;
            
        Ok(())
    }
}