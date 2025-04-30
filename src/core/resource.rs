use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use sysinfo::{System, SystemExt, CpuExt, ProcessExt};
use tokio::sync::Mutex;
use tracing::{info, debug, warn};

/// Resource requirements for plugins or tasks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub memory_mb: usize,
    pub cpu_cores: f32,
    pub disk_mb: usize,
    pub network_required: bool,
}

/// Process information for tracking
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub memory_usage: usize,
    pub cpu_usage: f32,
    pub start_time: Instant,
}

/// System resource usage information
#[derive(Debug)]
pub struct ResourceUsage {
    pub memory: MemoryUsage,
    pub cpu: CpuUsage,
    pub disk: DiskUsage,
    pub active_processes: Vec<ProcessInfo>,
}

/// Memory usage information
#[derive(Debug)]
pub struct MemoryUsage {
    pub total: usize,
    pub available: usize,
    pub used: usize,
    pub percent: f32,
}

/// CPU usage information
#[derive(Debug)]
pub struct CpuUsage {
    pub cores: usize,
    pub total_usage: f32,
    pub per_core_usage: Vec<f32>,
}

/// Disk usage information
#[derive(Debug)]
pub struct DiskUsage {
    pub total: usize,
    pub free: usize,
    pub used: usize,
    pub percent: f32,
}

/// Manager for system resources
pub struct ResourceManager {
    system: Arc<Mutex<System>>,
    max_memory: usize,
    max_cpu: usize,
    active_processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
}

impl ResourceManager {
    /// Create a new resource manager
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            system: Arc::new(Mutex::new(system)),
            max_memory: Self::get_system_memory(),
            max_cpu: num_cpus::get(),
            active_processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get total system memory in MB
    fn get_system_memory() -> usize {
        let mut system = System::new_all();
        system.refresh_memory();
        (system.total_memory() / 1024 / 1024) as usize
    }

    /// Check if the system has enough resources to run a task
    pub async fn check_resources(&self, requirements: &ResourceRequirements) -> Result<bool> {
        let mut system = self.system.lock().await;
        system.refresh_all();
        
        // Memory check
        let available_memory = (system.available_memory() / 1024 / 1024) as usize;
        if requirements.memory_mb > available_memory {
            debug!("Not enough memory: {}MB required, {}MB available", 
                  requirements.memory_mb, available_memory);
            return Ok(false);
        }

        // CPU check - only do a rough check here
        let cpu_usage = system.global_cpu_info().cpu_usage() / 100.0;
        let available_cpu = self.max_cpu as f32 * (1.0 - cpu_usage);
        
        if requirements.cpu_cores > available_cpu {
            debug!("Not enough CPU: {} cores required, {} available", 
                  requirements.cpu_cores, available_cpu);
            return Ok(false);
        }

        // Disk check
        if requirements.disk_mb > 0 {
            let free_space = (system.free_disk_space().unwrap_or(u64::MAX) / 1024 / 1024) as usize;
            if requirements.disk_mb > free_space {
                debug!("Not enough disk space: {}MB required, {}MB available", 
                      requirements.disk_mb, free_space);
                return Ok(false);
            }
        }

        // Network check (simplified)
        if requirements.network_required {
            // Just a placeholder - in a real application, you would check network connectivity
        }

        Ok(true)
    }

    /// Get current resource usage
    pub async fn get_resource_usage(&self) -> Result<ResourceUsage> {
        let mut system = self.system.lock().await;
        system.refresh_all();

        // Memory usage
        let total_memory = (system.total_memory() / 1024 / 1024) as usize;
        let used_memory = (system.used_memory() / 1024 / 1024) as usize;
        let available_memory = (system.available_memory() / 1024 / 1024) as usize;
        let memory_percent = (used_memory as f32 / total_memory as f32) * 100.0;

        // CPU usage
        let cpu_cores = system.cpus().len();
        let per_core_usage: Vec<f32> = system.cpus().iter()
            .map(|cpu| cpu.cpu_usage())
            .collect();
        let total_cpu_usage = system.global_cpu_info().cpu_usage();

        // Disk usage
        let total_disk = (system.total_disk_space().unwrap_or(0) / 1024 / 1024) as usize;
        let free_disk = (system.free_disk_space().unwrap_or(0) / 1024 / 1024) as usize;
        let used_disk = total_disk.saturating_sub(free_disk);
        let disk_percent = if total_disk > 0 {
            (used_disk as f32 / total_disk as f32) * 100.0
        } else {
            0.0
        };

        // Active processes
        let active_processes = self.get_active_processes().await;

        Ok(ResourceUsage {
            memory: MemoryUsage {
                total: total_memory,
                available: available_memory,
                used: used_memory,
                percent: memory_percent,
            },
            cpu: CpuUsage {
                cores: cpu_cores,
                total_usage: total_cpu_usage,
                per_core_usage,
            },
            disk: DiskUsage {
                total: total_disk,
                free: free_disk,
                used: used_disk,
                percent: disk_percent,
            },
            active_processes,
        })
    }

    /// Track a new process
    pub async fn track_process(&self, pid: u32, name: String) -> Result<()> {
        debug!("Tracking process {} ({})", name, pid);
        let mut active_processes = self.active_processes.lock().await;
        
        active_processes.insert(pid, ProcessInfo {
            name,
            pid,
            memory_usage: 0,
            cpu_usage: 0.0,
            start_time: Instant::now(),
        });

        Ok(())
    }

    /// Stop tracking a process
    pub async fn untrack_process(&self, pid: u32) -> Result<()> {
        debug!("Untracking process {}", pid);
        let mut active_processes = self.active_processes.lock().await;
        active_processes.remove(&pid);
        Ok(())
    }

    /// Get active processes
    async fn get_active_processes(&self) -> Vec<ProcessInfo> {
        let mut system = self.system.lock().await;
        let active_processes = self.active_processes.lock().await;
        
        // Update process information
        let mut results = Vec::new();
        
        for (pid, process_info) in active_processes.iter() {
            if let Some(process) = system.process(*pid) {
                let memory_usage = (process.memory() / 1024 / 1024) as usize;
                let cpu_usage = process.cpu_usage();
                
                results.push(ProcessInfo {
                    name: process_info.name.clone(),
                    pid: *pid,
                    memory_usage,
                    cpu_usage,
                    start_time: process_info.start_time,
                });
            } else {
                // Process no longer exists
                results.push(process_info.clone());
            }
        }
        
        results
    }

    /// Run a process with resource limits
    pub async fn run_with_limits<F, R>(&self, 
        name: &str, 
        requirements: &ResourceRequirements,
        timeout: Duration,
        f: F
    ) -> Result<R> 
    where 
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static
    {
        // Check if we have enough resources
        if !self.check_resources(requirements).await? {
            return Err(anyhow::anyhow!("Not enough resources available"));
        }
        
        // Track the task as a "process"
        let pid = rand::random::<u32>();
        self.track_process(pid, name.to_string()).await?;
        
        // Run the function with a timeout
        let result = tokio::time::timeout(timeout, tokio::task::spawn_blocking(f)).await??;
        
        // Untrack the process
        self.untrack_process(pid).await?;
        
        Ok(result)
    }
}