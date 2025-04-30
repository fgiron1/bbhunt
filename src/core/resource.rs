use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use sysinfo::{System, SystemTrait, CpuTrait as _, ProcessTrait as _};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use rand::random;

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
        let total_memory = system.total_memory() / (1024 * 1024);
        let available_memory = system.available_memory() / (1024 * 1024);
        
        // Remove disk space checks for now
        
        debug!(
            "Resource Check - Memory: {}/{} MB",
            available_memory, total_memory
        );

        Ok(
            available_memory >= requirements.memory_mb as u64
        )
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
    pub async fn get_active_processes(&self) -> Vec<ProcessInfo> {
        let mut system = self.system.lock().await;
        system.refresh_processes();

        system.processes()
            .iter()
            .filter_map(|(pid, process)| {
                Some(ProcessInfo {
                    name: process.name().to_string(),
                    pid: *pid,
                    memory_usage: process.memory() as usize,
                    cpu_usage: process.cpu_usage(),
                    start_time: Instant::now(), // Note: exact start time might need different approach
                })
            })
            .collect()
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