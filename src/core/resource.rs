// src/core/resource.rs
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use sysinfo::{Disks, Pid, System};
use tokio::sync::Mutex;
use tracing::debug;

// Resource requirements for plugins or tasks
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
    system: Arc<Mutex<System>>, // Fixed typo: 's' -> System
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
        system.refresh_memory();

        // Memory check
        let available_memory = system.available_memory() / 1024 / 1024;
        
        if requirements.memory_mb > available_memory as usize {
            debug!("Not enough memory: {}MB required, {}MB available", 
                  requirements.memory_mb, available_memory);
            return Ok(false);
        }

        // CPU check (use global CPU usage)
        system.refresh_cpu();
        let cpu_usage = system.global_cpu_info().cpu_usage();
        let available_cpu = self.max_cpu as f32 * (1.0 - cpu_usage / 100.0);
        
        if requirements.cpu_cores > available_cpu {
            debug!("Not enough CPU: {} cores required, {} available", 
                  requirements.cpu_cores, available_cpu);
            return Ok(false);
        }

        // Disk space check
        let free_disk_mb = self.calculate_free_disk_space();
        
        if requirements.disk_mb > free_disk_mb {
            debug!("Not enough disk space: {}MB required, {}MB available", 
                  requirements.disk_mb, free_disk_mb);
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate free disk space in MB
    fn calculate_free_disk_space(&self) -> usize {
        let disks = Disks::new_with_refreshed_list();
        let free_space = disks.list()
            .iter()
            .map(|disk| disk.available_space() / (1024 * 1024))
            .sum::<u64>() as usize;
        
        free_space
    }

    /// Get current resource usage
    pub async fn get_resource_usage(&self) -> Result<ResourceUsage> {
        let mut system = self.system.lock().await;
        system.refresh_all();

        // Memory usage
        let total_memory_mb = system.total_memory() / 1024 / 1024;
        let used_memory_mb = system.used_memory() / 1024 / 1024;
        let available_memory_mb = system.available_memory() / 1024 / 1024;
        let memory_percent = if total_memory_mb > 0 {
            (used_memory_mb as f32 / total_memory_mb as f32) * 100.0
        } else {
            0.0
        };

        // CPU usage
        system.refresh_cpu();
        let global_cpu_info = system.global_cpu_info();
        let total_cpu_usage = global_cpu_info.cpu_usage();

        // Disk usage
        let disk_info = self.get_disk_usage_info();
        
        // Active processes
        let active_processes = self.get_active_processes(&system).await;

        Ok(ResourceUsage {
            memory: MemoryUsage {
                total: total_memory_mb as usize,
                available: available_memory_mb as usize,
                used: used_memory_mb as usize,
                percent: memory_percent,
            },
            cpu: CpuUsage {
                cores: system.physical_core_count().unwrap_or(0),
                total_usage: total_cpu_usage,
                per_core_usage: Vec::new(), // This would require more complex iteration
            },
            disk: disk_info,
            active_processes,
        })
    }

    /// Get disk usage information
    fn get_disk_usage_info(&self) -> DiskUsage {
        let disks = Disks::new_with_refreshed_list();
        
        let total_disk: u64 = disks.list().iter().map(|disk| disk.total_space()).sum();
        let free_disk: u64 = disks.list().iter().map(|disk| disk.available_space()).sum();
        
        let total_disk_mb = total_disk / (1024 * 1024);
        let free_disk_mb = free_disk / (1024 * 1024);
        let used_disk_mb = total_disk_mb.saturating_sub(free_disk_mb);
        
        let disk_percent = if total_disk_mb > 0 {
            (used_disk_mb as f32 / total_disk_mb as f32) * 100.0
        } else {
            0.0
        };

        DiskUsage {
            total: total_disk_mb as usize,
            free: free_disk_mb as usize,
            used: used_disk_mb as usize,
            percent: disk_percent,
        }
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
    async fn get_active_processes(&self, system: &System) -> Vec<ProcessInfo> {
        let active_processes = self.active_processes.lock().await;
        
        active_processes.iter()
            .filter_map(|(pid, process_info)| {
                // Convert u32 to sysinfo::Pid
                let pid_sysinfo = Pid::from_u32(*pid);
                
                system.process(pid_sysinfo).map(|process| {
                    ProcessInfo {
                        name: process.name().to_string(),
                        pid: *pid,
                        memory_usage: (process.memory() / 1024 / 1024) as usize,
                        cpu_usage: process.cpu_usage(),
                        start_time: process_info.start_time,
                    }
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

    /// Get disk usage information for reporting
    pub fn get_disk_usage() -> HashMap<String, (u64, u64)> {
        let disks = Disks::new_with_refreshed_list();
        let mut result = HashMap::new();
        
        for disk in disks.list() {
            let total_space = disk.total_space();
            let available_space = disk.available_space();
            result.insert(
                disk.name().to_string_lossy().to_string(),
                (total_space, available_space)
            );
        }
        
        result
    }
}