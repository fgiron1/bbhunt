// src/core/mod.rs
pub mod plugin;
pub mod config;
pub mod resource_manager;
pub mod cli;
pub mod parallel;
pub mod target;
pub mod report;
pub mod task_generator;

pub use plugin::{Plugin, PluginManager};
pub use config::BBHuntConfig;
pub use resource_manager::ResourceManager;
pub use cli::BBHuntCli;
pub use parallel::ParallelTaskManager;
pub use target::TargetManager;
pub use report::ReportManager;
pub use task_generator::TaskGenerator;
