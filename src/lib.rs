pub mod cli;
pub mod config;
pub mod core;
pub mod engine;
pub mod plugins;
pub mod reporting;
pub mod utils;

// Re-export main types for easier access
pub use cli::App;
pub use config::Config;
pub use core::{
    Plugin, 
    PluginManager, 
    Target, 
    TargetManager,
    ResourceManager
};
pub use engine::Workflow;
pub use reporting::{
    ReportManager, 
    ReportFormat, 
    Report
};