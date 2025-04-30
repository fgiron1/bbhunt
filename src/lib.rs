pub mod cli;
pub mod config;
pub mod core;
pub mod engine;
pub mod plugins;
pub mod reporting;
pub mod utils;

// Re-export main types for easier access
pub use cli::app::App;
pub use config::Config;
pub use core::plugin::{Plugin, PluginManager};
pub use engine::workflow::Workflow;
pub use reporting::ReportManager;