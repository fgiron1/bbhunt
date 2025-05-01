// src/error.rs
use std::path::PathBuf;
use thiserror::Error;

/// Custom error system for BBHunt
#[derive(Error, Debug)]
pub enum BBHuntError {
    #[error("Plugin error: {0}")]
    PluginError(String),
    
    #[error("Target not found: {0}")]
    TargetNotFound(String),
    
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    
    #[error("Resource error: {0}")]
    ResourceError(String),
    
    #[error("Task execution failed: {task_id} - {message}")]
    TaskExecutionError {
        task_id: String,
        message: String,
    },
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("File error: {path:?} - {message}")]
    FileError {
        path: PathBuf,
        message: String,
    },
    
    #[error("External tool error: {tool} - {message}")]
    ExternalToolError {
        tool: String,
        message: String,
    },
    
    #[error("Timeout error: {operation} exceeded {seconds} seconds")]
    TimeoutError {
        operation: String,
        seconds: u64,
    },
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Dependency error: {0}")]
    DependencyError(String),
    
    #[error("OSINT error: {source_name} - {message}")]
    OsintError {
        source_name: String,
        message: String,
    },
    
    #[error("Context error: {0}")]
    ContextError(String),
    
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

// Type alias for BBHunt results
pub type BBHuntResult<T> = std::result::Result<T, BBHuntError>;

// Conversion from anyhow to BBHuntError
impl From<anyhow::Error> for BBHuntError {
    fn from(error: anyhow::Error) -> Self {
        BBHuntError::UnexpectedError(error.to_string())
    }
}

// Conversion from std::io::Error to BBHuntError
impl From<std::io::Error> for BBHuntError {
    fn from(error: std::io::Error) -> Self {
        BBHuntError::FileError {
            path: PathBuf::from("unknown"),
            message: error.to_string(),
        }
    }
}

// Conversion from reqwest::Error to BBHuntError
impl From<reqwest::Error> for BBHuntError {
    fn from(error: reqwest::Error) -> Self {
        BBHuntError::NetworkError(error.to_string())
    }
}

// Conversion from serde_json::Error to BBHuntError
impl From<serde_json::Error> for BBHuntError {
    fn from(error: serde_json::Error) -> Self {
        BBHuntError::SerializationError(error.to_string())
    }
}

// Error handling utilities
pub mod util {
    use super::*;
    
    /// Log an error but continue execution - for plugin failures and non-critical errors
    pub fn log_error<T: std::fmt::Display>(error: T) {
        eprintln!("ERROR: {}", error);
    }
    
    /// Wrap an operation that might fail and convert it to a BBHuntResult
    pub fn wrap_operation<T, E, F>(op: F, error_msg: &str) -> BBHuntResult<T>
    where
        F: FnOnce() -> Result<T, E>,
        E: std::fmt::Display,
    {
        op().map_err(|e| BBHuntError::UnexpectedError(format!("{}: {}", error_msg, e)))
    }
    
    /// Execute a plugin with error handling that ensures plugin failures don't crash the framework
    pub async fn execute_plugin_safely<F, T>(plugin_name: &str, f: F) -> BBHuntResult<Option<T>>
    where
        F: std::future::Future<Output = Result<T, anyhow::Error>>,
    {
        match f.await {
            Ok(result) => Ok(Some(result)),
            Err(e) => {
                log_error(format!("Plugin '{}' failed: {}", plugin_name, e));
                Ok(None) // Return None but don't fail the framework
            }
        }
    }
}