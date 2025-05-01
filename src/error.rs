use std::path::PathBuf;
use thiserror::Error;

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
        source_name: String,  // Renamed from source to source_name
        message: String,
    },
    
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

impl From<anyhow::Error> for BBHuntError {
    fn from(error: anyhow::Error) -> Self {
        BBHuntError::UnexpectedError(error.to_string())
    }
}

pub type BBHuntResult<T> = std::result::Result<T, BBHuntError>;