// src/utils/shell.rs
use std::path::Path;
use std::process::Output;
use anyhow::{Result, Context};
use tokio::process::Command;
use tracing::{debug, trace, warn};

/// Execute a shell command
pub async fn execute_command(cmd: &str) -> Result<Output> {
    debug!("Executing command: {}", cmd);
    
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .context(format!("Failed to execute command: {}", cmd))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Command failed: {}\nStderr: {}", cmd, stderr);
    } else {
        trace!("Command succeeded: {}", cmd);
    }
    
    Ok(output)
}

/// Execute a shell command with a timeout
pub async fn execute_command_with_timeout(cmd: &str, timeout_secs: u64) -> Result<Output> {
    debug!("Executing command with timeout {}: {}", timeout_secs, cmd);
    
    let command_future = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), command_future).await {
        Ok(result) => result.context(format!("Failed to execute command: {}", cmd)),
        Err(_) => {
            warn!("Command timed out after {} seconds: {}", timeout_secs, cmd);
            Err(anyhow::anyhow!("Command timed out after {} seconds: {}", timeout_secs, cmd))
        }
    }
}

/// Execute a command and save output to a file
pub async fn execute_command_to_file(cmd: &str, output_path: &Path) -> Result<()> {
    debug!("Executing command to file {}: {}", output_path.display(), cmd);
    
    let output = execute_command(cmd).await?;
    
    if output.status.success() {
        tokio::fs::write(output_path, output.stdout).await
            .context(format!("Failed to write command output to {}", output_path.display()))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("Command failed: {}\nStderr: {}", cmd, stderr))
    }
}