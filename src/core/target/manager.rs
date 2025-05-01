// src/core/target/manager.rs
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use tracing::{info, debug};
use tokio::fs;
use uuid::Uuid;

use super::model::TargetData;

/// Manager for handling target data
pub struct TargetManager {
    targets: HashMap<String, TargetData>,
    data_dir: PathBuf,
}

impl TargetManager {
    /// Create a new target manager with the specified data directory
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            targets: HashMap::new(),
            data_dir,
        }
    }

    /// Initialize the target manager (create directories, etc.)
    pub async fn init(&self) -> Result<()> {
        let targets_dir = self.data_dir.join("targets");
        if !targets_dir.exists() {
            fs::create_dir_all(&targets_dir)
                .await
                .context("Failed to create targets directory")?;
        }
        Ok(())
    }

    /// Create a new target
    pub async fn create_target(&mut self, name: String, description: Option<String>) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let mut target = TargetData::new(id.clone(), name);
        
        if let Some(desc) = description {
            target.description = Some(desc);
        }
        
        self.targets.insert(id.clone(), target.clone());
        self.save_target(&target).await?;
        
        info!("Created new target with ID: {}", id);
        Ok(id)
    }

    /// Get a target by ID
    pub fn get_target(&self, id: &str) -> Option<&TargetData> {
        self.targets.get(id)
    }
    
    /// Get a mutable reference to a target by ID
    pub fn get_target_mut(&mut self, id: &str) -> Option<&mut TargetData> {
        self.targets.get_mut(id)
    }
    
    /// List all targets
    pub fn list_targets(&self) -> Vec<&TargetData> {
        self.targets.values().collect()
    }
    
    /// Delete a target
    pub async fn delete_target(&mut self, id: &str) -> Result<()> {
        if let Some(target) = self.targets.remove(id) {
            let target_file = self.get_target_file_path(&target.id);
            if target_file.exists() {
                fs::remove_file(&target_file)
                    .await
                    .context(format!("Failed to delete target file for {}", id))?;
            }
            info!("Deleted target with ID: {}", id);
        }
        Ok(())
    }
    
    /// Save a target to disk
    pub async fn save_target(&self, target: &TargetData) -> Result<()> {
        let path = self.get_target_file_path(&target.id);
        let json = serde_json::to_string_pretty(target)?;
        
        fs::write(&path, json)
            .await
            .context(format!("Failed to save target {} to {}", target.id, path.display()))?;
        
        debug!("Saved target {} to {}", target.id, path.display());
        Ok(())
    }
    
    /// Load a target from disk
    pub async fn load_target(&mut self, id: &str) -> Result<&TargetData> {
        let path = self.get_target_file_path(id);
        
        let json = fs::read_to_string(&path)
            .await
            .context(format!("Failed to read target file: {}", path.display()))?;
            
        let target: TargetData = serde_json::from_str(&json)
            .context(format!("Failed to parse target JSON from {}", path.display()))?;
            
        self.targets.insert(id.to_string(), target);
        
        Ok(self.targets.get(id).unwrap())
    }
    
    /// Load all targets from disk
    pub async fn load_all_targets(&mut self) -> Result<()> {
        let targets_dir = self.data_dir.join("targets");
        
        let mut entries = fs::read_dir(&targets_dir)
            .await
            .context(format!("Failed to read targets directory: {}", targets_dir.display()))?;
            
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Some(file_stem) = path.file_stem() {
                    if let Some(id) = file_stem.to_str() {
                        let _ = self.load_target(id).await;
                    }
                }
            }
        }
        
        info!("Loaded {} targets", self.targets.len());
        Ok(())
    }
    
    /// Get the file path for a target
    fn get_target_file_path(&self, id: &str) -> PathBuf {
        self.data_dir.join("targets").join(format!("{}.json", id))
    }
    
    /// Import target data from a file
    pub async fn import_target_from_file(&mut self, path: &Path) -> Result<String> {
        let json = fs::read_to_string(path)
            .await
            .context(format!("Failed to read target file: {}", path.display()))?;
            
        let mut target: TargetData = serde_json::from_str(&json)
            .context(format!("Failed to parse target JSON from {}", path.display()))?;
            
        // Generate a new ID to avoid conflicts
        let new_id = Uuid::new_v4().to_string();
        target.id = new_id.clone();
        
        self.targets.insert(new_id.clone(), target.clone());
        self.save_target(&target).await?;
        
        info!("Imported target with new ID: {}", new_id);
        Ok(new_id)
    }
    
    /// Export target data to a file
    pub async fn export_target_to_file(&self, id: &str, path: &Path) -> Result<()> {
        let target = self.get_target(id).context(format!("Target not found: {}", id))?;
        
        let json = serde_json::to_string_pretty(target)?;
        fs::write(path, json)
            .await
            .context(format!("Failed to write target data to {}", path.display()))?;
            
        info!("Exported target {} to {}", id, path.display());
        Ok(())
    }
}