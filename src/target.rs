// src/target.rs
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::net::IpAddr;
use std::sync::Arc;
use anyhow::{Result, Context, bail};
use ipnetwork::IpNetwork;
use serde::{Serialize, Deserialize};
use tokio::fs;
use uuid::Uuid;
use tracing::{info, debug, error};
use chrono::{DateTime, Utc};

use crate::config::AppConfig;

/// Manager for handling target data
pub struct TargetManager {
    config: AppConfig,
    targets_cache: tokio::sync::Mutex<HashMap<String, TargetData>>,
}

impl TargetManager {
    /// Create a new target manager with application config
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            targets_cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Initialize the target manager
    pub async fn initialize(&self) -> Result<()> {
        // Get data directory from config
        let data_dir = self.config.data_dir().await;
        let targets_dir = data_dir.join("targets");
        
        // Create targets directory if it doesn't exist
        if !targets_dir.exists() {
            fs::create_dir_all(&targets_dir).await
                .context(format!("Failed to create targets directory: {}", targets_dir.display()))?;
        }
        
        // Load all existing targets
        self.load_all_targets().await?;
        
        info!("Target manager initialized successfully");
        Ok(())
    }
    
    /// Create a new target with basic information
    pub async fn create_target(&self, name: &str, description: Option<&str>) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let target = TargetData {
            id: id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: now,
            updated_at: now,
            tags: HashMap::new(),
            primary_domain: None,
            domains: HashSet::new(),
            subdomains: HashSet::new(),
            ip_addresses: HashSet::new(),
            ip_ranges: HashSet::new(),
            open_ports: HashMap::new(),
            urls: HashSet::new(),
            technologies: HashSet::new(),
            osint_data: OsintData::default(),
        };
        
        // Save the target
        self.save_target(&target).await?;
        
        // Add to cache
        let mut cache = self.targets_cache.lock().await;
        cache.insert(id.clone(), target);
        
        info!("Created new target with ID: {}", id);
        Ok(id)
    }
    
    /// Add a domain to a target
    pub async fn add_domain(&self, target_id: &str, domain: &str) -> Result<()> {
        let mut cache = self.targets_cache.lock().await;
        
        let target = cache.get_mut(target_id)
            .ok_or_else(|| anyhow::anyhow!("Target not found: {}", target_id))?;
            
        target.domains.insert(domain.to_string());
        
        if target.primary_domain.is_none() {
            target.primary_domain = Some(domain.to_string());
        }
        
        target.updated_at = Utc::now();
        
        // Save the updated target
        drop(cache); // Release the lock before await
        self.save_target_by_id(target_id).await?;
        
        Ok(())
    }
    
    /// Add an IP address to a target
    pub async fn add_ip_address(&self, target_id: &str, ip_str: &str) -> Result<()> {
        let ip: IpAddr = ip_str.parse()
            .context(format!("Invalid IP address: {}", ip_str))?;
            
        let mut cache = self.targets_cache.lock().await;
        
        let target = cache.get_mut(target_id)
            .ok_or_else(|| anyhow::anyhow!("Target not found: {}", target_id))?;
            
        target.ip_addresses.insert(ip);
        target.updated_at = Utc::now();
        
        // Save the updated target
        drop(cache); // Release the lock before await
        self.save_target_by_id(target_id).await?;
        
        Ok(())
    }
    
    /// Add an IP range to a target
    pub async fn add_ip_range(&self, target_id: &str, cidr_str: &str) -> Result<()> {
        let range: IpNetwork = cidr_str.parse()
            .context(format!("Invalid CIDR range: {}", cidr_str))?;
            
        let mut cache = self.targets_cache.lock().await;
        
        let target = cache.get_mut(target_id)
            .ok_or_else(|| anyhow::anyhow!("Target not found: {}", target_id))?;
            
        target.ip_ranges.insert(range);
        target.updated_at = Utc::now();
        
        // Save the updated target
        drop(cache); // Release the lock before await
        self.save_target_by_id(target_id).await?;
        
        Ok(())
    }
    
    /// Get a target by ID
    pub async fn get_target(&self, id: &str) -> Result<TargetData> {
        let cache = self.targets_cache.lock().await;
        
        cache.get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Target not found: {}", id))
    }
    
    /// Get a target by name or ID
    pub async fn get_target_by_name_or_id(&self, name_or_id: &str) -> Result<TargetData> {
        let cache = self.targets_cache.lock().await;
        
        // Try to find by ID first
        if let Some(target) = cache.get(name_or_id) {
            return Ok(target.clone());
        }
        
        // Try to find by name
        for target in cache.values() {
            if target.name == name_or_id {
                return Ok(target.clone());
            }
        }
        
        bail!("Target not found: {}", name_or_id)
    }
    
    /// List all targets
    pub async fn list_targets(&self) -> Result<Vec<TargetData>> {
        let cache = self.targets_cache.lock().await;
        let targets: Vec<TargetData> = cache.values().cloned().collect();
        Ok(targets)
    }
    
    /// Delete a target by ID
    pub async fn delete_target(&self, id: &str) -> Result<()> {
        // Remove from cache
        let mut cache = self.targets_cache.lock().await;
        
        if !cache.contains_key(id) {
            bail!("Target not found: {}", id);
        }
        
        cache.remove(id);
        
        // Remove from disk
        let data_dir = self.config.data_dir().await;
        let target_file = data_dir.join("targets").join(format!("{}.json", id));
        
        if target_file.exists() {
            fs::remove_file(&target_file).await
                .context(format!("Failed to delete target file: {}", target_file.display()))?;
        }
        
        info!("Deleted target with ID: {}", id);
        Ok(())
    }
    
    /// Delete a target by name or ID
    pub async fn delete_target_by_name_or_id(&self, name_or_id: &str) -> Result<()> {
        // Find the target ID first
        let target = self.get_target_by_name_or_id(name_or_id).await?;
        
        // Delete the target by ID
        self.delete_target(&target.id).await
    }
    
    /// Save a target to disk
    async fn save_target(&self, target: &TargetData) -> Result<()> {
        let data_dir = self.config.data_dir().await;
        let targets_dir = data_dir.join("targets");
        let target_file = targets_dir.join(format!("{}.json", target.id));
        
        let json = serde_json::to_string_pretty(target)
            .context("Failed to serialize target data")?;
            
        fs::write(&target_file, json).await
            .context(format!("Failed to write target file: {}", target_file.display()))?;
            
        debug!("Saved target {} to {}", target.id, target_file.display());
        Ok(())
    }
    
    /// Save a target to disk by ID
    async fn save_target_by_id(&self, id: &str) -> Result<()> {
        let target = self.get_target(id).await?;
        self.save_target(&target).await
    }
    
    /// Load a target from disk
    async fn load_target(&self, id: &str) -> Result<TargetData> {
        let data_dir = self.config.data_dir().await;
        let target_file = data_dir.join("targets").join(format!("{}.json", id));
        
        if !target_file.exists() {
            bail!("Target file not found: {}", target_file.display());
        }
        
        let json = fs::read_to_string(&target_file).await
            .context(format!("Failed to read target file: {}", target_file.display()))?;
            
        let target: TargetData = serde_json::from_str(&json)
            .context(format!("Failed to parse target JSON from {}", target_file.display()))?;
            
        Ok(target)
    }
    
    /// Load all targets from disk
    async fn load_all_targets(&self) -> Result<()> {
        let data_dir = self.config.data_dir().await;
        let targets_dir = data_dir.join("targets");
        
        if !targets_dir.exists() {
            return Ok(());
        }
        
        let mut entries = fs::read_dir(&targets_dir).await
            .context(format!("Failed to read targets directory: {}", targets_dir.display()))?;
            
        let mut loaded_count = 0;
        let mut cache = self.targets_cache.lock().await;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Some(file_stem) = path.file_stem() {
                    if let Some(id) = file_stem.to_str() {
                        // Don't hold the lock during I/O
                        drop(cache);
                        
                        match self.load_target(id).await {
                            Ok(target) => {
                                cache = self.targets_cache.lock().await;
                                cache.insert(id.to_string(), target);
                                loaded_count += 1;
                            },
                            Err(e) => {
                                error!("Failed to load target {}: {}", id, e);
                                cache = self.targets_cache.lock().await;
                            }
                        }
                    }
                }
            }
        }
        
        info!("Loaded {} targets", loaded_count);
        Ok(())
    }

    /// Store OSINT data for a target
    pub async fn store_osint_data(&self, target_id: &str, osint_data: OsintData) -> Result<()> {
        let mut cache = self.targets_cache.lock().await;
        
        let target = cache.get_mut(target_id)
            .ok_or_else(|| anyhow::anyhow!("Target not found: {}", target_id))?;
            
        target.osint_data = osint_data;
        target.updated_at = Utc::now();
        
        // Save the updated target
        drop(cache); // Release the lock before await
        self.save_target_by_id(target_id).await?;
        
        Ok(())
    }
}

/// Centralized target data model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetData {
    // Basic information
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: HashMap<String, String>,
    
    // Domain information
    pub primary_domain: Option<String>,
    pub domains: HashSet<String>,
    pub subdomains: HashSet<String>,
    
    // Network information
    pub ip_addresses: HashSet<IpAddr>,
    pub ip_ranges: HashSet<IpNetwork>,
    pub open_ports: HashMap<IpAddr, HashSet<u16>>,
    
    // Web information
    pub urls: HashSet<String>,
    pub technologies: HashSet<String>,
    
    // OSINT data
    pub osint_data: OsintData,
}

/// OSINT data collected for a target
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsintData {
    pub company_info: Option<CompanyInfo>,
    pub social_profiles: HashMap<String, String>,
    pub email_addresses: HashSet<String>,
    pub documents: Vec<DocumentInfo>,
    pub discovered_subdomains: HashSet<String>,
    pub employees: Vec<EmployeeInfo>,
    pub data_leaks: Vec<DataLeakInfo>,
    pub dns_records: HashMap<String, Vec<DnsRecord>>,
    pub whois_data: Option<WhoisData>,
    pub certificates: Vec<CertificateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyInfo {
    pub name: String,
    pub description: Option<String>,
    pub founded: Option<i32>,
    pub industry: Option<String>,
    pub size: Option<String>,
    pub website: Option<String>,
    pub addresses: Vec<AddressInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub street: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub postal_code: Option<String>,
    pub address_type: Option<String>, // HQ, Branch, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeeInfo {
    pub name: String,
    pub title: Option<String>,
    pub email: Option<String>,
    pub social_profiles: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub title: String,
    pub url: String,
    pub file_type: String,
    pub found_at: DateTime<Utc>,
    pub extraction_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLeakInfo {
    pub source: String,
    pub date: Option<DateTime<Utc>>,
    pub leak_type: String, // Passwords, Email addresses, etc.
    pub affected_accounts: Option<usize>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String, // A, AAAA, MX, TXT, etc.
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisData {
    pub registrar: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub name_servers: Vec<String>,
    pub registrant: Option<WhoisContact>,
    pub admin_contact: Option<WhoisContact>,
    pub tech_contact: Option<WhoisContact>,
    pub raw_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisContact {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub domain: String,
    pub issuer: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub alt_names: Vec<String>,
    pub organization: Option<String>,
}