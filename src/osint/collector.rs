// src/osint/collector.rs
use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn, debug};

use crate::core::target::model::{TargetData, OsintData};
use crate::error::{BBHuntError, BBHuntResult};
use super::sources::OsintSource;

/// OSINT data collector
pub struct OsintCollector {
    sources: HashMap<String, Box<dyn OsintSource>>,
    config: HashMap<String, HashMap<String, String>>, // source -> config
}

impl OsintCollector {
    /// Create a new OSINT collector
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            config: HashMap::new(),
        }
    }
    
    /// Register an OSINT source
    pub fn register_source(&mut self, source: Box<dyn OsintSource>) -> BBHuntResult<()> {
        let source_name = source.name().to_string();
        debug!("Registering OSINT source: {}", source_name);
        self.sources.insert(source_name, source);
        Ok(())
    }
    
    /// Configure an OSINT source
    pub fn configure_source(&mut self, source_name: &str, config: HashMap<String, String>) -> BBHuntResult<()> {
        if !self.sources.contains_key(source_name) {
            return Err(BBHuntError::InvalidInput(format!("OSINT source not found: {}", source_name)));
        }
        
        self.config.insert(source_name.to_string(), config);
        Ok(())
    }
    
    /// Run all OSINT collection on a target
    pub async fn collect_all(&self, target: &mut TargetData) -> BBHuntResult<()> {
        info!("Running OSINT collection for target: {}", target.name);
        
        let mut osint_data = OsintData::default();
        
        for (name, source) in &self.sources {
            debug!("Running OSINT source: {}", name);
            
            let config = self.config.get(name).cloned().unwrap_or_default();
            
            match source.collect(target, &config).await {
                Ok(data) => {
                    // Merge data into the combined OSINT data
                    self.merge_osint_data(&mut osint_data, data);
                    debug!("Successfully collected data from {}", name);
                }
                Err(e) => {
                    warn!("Failed to collect OSINT data from {}: {}", name, e);
                }
            }
        }
        
        // Update target with collected OSINT data
        target.set_osint_data(osint_data);
        
        info!("Completed OSINT collection for target: {}", target.name);
        Ok(())
    }
    
    /// Run a specific OSINT source on a target
    pub async fn collect_from_source(&self, target: &mut TargetData, source_name: &str) -> BBHuntResult<()> {
        let source = self.sources.get(source_name)
            .ok_or_else(|| BBHuntError::InvalidInput(format!("OSINT source not found: {}", source_name)))?;
            
        info!("Running OSINT source {} for target: {}", source_name, target.name);
        
        let config = self.config.get(source_name).cloned().unwrap_or_default();
        
        let data = source.collect(target, &config).await
        .map_err(|e| BBHuntError::OsintError {
            source_name: source_name.to_string(),  // Update this line
            message: e.to_string(),
        })?;
            
        // Merge data into the target's OSINT data
        let mut current_osint = target.osint.clone();
        self.merge_osint_data(&mut current_osint, data);
        target.set_osint_data(current_osint);
        
        Ok(())
    }
    
    /// Merge OSINT data from a source into the combined data
    fn merge_osint_data(&self, target_data: &mut OsintData, source_data: OsintData) {
        // Merge company info
        if source_data.company_info.is_some() && target_data.company_info.is_none() {
            target_data.company_info = source_data.company_info;
        }
        
        // Merge social profiles
        for (platform, url) in source_data.social_profiles {
            target_data.social_profiles.insert(platform, url);
        }
        
        // Merge email addresses
        for email in source_data.email_addresses {
            target_data.email_addresses.insert(email);
        }
        
        // Merge documents
        target_data.documents.extend(source_data.documents);
        
        // Merge employees
        target_data.employees.extend(source_data.employees);
        
        // Merge data leaks
        target_data.data_leaks.extend(source_data.data_leaks);
        
        // Merge DNS records
        for (domain, records) in source_data.dns_records {
            target_data.dns_records.entry(domain).or_default().extend(records);
        }
        
        // Merge WHOIS data
        if source_data.whois_data.is_some() && target_data.whois_data.is_none() {
            target_data.whois_data = source_data.whois_data;
        }
        
        // Merge certificates
        target_data.certificates.extend(source_data.certificates);
    }
    
    /// List all available OSINT sources
    pub fn list_sources(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }
}