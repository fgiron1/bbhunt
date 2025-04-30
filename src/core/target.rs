use std::collections::{HashSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use ipnetwork::IpNetwork;
use regex::Regex;
use chrono::{DateTime, Utc};
use tracing::{info, debug};

/// Target definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub includes: Vec<TargetSpecifier>,
    pub excludes: Vec<TargetSpecifier>,
    pub tags: HashMap<String, String>,
    pub notes: Option<String>,
    pub added_at: DateTime<Utc>,
}

/// Target specifier types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSpecifier {
    Domain(String),
    Subdomain(String, String), // (parent domain, specific subdomain)
    Ip(IpAddr),
    CidrRange(IpNetwork),
    UrlPattern(String),
    Regex(String),
}

/// Manager for handling targets
pub struct TargetManager {
    targets: HashMap<String, Target>,
    cache: HashMap<String, HashSet<String>>, // Resolved targets cache
}

impl TargetManager {
    /// Create a new target manager
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            cache: HashMap::new(),
        }
    }
    
    /// Add a new target
    pub fn add_target(&mut self, target: Target) -> Result<()> {
        if self.targets.contains_key(&target.name) {
            return Err(anyhow::anyhow!("Target with name '{}' already exists", target.name));
        }
        
        info!("Adding target: {}", target.name);
        self.targets.insert(target.name.clone(), target);
        Ok(())
    }
    
    /// Remove a target
    pub fn remove_target(&mut self, name: &str) -> Result<()> {
        if !self.targets.contains_key(name) {
            return Err(anyhow::anyhow!("Target '{}' not found", name));
        }
        
        info!("Removing target: {}", name);
        self.targets.remove(name);
        self.cache.remove(name);
        Ok(())
    }
    
    /// Add an include specifier to a target
    pub fn add_include(&mut self, target_name: &str, specifier: TargetSpecifier) -> Result<()> {
        let target = self.targets.get_mut(target_name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?;
        
        debug!("Adding include to target {}: {:?}", target_name, specifier);
        target.includes.push(specifier);
        
        // Invalidate cache
        self.cache.remove(target_name);
        Ok(())
    }
    
    /// Add an exclude specifier to a target
    pub fn add_exclude(&mut self, target_name: &str, specifier: TargetSpecifier) -> Result<()> {
        let target = self.targets.get_mut(target_name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?;
        
        debug!("Adding exclude to target {}: {:?}", target_name, specifier);
        target.excludes.push(specifier);
        
        // Invalidate cache
        self.cache.remove(target_name);
        Ok(())
    }
    
    /// Get a target by name
    pub fn get_target(&self, name: &str) -> Result<&Target> {
        self.targets.get(name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", name))
    }
    
    /// Get all targets
    pub fn get_all_targets(&self) -> impl Iterator<Item = (&String, &Target)> {
        self.targets.iter()
    }
    
    /// Resolve a target into a set of concrete targets (domains, IPs)
    pub async fn resolve_target(&mut self, target_name: &str) -> Result<HashSet<String>> {
        // Check cache first
        if let Some(resolved) = self.cache.get(target_name) {
            return Ok(resolved.clone());
        }
        
        let target = self.targets.get(target_name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?;
        
        let mut included = HashSet::new();
        
        // Process all includes
        for include in &target.includes {
            match include {
                TargetSpecifier::Domain(domain) => {
                    included.insert(domain.clone());
                    
                    // Add subdomains through DNS enumeration
                    if let Ok(subdomains) = self.enumerate_subdomains(domain).await {
                        for subdomain in subdomains {
                            included.insert(subdomain);
                        }
                    }
                }
                TargetSpecifier::Subdomain(parent, subdomain) => {
                    included.insert(format!("{}.{}", subdomain, parent));
                }
                TargetSpecifier::Ip(ip) => {
                    included.insert(ip.to_string());
                }
                TargetSpecifier::CidrRange(network) => {
                    for ip in network.iter() {
                        included.insert(ip.to_string());
                    }
                }
                TargetSpecifier::UrlPattern(pattern) => {
                    included.insert(pattern.clone());
                }
                TargetSpecifier::Regex(pattern) => {
                    included.insert(format!("regex:{}", pattern));
                }
            }
        }
        
        // Process all excludes
        let mut excluded = HashSet::new();
        for exclude in &target.excludes {
            match exclude {
                TargetSpecifier::Domain(domain) => {
                    excluded.insert(domain.clone());
                    
                    // Exclude all subdomains
                    for target in &included {
                        if target.ends_with(domain) {
                            excluded.insert(target.clone());
                        }
                    }
                }
                TargetSpecifier::Subdomain(parent, subdomain) => {
                    excluded.insert(format!("{}.{}", subdomain, parent));
                }
                TargetSpecifier::Ip(ip) => {
                    excluded.insert(ip.to_string());
                }
                TargetSpecifier::CidrRange(network) => {
                    for ip in network.iter() {
                        excluded.insert(ip.to_string());
                    }
                }
                TargetSpecifier::UrlPattern(pattern) => {
                    excluded.insert(pattern.clone());
                }
                TargetSpecifier::Regex(regex_pattern) => {
                    if let Ok(regex) = Regex::new(regex_pattern) {
                        for target in &included {
                            if regex.is_match(target) {
                                excluded.insert(target.clone());
                            }
                        }
                    }
                }
            }
        }
        
        // Final result: included - excluded
        let result: HashSet<String> = included.difference(&excluded).cloned().collect();
        
        // Cache the result
        self.cache.insert(target_name.to_string(), result.clone());
        
        info!("Resolved target '{}' into {} concrete targets", target_name, result.len());
        Ok(result)
    }
    
    /// Helper method to enumerate subdomains
    async fn enumerate_subdomains(&self, domain: &str) -> Result<Vec<String>> {
        // This would integrate with subdomain enumeration plugins
        // For now, just return a placeholder
        Ok(vec![format!("www.{}", domain)])
    }
    
    /// Check if a host is in scope for a target
    pub async fn is_in_scope(&self, target_name: &str, host: &str) -> Result<bool> {
        // We need to clone self since resolve_target borrows mutably
        let resolved = self.resolve_target(target_name).await?;
        
        // Check if the host is directly in the resolved targets
        if resolved.contains(host) {
            return Ok(true);
        }
        
        // Check if the host matches any of the resolved targets (for subdomains)
        for target in resolved {
            if host.ends_with(target) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Export targets to a file
    pub fn export_targets(&self, path: &Path) -> Result<()> {
        info!("Exporting targets to {}", path.display());
        let json = serde_json::to_string_pretty(&self.targets)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Import targets from a file
    pub fn import_targets(&mut self, path: &Path) -> Result<()> {
        info!("Importing targets from {}", path.display());
        let json = std::fs::read_to_string(path)?;
        let targets: HashMap<String, Target> = serde_json::from_str(&json)?;
        self.targets = targets;
        self.cache.clear(); // Invalidate cache on import
        Ok(())
    }
}

/// Format a target specifier for display
pub fn format_target_specifier(specifier: &TargetSpecifier) -> String {
    match specifier {
        TargetSpecifier::Domain(domain) => format!("Domain: {}", domain),
        TargetSpecifier::Subdomain(parent, subdomain) => format!("Subdomain: {}.{}", subdomain, parent),
        TargetSpecifier::Ip(ip) => format!("IP: {}", ip),
        TargetSpecifier::CidrRange(network) => format!("CIDR: {}", network),
        TargetSpecifier::UrlPattern(pattern) => format!("URL Pattern: {}", pattern),
        TargetSpecifier::Regex(pattern) => format!("Regex: {}", pattern),
    }
}