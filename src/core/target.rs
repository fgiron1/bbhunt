// src/core/target.rs
use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use url::Url;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use regex::Regex;
use async_trait::async_trait;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub includes: Vec<TargetSpecifier>,
    pub excludes: Vec<TargetSpecifier>,
    pub tags: HashMap<String, String>,
    pub notes: Option<String>,
    pub added_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSpecifier {
    Domain(String),
    Subdomain(String, String), // (parent domain, specific subdomain)
    Ip(IpAddr),
    CidrRange(IpNetwork),
    UrlPattern(String),
    Regex(String),
}

#[derive(Debug)]
pub struct TargetManager {
    targets: HashMap<String, Target>,
    cache: HashMap<String, HashSet<String>>, // Resolved targets cache
}

impl TargetManager {
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            cache: HashMap::new(),
        }
    }
    
    pub fn add_target(&mut self, target: Target) -> Result<()> {
        if self.targets.contains_key(&target.name) {
            return Err(anyhow::anyhow!("Target with name '{}' already exists", target.name));
        }
        self.targets.insert(target.name.clone(), target);
        Ok(())
    }
    
    pub fn remove_target(&mut self, name: &str) -> Result<()> {
        if !self.targets.contains_key(name) {
            return Err(anyhow::anyhow!("Target '{}' not found", name));
        }
        self.targets.remove(name);
        Ok(())
    }
    
    pub fn add_include(&mut self, target_name: &str, specifier: TargetSpecifier) -> Result<()> {
        let target = self.targets.get_mut(target_name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?;
        target.includes.push(specifier);
        // Invalidate cache
        self.cache.remove(target_name);
        Ok(())
    }
    
    pub fn add_exclude(&mut self, target_name: &str, specifier: TargetSpecifier) -> Result<()> {
        let target = self.targets.get_mut(target_name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?;
        target.excludes.push(specifier);
        // Invalidate cache
        self.cache.remove(target_name);
        Ok(())
    }
    
    pub fn get_target(&self, name: &str) -> Result<&Target> {
        self.targets.get(name)
            .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", name))
    }

    pub fn get_all_targets(&self) -> impl Iterator<Item = (&String, &Target)> {
        self.targets.iter()
    }
    
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
                    // Implement URL pattern expansion
                    included.insert(pattern.clone());
                }
                TargetSpecifier::Regex(pattern) => {
                    // For regex, we'd typically match against other entries
                    // This is a placeholder for more complex implementation
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
        
        Ok(result)
    }
    
    // Helper method to enumerate subdomains
    async fn enumerate_subdomains(&self, domain: &str) -> Result<Vec<String>> {
        // This would integrate with your subdomain enumeration plugin
        // Simplified placeholder implementation
        Ok(vec![format!("www.{}", domain)])
    }
    
    pub async fn is_in_scope(&self, target_name: &str, host: &str) -> Result<bool> {
        // Clone self to avoid mutable borrow issues with resolve_target
        let resolved = self.resolve_target(target_name).await?;
        
        // Check if the host is directly in the resolved targets
        if resolved.contains(host) {
            return Ok(true);
        }
        
        // Check if the host matches any of the resolved targets (for subdomains)
        for target in &resolved {
            if host.ends_with(target) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    pub fn export_targets(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.targets)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    pub fn import_targets(&mut self, path: &std::path::Path) -> Result<()> {
        let json = std::fs::read_to_string(path)?;
        let targets: HashMap<String, Target> = serde_json::from_str(&json)?;
        self.targets = targets;
        self.cache.clear(); // Invalidate cache on import
        Ok(())
    }
}

// Helper function for target specifier formatting
pub fn target_specifier_to_string(specifier: &TargetSpecifier) -> String {
    match specifier {
        TargetSpecifier::Domain(domain) => format!("Domain: {}", domain),
        TargetSpecifier::Subdomain(parent, subdomain) => format!("Subdomain: {}.{}", subdomain, parent),
        TargetSpecifier::Ip(ip) => format!("IP: {}", ip),
        TargetSpecifier::CidrRange(network) => format!("CIDR: {}", network),
        TargetSpecifier::UrlPattern(pattern) => format!("URL Pattern: {}", pattern),
        TargetSpecifier::Regex(pattern) => format!("Regex: {}", pattern),
    }
}
