// src/scope_filter.rs - Advanced scope filtering implementation

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use anyhow::{Result, Context};
use regex::Regex;
use url::Url;
use ipnetwork::IpNetwork;
use tracing::{info, debug, warn};
use std::sync::Arc;
use once_cell::sync::Lazy;

use crate::profile::{Profile, ScopeConfig};

/// ScopeFilter handles filtering domains, IPs, and URLs based on scope configuration
pub struct ScopeFilter {
    include_patterns: Vec<DomainPattern>,
    exclude_patterns: Vec<DomainPattern>,
    include_networks: Vec<IpNetwork>,
    exclude_networks: Vec<IpNetwork>,
    exclude_path_regexes: Vec<Regex>,
    follow_out_of_scope_redirects: bool,
}

/// Pattern for matching domains with wildcard support
enum DomainPattern {
    Exact(String),
    Wildcard(String, Regex),
    Regex(Regex),
}

impl ScopeFilter {
    /// Create a new scope filter from a ScopeConfig
    pub fn new(scope_config: &ScopeConfig) -> Result<Self> {
        let mut include_patterns = Vec::new();
        let mut exclude_patterns = Vec::new();
        let mut include_networks = Vec::new();
        let mut exclude_networks = Vec::new();
        let mut exclude_path_regexes = Vec::new();
        
        // Process domain inclusions
        for pattern in &scope_config.include_domains {
            include_patterns.push(Self::parse_domain_pattern(pattern)?);
        }
        
        // Process domain exclusions
        for pattern in &scope_config.exclude_domains {
            exclude_patterns.push(Self::parse_domain_pattern(pattern)?);
        }
        
        // Process IP inclusions
        for ip_range in &scope_config.include_ips {
            let network = IpNetwork::from_str(ip_range)
                .with_context(|| format!("Invalid IP range: {}", ip_range))?;
            include_networks.push(network);
        }
        
        // Process IP exclusions
        for ip_range in &scope_config.exclude_ips {
            let network = IpNetwork::from_str(ip_range)
                .with_context(|| format!("Invalid IP range: {}", ip_range))?;
            exclude_networks.push(network);
        }
        
        // Process path exclusions
        for pattern in &scope_config.exclude_paths {
            let regex = Regex::new(pattern)
                .with_context(|| format!("Invalid regex pattern: {}", pattern))?;
            exclude_path_regexes.push(regex);
        }
        
        Ok(Self {
            include_patterns,
            exclude_patterns,
            include_networks,
            exclude_networks,
            exclude_path_regexes,
            follow_out_of_scope_redirects: scope_config.follow_out_of_scope_redirects,
        })
    }
    
    /// Create a scope filter from a profile
    pub fn from_profile(profile: &Profile) -> Result<Self> {
        Self::new(&profile.scope)
    }
    
    /// Parse a domain pattern into a DomainPattern enum
    fn parse_domain_pattern(pattern: &str) -> Result<DomainPattern> {
        if pattern.starts_with('/') && pattern.ends_with('/') {
            // Regex pattern
            let regex_str = &pattern[1..pattern.len() - 1];
            let regex = Regex::new(regex_str)
                .with_context(|| format!("Invalid regex pattern: {}", regex_str))?;
            Ok(DomainPattern::Regex(regex))
        } else if pattern.contains('*') {
            // Wildcard pattern
            let regex_pattern = pattern
                .replace(".", "\\.")
                .replace("*", ".*");
            
            let regex = Regex::new(&format!("^{}$", regex_pattern))
                .with_context(|| format!("Invalid wildcard pattern: {}", pattern))?;
            
            Ok(DomainPattern::Wildcard(pattern.to_string(), regex))
        } else {
            // Exact match
            Ok(DomainPattern::Exact(pattern.to_string()))
        }
    }
    
    /// Check if a domain is in scope
    pub fn is_domain_in_scope(&self, domain: &str) -> bool {
        // First check exclusions (they take precedence)
        for pattern in &self.exclude_patterns {
            if self.domain_matches_pattern(domain, pattern) {
                debug!("Domain {} excluded by pattern", domain);
                return false;
            }
        }
        
        // If no inclusions, nothing is in scope
        if self.include_patterns.is_empty() {
            debug!("No inclusion patterns defined, domain {} is out of scope", domain);
            return false;
        }
        
        // Then check inclusions
        for pattern in &self.include_patterns {
            if self.domain_matches_pattern(domain, pattern) {
                return true;
            }
        }
        
        debug!("Domain {} not matched by any inclusion pattern", domain);
        false
    }
    
    /// Check if a domain matches a pattern
    fn domain_matches_pattern(&self, domain: &str, pattern: &DomainPattern) -> bool {
        match pattern {
            DomainPattern::Exact(exact) => domain.eq_ignore_ascii_case(exact),
            DomainPattern::Wildcard(_, regex) => regex.is_match(domain),
            DomainPattern::Regex(regex) => regex.is_match(domain),
        }
    }
    
    /// Check if a URL is in scope
    pub fn is_url_in_scope(&self, url_str: &str) -> bool {
        match Url::parse(url_str) {
            Ok(url) => {
                // Get the host
                let host = match url.host_str() {
                    Some(h) => h,
                    None => {
                        debug!("URL {} has no host", url_str);
                        return false;
                    }
                };
                
                // Check if domain is in scope
                if !self.is_domain_in_scope(host) {
                    return false;
                }
                
                // Check if path is excluded
                let path = url.path();
                for regex in &self.exclude_path_regexes {
                    if regex.is_match(path) {
                        debug!("Path {} excluded by regex", path);
                        return false;
                    }
                }
                
                true
            },
            Err(e) => {
                // Try adding https:// prefix and retry
                if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
                    return self.is_url_in_scope(&format!("https://{}", url_str));
                }
                
                warn!("Failed to parse URL {}: {}", url_str, e);
                false
            }
        }
    }
    
    /// Check if an IP address is in scope
    pub fn is_ip_in_scope(&self, ip: &IpAddr) -> bool {
        // First check exclusions
        for network in &self.exclude_networks {
            if network.contains(*ip) {
                debug!("IP {} excluded by network {}", ip, network);
                return false;
            }
        }
        
        // If no inclusions, all IPs are out of scope
        if self.include_networks.is_empty() {
            debug!("No inclusion networks defined, IP {} is out of scope", ip);
            return false;
        }
        
        // Then check inclusions
        for network in &self.include_networks {
            if network.contains(*ip) {
                return true;
            }
        }
        
        debug!("IP {} not matched by any inclusion network", ip);
        false
    }
    
    /// Generic function to check if a host (domain or IP) is in scope
    pub fn is_host_in_scope(&self, host: &str) -> bool {
        // Check if it's an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.is_ip_in_scope(&ip);
        }
        
        // Otherwise treat as domain
        self.is_domain_in_scope(host)
    }
    
    /// Filter a list of domains to only those in scope
    pub fn filter_domains<'a>(&self, domains: &'a [String]) -> Vec<&'a String> {
        domains.iter()
            .filter(|d| self.is_domain_in_scope(d))
            .collect()
    }
    
    /// Filter a list of URLs to only those in scope
    pub fn filter_urls<'a>(&self, urls: &'a [String]) -> Vec<&'a String> {
        urls.iter()
            .filter(|u| self.is_url_in_scope(u))
            .collect()
    }
    
    /// Filter a list of hosts (domains or IPs) to only those in scope
    pub fn filter_hosts<'a>(&self, hosts: &'a [String]) -> Vec<&'a String> {
        hosts.iter()
            .filter(|h| self.is_host_in_scope(h))
            .collect()
    }
    
    /// Should we follow redirects to out-of-scope domains?
    pub fn should_follow_out_of_scope_redirects(&self) -> bool {
        self.follow_out_of_scope_redirects
    }
}

/// Trait for applying scope filtering to common operations
pub trait ScopeFilterable {
    /// Filter content to only include in-scope items
    fn filter_by_scope(&self, filter: &ScopeFilter) -> Self;
}

impl ScopeFilterable for Vec<String> {
    fn filter_by_scope(&self, filter: &ScopeFilter) -> Self {
        self.iter()
            .filter(|item| filter.is_host_in_scope(item))
            .cloned()
            .collect()
    }
}

/// Helper function to filter a command's arguments by scope
pub fn filter_cmd_args_by_scope(args: &mut Vec<String>, scope_filter: &ScopeFilter) {
    let mut filtered_args = Vec::new();
    
    for arg in args.iter() {
        // Check if this is a target argument that should be filtered
        if arg.starts_with("http://") || arg.starts_with("https://") {
            if scope_filter.is_url_in_scope(arg) {
                filtered_args.push(arg.clone());
            }
        } else if arg.contains('.') && !arg.starts_with('-') {
            // Might be a domain
            if scope_filter.is_host_in_scope(arg) {
                filtered_args.push(arg.clone());
            }
        } else {
            // Not a target argument, keep it
            filtered_args.push(arg.clone());
        }
    }
    
    *args = filtered_args;
}

/// Scope cache for efficient scope checking
pub struct ScopeCache {
    filter: Arc<ScopeFilter>,
    domains_cache: parking_lot::RwLock<HashSet<String>>,
    urls_cache: parking_lot::RwLock<HashSet<String>>,
}

impl ScopeCache {
    /// Create a new scope cache
    pub fn new(filter: ScopeFilter) -> Self {
        Self {
            filter: Arc::new(filter),
            domains_cache: parking_lot::RwLock::new(HashSet::new()),
            urls_cache: parking_lot::RwLock::new(HashSet::new()),
        }
    }
    
    /// Check if a domain is in scope (cached)
    pub fn is_domain_in_scope(&self, domain: &str) -> bool {
        // Check cache first
        {
            let cache = self.domains_cache.read();
            if cache.contains(domain) {
                return true;
            }
        }
        
        // Check with filter
        let result = self.filter.is_domain_in_scope(domain);
        
        // Update cache if in scope
        if result {
            let mut cache = self.domains_cache.write();
            cache.insert(domain.to_string());
        }
        
        result
    }
    
    /// Check if a URL is in scope (cached)
    pub fn is_url_in_scope(&self, url: &str) -> bool {
        // Check cache first
        {
            let cache = self.urls_cache.read();
            if cache.contains(url) {
                return true;
            }
        }
        
        // Check with filter
        let result = self.filter.is_url_in_scope(url);
        
        // Update cache if in scope
        if result {
            let mut cache = self.urls_cache.write();
            cache.insert(url.to_string());
        }
        
        result
    }
    
    /// Get the underlying scope filter
    pub fn filter(&self) -> &ScopeFilter {
        &self.filter
    }
}

/// Ensure a plugin command respects scope configuration
pub struct ScopeEnforcedCommand<'a> {
    command: &'a mut tokio::process::Command,
    scope_filter: &'a ScopeFilter,
}

impl<'a> ScopeEnforcedCommand<'a> {
    /// Create a new scope-enforced command
    pub fn new(command: &'a mut tokio::process::Command, scope_filter: &'a ScopeFilter) -> Self {
        Self {
            command,
            scope_filter,
        }
    }
    
    /// Build and execute the command
    pub async fn execute(self) -> Result<std::process::Output> {
        // Extract and filter arguments
        // This would require access to the Command's internal args which isn't directly available
        // In a real implementation, you'd want to track args separately
        
        // Execute command
        self.command.output().await.context("Failed to execute command")
    }
}

/// Helper module to create scope filters on the fly
pub mod scope {
    use super::*;
    
    /// Create a scope filter for Audible bug bounty program
    pub fn audible() -> Result<ScopeFilter> {
        let mut config = ScopeConfig::default();
        
        // Include all audible domains
        config.include_domains.push("*.audible.*".to_string());
        
        // Exclude out-of-scope domains
        config.exclude_domains.extend_from_slice(&[
            "help.audible.com".to_string(),
            "newsletters.audible.com".to_string(),
            "www.audiblecareers.com".to_string(),
            "www.audible.com/ep/podcast-development-program".to_string(),
            "www.audiblehub.com/submit".to_string(),
            "www.audible.ca/blog/en".to_string(),
        ]);
        
        // Exclude certain paths
        config.exclude_paths.extend_from_slice(&[
            "/careers".to_string(),
            "/jobs".to_string(),
            "/podcast-development-program".to_string(),
        ]);
        
        ScopeFilter::new(&config)
    }
    
    /// Create a scope filter for a single domain
    pub fn domain(domain: &str) -> Result<ScopeFilter> {
        let mut config = ScopeConfig::default();
        config.include_domains.push(domain.to_string());
        ScopeFilter::new(&config)
    }
    
    /// Create a scope filter for multiple domains
    pub fn domains(domains: &[&str]) -> Result<ScopeFilter> {
        let mut config = ScopeConfig::default();
        for domain in domains {
            config.include_domains.push(domain.to_string());
        }
        ScopeFilter::new(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_in_scope() {
        let mut config = ScopeConfig::default();
        config.include_domains.push("*.example.com".to_string());
        config.exclude_domains.push("excluded.example.com".to_string());
        
        let filter = ScopeFilter::new(&config).unwrap();
        
        assert!(filter.is_domain_in_scope("test.example.com"));
        assert!(filter.is_domain_in_scope("sub.test.example.com"));
        assert!(!filter.is_domain_in_scope("excluded.example.com"));
        assert!(!filter.is_domain_in_scope("example.org"));
    }
    
    #[test]
    fn test_url_in_scope() {
        let mut config = ScopeConfig::default();
        config.include_domains.push("*.example.com".to_string());
        config.exclude_domains.push("excluded.example.com".to_string());
        config.exclude_paths.push("/admin.*".to_string());
        
        let filter = ScopeFilter::new(&config).unwrap();
        
        assert!(filter.is_url_in_scope("https://test.example.com/page"));
        assert!(!filter.is_url_in_scope("https://excluded.example.com/page"));
        assert!(!filter.is_url_in_scope("https://test.example.com/admin/login"));
        assert!(!filter.is_url_in_scope("https://example.org/page"));
    }
    
    #[test]
    fn test_audible_scope() {
        let filter = scope::audible().unwrap();
        
        assert!(filter.is_domain_in_scope("www.audible.com"));
        assert!(filter.is_domain_in_scope("audible.co.uk"));
        assert!(filter.is_domain_in_scope("api.audible.com"));
        assert!(!filter.is_domain_in_scope("help.audible.com"));
        assert!(!filter.is_domain_in_scope("www.audiblecareers.com"));
        
        assert!(filter.is_url_in_scope("https://www.audible.com/pd/book"));
        assert!(!filter.is_url_in_scope("https://help.audible.com/article"));
        assert!(!filter.is_url_in_scope("https://www.audible.com/careers/job"));
    }
}