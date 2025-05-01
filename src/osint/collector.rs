// src/osint/collector.rs
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{info, warn, debug};
use reqwest::Client;

use crate::core::target::model::{TargetData, OsintData};
use crate::error::{BBHuntResult, BBHuntError};
use crate::context::Context;
use super::sources::OsintSource;

/// OSINT data collector
pub struct OsintCollector {
    sources: HashMap<String, Box<dyn OsintSource>>,
    config: HashMap<String, HashMap<String, String>>, // source -> config
    context: Option<Arc<Context>>,
}

impl OsintCollector {
    /// Create a new OSINT collector
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            config: HashMap::new(),
            context: None,
        }
    }
    
    /// Create a new OSINT collector with context
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            sources: HashMap::new(),
            config: HashMap::new(),
            context: Some(context),
        }
    }
    
    /// Set the context
    pub fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
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
                    // Continue with other sources - don't fail the entire collection
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
                source_name: source_name.to_string(),
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
        
        // Merge subdomains
        for subdomain in source_data.subdomains {
            target_data.subdomains.insert(subdomain);
        }
        
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

// src/osint/sources.rs
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::warn;
use reqwest::Client;

use crate::core::target::model::{TargetData, OsintData, DnsRecord, WhoisData, CertificateInfo};
use crate::error::{BBHuntResult, BBHuntError};
use crate::context::Context;

/// Trait for OSINT data sources
#[async_trait]
pub trait OsintSource: Send + Sync {
    /// Get the name of the source
    fn name(&self) -> &str;
    
    /// Get a description of the source
    fn description(&self) -> &str;
    
    /// Collect OSINT data for a target
    async fn collect(&self, target: &TargetData, config: &HashMap<String, String>) -> BBHuntResult<OsintData>;
    
    /// Check if the source requires authentication
    fn requires_auth(&self) -> bool {
        false
    }
    
    /// Get required configuration keys
    fn required_config(&self) -> Vec<String> {
        Vec::new()
    }
    
    /// Set the context
    fn set_context(&mut self, _context: Arc<Context>) {
        // Default empty implementation
    }
}

/// DNS information source
pub struct DnsOsintSource {
    client: Client,
    context: Option<Arc<Context>>,
}

impl DnsOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            context: None,
        }
    }
    
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            client: Client::new(),
            context: Some(context),
        }
    }
    
    async fn query_dns_records(&self, domain: &str) -> BBHuntResult<Vec<DnsRecord>> {
        // This would normally use a DNS library or external tool
        // For now, we'll simulate some basic records
        
        let mut records = Vec::new();
        
        // Simulate A record
        records.push(DnsRecord {
            record_type: "A".to_string(),
            value: "192.0.2.1".to_string(),
            ttl: Some(3600),
        });
        
        // Simulate MX record
        records.push(DnsRecord {
            record_type: "MX".to_string(),
            value: "10 mail.example.com".to_string(),
            ttl: Some(3600),
        });
        
        // Simulate TXT record
        records.push(DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 include:_spf.example.com ~all".to_string(),
            ttl: Some(3600),
        });
        
        Ok(records)
    }
}

#[async_trait]
impl OsintSource for DnsOsintSource {
    fn name(&self) -> &str {
        "dns"
    }
    
    fn description(&self) -> &str {
        "Collects DNS records for target domains"
    }
    
    fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    async fn collect(&self, target: &TargetData, _config: &HashMap<String, String>) -> BBHuntResult<OsintData> {
        let mut osint_data = OsintData::default();
        let mut dns_records = HashMap::new();
        
        // Query DNS records for primary domain
        if let Some(domain) = &target.primary_domain {
            match self.query_dns_records(domain).await {
                Ok(records) => {
                    dns_records.insert(domain.clone(), records);
                }
                Err(e) => {
                    warn!("Failed to query DNS records for {}: {}", domain, e);
                }
            }
        }
        
        // Query DNS records for all domains
        for domain in &target.domains {
            if domain == target.primary_domain.as_ref().unwrap_or(&String::new()) {
                continue; // Skip primary domain (already processed)
            }
            
            match self.query_dns_records(domain).await {
                Ok(records) => {
                    dns_records.insert(domain.clone(), records);
                }
                Err(e) => {
                    warn!("Failed to query DNS records for {}: {}", domain, e);
                }
            }
        }
        
        osint_data.dns_records = dns_records;
        Ok(osint_data)
    }
}

/// WHOIS data source
pub struct WhoisOsintSource {
    client: Client,
    context: Option<Arc<Context>>,
}

impl WhoisOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            context: None,
        }
    }
    
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            client: Client::new(),
            context: Some(context),
        }
    }
    
    async fn query_whois(&self, domain: &str) -> BBHuntResult<WhoisData> {
        // This would normally use a WHOIS library or external tool
        // For now, we'll simulate basic WHOIS data
        
        Ok(WhoisData {
            registrar: Some("Example Registrar, Inc.".to_string()),
            created_date: Some(chrono::Utc::now() - chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now() - chrono::Duration::days(30)),
            expiry_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            name_servers: vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
            ],
            registrant: None,
            admin_contact: None,
            tech_contact: None,
            raw_data: "Simulated WHOIS data".to_string(),
        })
    }
}

#[async_trait]
impl OsintSource for WhoisOsintSource {
    fn name(&self) -> &str {
        "whois"
    }
    
    fn description(&self) -> &str {
        "Collects WHOIS data for target domains"
    }
    
    fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    async fn collect(&self, target: &TargetData, _config: &HashMap<String, String>) -> BBHuntResult<OsintData> {
        let mut osint_data = OsintData::default();
        
        // Query WHOIS for primary domain
        if let Some(domain) = &target.primary_domain {
            match self.query_whois(domain).await {
                Ok(whois_data) => {
                    osint_data.whois_data = Some(whois_data);
                }
                Err(e) => {
                    warn!("Failed to query WHOIS for {}: {}", domain, e);
                }
            }
        }
        
        Ok(osint_data)
    }
}

/// SSL certificate information source
pub struct SslCertificateOsintSource {
    client: Client,
    context: Option<Arc<Context>>,
}

impl SslCertificateOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            context: None,
        }
    }
    
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            client: Client::new(),
            context: Some(context),
        }
    }
    
    async fn query_ssl_cert(&self, domain: &str) -> BBHuntResult<CertificateInfo> {
        // This would normally use a SSL library or external tool
        // For now, we'll simulate basic certificate data
        
        Ok(CertificateInfo {
            domain: domain.to_string(),
            issuer: "Let's Encrypt Authority X3".to_string(),
            valid_from: chrono::Utc::now() - chrono::Duration::days(30),
            valid_to: chrono::Utc::now() + chrono::Duration::days(60),
            alt_names: vec![
                domain.to_string(),
                format!("www.{}", domain),
            ],
            organization: None,
        })
    }
}

#[async_trait]
impl OsintSource for SslCertificateOsintSource {
    fn name(&self) -> &str {
        "ssl_certificate"
    }
    
    fn description(&self) -> &str {
        "Collects SSL certificate information for target domains"
    }
    
    fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    async fn collect(&self, target: &TargetData, _config: &HashMap<String, String>) -> BBHuntResult<OsintData> {
        let mut osint_data = OsintData::default();
        let mut certificates = Vec::new();
        
        // Query SSL cert for primary domain
        if let Some(domain) = &target.primary_domain {
            match self.query_ssl_cert(domain).await {
                Ok(cert) => {
                    certificates.push(cert);
                }
                Err(e) => {
                    warn!("Failed to query SSL certificate for {}: {}", domain, e);
                }
            }
        }
        
        // Query SSL certs for all domains
        for domain in &target.domains {
            if domain == target.primary_domain.as_ref().unwrap_or(&String::new()) {
                continue; // Skip primary domain (already processed)
            }
            
            match self.query_ssl_cert(domain).await {
                Ok(cert) => {
                    certificates.push(cert);
                }
                Err(e) => {
                    warn!("Failed to query SSL certificate for {}: {}", domain, e);
                }
            }
        }
        
        osint_data.certificates = certificates;
        Ok(osint_data)
    }
}

/// Certificate Transparency Log source
pub struct CtLogOsintSource {
    client: Client,
    context: Option<Arc<Context>>,
}

impl CtLogOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            context: None,
        }
    }
    
    pub fn new_with_context(context: Arc<Context>) -> Self {
        Self {
            client: Client::new(),
            context: Some(context),
        }
    }
    
    async fn query_ct_logs(&self, domain: &str) -> BBHuntResult<Vec<String>> {
        // This would normally query Certificate Transparency logs
        // For now, we'll simulate some discovered subdomains
        
        Ok(vec![
            format!("api.{}", domain),
            format!("www.{}", domain),
            format!("mail.{}", domain),
            format!("dev.{}", domain),
            format!("stage.{}", domain),
        ])
    }
}

#[async_trait]
impl OsintSource for CtLogOsintSource {
    fn name(&self) -> &str {
        "ct_logs"
    }
    
    fn description(&self) -> &str {
        "Discovers subdomains using Certificate Transparency logs"
    }
    
    fn set_context(&mut self, context: Arc<Context>) {
        self.context = Some(context);
    }
    
    async fn collect(&self, target: &TargetData, _config: &HashMap<String, String>) -> BBHuntResult<OsintData> {
        let mut osint_data = OsintData::default();
        
        // Query CT logs for primary domain
        if let Some(domain) = &target.primary_domain {
            match self.query_ct_logs(domain).await {
                Ok(subdomains) => {
                    for subdomain in subdomains {
                        osint_data.subdomains.insert(subdomain);
                    }
                }
                Err(e) => {
                    warn!("Failed to query CT logs for {}: {}", domain, e);
                }
            }
        }
        
        Ok(osint_data)
    }
}