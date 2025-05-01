// src/osint.rs
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use anyhow::{Result, Context, bail};
use async_trait::async_trait;
use tracing::{info, debug, warn};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;

use crate::config::AppConfig;
use crate::target::TargetData;
// Import OsintData and related types from target.rs instead of defining duplicates
use crate::target::{OsintData, CompanyInfo, EmployeeInfo, DocumentInfo, 
                   DataLeakInfo, DnsRecord, WhoisData, WhoisContact, 
                   CertificateInfo, AddressInfo};

/// OSINT collector with lazy loading of sources
pub struct OsintCollector {
    config: AppConfig,
    sources: Arc<Mutex<HashMap<String, Box<dyn OsintSource>>>>,
    initialized: AtomicBool,
}

impl OsintCollector {
    /// Create a new OSINT collector
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            sources: Arc::new(Mutex::new(HashMap::new())),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// Initialize the OSINT collector
    pub async fn initialize(&self) -> Result<()> {
        // Only initialize once
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // Register built-in sources
        let mut sources = self.sources.lock().await;
        
        // DNS OSINT source
        sources.insert(
            "dns".to_string(), 
            Box::new(DnsOsintSource::new(self.config.clone()))
        );
        
        // WHOIS OSINT source
        sources.insert(
            "whois".to_string(), 
            Box::new(WhoisOsintSource::new(self.config.clone()))
        );
        
        // SSL Certificate OSINT source
        sources.insert(
            "ssl_certificate".to_string(), 
            Box::new(SslCertificateOsintSource::new(self.config.clone()))
        );
        
        // Certificate Transparency Log OSINT source
        sources.insert(
            "ct_logs".to_string(), 
            Box::new(CtLogOsintSource::new(self.config.clone()))
        );
        
        // Mark as initialized
        self.initialized.store(true, Ordering::SeqCst);
        
        info!("OSINT collector initialized with {} sources", sources.len());
        Ok(())
    }
    
    /// Run all OSINT collection on a target
    pub async fn collect_all(&self, target: &mut TargetData) -> Result<()> {
        // Ensure initialization
        self.ensure_initialized().await?;
        
        info!("Running OSINT collection for target: {}", target.name);
        
        let mut osint_data = target.osint_data.clone();
        let sources = self.sources.lock().await;
        
        for (name, source) in sources.iter() {
            debug!("Running OSINT source: {}", name);
            
            match source.collect(target).await {
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
        target.osint_data = osint_data;
        
        info!("Completed OSINT collection for target: {}", target.name);
        Ok(())
    }
    
    /// Run a specific OSINT source on a target
    pub async fn collect_from_source(&self, target: &mut TargetData, source_name: &str) -> Result<()> {
        // Ensure initialization
        self.ensure_initialized().await?;
        
        let sources = self.sources.lock().await;
        
        let source = sources.get(source_name)
            .ok_or_else(|| anyhow::anyhow!("OSINT source not found: {}", source_name))?;
            
        info!("Running OSINT source {} for target: {}", source_name, target.name);
        
        let data = source.collect(target).await
            .context(format!("Failed to collect data from source {}", source_name))?;
            
        // Merge data into the target's OSINT data
        self.merge_osint_data(&mut target.osint_data, data);
        
        Ok(())
    }
    
    /// Ensure the collector is initialized
    async fn ensure_initialized(&self) -> Result<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            // Double-check locking pattern
            if !self.initialized.load(Ordering::SeqCst) {
                self.initialize().await?;
            }
        }
        Ok(())
    }
    
    /// Merge OSINT data from a source into the combined data
    fn merge_osint_data(&self, target_data: &mut OsintData, source_data: OsintData) {
        // Merge company info if not already set
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
        
        // Merge discovered subdomains
        for subdomain in source_data.discovered_subdomains {
            target_data.discovered_subdomains.insert(subdomain);
        }
        
        // Merge employees
        target_data.employees.extend(source_data.employees);
        
        // Merge data leaks
        target_data.data_leaks.extend(source_data.data_leaks);
        
        // Merge DNS records
        for (domain, records) in source_data.dns_records {
            target_data.dns_records.entry(domain)
                .or_insert_with(Vec::new)
                .extend(records);
        }
        
        // Merge WHOIS data if not already set
        if source_data.whois_data.is_some() && target_data.whois_data.is_none() {
            target_data.whois_data = source_data.whois_data;
        }
        
        // Merge certificates
        target_data.certificates.extend(source_data.certificates);
    }
    
    /// List all available OSINT sources
    pub async fn list_sources(&self) -> Result<Vec<String>> {
        // Ensure initialization
        self.ensure_initialized().await?;
        
        let sources = self.sources.lock().await;
        let source_names = sources.keys().cloned().collect();
        Ok(source_names)
    }
    
    /// Register a custom OSINT source
    pub async fn register_source(&self, name: &str, source: Box<dyn OsintSource>) -> Result<()> {
        // Ensure initialization
        self.ensure_initialized().await?;
        
        let mut sources = self.sources.lock().await;
        
        if sources.contains_key(name) {
            warn!("Overwriting existing OSINT source: {}", name);
        }
        
        sources.insert(name.to_string(), source);
        debug!("Registered OSINT source: {}", name);
        
        Ok(())
    }
}

/// Trait for OSINT data sources
#[async_trait]
pub trait OsintSource: Send + Sync {
    /// Get the name of the source
    fn name(&self) -> &str;
    
    /// Get a description of the source
    fn description(&self) -> &str;
    
    /// Collect OSINT data for a target
    async fn collect(&self, target: &TargetData) -> Result<OsintData>;
}

// ---------------------------------------------------------------
// OSINT Source Implementations
// ---------------------------------------------------------------

/// DNS information source
pub struct DnsOsintSource {
    config: AppConfig,
    client: OnceCell<reqwest::Client>,
}

impl DnsOsintSource {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }
    
    // Lazy initialize the HTTP client
    async fn get_client(&self) -> Result<&reqwest::Client> {
        self.client.get_or_try_init(|| {
            Ok(reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?)
        })
    }
    
    async fn query_dns_records(&self, _domain: &str) -> Result<Vec<DnsRecord>> {
        // This would normally use a DNS library or external tool
        // For now, we'll simulate some basic records
        
        // In a real implementation, you would make actual DNS queries
        
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
    
    async fn collect(&self, target: &TargetData) -> Result<OsintData> {
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
    config: AppConfig,
    client: OnceCell<reqwest::Client>,
}

impl WhoisOsintSource {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }
    
    // Lazy initialize the HTTP client
    async fn get_client(&self) -> Result<&reqwest::Client> {
        self.client.get_or_try_init(|| {
            Ok(reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?)
        })
    }
    
    async fn query_whois(&self, _domain: &str) -> Result<WhoisData> {
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
    
    async fn collect(&self, target: &TargetData) -> Result<OsintData> {
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
    config: AppConfig,
    client: OnceCell<reqwest::Client>,
}

impl SslCertificateOsintSource {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }
    
    // Lazy initialize the HTTP client
    async fn get_client(&self) -> Result<&reqwest::Client> {
        self.client.get_or_try_init(|| {
            Ok(reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?)
        })
    }
    
    async fn query_ssl_cert(&self, domain: &str) -> Result<CertificateInfo> {
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
    
    async fn collect(&self, target: &TargetData) -> Result<OsintData> {
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
    config: AppConfig,
    client: OnceCell<reqwest::Client>,
}

impl CtLogOsintSource {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }
    
    // Lazy initialize the HTTP client
    async fn get_client(&self) -> Result<&reqwest::Client> {
        self.client.get_or_try_init(|| {
            Ok(reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?)
        })
    }
    
    async fn query_ct_logs(&self, domain: &str) -> Result<Vec<String>> {
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
    
    async fn collect(&self, target: &TargetData) -> Result<OsintData> {
        let mut osint_data = OsintData::default();
        
        // Query CT logs for primary domain
        if let Some(domain) = &target.primary_domain {
            match self.query_ct_logs(domain).await {
                Ok(subdomains) => {
                    for subdomain in subdomains {
                        osint_data.discovered_subdomains.insert(subdomain);
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