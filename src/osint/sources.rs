// src/osint/sources.rs
use std::collections::HashMap;
use async_trait::async_trait;
use tracing::warn;
use reqwest::Client;

use crate::core::target::model::{TargetData, OsintData, DnsRecord, WhoisData, CertificateInfo};
use crate::error::BBHuntResult;

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
}

/// DNS information source
pub struct DnsOsintSource {
    client: Client,
}

impl DnsOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
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
}

impl WhoisOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
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
}

impl SslCertificateOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
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
}

impl CtLogOsintSource {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
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