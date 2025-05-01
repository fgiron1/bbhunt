// src/core/target/model.rs
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use ipnetwork::IpNetwork;
use url::Url;

/// Centralized target data model that consolidates all possible information
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
    pub web_paths: HashMap<String, HashSet<String>>, // domain -> paths
    
    // Organization information
    pub organization_name: Option<String>,
    pub contacts: Vec<ContactInfo>,
    pub asn: Option<u32>,
    
    // Scope information
    pub in_scope: HashSet<TargetSpecifier>,
    pub out_of_scope: HashSet<TargetSpecifier>,
    
    // Custom data (for plugins to store arbitrary information)
    pub custom_data: HashMap<String, serde_json::Value>,
    
    // OSINT data
    pub osint: OsintData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum TargetSpecifier {
    Domain(String),
    Subdomain(String),
    IpAddress(IpAddr),
    IpRange(IpNetwork),
    UrlPattern(String),
    Regex(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub social_links: HashMap<String, String>, // platform -> URL
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsintData {
    pub company_info: Option<CompanyInfo>,
    pub social_profiles: HashMap<String, String>,
    pub email_addresses: HashSet<String>,
    pub documents: Vec<DocumentInfo>,
    pub subdomains: HashSet<String>,
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

impl TargetData {
    /// Create a new target data instance with basic information
    pub fn new(id: String, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description: None,
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
            web_paths: HashMap::new(),
            organization_name: None,
            contacts: Vec::new(),
            asn: None,
            in_scope: HashSet::new(),
            out_of_scope: HashSet::new(),
            custom_data: HashMap::new(),
            osint: OsintData::default(),
        }
    }

    /// Add a domain to the target
    pub fn add_domain(&mut self, domain: String) {
        self.domains.insert(domain.clone());
        self.in_scope.insert(TargetSpecifier::Domain(domain));
        self.updated_at = Utc::now();
    }

    /// Add a subdomain to the target
    pub fn add_subdomain(&mut self, subdomain: String) {
        self.subdomains.insert(subdomain.clone());
        self.in_scope.insert(TargetSpecifier::Subdomain(subdomain));
        self.updated_at = Utc::now();
    }

    /// Add an IP address to the target
    pub fn add_ip_address(&mut self, ip: IpAddr) {
        self.ip_addresses.insert(ip);
        self.in_scope.insert(TargetSpecifier::IpAddress(ip));
        self.updated_at = Utc::now();
    }

    /// Add an IP range to the target
    pub fn add_ip_range(&mut self, range: IpNetwork) {
        self.ip_ranges.insert(range);
        self.in_scope.insert(TargetSpecifier::IpRange(range));
        self.updated_at = Utc::now();
    }

    /// Add a URL to the target
    pub fn add_url(&mut self, url: Url) {
        self.urls.insert(url.to_string());
        self.updated_at = Utc::now();
    }

    /// Set OSINT data for the target
    pub fn set_osint_data(&mut self, osint: OsintData) {
        self.osint = osint;
        self.updated_at = Utc::now();
    }

    /// Store custom data from a plugin
    pub fn store_plugin_data(&mut self, plugin_name: &str, data: serde_json::Value) {
        self.custom_data.insert(plugin_name.to_string(), data);
        self.updated_at = Utc::now();
    }

    /// Get custom data from a plugin
    pub fn get_plugin_data(&self, plugin_name: &str) -> Option<&serde_json::Value> {
        self.custom_data.get(plugin_name)
    }
}