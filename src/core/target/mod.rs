// src/core/target/mod.rs
pub mod model;
pub mod manager;

pub use model::{
    TargetData, TargetSpecifier, ContactInfo, OsintData, 
    CompanyInfo, AddressInfo, EmployeeInfo, DocumentInfo,
    DataLeakInfo, DnsRecord, WhoisData, WhoisContact, CertificateInfo
};
pub use manager::TargetManager;