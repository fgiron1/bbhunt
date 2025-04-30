pub mod generator;
pub mod model;
pub mod formats;
pub mod format;

pub use generator::ReportManager;
pub use model::{
    Report, 
    ReportSummary, 
    Finding, 
    Evidence, 
    RequestResponse, 
    Severity, 
    Reference, 
    ReferenceType
};
pub use format::{
    ReportFormat, 
    ReportGenerator, 
    format_to_extension, 
    extension_to_format
};