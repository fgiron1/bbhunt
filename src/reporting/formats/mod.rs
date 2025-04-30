pub mod json;
pub mod markdown;
pub mod html;

pub use crate::reporting::format::{
    ReportFormat, 
    ReportGenerator, 
    format_to_extension, 
    extension_to_format
};