pub mod json;
pub mod markdown;
pub mod html;

pub use super::formats::{ReportFormat, ReportGenerator, format_to_extension, extension_to_format};