pub mod plugin;
pub mod target;
pub mod resource;

pub use plugin::{
    Plugin, 
    PluginManager, 
    PluginMetadata, 
    PluginResult, 
    PluginStatus, 
    PluginCategory
};
pub use target::{
    Target, 
    TargetManager, 
    TargetSpecifier, 
    format_target_specifier
};
pub use resource::{
    ResourceCollector, 
    ResourceInfo,
};