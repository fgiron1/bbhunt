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
    TargetData, 
    TargetManager, 
    TargetSpecifier,
};
pub use resource::ResourceManager;