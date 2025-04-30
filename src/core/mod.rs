mod plugin;
mod target;
mod resource;

pub use plugin::{Plugin, PluginManager, PluginMetadata, PluginResult, PluginStatus, PluginCategory};
pub use target::{Target, TargetManager, TargetSpecifier};
pub use resource::{ResourceManager, ResourceRequirements, ResourceUsage};