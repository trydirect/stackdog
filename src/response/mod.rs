//! Response module
//!
//! Automated threat response actions

pub mod actions;
#[cfg(target_os = "linux")]
pub mod pipeline;

/// Marker struct for module tests
pub struct ResponseMarker;

#[cfg(target_os = "linux")]
pub use pipeline::{ActionPipeline, PipelineAction, PipelinePlan};
