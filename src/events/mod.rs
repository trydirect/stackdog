//! Events module
//!
//! Contains all security event types, conversions, validation, and streaming

pub mod security;
pub mod stream;
pub mod syscall;
pub mod validation;

/// Marker struct for module tests
pub struct EventsMarker;
