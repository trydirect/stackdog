//! ML module
//!
//! Machine learning for anomaly detection using Candle

pub mod anomaly;
pub mod candle_backend;
pub mod features;
pub mod models;
pub mod scorer;

/// Marker struct for module tests
pub struct MlMarker;
