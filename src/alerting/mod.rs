//! Alerting module
//!
//! Alert generation, management, and notifications

pub mod alert;
pub mod dedup;
pub mod manager;
pub mod notifications;
pub mod rules;

/// Marker struct for module tests
pub struct AlertingMarker;

// Re-export commonly used types
pub use alert::{Alert, AlertSeverity, AlertStatus, AlertType};
pub use dedup::{AlertDeduplicator, DedupConfig, DedupResult, Fingerprint};
pub use manager::{AlertManager, AlertStats};
pub use notifications::{NotificationChannel, NotificationConfig, NotificationResult};
pub use rules::AlertRule;
