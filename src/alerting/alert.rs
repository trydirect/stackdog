//! Alert data model
//!
//! Defines alert structures for security notifications

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::security::SecurityEvent;

/// Alert types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    ThreatDetected,
    AnomalyDetected,
    RuleViolation,
    ThresholdExceeded,
    QuarantineApplied,
    SystemEvent,
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertType::ThreatDetected => write!(f, "ThreatDetected"),
            AlertType::AnomalyDetected => write!(f, "AnomalyDetected"),
            AlertType::RuleViolation => write!(f, "RuleViolation"),
            AlertType::ThresholdExceeded => write!(f, "ThresholdExceeded"),
            AlertType::QuarantineApplied => write!(f, "QuarantineApplied"),
            AlertType::SystemEvent => write!(f, "SystemEvent"),
        }
    }
}

impl std::str::FromStr for AlertType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ThreatDetected" => Ok(Self::ThreatDetected),
            "AnomalyDetected" => Ok(Self::AnomalyDetected),
            "RuleViolation" => Ok(Self::RuleViolation),
            "ThresholdExceeded" => Ok(Self::ThresholdExceeded),
            "QuarantineApplied" => Ok(Self::QuarantineApplied),
            "SystemEvent" => Ok(Self::SystemEvent),
            _ => Err(format!("unknown alert type: {value}")),
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info = 0,
    Low = 20,
    Medium = 40,
    High = 70,
    Critical = 90,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "Info"),
            AlertSeverity::Low => write!(f, "Low"),
            AlertSeverity::Medium => write!(f, "Medium"),
            AlertSeverity::High => write!(f, "High"),
            AlertSeverity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for AlertSeverity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Info" => Ok(Self::Info),
            "Low" => Ok(Self::Low),
            "Medium" => Ok(Self::Medium),
            "High" => Ok(Self::High),
            "Critical" => Ok(Self::Critical),
            _ => Err(format!("unknown alert severity: {value}")),
        }
    }
}

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Acknowledged,
    Resolved,
    FalsePositive,
}

impl std::fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertStatus::New => write!(f, "New"),
            AlertStatus::Acknowledged => write!(f, "Acknowledged"),
            AlertStatus::Resolved => write!(f, "Resolved"),
            AlertStatus::FalsePositive => write!(f, "FalsePositive"),
        }
    }
}

impl std::str::FromStr for AlertStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "New" => Ok(Self::New),
            "Acknowledged" => Ok(Self::Acknowledged),
            "Resolved" => Ok(Self::Resolved),
            "FalsePositive" => Ok(Self::FalsePositive),
            _ => Err(format!("unknown alert status: {value}")),
        }
    }
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    id: String,
    alert_type: AlertType,
    severity: AlertSeverity,
    message: String,
    status: AlertStatus,
    timestamp: DateTime<Utc>,
    source_event: Option<SecurityEvent>,
    metadata: std::collections::HashMap<String, String>,
    resolved_at: Option<DateTime<Utc>>,
    resolution_note: Option<String>,
}

impl Alert {
    /// Create a new alert
    pub fn new(alert_type: AlertType, severity: AlertSeverity, message: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            alert_type,
            severity,
            message,
            status: AlertStatus::New,
            timestamp: Utc::now(),
            source_event: None,
            metadata: std::collections::HashMap::new(),
            resolved_at: None,
            resolution_note: None,
        }
    }

    /// Get alert ID
    /// Keep an existing identity instead of the generated one.
    ///
    /// Used when replaying a stored alert through the notification channels: a
    /// fresh id would make the link in the message point at nothing.
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get alert type
    pub fn alert_type(&self) -> AlertType {
        self.alert_type
    }

    /// Get severity
    pub fn severity(&self) -> AlertSeverity {
        self.severity
    }

    /// Get message
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get status
    pub fn status(&self) -> AlertStatus {
        self.status
    }

    /// Get timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Get source event
    pub fn source_event(&self) -> Option<&SecurityEvent> {
        self.source_event.as_ref()
    }

    /// Set source event
    pub fn set_source_event(&mut self, event: SecurityEvent) {
        self.source_event = Some(event);
    }

    /// Get metadata
    pub fn metadata(&self) -> &std::collections::HashMap<String, String> {
        &self.metadata
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Acknowledge the alert
    pub fn acknowledge(&mut self) {
        if self.status == AlertStatus::New {
            self.status = AlertStatus::Acknowledged;
        }
    }

    /// Resolve the alert
    pub fn resolve(&mut self) {
        if self.status == AlertStatus::Acknowledged || self.status == AlertStatus::New {
            self.status = AlertStatus::Resolved;
            self.resolved_at = Some(Utc::now());
        }
    }

    /// Set resolution note
    pub fn set_resolution_note(&mut self, note: String) {
        self.resolution_note = Some(note);
    }

    /// Calculate fingerprint for deduplication
    pub fn fingerprint(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.alert_type.hash(&mut hasher);
        self.severity.hash(&mut hasher);
        self.message.hash(&mut hasher);

        format!("{:x}", hasher.finish())
    }
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} - {} ({})",
            self.severity, self.alert_type, self.message, self.status
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_type_display() {
        assert_eq!(format!("{}", AlertType::ThreatDetected), "ThreatDetected");
    }

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(format!("{}", AlertSeverity::High), "High");
    }

    #[test]
    fn test_alert_status_display() {
        assert_eq!(format!("{}", AlertStatus::New), "New");
    }
}
