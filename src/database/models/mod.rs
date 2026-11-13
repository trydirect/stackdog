//! Database models

use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};

/// Structured alert metadata stored in the database as JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl AlertMetadata {
    pub fn with_container_id(mut self, container_id: impl Into<String>) -> Self {
        self.container_id = Some(container_id.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.container_id.is_none()
            && self.source.is_none()
            && self.reason.is_none()
            && self.extra.is_empty()
    }

    pub fn from_storage(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        serde_json::from_str(trimmed)
            .ok()
            .or_else(|| Self::from_legacy_pairs(trimmed))
            .or_else(|| Some(Self::default().with_reason(trimmed.to_string())))
    }

    fn from_legacy_pairs(raw: &str) -> Option<Self> {
        let mut metadata = Self::default();
        let mut found_pair = false;

        for part in raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };

            found_pair = true;
            let value = value.trim().to_string();
            match key.trim() {
                "container_id" => metadata.container_id = Some(value),
                "source" => metadata.source = Some(value),
                "reason" => metadata.reason = Some(value),
                other => {
                    metadata.extra.insert(other.to_string(), value);
                }
            }
        }

        found_pair.then_some(metadata)
    }
}

/// Alert model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub status: AlertStatus,
    pub timestamp: String,
    pub metadata: Option<AlertMetadata>,
}

impl Alert {
    pub fn new(alert_type: AlertType, severity: AlertSeverity, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            alert_type,
            severity,
            message: message.into(),
            status: AlertStatus::New,
            timestamp: Utc::now().to_rfc3339(),
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: AlertMetadata) -> Self {
        self.metadata = (!metadata.is_empty()).then_some(metadata);
        self
    }
}

/// Threat model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub threat_type: String,
    pub severity: String,
    pub score: i32,
    pub source: String,
    pub timestamp: String,
    pub status: String,
    pub metadata: Option<String>,
}

/// Container cache model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCache {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub risk_score: i32,
    pub security_state: String,
    pub threats_count: i32,
}
