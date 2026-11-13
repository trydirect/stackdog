//! Threat API response types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Threat response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub id: String,
    pub r#type: String,
    pub severity: String,
    pub score: u32,
    pub source: String,
    pub timestamp: String,
    pub status: String,
}

/// Threat statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStatisticsResponse {
    pub total_threats: u32,
    pub by_severity: HashMap<String, u32>,
    pub by_type: HashMap<String, u32>,
    pub trend: String,
}

impl ThreatStatisticsResponse {
    pub fn new() -> Self {
        Self {
            total_threats: 0,
            by_severity: HashMap::new(),
            by_type: HashMap::new(),
            trend: "stable".to_string(),
        }
    }
}

impl Default for ThreatStatisticsResponse {
    fn default() -> Self {
        Self::new()
    }
}
