//! Container API response types

use serde::{Deserialize, Serialize};

/// Container response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResponse {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub security_status: ContainerSecurityStatus,
    pub risk_score: u32,
    pub network_activity: NetworkActivity,
    pub created_at: String,
}

/// Container security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityStatus {
    pub state: String,
    pub threats: u32,
    pub vulnerabilities: Option<u32>,
    pub last_scan: Option<String>,
}

/// Network activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub inbound_connections: Option<u32>,
    pub outbound_connections: Option<u32>,
    pub blocked_connections: Option<u32>,
    pub received_bytes: Option<u64>,
    pub transmitted_bytes: Option<u64>,
    pub received_packets: Option<u64>,
    pub transmitted_packets: Option<u64>,
    pub suspicious_activity: bool,
}

/// Quarantine request
#[derive(Debug, Clone, Deserialize)]
pub struct QuarantineRequest {
    pub reason: String,
}
