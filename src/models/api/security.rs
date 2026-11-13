//! API response types

use serde::{Deserialize, Serialize};

/// Security status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusResponse {
    pub overall_score: u32,
    pub active_threats: u32,
    pub quarantined_containers: u32,
    pub alerts_new: u32,
    pub alerts_acknowledged: u32,
    pub last_updated: String,
}

impl SecurityStatusResponse {
    pub fn new() -> Self {
        Self::from_state(100, 0, 0, 0, 0)
    }

    pub fn from_state(
        overall_score: u32,
        active_threats: u32,
        quarantined_containers: u32,
        alerts_new: u32,
        alerts_acknowledged: u32,
    ) -> Self {
        Self {
            overall_score,
            active_threats,
            quarantined_containers,
            alerts_new,
            alerts_acknowledged,
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for SecurityStatusResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_status_from_state() {
        let status = SecurityStatusResponse::from_state(64, 2, 1, 3, 1);
        assert_eq!(status.active_threats, 2);
        assert_eq!(status.quarantined_containers, 1);
        assert_eq!(status.alerts_new, 3);
        assert_eq!(status.alerts_acknowledged, 1);
        assert_eq!(status.overall_score, 64);
    }
}
