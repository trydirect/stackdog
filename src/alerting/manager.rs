//! Alert manager
//!
//! Manages alert generation, storage, and lifecycle

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::alerting::alert::{Alert, AlertSeverity, AlertStatus, AlertType};
use crate::rules::result::Severity;

/// Alert statistics
#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub total_count: u64,
    pub new_count: u64,
    pub acknowledged_count: u64,
    pub resolved_count: u64,
    pub false_positive_count: u64,
}

/// Alert manager
pub struct AlertManager {
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    stats: Arc<RwLock<AlertStats>>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AlertStats::default())),
        })
    }

    /// Generate an alert
    pub fn generate_alert(
        &mut self,
        alert_type: AlertType,
        severity: Severity,
        message: String,
        source_event: Option<crate::events::security::SecurityEvent>,
    ) -> Result<Alert> {
        let mut alert = Alert::new(alert_type, severity_to_alert_severity(severity), message);

        if let Some(event) = source_event {
            alert.set_source_event(event);
        }

        // Store alert
        let alert_id = alert.id().to_string();
        {
            let mut alerts = self.alerts.write().unwrap();
            alerts.insert(alert_id.clone(), alert.clone());
        }

        // Update stats
        self.update_stats_new();

        Ok(alert)
    }

    /// Get alert by ID
    pub fn get_alert(&self, alert_id: &str) -> Option<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts.get(alert_id).cloned()
    }

    /// Get all alerts
    pub fn get_all_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts.values().cloned().collect()
    }

    /// Get alerts by severity
    pub fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts
            .values()
            .filter(|a| a.severity() == severity)
            .cloned()
            .collect()
    }

    /// Get alerts by status
    pub fn get_alerts_by_status(&self, status: AlertStatus) -> Vec<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts
            .values()
            .filter(|a| a.status() == status)
            .cloned()
            .collect()
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(&mut self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().unwrap();

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.acknowledge();
            self.update_stats_ack();
            Ok(())
        } else {
            anyhow::bail!("Alert not found: {}", alert_id)
        }
    }

    /// Resolve an alert
    pub fn resolve_alert(&mut self, alert_id: &str, note: String) -> Result<()> {
        let mut alerts = self.alerts.write().unwrap();

        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.resolve();
            alert.set_resolution_note(note);
            self.update_stats_resolve();
            Ok(())
        } else {
            anyhow::bail!("Alert not found: {}", alert_id)
        }
    }

    /// Get alert count
    pub fn alert_count(&self) -> usize {
        let alerts = self.alerts.read().unwrap();
        alerts.len()
    }

    /// Get statistics
    pub fn get_stats(&self) -> AlertStats {
        let _stats = self.stats.read().unwrap();

        // Calculate current counts from alerts
        let alerts = self.alerts.read().unwrap();
        let mut new_count = 0;
        let mut ack_count = 0;
        let mut resolved_count = 0;
        let mut fp_count = 0;

        for alert in alerts.values() {
            match alert.status() {
                AlertStatus::New => new_count += 1,
                AlertStatus::Acknowledged => ack_count += 1,
                AlertStatus::Resolved => resolved_count += 1,
                AlertStatus::FalsePositive => fp_count += 1,
            }
        }

        AlertStats {
            total_count: alerts.len() as u64,
            new_count,
            acknowledged_count: ack_count,
            resolved_count,
            false_positive_count: fp_count,
        }
    }

    /// Clear resolved alerts
    pub fn clear_resolved_alerts(&mut self) -> usize {
        let mut alerts = self.alerts.write().unwrap();
        let initial_count = alerts.len();

        alerts.retain(|_, alert| alert.status() != AlertStatus::Resolved);

        initial_count - alerts.len()
    }

    /// Update stats for new alert
    fn update_stats_new(&self) {
        let mut stats = self.stats.write().unwrap();
        stats.total_count += 1;
        stats.new_count += 1;
    }

    /// Update stats for acknowledgment
    fn update_stats_ack(&self) {
        let mut stats = self.stats.write().unwrap();
        if stats.new_count > 0 {
            stats.new_count -= 1;
            stats.acknowledged_count += 1;
        }
    }

    /// Update stats for resolution
    fn update_stats_resolve(&self) {
        let mut stats = self.stats.write().unwrap();
        if stats.acknowledged_count > 0 {
            stats.acknowledged_count -= 1;
            stats.resolved_count += 1;
        } else if stats.new_count > 0 {
            stats.new_count -= 1;
            stats.resolved_count += 1;
        }
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new().expect("Failed to create AlertManager")
    }
}

/// Convert rules Severity to alert AlertSeverity
fn severity_to_alert_severity(severity: Severity) -> AlertSeverity {
    match severity {
        Severity::Info => AlertSeverity::Info,
        Severity::Low => AlertSeverity::Low,
        Severity::Medium => AlertSeverity::Medium,
        Severity::High => AlertSeverity::High,
        Severity::Critical => AlertSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let manager = AlertManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_alert_generation() {
        let mut manager = AlertManager::new().expect("Failed to create manager");

        let alert = manager.generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test".to_string(),
            None,
        );

        assert!(alert.is_ok());
        assert_eq!(manager.alert_count(), 1);
    }
}
