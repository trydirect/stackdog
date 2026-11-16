//! Alert manager tests
//!
//! Tests for alert management functionality

use stackdog::alerting::alert::{AlertSeverity, AlertType};
use stackdog::alerting::manager::AlertManager;
use stackdog::rules::result::Severity;

#[test]
fn test_alert_manager_creation() {
    let manager = AlertManager::new();
    assert!(manager.is_ok());
}

#[test]
fn test_alert_generation_from_rule() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Generate alert from rule match
    let alert = manager.generate_alert(
        AlertType::RuleViolation,
        Severity::High,
        "Rule violation detected".to_string(),
        None,
    );

    assert!(alert.is_ok());
    assert_eq!(manager.alert_count(), 1);
}

#[test]
fn test_alert_generation_from_threshold() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Generate alert when threshold exceeded
    let alert = manager.generate_alert(
        AlertType::ThresholdExceeded,
        Severity::Medium,
        "Threat score exceeded threshold".to_string(),
        None,
    );

    assert!(alert.is_ok());
}

#[test]
fn test_alert_storage() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Add multiple alerts
    for i in 0..5 {
        let _ = manager.generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            format!("Alert {}", i),
            None,
        );
    }

    assert_eq!(manager.alert_count(), 5);
}

#[test]
fn test_alert_querying() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Add alerts with different severities
    let _ = manager.generate_alert(
        AlertType::ThreatDetected,
        Severity::High,
        "High alert".to_string(),
        None,
    );

    let _ = manager.generate_alert(
        AlertType::ThreatDetected,
        Severity::Low,
        "Low alert".to_string(),
        None,
    );

    // Query by severity
    let high_alerts = manager.get_alerts_by_severity(AlertSeverity::High);
    assert_eq!(high_alerts.len(), 1);

    // Get all alerts
    let all_alerts = manager.get_all_alerts();
    assert_eq!(all_alerts.len(), 2);
}

#[test]
fn test_alert_acknowledgment() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    let alert = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let alert_id = alert.id();

    // Acknowledge the alert
    let result = manager.acknowledge_alert(alert_id);
    assert!(result.is_ok());

    // Verify status changed
    let updated = manager.get_alert(alert_id);
    assert!(updated.is_some());
}

#[test]
fn test_alert_resolution() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    let alert = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let alert_id = alert.id();

    // First acknowledge, then resolve
    let _ = manager.acknowledge_alert(alert_id);
    let result = manager.resolve_alert(alert_id, "Issue resolved".to_string());

    assert!(result.is_ok());
}

#[test]
fn test_alert_retrieval_by_id() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    let alert = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let alert_id = alert.id();

    // Retrieve by ID
    let retrieved = manager.get_alert(alert_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id(), alert_id);
}

#[test]
fn test_alert_retrieval_not_found() {
    let manager = AlertManager::new().expect("Failed to create manager");

    // Try to get non-existent alert
    let retrieved = manager.get_alert("non-existent-id");
    assert!(retrieved.is_none());
}

#[test]
fn test_alert_count_by_status() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Create alerts and change some status
    let alert1 = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test 1".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let _alert2 = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test 2".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let id1 = alert1.id();
    let _ = manager.acknowledge_alert(id1);

    let stats = manager.get_stats();
    assert!(stats.new_count >= 1); // alert2 should be new
    assert!(stats.acknowledged_count >= 1); // alert1 should be acked
}

#[test]
fn test_clear_resolved_alerts() {
    let mut manager = AlertManager::new().expect("Failed to create manager");

    // Create and resolve alert
    let alert = manager
        .generate_alert(
            AlertType::ThreatDetected,
            Severity::High,
            "Test".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    let alert_id = alert.id();
    let _ = manager.acknowledge_alert(alert_id);
    let _ = manager.resolve_alert(alert_id, "Resolved".to_string());

    // Clear resolved
    let cleared = manager.clear_resolved_alerts();
    assert!(cleared >= 1);

    // Alert should be gone
    assert_eq!(manager.alert_count(), 0);
}
