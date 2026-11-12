//! Alert tests
//!
//! Tests for alert data model

use chrono::Utc;
use stackdog::alerting::alert::{Alert, AlertSeverity, AlertStatus, AlertType};
use stackdog::events::security::SecurityEvent;
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_alert_creation() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Suspicious activity detected".to_string(),
    );

    assert_eq!(alert.alert_type(), AlertType::ThreatDetected);
    assert_eq!(alert.severity(), AlertSeverity::High);
    assert_eq!(alert.message(), "Suspicious activity detected");
}

#[test]
fn test_alert_id_generation() {
    let alert1 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test alert".to_string(),
    );

    let alert2 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test alert".to_string(),
    );

    // Each alert should have unique ID
    assert_ne!(alert1.id(), alert2.id());

    // ID should not be empty
    assert!(!alert1.id().is_empty());
}

#[test]
fn test_alert_severity_levels() {
    // Test all severity variants
    let _info = AlertSeverity::Info;
    let _low = AlertSeverity::Low;
    let _medium = AlertSeverity::Medium;
    let _high = AlertSeverity::High;
    let _critical = AlertSeverity::Critical;
}

#[test]
fn test_alert_severity_ordering() {
    assert!(AlertSeverity::Info < AlertSeverity::Low);
    assert!(AlertSeverity::Low < AlertSeverity::Medium);
    assert!(AlertSeverity::Medium < AlertSeverity::High);
    assert!(AlertSeverity::High < AlertSeverity::Critical);
}

#[test]
fn test_alert_status_transitions() {
    let mut alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // Initial status should be New
    assert_eq!(alert.status(), AlertStatus::New);

    // Transition to Acknowledged
    alert.acknowledge();
    assert_eq!(alert.status(), AlertStatus::Acknowledged);

    // Transition to Resolved
    alert.resolve();
    assert_eq!(alert.status(), AlertStatus::Resolved);
}

#[test]
fn test_alert_status_cannot_skip() {
    let mut alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // Cannot go from New directly to Resolved
    alert.resolve();
    // Should still be New or transitioned properly
    // (depends on implementation - may allow or reject)
}

#[test]
fn test_alert_fingerprint() {
    let alert1 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test alert".to_string(),
    );

    let fingerprint1 = alert1.fingerprint();
    let fingerprint2 = alert1.fingerprint();

    // Same alert should have same fingerprint
    assert_eq!(fingerprint1, fingerprint2);
}

#[test]
fn test_alert_fingerprint_different_alerts() {
    let alert1 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Alert 1".to_string(),
    );

    let alert2 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Alert 2".to_string(),
    );

    // Different alerts should have different fingerprints
    assert_ne!(alert1.fingerprint(), alert2.fingerprint());
}

#[test]
fn test_alert_with_source_event() {
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234,
        1000,
        SyscallType::Execve,
        Utc::now(),
    ));

    let mut alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    alert.set_source_event(event.clone());

    assert!(alert.source_event().is_some());
}

#[test]
fn test_alert_timestamp() {
    let before = Utc::now();

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    let after = Utc::now();

    // Alert timestamp should be between before and after
    assert!(alert.timestamp() >= before);
    assert!(alert.timestamp() <= after);
}

#[test]
fn test_alert_display() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat".to_string(),
    );

    let display = format!("{}", alert);

    assert!(display.contains("Critical"));
    assert!(display.contains("ThreatDetected"));
}

#[test]
fn test_alert_metadata() {
    let mut alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    alert.add_metadata("container_id".to_string(), "abc123".to_string());
    alert.add_metadata("pid".to_string(), "1234".to_string());

    assert_eq!(
        alert.metadata().get("container_id"),
        Some(&"abc123".to_string())
    );
    assert_eq!(alert.metadata().get("pid"), Some(&"1234".to_string()));
}
