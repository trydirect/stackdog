//! Deduplication tests
//!
//! Tests for alert deduplication functionality

use stackdog::alerting::alert::{Alert, AlertSeverity, AlertType};
use stackdog::alerting::dedup::{AlertDeduplicator, DedupConfig};

#[test]
fn test_deduplication_fingerprint() {
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

    let dedup = AlertDeduplicator::new(DedupConfig::default());

    let fp1 = dedup.calculate_fingerprint(&alert1);
    let fp2 = dedup.calculate_fingerprint(&alert2);

    // Same alert content should produce same fingerprint
    assert_eq!(fp1, fp2);
}

#[test]
fn test_deduplication_fingerprint_different_content() {
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

    let dedup = AlertDeduplicator::new(DedupConfig::default());

    let fp1 = dedup.calculate_fingerprint(&alert1);
    let fp2 = dedup.calculate_fingerprint(&alert2);

    // Different content should produce different fingerprint
    assert_ne!(fp1, fp2);
}

#[test]
fn test_deduplication_time_window() {
    let config = DedupConfig::default().with_window_seconds(60);
    let mut dedup = AlertDeduplicator::new(config);

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // First alert should not be duplicate
    assert!(!dedup.is_duplicate(&alert));

    // Same alert within window should be duplicate
    assert!(dedup.is_duplicate(&alert));
}

#[test]
fn test_deduplication_time_window_expired() {
    // Very short window
    let config = DedupConfig::default().with_window_seconds(1);
    let mut dedup = AlertDeduplicator::new(config);

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // First alert should not be duplicate
    assert!(!dedup.is_duplicate(&alert));

    // Wait for window to expire
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Same alert after window should not be duplicate
    assert!(!dedup.is_duplicate(&alert));
}

#[test]
fn test_deduplication_aggregation() {
    let config = DedupConfig::default()
        .with_window_seconds(60)
        .with_aggregation(true);

    let mut dedup = AlertDeduplicator::new(config);

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // First alert
    let result1 = dedup.check(&alert);
    assert!(!result1.is_duplicate);
    assert_eq!(result1.count, 1);

    // Duplicate alert (should be aggregated)
    let result2 = dedup.check(&alert);
    assert!(result2.is_duplicate);
    assert_eq!(result2.count, 2);
}

#[test]
fn test_deduplication_disabled() {
    let config = DedupConfig::default().with_enabled(false);
    let mut dedup = AlertDeduplicator::new(config);

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // Deduplication disabled - should never be duplicate
    assert!(!dedup.is_duplicate(&alert));
    assert!(!dedup.is_duplicate(&alert));
}

#[test]
fn test_dedup_config_builder() {
    let config = DedupConfig::default()
        .with_enabled(true)
        .with_window_seconds(120)
        .with_aggregation(true);

    assert!(config.enabled());
    assert_eq!(config.window_seconds(), 120);
    assert!(config.aggregation_enabled());
}

#[test]
fn test_fingerprint_display() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    let dedup = AlertDeduplicator::new(DedupConfig::default());
    let fp = dedup.calculate_fingerprint(&alert);

    let display = format!("{}", fp);

    // Fingerprint should be non-empty string
    assert!(!display.is_empty());
}

#[test]
fn test_deduplication_different_types() {
    let dedup = AlertDeduplicator::new(DedupConfig::default());

    let alert1 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    let alert2 = Alert::new(
        AlertType::RuleViolation,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // Different types should have different fingerprints
    let fp1 = dedup.calculate_fingerprint(&alert1);
    let fp2 = dedup.calculate_fingerprint(&alert2);

    assert_ne!(fp1, fp2);
}

#[test]
fn test_deduplication_different_severities() {
    let dedup = AlertDeduplicator::new(DedupConfig::default());

    let alert1 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    let alert2 = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Low,
        "Test".to_string(),
    );

    // Different severities should have different fingerprints
    let fp1 = dedup.calculate_fingerprint(&alert1);
    let fp2 = dedup.calculate_fingerprint(&alert2);

    assert_ne!(fp1, fp2);
}

#[test]
fn test_dedup_stats() {
    let mut dedup = AlertDeduplicator::new(DedupConfig::default());

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test".to_string(),
    );

    // Generate some duplicates
    let _ = dedup.check(&alert);
    let _ = dedup.check(&alert);
    let _ = dedup.check(&alert);

    let stats = dedup.get_stats();

    assert!(stats.total_checked >= 3);
    assert!(stats.duplicates_found >= 2);
}
