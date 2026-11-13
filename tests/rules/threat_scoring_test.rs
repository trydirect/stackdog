//! Threat scoring tests
//!
//! Tests for threat scoring engine

use stackdog::rules::threat_scorer::{ThreatScorer, ThreatScore, ScoringConfig};
use stackdog::rules::result::Severity;
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::{Utc, Duration};

#[test]
fn test_threat_score_creation() {
    let score = ThreatScore::new(75);
    assert_eq!(score.value(), 75);
}

#[test]
fn test_threat_score_severity_conversion() {
    let score_low = ThreatScore::new(20);
    assert_eq!(score_low.severity(), Severity::Low);
    
    let score_medium = ThreatScore::new(50);
    assert_eq!(score_medium.severity(), Severity::Medium);
    
    let score_high = ThreatScore::new(80);
    assert_eq!(score_high.severity(), Severity::High);
    
    let score_critical = ThreatScore::new(95);
    assert_eq!(score_critical.severity(), Severity::Critical);
}

#[test]
fn test_cumulative_scoring() {
    let scorer = ThreatScorer::new();
    
    // Add multiple matches
    let mut total_score = 0;
    total_score += scorer.calculate_score(&SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, Utc::now(),
    ))).value();
    
    total_score += scorer.calculate_score(&SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Mount, Utc::now(),
    ))).value();
    
    // Cumulative score should be higher than individual
    assert!(total_score > 50);
}

#[test]
fn test_time_decay_scoring() {
    let config = ScoringConfig::default().with_time_decay(true);
    let scorer = ThreatScorer::with_config(config);
    
    let now = Utc::now();
    
    // Recent event should have higher score
    let recent_event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, now,
    ));
    
    // Old event should have lower score (if decay applied)
    let old_event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, now - Duration::hours(1),
    ));
    
    let recent_score = scorer.calculate_score(&recent_event);
    let old_score = scorer.calculate_score(&old_event);
    
    // With time decay, recent should be >= old
    assert!(recent_score.value() >= old_score.value());
}

#[test]
fn test_threshold_alerting() {
    let scorer = ThreatScorer::new();
    
    // Low severity event
    let low_event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Openat, Utc::now(),
    ));
    
    let score = scorer.calculate_score(&low_event);
    
    // Check threshold methods
    assert!(!score.exceeds_threshold(80));
    assert!(score.exceeds_threshold(20));
}

#[test]
fn test_severity_aggregation() {
    use stackdog::rules::threat_scorer::aggregate_severities;
    
    let severities = vec![
        Severity::Low,
        Severity::Medium,
        Severity::High,
    ];
    
    let aggregate = aggregate_severities(&severities);
    
    // Should return highest severity
    assert_eq!(aggregate, Severity::High);
}

#[test]
fn test_severity_aggregation_empty() {
    use stackdog::rules::threat_scorer::aggregate_severities;
    
    let severities: Vec<Severity> = vec![];
    let aggregate = aggregate_severities(&severities);
    
    // Empty should return Info
    assert_eq!(aggregate, Severity::Info);
}

#[test]
fn test_threat_score_display() {
    let score = ThreatScore::new(75);
    let display = format!("{}", score);
    
    assert!(display.contains("75"));
}

#[test]
fn test_scoring_config_builder() {
    let config = ScoringConfig::default()
        .with_time_decay(true)
        .with_base_score(50)
        .with_multiplier(2.0);
    
    assert!(config.time_decay_enabled());
    assert_eq!(config.base_score(), 50);
}

#[test]
fn test_threat_score_threshold_checks() {
    let score = ThreatScore::new(75);
    
    assert!(score.is_high_or_higher());
    assert!(!score.is_critical());
    
    let critical_score = ThreatScore::new(95);
    assert!(critical_score.is_critical());
}

#[test]
fn test_scorer_with_custom_config() {
    let config = ScoringConfig::default()
        .with_base_score(100)
        .with_multiplier(0.5);
    
    let scorer = ThreatScorer::with_config(config);
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let score = scorer.calculate_score(&event);
    
    // Score should be calculated with custom config
    assert!(score.value() > 0);
}
