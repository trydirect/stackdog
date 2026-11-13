//! Detection statistics tests
//!
//! Tests for detection metrics tracking

use stackdog::rules::stats::{DetectionStats, StatsTracker};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::Utc;

#[test]
fn test_detection_stats_creation() {
    let stats = DetectionStats::new();
    assert_eq!(stats.events_processed(), 0);
    assert_eq!(stats.signatures_matched(), 0);
}

#[test]
fn test_events_processed_count() {
    let mut stats = DetectionStats::new();
    
    stats.record_event();
    stats.record_event();
    stats.record_event();
    
    assert_eq!(stats.events_processed(), 3);
}

#[test]
fn test_signatures_matched_count() {
    let mut stats = DetectionStats::new();
    
    stats.record_match();
    stats.record_match();
    
    assert_eq!(stats.signatures_matched(), 2);
}

#[test]
fn test_detection_rate_calculation() {
    let mut stats = DetectionStats::new();
    
    // Record 10 events, 3 matches
    for _ in 0..10 {
        stats.record_event();
    }
    for _ in 0..3 {
        stats.record_match();
    }
    
    let rate = stats.detection_rate();
    
    // Should be 30%
    assert!((rate - 0.3).abs() < 0.01);
}

#[test]
fn test_detection_rate_zero_events() {
    let stats = DetectionStats::new();
    let rate = stats.detection_rate();
    
    // Should be 0 when no events
    assert_eq!(rate, 0.0);
}

#[test]
fn test_stats_tracker_creation() {
    let tracker = StatsTracker::new();
    assert!(tracker.is_ok());
}

#[test]
fn test_stats_tracker_record() {
    let mut tracker = StatsTracker::new().expect("Failed to create tracker");
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    tracker.record_event(&event, true);  // Match
    tracker.record_event(&event, false); // No match
    
    let stats = tracker.stats();
    assert_eq!(stats.events_processed(), 2);
    assert_eq!(stats.signatures_matched(), 1);
}

#[test]
fn test_stats_tracker_reset() {
    let mut tracker = StatsTracker::new().expect("Failed to create tracker");
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    tracker.record_event(&event, true);
    tracker.reset();
    
    let stats = tracker.stats();
    assert_eq!(stats.events_processed(), 0);
    assert_eq!(stats.signatures_matched(), 0);
}

#[test]
fn test_stats_display() {
    let mut stats = DetectionStats::new();
    
    for _ in 0..100 {
        stats.record_event();
    }
    for _ in 0..25 {
        stats.record_match();
    }
    
    let display = format!("{}", stats);
    
    assert!(display.contains("100"));
    assert!(display.contains("25"));
    assert!(display.contains("25.0%") || display.contains("0.25"));
}

#[test]
fn test_stats_clone() {
    let mut stats = DetectionStats::new();
    stats.record_event();
    stats.record_match();
    
    let cloned = stats.clone();
    
    assert_eq!(cloned.events_processed(), 1);
    assert_eq!(cloned.signatures_matched(), 1);
}

#[test]
fn test_detection_rate_100_percent() {
    let mut stats = DetectionStats::new();
    
    for _ in 0..5 {
        stats.record_event();
        stats.record_match();
    }
    
    let rate = stats.detection_rate();
    assert!((rate - 1.0).abs() < 0.01);
}

#[test]
fn test_stats_with_high_volume() {
    let mut stats = DetectionStats::new();
    
    // Simulate high volume
    for i in 0..1000 {
        stats.record_event();
        if i % 10 == 0 {
            stats.record_match();
        }
    }
    
    assert_eq!(stats.events_processed(), 1000);
    assert_eq!(stats.signatures_matched(), 100);
    
    let rate = stats.detection_rate();
    assert!((rate - 0.1).abs() < 0.01);
}
