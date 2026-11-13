//! Signature matching tests
//!
//! Tests for advanced signature matching capabilities

use stackdog::rules::signature_matcher::{SignatureMatcher, PatternMatch, MatchResult};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::{Utc, Duration};

#[test]
fn test_single_event_signature_match() {
    let matcher = SignatureMatcher::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = matcher.match_single(&event);
    
    // Should match some signatures
    assert!(result.matches().len() > 0);
}

#[test]
fn test_multi_event_pattern_match() {
    let mut matcher = SignatureMatcher::new();
    
    // Create pattern: execve followed by connect
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Connect);
    
    matcher.add_pattern(pattern);
    
    // Create events
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now())),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Connect, Utc::now())),
    ];
    
    let result = matcher.match_sequence(&events);
    
    // Should match the pattern
    assert!(result.is_match());
}

#[test]
fn test_temporal_correlation_match() {
    let mut matcher = SignatureMatcher::new();
    
    // Create pattern with time window
    let now = Utc::now();
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Connect)
        .within_seconds(60);
    
    matcher.add_pattern(pattern);
    
    // Create events within time window
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Execve, now)),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Connect, now + Duration::seconds(30))),
    ];
    
    let result = matcher.match_sequence(&events);
    
    // Should match (within 60 seconds)
    assert!(result.is_match());
}

#[test]
fn test_temporal_correlation_no_match() {
    let mut matcher = SignatureMatcher::new();
    
    // Create pattern with short time window
    let now = Utc::now();
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Connect)
        .within_seconds(5);
    
    matcher.add_pattern(pattern);
    
    // Create events outside time window
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Execve, now)),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Connect, now + Duration::seconds(30))),
    ];
    
    let result = matcher.match_sequence(&events);
    
    // Should NOT match (outside 5 second window)
    assert!(!result.is_match());
}

#[test]
fn test_sequence_detection() {
    let mut matcher = SignatureMatcher::new();
    
    // Create 3-step pattern
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Openat)
        .then_syscall(SyscallType::Connect);
    
    matcher.add_pattern(pattern);
    
    // Create matching sequence
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now())),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Openat, Utc::now())),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Connect, Utc::now())),
    ];
    
    let result = matcher.match_sequence(&events);
    
    // Should match the 3-step pattern
    assert!(result.is_match());
}

#[test]
fn test_sequence_detection_wrong_order() {
    let mut matcher = SignatureMatcher::new();
    
    // Create pattern: execve -> openat -> connect
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Openat)
        .then_syscall(SyscallType::Connect);
    
    matcher.add_pattern(pattern);
    
    // Create events in wrong order
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Connect, Utc::now())),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Openat, Utc::now())),
        SecurityEvent::Syscall(SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now())),
    ];
    
    let result = matcher.match_sequence(&events);
    
    // Should NOT match (wrong order)
    assert!(!result.is_match());
}

#[test]
fn test_match_result_display() {
    let matcher = SignatureMatcher::new();
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, Utc::now(),
    ));
    
    let result = matcher.match_single(&event);
    let display = format!("{}", result);
    
    // Display should contain match information
    assert!(display.contains("Match") || display.contains("NoMatch"));
}

#[test]
fn test_pattern_match_builder() {
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .with_syscall(SyscallType::Connect)
        .within_seconds(30);
    
    assert_eq!(pattern.syscalls().len(), 2);
    assert_eq!(pattern.time_window(), Some(30));
}

#[test]
fn test_match_result_matches_method() {
    let matcher = SignatureMatcher::new();
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = matcher.match_single(&event);
    let matches = result.matches();
    
    // Should have some matches for execve
    assert!(matches.len() > 0);
}
