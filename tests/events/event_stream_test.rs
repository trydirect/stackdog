//! Event stream tests
//!
//! Tests for event batch, filter, and iterator types

use chrono::{Duration, Utc};
use stackdog::events::security::SecurityEvent;
use stackdog::events::stream::{EventBatch, EventFilter, EventIterator};
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_event_batch_creation() {
    let batch = EventBatch::new();
    assert_eq!(batch.len(), 0);
    assert!(batch.is_empty());
}

#[test]
fn test_event_batch_add() {
    let mut batch = EventBatch::new();

    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

    batch.add(event);
    assert_eq!(batch.len(), 1);
    assert!(!batch.is_empty());
}

#[test]
fn test_event_batch_add_multiple() {
    let mut batch = EventBatch::new();

    for i in 0..10 {
        let event = SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into();
        batch.add(event);
    }

    assert_eq!(batch.len(), 10);
}

#[test]
fn test_event_batch_from_vec() {
    let events: Vec<SecurityEvent> = (0..5)
        .map(|i| SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into())
        .collect();

    let batch = EventBatch::from(events.clone());
    assert_eq!(batch.len(), 5);
}

#[test]
fn test_event_batch_clear() {
    let mut batch = EventBatch::new();

    for i in 0..3 {
        let event = SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into();
        batch.add(event);
    }

    assert_eq!(batch.len(), 3);
    batch.clear();
    assert_eq!(batch.len(), 0);
}

#[test]
fn test_event_filter_default() {
    let filter = EventFilter::default();

    // Default filter should match everything
    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

    assert!(filter.matches(&event));
}

#[test]
fn test_event_filter_by_syscall_type() {
    let mut filter = EventFilter::new();
    filter = filter.with_syscall_type(SyscallType::Execve);

    let execve_event: SecurityEvent =
        SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

    let connect_event: SecurityEvent =
        SyscallEvent::new(1234, 1000, SyscallType::Connect, Utc::now()).into();

    assert!(filter.matches(&execve_event));
    assert!(!filter.matches(&connect_event));
}

#[test]
fn test_event_filter_by_pid() {
    let mut filter = EventFilter::new();
    filter = filter.with_pid(1234);

    let matching_event: SecurityEvent =
        SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

    let non_matching_event: SecurityEvent =
        SyscallEvent::new(5678, 1000, SyscallType::Execve, Utc::now()).into();

    assert!(filter.matches(&matching_event));
    assert!(!filter.matches(&non_matching_event));
}

#[test]
fn test_event_filter_chained() {
    let mut filter = EventFilter::new();
    filter = filter
        .with_syscall_type(SyscallType::Execve)
        .with_pid(1234)
        .with_uid(1000);

    let matching_event: SecurityEvent =
        SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

    let wrong_pid_event: SecurityEvent =
        SyscallEvent::new(5678, 1000, SyscallType::Execve, Utc::now()).into();

    assert!(filter.matches(&matching_event));
    assert!(!filter.matches(&wrong_pid_event));
}

#[test]
fn test_event_iterator_creation() {
    let events: Vec<SecurityEvent> = (0..5)
        .map(|i| SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into())
        .collect();

    let iterator = EventIterator::new(events);
    assert_eq!(iterator.count(), 5);
}

#[test]
fn test_event_iterator_filter() {
    let events: Vec<SecurityEvent> = (0..10)
        .map(|i| SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into())
        .collect();

    let iterator = EventIterator::new(events);
    let filter = EventFilter::new().with_pid(5);

    let filtered: Vec<_> = iterator.filter(&filter).collect();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].pid().unwrap_or(0), 5);
}

#[test]
fn test_event_iterator_time_range() {
    let now = Utc::now();
    let events: Vec<SecurityEvent> = vec![
        SyscallEvent::new(1, 1000, SyscallType::Execve, now - Duration::seconds(10)).into(),
        SyscallEvent::new(2, 1000, SyscallType::Execve, now - Duration::seconds(5)).into(),
        SyscallEvent::new(3, 1000, SyscallType::Execve, now).into(),
    ];

    let iterator = EventIterator::new(events);
    let start = now - Duration::seconds(6);
    let filtered: Vec<_> = iterator.time_range(start, now).collect();

    assert_eq!(filtered.len(), 2);
}

#[test]
fn test_event_iterator_collect() {
    let events: Vec<SecurityEvent> = (0..5)
        .map(|i| SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now()).into())
        .collect();

    let iterator = EventIterator::new(events);
    let collected: Vec<_> = iterator.collect();

    assert_eq!(collected.len(), 5);
}
