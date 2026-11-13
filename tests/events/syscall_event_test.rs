//! Syscall event tests
//!
//! Tests for syscall event types, creation, and builder pattern.

use chrono::Utc;
use stackdog::events::syscall::{SyscallEvent, SyscallEventBuilder, SyscallType};

#[test]
fn test_syscall_type_variants() {
    // Test all syscall type variants can be created
    let _execve = SyscallType::Execve;
    let _execveat = SyscallType::Execveat;
    let _connect = SyscallType::Connect;
    let _accept = SyscallType::Accept;
    let _bind = SyscallType::Bind;
    let _open = SyscallType::Open;
    let _openat = SyscallType::Openat;
    let _ptrace = SyscallType::Ptrace;
    let _setuid = SyscallType::Setuid;
    let _setgid = SyscallType::Setgid;
    let _mount = SyscallType::Mount;
    let _umount = SyscallType::Umount;
    let _unknown = SyscallType::Unknown;
}

#[test]
fn test_syscall_event_creation() {
    let timestamp = Utc::now();
    let event = SyscallEvent::new(
        1234, // pid
        1000, // uid
        SyscallType::Execve,
        timestamp,
    );

    assert_eq!(event.pid, 1234);
    assert_eq!(event.uid, 1000);
    assert_eq!(event.syscall_type, SyscallType::Execve);
    assert_eq!(event.timestamp, timestamp);
    assert_eq!(event.container_id, None);
    assert_eq!(event.comm, None);
}

#[test]
fn test_syscall_event_with_container_id() {
    let timestamp = Utc::now();
    let mut event = SyscallEvent::new(1234, 1000, SyscallType::Execve, timestamp);
    event.container_id = Some("abc123def456".to_string());

    assert_eq!(event.container_id, Some("abc123def456".to_string()));
}

#[test]
fn test_syscall_event_builder() {
    let timestamp = Utc::now();
    let event = SyscallEvent::builder()
        .pid(1234)
        .uid(1000)
        .syscall_type(SyscallType::Execve)
        .timestamp(timestamp)
        .container_id(Some("abc123".to_string()))
        .comm(Some("bash".to_string()))
        .build();

    assert_eq!(event.pid, 1234);
    assert_eq!(event.uid, 1000);
    assert_eq!(event.syscall_type, SyscallType::Execve);
    assert_eq!(event.timestamp, timestamp);
    assert_eq!(event.container_id, Some("abc123".to_string()));
    assert_eq!(event.comm, Some("bash".to_string()));
}

#[test]
fn test_syscall_event_builder_minimal() {
    let event = SyscallEvent::builder()
        .pid(1234)
        .uid(1000)
        .syscall_type(SyscallType::Connect)
        .build();

    assert_eq!(event.pid, 1234);
    assert_eq!(event.uid, 1000);
    assert_eq!(event.syscall_type, SyscallType::Connect);
    // Timestamp should be set to now if not provided
    assert!(event.timestamp <= Utc::now());
    assert_eq!(event.container_id, None);
    assert_eq!(event.comm, None);
}

#[test]
fn test_syscall_event_builder_default() {
    let event = SyscallEventBuilder::default()
        .pid(5678)
        .uid(2000)
        .syscall_type(SyscallType::Open)
        .build();

    assert_eq!(event.pid, 5678);
    assert_eq!(event.uid, 2000);
    assert_eq!(event.syscall_type, SyscallType::Open);
}

#[test]
fn test_syscall_event_clone() {
    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    let cloned = event.clone();

    assert_eq!(event.pid, cloned.pid);
    assert_eq!(event.uid, cloned.uid);
    assert_eq!(event.syscall_type, cloned.syscall_type);
}

#[test]
fn test_syscall_event_debug() {
    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    // Test that Debug trait is implemented
    let debug_str = format!("{:?}", event);
    assert!(debug_str.contains("SyscallEvent"));
    assert!(debug_str.contains("pid"));
}

#[test]
fn test_syscall_event_partial_eq() {
    let timestamp = Utc::now();
    let event1 = SyscallEvent::new(1234, 1000, SyscallType::Execve, timestamp);
    let event2 = SyscallEvent::new(1234, 1000, SyscallType::Execve, timestamp);
    let event3 = SyscallEvent::new(5678, 1000, SyscallType::Execve, timestamp);

    assert_eq!(event1, event2);
    assert_ne!(event1, event3);
}
