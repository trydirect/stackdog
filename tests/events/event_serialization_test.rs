//! Event serialization tests
//!
//! Tests for JSON and binary serialization of events

use chrono::Utc;
use stackdog::events::security::SecurityEvent;
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_syscall_event_json_serialize() {
    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    let json = serde_json::to_string(&event).expect("Failed to serialize");

    assert!(json.contains("\"pid\":1234"));
    assert!(json.contains("\"uid\":1000"));
    assert!(json.contains("\"syscall_type\":\"Execve\""));
}

#[test]
fn test_syscall_event_json_deserialize() {
    let json = r#"{
        "pid": 5678,
        "uid": 2000,
        "syscall_type": "Connect",
        "timestamp": "2026-03-13T10:00:00Z",
        "container_id": null,
        "comm": null
    }"#;

    let event: SyscallEvent = serde_json::from_str(json).expect("Failed to deserialize");

    assert_eq!(event.pid, 5678);
    assert_eq!(event.uid, 2000);
    assert_eq!(event.syscall_type, SyscallType::Connect);
}

#[test]
fn test_syscall_event_json_roundtrip() {
    let original = SyscallEvent::new(1234, 1000, SyscallType::Ptrace, Utc::now());

    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let deserialized: SyscallEvent = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(original.pid, deserialized.pid);
    assert_eq!(original.uid, deserialized.uid);
    assert_eq!(original.syscall_type, deserialized.syscall_type);
}

#[test]
fn test_security_event_json_serialize() {
    let syscall_event = SyscallEvent::new(1234, 1000, SyscallType::Mount, Utc::now());
    let security_event = SecurityEvent::Syscall(syscall_event);

    let json = serde_json::to_string(&security_event).expect("Failed to serialize");

    assert!(json.contains("Syscall"));
    assert!(json.contains("\"pid\":1234"));
}

#[test]
fn test_security_event_json_roundtrip() {
    let syscall_event = SyscallEvent::new(9999, 0, SyscallType::Setuid, Utc::now());
    let original = SecurityEvent::Syscall(syscall_event);

    let json = serde_json::to_string(&original).expect("Failed to serialize");
    let deserialized: SecurityEvent = serde_json::from_str(&json).expect("Failed to deserialize");

    match deserialized {
        SecurityEvent::Syscall(e) => {
            assert_eq!(e.pid, 9999);
            assert_eq!(e.uid, 0);
            assert_eq!(e.syscall_type, SyscallType::Setuid);
        }
        _ => panic!("Expected Syscall variant"),
    }
}

#[test]
fn test_syscall_type_serialization() {
    let syscall_types = vec![
        SyscallType::Execve,
        SyscallType::Connect,
        SyscallType::Open,
        SyscallType::Ptrace,
        SyscallType::Mount,
    ];

    for syscall_type in syscall_types {
        let json = serde_json::to_string(&syscall_type).expect("Failed to serialize");
        let deserialized: SyscallType = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(syscall_type, deserialized);
    }
}

#[test]
fn test_syscall_event_with_container_serialization() {
    let mut event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());
    event.container_id = Some("container_abc123".to_string());
    event.comm = Some("/bin/bash".to_string());

    let json = serde_json::to_string(&event).expect("Failed to serialize");

    assert!(json.contains("container_abc123"));
    assert!(json.contains("/bin/bash"));

    let deserialized: SyscallEvent = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(
        deserialized.container_id,
        Some("container_abc123".to_string())
    );
    assert_eq!(deserialized.comm, Some("/bin/bash".to_string()));
}
