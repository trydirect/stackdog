//! Event conversion tests
//!
//! Tests for From/Into trait implementations between event types

use chrono::Utc;
use stackdog::events::security::{
    AlertEvent, AlertSeverity, AlertType, ContainerEvent, ContainerEventType, NetworkEvent,
    SecurityEvent,
};
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_syscall_event_to_security_event() {
    let syscall_event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    // Test From trait
    let security_event: SecurityEvent = syscall_event.clone().into();

    match security_event {
        SecurityEvent::Syscall(e) => {
            assert_eq!(e.pid, syscall_event.pid);
            assert_eq!(e.uid, syscall_event.uid);
            assert_eq!(e.syscall_type, syscall_event.syscall_type);
        }
        _ => panic!("Expected Syscall variant"),
    }
}

#[test]
fn test_network_event_to_security_event() {
    let network_event = NetworkEvent {
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: 12345,
        dst_port: 80,
        protocol: "TCP".to_string(),
        timestamp: Utc::now(),
        container_id: Some("abc123".to_string()),
    };

    let security_event: SecurityEvent = network_event.clone().into();

    match security_event {
        SecurityEvent::Network(e) => {
            assert_eq!(e.src_ip, network_event.src_ip);
            assert_eq!(e.dst_port, network_event.dst_port);
        }
        _ => panic!("Expected Network variant"),
    }
}

#[test]
fn test_container_event_to_security_event() {
    let container_event = ContainerEvent {
        container_id: "abc123".to_string(),
        event_type: ContainerEventType::Start,
        timestamp: Utc::now(),
        details: Some("Container started".to_string()),
    };

    let security_event: SecurityEvent = container_event.clone().into();

    match security_event {
        SecurityEvent::Container(e) => {
            assert_eq!(e.container_id, container_event.container_id);
            assert_eq!(e.event_type, container_event.event_type);
        }
        _ => panic!("Expected Container variant"),
    }
}

#[test]
fn test_alert_event_to_security_event() {
    let alert_event = AlertEvent {
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::High,
        message: "Suspicious activity".to_string(),
        timestamp: Utc::now(),
        source_event_id: Some("evt_123".to_string()),
    };

    let security_event: SecurityEvent = alert_event.clone().into();

    match security_event {
        SecurityEvent::Alert(e) => {
            assert_eq!(e.alert_type, alert_event.alert_type);
            assert_eq!(e.severity, alert_event.severity);
        }
        _ => panic!("Expected Alert variant"),
    }
}

#[test]
fn test_security_event_into_syscall() {
    let syscall_event = SyscallEvent::new(1234, 1000, SyscallType::Connect, Utc::now());

    let security_event = SecurityEvent::Syscall(syscall_event.clone());

    // Test conversion back to SyscallEvent
    let result = syscall_event_from_security(security_event);
    assert!(result.is_some());
    let extracted = result.unwrap();
    assert_eq!(extracted.pid, 1234);
    assert_eq!(extracted.syscall_type, SyscallType::Connect);
}

#[test]
fn test_security_event_wrong_variant() {
    let network_event = NetworkEvent {
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: 12345,
        dst_port: 80,
        protocol: "TCP".to_string(),
        timestamp: Utc::now(),
        container_id: None,
    };

    let security_event = SecurityEvent::Network(network_event);

    // Try to extract as SyscallEvent (should fail)
    let result = syscall_event_from_security(security_event);
    assert!(result.is_none());
}

// Helper function to extract SyscallEvent from SecurityEvent
fn syscall_event_from_security(event: SecurityEvent) -> Option<SyscallEvent> {
    match event {
        SecurityEvent::Syscall(e) => Some(e),
        _ => None,
    }
}
