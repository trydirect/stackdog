//! Security event tests
//!
//! Tests for the SecurityEvent enum and related event types.

use chrono::Utc;
use stackdog::events::security::{
    AlertEvent, AlertSeverity, AlertType, ContainerEvent, ContainerEventType, NetworkEvent,
    SecurityEvent,
};
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_security_event_syscall_variant() {
    let syscall_event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    let security_event = SecurityEvent::Syscall(syscall_event);

    // Test that we can match on the variant
    match security_event {
        SecurityEvent::Syscall(e) => {
            assert_eq!(e.pid, 1234);
            assert_eq!(e.syscall_type, SyscallType::Execve);
        }
        _ => panic!("Expected Syscall variant"),
    }
}

#[test]
fn test_security_event_network_variant() {
    let network_event = NetworkEvent {
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: 12345,
        dst_port: 80,
        protocol: "TCP".to_string(),
        timestamp: Utc::now(),
        container_id: Some("abc123".to_string()),
    };

    let security_event = SecurityEvent::Network(network_event);

    match security_event {
        SecurityEvent::Network(e) => {
            assert_eq!(e.src_ip, "192.168.1.1");
            assert_eq!(e.dst_port, 80);
        }
        _ => panic!("Expected Network variant"),
    }
}

#[test]
fn test_security_event_container_variant() {
    let container_event = ContainerEvent {
        container_id: "abc123".to_string(),
        event_type: ContainerEventType::Start,
        timestamp: Utc::now(),
        details: Some("Container started".to_string()),
    };

    let security_event = SecurityEvent::Container(container_event);

    match security_event {
        SecurityEvent::Container(e) => {
            assert_eq!(e.container_id, "abc123");
            assert_eq!(e.event_type, ContainerEventType::Start);
        }
        _ => panic!("Expected Container variant"),
    }
}

#[test]
fn test_security_event_alert_variant() {
    let alert_event = AlertEvent {
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::High,
        message: "Suspicious activity detected".to_string(),
        timestamp: Utc::now(),
        source_event_id: Some("evt_123".to_string()),
    };

    let security_event = SecurityEvent::Alert(alert_event);

    match security_event {
        SecurityEvent::Alert(e) => {
            assert_eq!(e.alert_type, AlertType::ThreatDetected);
            assert_eq!(e.severity, AlertSeverity::High);
        }
        _ => panic!("Expected Alert variant"),
    }
}

#[test]
fn test_container_event_type_variants() {
    let _start = ContainerEventType::Start;
    let _stop = ContainerEventType::Stop;
    let _create = ContainerEventType::Create;
    let _destroy = ContainerEventType::Destroy;
    let _pause = ContainerEventType::Pause;
    let _unpause = ContainerEventType::Unpause;
}

#[test]
fn test_alert_type_variants() {
    let _threat = AlertType::ThreatDetected;
    let _anomaly = AlertType::AnomalyDetected;
    let _violation = AlertType::RuleViolation;
    let _quarantine = AlertType::QuarantineApplied;
}

#[test]
fn test_alert_severity_variants() {
    let _info = AlertSeverity::Info;
    let _low = AlertSeverity::Low;
    let _medium = AlertSeverity::Medium;
    let _high = AlertSeverity::High;
    let _critical = AlertSeverity::Critical;
}

#[test]
fn test_network_event_clone() {
    let event = NetworkEvent {
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: 12345,
        dst_port: 80,
        protocol: "TCP".to_string(),
        timestamp: Utc::now(),
        container_id: Some("abc123".to_string()),
    };

    let cloned = event.clone();
    assert_eq!(event.src_ip, cloned.src_ip);
    assert_eq!(event.dst_port, cloned.dst_port);
}

#[test]
fn test_container_event_clone() {
    let event = ContainerEvent {
        container_id: "abc123".to_string(),
        event_type: ContainerEventType::Start,
        timestamp: Utc::now(),
        details: None,
    };

    let cloned = event.clone();
    assert_eq!(event.container_id, cloned.container_id);
    assert_eq!(event.event_type, cloned.event_type);
}

#[test]
fn test_alert_event_debug() {
    let event = AlertEvent {
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::Critical,
        message: "Test alert".to_string(),
        timestamp: Utc::now(),
        source_event_id: None,
    };

    let debug_str = format!("{:?}", event);
    assert!(debug_str.contains("AlertEvent"));
    assert!(debug_str.contains("ThreatDetected"));
}
