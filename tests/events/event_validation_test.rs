//! Event validation tests
//!
//! Tests for event validation logic

use chrono::Utc;
use stackdog::events::security::{AlertEvent, AlertSeverity, AlertType, NetworkEvent};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::validation::{EventValidator, ValidationResult};

#[test]
fn test_valid_syscall_event() {
    let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    let result = EventValidator::validate_syscall(&event);
    assert!(result.is_valid());
    assert_eq!(result, ValidationResult::Valid);
}

#[test]
fn test_syscall_event_zero_pid() {
    let event = SyscallEvent::new(
        0, // kernel thread
        0,
        SyscallType::Execve,
        Utc::now(),
    );

    let result = EventValidator::validate_syscall(&event);
    // PID 0 is valid (kernel threads)
    assert!(result.is_valid());
}

#[test]
fn test_invalid_ip_address() {
    let event = NetworkEvent {
        src_ip: "invalid_ip".to_string(),
        dst_ip: "10.0.0.1".to_string(),
        src_port: 12345,
        dst_port: 80,
        protocol: "TCP".to_string(),
        timestamp: Utc::now(),
        container_id: None,
    };

    let result = EventValidator::validate_network(&event);
    assert!(!result.is_valid());
    assert!(matches!(result, ValidationResult::Invalid(_)));
}

#[test]
fn test_valid_ip_addresses() {
    let valid_ips = vec![
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "::1",
        "2001:db8::1",
    ];

    for ip in valid_ips {
        let event = NetworkEvent {
            src_ip: ip.to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            timestamp: Utc::now(),
            container_id: None,
        };

        let result = EventValidator::validate_network(&event);
        assert!(result.is_valid(), "IP {} should be valid", ip);
    }
}

#[test]
fn test_invalid_port_not_representable_for_u16() {
    // NetworkEvent ports are u16, so values > 65535 cannot be constructed.
    // This test asserts type-level safety explicitly.
    let max = u16::MAX;
    assert_eq!(max, 65535);
}

#[test]
fn test_valid_port_range() {
    let valid_ports = vec![0, 80, 443, 8080, 65535];

    for port in valid_ports {
        let event = NetworkEvent {
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: port,
            dst_port: 80,
            protocol: "TCP".to_string(),
            timestamp: Utc::now(),
            container_id: None,
        };

        let result = EventValidator::validate_network(&event);
        assert!(result.is_valid(), "Port {} should be valid", port);
    }
}

#[test]
fn test_alert_event_validation() {
    let event = AlertEvent {
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::High,
        message: "Test alert".to_string(),
        timestamp: Utc::now(),
        source_event_id: None,
    };

    let result = EventValidator::validate_alert(&event);
    assert!(result.is_valid());
}

#[test]
fn test_alert_empty_message() {
    let event = AlertEvent {
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::High,
        message: "".to_string(),
        timestamp: Utc::now(),
        source_event_id: None,
    };

    let result = EventValidator::validate_alert(&event);
    assert!(!result.is_valid());
}

#[test]
fn test_validation_result_error() {
    let result = ValidationResult::error("Test error message");
    assert!(!result.is_valid());
    assert!(matches!(result, ValidationResult::Error(_)));
}

#[test]
fn test_validation_result_display() {
    let valid = ValidationResult::Valid;
    assert_eq!(format!("{}", valid), "Valid");

    let invalid = ValidationResult::Invalid("reason".to_string());
    assert!(format!("{}", invalid).contains("Invalid"));

    let error = ValidationResult::Error("error".to_string());
    assert!(format!("{}", error).contains("error"));
}
