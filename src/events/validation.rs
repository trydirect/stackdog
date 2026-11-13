//! Event validation
//!
//! Provides validation for security events

use crate::events::security::{AlertEvent, NetworkEvent};
use crate::events::syscall::SyscallEvent;
use std::net::IpAddr;

/// Result of event validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
    Error(String),
}

impl ValidationResult {
    /// Create a valid result
    pub fn valid() -> Self {
        ValidationResult::Valid
    }

    /// Create an invalid result with reason
    pub fn invalid(reason: impl Into<String>) -> Self {
        ValidationResult::Invalid(reason.into())
    }

    /// Create an error result with message
    pub fn error(message: impl Into<String>) -> Self {
        ValidationResult::Error(message.into())
    }

    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    /// Check if validation failed
    pub fn is_invalid(&self) -> bool {
        matches!(
            self,
            ValidationResult::Invalid(_) | ValidationResult::Error(_)
        )
    }
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationResult::Valid => write!(f, "Valid"),
            ValidationResult::Invalid(reason) => write!(f, "Invalid: {}", reason),
            ValidationResult::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Event validator
pub struct EventValidator;

impl EventValidator {
    /// Validate a syscall event
    pub fn validate_syscall(event: &SyscallEvent) -> ValidationResult {
        // PID 0 is valid (kernel threads)
        // All other PIDs should be positive
        if event.pid == 0 {
            return ValidationResult::valid();
        }

        // UID 0 is valid (root)
        // All syscalls are valid
        ValidationResult::valid()
    }

    /// Validate a network event
    pub fn validate_network(event: &NetworkEvent) -> ValidationResult {
        // Validate source IP
        if let Err(e) = event.src_ip.parse::<IpAddr>() {
            return ValidationResult::invalid(format!("Invalid source IP: {}", e));
        }

        // Validate destination IP
        if let Err(e) = event.dst_ip.parse::<IpAddr>() {
            return ValidationResult::invalid(format!("Invalid destination IP: {}", e));
        }

        // Validate port range (0-65535 is always valid for u16)
        // No additional validation needed for u16

        ValidationResult::valid()
    }

    /// Validate an alert event
    pub fn validate_alert(event: &AlertEvent) -> ValidationResult {
        // Validate message is not empty
        if event.message.trim().is_empty() {
            return ValidationResult::invalid("Alert message cannot be empty");
        }

        ValidationResult::valid()
    }

    /// Validate an IP address string
    pub fn validate_ip(ip: &str) -> ValidationResult {
        match ip.parse::<IpAddr>() {
            Ok(_) => ValidationResult::valid(),
            Err(e) => ValidationResult::invalid(format!("Invalid IP address: {}", e)),
        }
    }

    /// Validate a port number
    pub fn validate_port(_port: u16) -> ValidationResult {
        // All u16 values are valid ports (0-65535)
        ValidationResult::valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::syscall::SyscallType;
    use chrono::Utc;

    #[test]
    fn test_validation_result_valid() {
        let result = ValidationResult::valid();
        assert!(result.is_valid());
        assert!(!result.is_invalid());
    }

    #[test]
    fn test_validation_result_invalid() {
        let result = ValidationResult::invalid("test reason");
        assert!(!result.is_valid());
        assert!(result.is_invalid());
    }

    #[test]
    fn test_validation_result_error() {
        let result = ValidationResult::error("test error");
        assert!(!result.is_valid());
        assert!(result.is_invalid());
    }

    #[test]
    fn test_validate_syscall_event() {
        let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());
        let result = EventValidator::validate_syscall(&event);
        assert!(result.is_valid());
    }

    #[test]
    fn test_validate_ip() {
        assert!(EventValidator::validate_ip("192.168.1.1").is_valid());
        assert!(EventValidator::validate_ip("::1").is_valid());
        assert!(EventValidator::validate_ip("invalid").is_invalid());
    }
}
