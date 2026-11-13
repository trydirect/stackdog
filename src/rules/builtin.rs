//! Built-in rules
//!
//! Pre-defined rules for common security scenarios

use crate::events::security::SecurityEvent;
use crate::events::syscall::{SyscallDetails, SyscallType};
use crate::rules::rule::{Rule, RuleResult};

/// Syscall allowlist rule
/// Matches if the syscall is in the allowed list
pub struct SyscallAllowlistRule {
    allowed: Vec<SyscallType>,
}

impl SyscallAllowlistRule {
    pub fn new(allowed: Vec<SyscallType>) -> Self {
        Self { allowed }
    }
}

impl Rule for SyscallAllowlistRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        if let SecurityEvent::Syscall(syscall_event) = event {
            if self.allowed.contains(&syscall_event.syscall_type) {
                RuleResult::Match
            } else {
                RuleResult::NoMatch
            }
        } else {
            RuleResult::NoMatch
        }
    }

    fn name(&self) -> &str {
        "syscall_allowlist"
    }

    fn priority(&self) -> u32 {
        50
    }
}

/// Syscall blocklist rule
/// Matches if the syscall is in the blocked list
pub struct SyscallBlocklistRule {
    blocked: Vec<SyscallType>,
}

impl SyscallBlocklistRule {
    pub fn new(blocked: Vec<SyscallType>) -> Self {
        Self { blocked }
    }
}

impl Rule for SyscallBlocklistRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        if let SecurityEvent::Syscall(syscall_event) = event {
            if self.blocked.contains(&syscall_event.syscall_type) {
                RuleResult::Match // Match means violation detected
            } else {
                RuleResult::NoMatch
            }
        } else {
            RuleResult::NoMatch
        }
    }

    fn name(&self) -> &str {
        "syscall_blocklist"
    }

    fn priority(&self) -> u32 {
        10 // High priority for security violations
    }
}

/// Process execution rule
/// Matches execve syscalls
pub struct ProcessExecutionRule {
    _phantom: (),
}

impl ProcessExecutionRule {
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

impl Default for ProcessExecutionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ProcessExecutionRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        if let SecurityEvent::Syscall(syscall_event) = event {
            if syscall_event.syscall_type == SyscallType::Execve
                || syscall_event.syscall_type == SyscallType::Execveat
            {
                RuleResult::Match
            } else {
                RuleResult::NoMatch
            }
        } else {
            RuleResult::NoMatch
        }
    }

    fn name(&self) -> &str {
        "process_execution"
    }

    fn priority(&self) -> u32 {
        30
    }
}

/// Network connection rule
/// Matches network-related syscalls
pub struct NetworkConnectionRule {
    _phantom: (),
}

impl NetworkConnectionRule {
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

impl Default for NetworkConnectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NetworkConnectionRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        if let SecurityEvent::Syscall(syscall_event) = event {
            match syscall_event.syscall_type {
                SyscallType::Connect
                | SyscallType::Accept
                | SyscallType::Bind
                | SyscallType::Listen
                | SyscallType::Socket => RuleResult::Match,
                _ => RuleResult::NoMatch,
            }
        } else {
            RuleResult::NoMatch
        }
    }

    fn name(&self) -> &str {
        "network_connection"
    }

    fn priority(&self) -> u32 {
        40
    }
}

/// SMTP connection rule
/// Matches outbound connections to common mail submission ports.
pub struct SmtpConnectionRule {
    ports: Vec<u16>,
}

impl SmtpConnectionRule {
    pub fn new() -> Self {
        Self {
            ports: vec![25, 465, 587, 2525],
        }
    }
}

impl Default for SmtpConnectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SmtpConnectionRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        let SecurityEvent::Syscall(syscall_event) = event else {
            return RuleResult::NoMatch;
        };

        if syscall_event.syscall_type != SyscallType::Connect {
            return RuleResult::NoMatch;
        }

        match syscall_event.details.as_ref() {
            Some(SyscallDetails::Connect { dst_port, .. }) if self.ports.contains(dst_port) => {
                RuleResult::Match
            }
            _ => RuleResult::NoMatch,
        }
    }

    fn name(&self) -> &str {
        "smtp_connection"
    }

    fn priority(&self) -> u32 {
        20
    }
}

/// File access rule
/// Matches file-related syscalls
pub struct FileAccessRule {
    _phantom: (),
}

impl FileAccessRule {
    pub fn new() -> Self {
        Self { _phantom: () }
    }
}

impl Default for FileAccessRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FileAccessRule {
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult {
        if let SecurityEvent::Syscall(syscall_event) = event {
            match syscall_event.syscall_type {
                SyscallType::Open
                | SyscallType::Openat
                | SyscallType::Close
                | SyscallType::Read
                | SyscallType::Write => RuleResult::Match,
                _ => RuleResult::NoMatch,
            }
        } else {
            RuleResult::NoMatch
        }
    }

    fn name(&self) -> &str {
        "file_access"
    }

    fn priority(&self) -> u32 {
        60
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::syscall::{SyscallDetails, SyscallEvent};
    use chrono::Utc;

    #[test]
    fn test_allowlist_rule() {
        let rule = SyscallAllowlistRule::new(vec![SyscallType::Execve]);
        let event = SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Execve,
            Utc::now(),
        ));
        assert!(rule.evaluate(&event).is_match());
    }

    #[test]
    fn test_blocklist_rule() {
        let rule = SyscallBlocklistRule::new(vec![SyscallType::Ptrace]);
        let event = SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Ptrace,
            Utc::now(),
        ));
        assert!(rule.evaluate(&event).is_match());
    }

    #[test]
    fn test_smtp_connection_rule_matches_mail_port() {
        let rule = SmtpConnectionRule::new();
        let event = SecurityEvent::Syscall(
            SyscallEvent::builder()
                .pid(1234)
                .uid(1000)
                .syscall_type(SyscallType::Connect)
                .timestamp(Utc::now())
                .details(Some(SyscallDetails::Connect {
                    dst_addr: Some("198.51.100.25".to_string()),
                    dst_port: 587,
                    family: 2,
                }))
                .build(),
        );

        assert!(rule.evaluate(&event).is_match());
    }

    #[test]
    fn test_smtp_connection_rule_ignores_non_mail_port() {
        let rule = SmtpConnectionRule::new();
        let event = SecurityEvent::Syscall(
            SyscallEvent::builder()
                .pid(1234)
                .uid(1000)
                .syscall_type(SyscallType::Connect)
                .timestamp(Utc::now())
                .details(Some(SyscallDetails::Connect {
                    dst_addr: Some("198.51.100.25".to_string()),
                    dst_port: 443,
                    family: 2,
                }))
                .build(),
        );

        assert!(rule.evaluate(&event).is_no_match());
    }
}
