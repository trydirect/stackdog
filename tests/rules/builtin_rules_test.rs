//! Built-in rules tests
//!
//! Tests for built-in rule implementations

use stackdog::rules::builtin::{
    SyscallAllowlistRule, SyscallBlocklistRule,
    ProcessExecutionRule, NetworkConnectionRule, FileAccessRule,
};
use stackdog::rules::rule::{Rule, RuleResult};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::Utc;

#[test]
fn test_syscall_allowlist_rule_creation() {
    let allowed = vec![SyscallType::Execve, SyscallType::Openat];
    let rule = SyscallAllowlistRule::new(allowed);
    
    assert_eq!(rule.name(), "syscall_allowlist");
}

#[test]
fn test_syscall_allowlist_rule_match() {
    let allowed = vec![SyscallType::Execve, SyscallType::Openat];
    let rule = SyscallAllowlistRule::new(allowed);
    
    // Allowed syscall should match
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_syscall_allowlist_rule_no_match() {
    let allowed = vec![SyscallType::Execve, SyscallType::Openat];
    let rule = SyscallAllowlistRule::new(allowed);
    
    // Non-allowed syscall should not match
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::NoMatch));
}

#[test]
fn test_syscall_blocklist_rule_creation() {
    let blocked = vec![SyscallType::Ptrace, SyscallType::Setuid];
    let rule = SyscallBlocklistRule::new(blocked);
    
    assert_eq!(rule.name(), "syscall_blocklist");
}

#[test]
fn test_syscall_blocklist_rule_match() {
    let blocked = vec![SyscallType::Ptrace, SyscallType::Setuid];
    let rule = SyscallBlocklistRule::new(blocked);
    
    // Blocked syscall should match (as a violation)
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_syscall_blocklist_rule_no_match() {
    let blocked = vec![SyscallType::Ptrace, SyscallType::Setuid];
    let rule = SyscallBlocklistRule::new(blocked);
    
    // Non-blocked syscall should not match
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::NoMatch));
}

#[test]
fn test_process_execution_rule_creation() {
    let rule = ProcessExecutionRule::new();
    assert_eq!(rule.name(), "process_execution");
}

#[test]
fn test_process_execution_rule_detects_execve() {
    let rule = ProcessExecutionRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_process_execution_rule_ignores_other_syscalls() {
    let rule = ProcessExecutionRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Connect, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::NoMatch));
}

#[test]
fn test_network_connection_rule_creation() {
    let rule = NetworkConnectionRule::new();
    assert_eq!(rule.name(), "network_connection");
}

#[test]
fn test_network_connection_rule_detects_connect() {
    let rule = NetworkConnectionRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Connect, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_network_connection_rule_detects_accept() {
    let rule = NetworkConnectionRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Accept, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_file_access_rule_creation() {
    let rule = FileAccessRule::new();
    assert_eq!(rule.name(), "file_access");
}

#[test]
fn test_file_access_rule_detects_openat() {
    let rule = FileAccessRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Openat, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::Match));
}

#[test]
fn test_file_access_rule_ignores_other_syscalls() {
    let rule = FileAccessRule::new();
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Connect, Utc::now(),
    ));
    
    let result = rule.evaluate(&event);
    assert!(matches!(result, RuleResult::NoMatch));
}

#[test]
fn test_builtin_rules_have_reasonable_priority() {
    let allowlist = SyscallAllowlistRule::new(vec![SyscallType::Execve]);
    let blocklist = SyscallBlocklistRule::new(vec![SyscallType::Ptrace]);
    let exec_rule = ProcessExecutionRule::new();
    let network_rule = NetworkConnectionRule::new();
    let file_rule = FileAccessRule::new();
    
    // All priorities should be in valid range (1-100)
    assert!(allowlist.priority() >= 1 && allowlist.priority() <= 100);
    assert!(blocklist.priority() >= 1 && blocklist.priority() <= 100);
    assert!(exec_rule.priority() >= 1 && exec_rule.priority() <= 100);
    assert!(network_rule.priority() >= 1 && network_rule.priority() <= 100);
    assert!(file_rule.priority() >= 1 && file_rule.priority() <= 100);
}
