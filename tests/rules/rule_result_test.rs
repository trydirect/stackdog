//! Rule result tests
//!
//! Tests for rule result types and aggregation

use stackdog::rules::result::{RuleResult, RuleEvaluationResult, Severity};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::Utc;

#[test]
fn test_rule_result_variants() {
    let match_result = RuleResult::Match;
    let no_match_result = RuleResult::NoMatch;
    let error_result = RuleResult::Error("test error".to_string());
    
    assert!(match_result.is_match());
    assert!(!match_result.is_no_match());
    assert!(!match_result.is_error());
    
    assert!(!no_match_result.is_match());
    assert!(no_match_result.is_no_match());
    assert!(!no_match_result.is_error());
    
    assert!(!error_result.is_match());
    assert!(!error_result.is_no_match());
    assert!(error_result.is_error());
}

#[test]
fn test_rule_result_display() {
    let match_result = RuleResult::Match;
    assert_eq!(format!("{}", match_result), "Match");
    
    let no_match_result = RuleResult::NoMatch;
    assert_eq!(format!("{}", no_match_result), "NoMatch");
    
    let error_result = RuleResult::Error("test".to_string());
    assert!(format!("{}", error_result).contains("test"));
}

#[test]
fn test_rule_evaluation_result_creation() {
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = RuleEvaluationResult::new(
        "test_rule".to_string(),
        event.clone(),
        RuleResult::Match,
    );
    
    assert_eq!(result.rule_name(), "test_rule");
    assert!(result.matched());
}

#[test]
fn test_rule_evaluation_result_matched() {
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = RuleEvaluationResult::new(
        "test_rule".to_string(),
        event,
        RuleResult::Match,
    );
    
    assert!(result.matched());
    assert!(!result.not_matched());
}

#[test]
fn test_rule_evaluation_result_not_matched() {
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let result = RuleEvaluationResult::new(
        "test_rule".to_string(),
        event,
        RuleResult::NoMatch,
    );
    
    assert!(!result.matched());
    assert!(result.not_matched());
}

#[test]
fn test_severity_variants() {
    let info = Severity::Info;
    let low = Severity::Low;
    let medium = Severity::Medium;
    let high = Severity::High;
    let critical = Severity::Critical;
    
    assert!(info < low);
    assert!(low < medium);
    assert!(medium < high);
    assert!(high < critical);
}

#[test]
fn test_severity_from_score() {
    assert_eq!(Severity::from_score(0), Severity::Info);
    assert_eq!(Severity::from_score(20), Severity::Low);
    assert_eq!(Severity::from_score(40), Severity::Medium);
    assert_eq!(Severity::from_score(70), Severity::High);
    assert_eq!(Severity::from_score(90), Severity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Info), "Info");
    assert_eq!(format!("{}", Severity::Low), "Low");
    assert_eq!(format!("{}", Severity::Medium), "Medium");
    assert_eq!(format!("{}", Severity::High), "High");
    assert_eq!(format!("{}", Severity::Critical), "Critical");
}

#[test]
fn test_result_aggregation() {
    let mut results = Vec::new();
    
    results.push(RuleResult::Match);
    results.push(RuleResult::NoMatch);
    results.push(RuleResult::Match);
    
    let match_count = results.iter().filter(|r| r.is_match()).count();
    assert_eq!(match_count, 2);
    
    let no_match_count = results.iter().filter(|r| r.is_no_match()).count();
    assert_eq!(no_match_count, 1);
}

#[test]
fn test_aggregate_severity_calculation() {
    use stackdog::rules::result::calculate_aggregate_severity;
    
    // Single match should return base severity
    let severities = vec![Severity::High];
    let aggregate = calculate_aggregate_severity(&severities);
    assert_eq!(aggregate, Severity::High);
    
    // Multiple matches should return highest
    let severities = vec![Severity::Low, Severity::Medium, Severity::High];
    let aggregate = calculate_aggregate_severity(&severities);
    assert_eq!(aggregate, Severity::High);
}

#[test]
fn test_rule_result_error_message() {
    let error = RuleResult::Error("something went wrong".to_string());
    
    if let RuleResult::Error(msg) = error {
        assert_eq!(msg, "something went wrong");
    } else {
        panic!("Expected Error variant");
    }
}
