//! Rule engine tests
//!
//! Tests for rule engine functionality

use stackdog::rules::engine::RuleEngine;
use stackdog::rules::rule::{Rule, RuleResult};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::Utc;

// Test rule implementation
struct TestRule {
    name: String,
    priority: u32,
    should_match: bool,
}

impl Rule for TestRule {
    fn evaluate(&self, _event: &SecurityEvent) -> RuleResult {
        if self.should_match {
            RuleResult::Match
        } else {
            RuleResult::NoMatch
        }
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn priority(&self) -> u32 {
        self.priority
    }
}

#[test]
fn test_rule_engine_creation() {
    let engine = RuleEngine::new();
    assert_eq!(engine.rule_count(), 0);
}

#[test]
fn test_rule_registration() {
    let mut engine = RuleEngine::new();
    
    let rule = Box::new(TestRule {
        name: "test_rule".to_string(),
        priority: 10,
        should_match: true,
    });
    
    engine.register_rule(rule);
    assert_eq!(engine.rule_count(), 1);
}

#[test]
fn test_rule_priority_ordering() {
    let mut engine = RuleEngine::new();
    
    // Register rules in random order
    engine.register_rule(Box::new(TestRule {
        name: "low_priority".to_string(),
        priority: 100,
        should_match: true,
    }));
    
    engine.register_rule(Box::new(TestRule {
        name: "high_priority".to_string(),
        priority: 1,
        should_match: true,
    }));
    
    engine.register_rule(Box::new(TestRule {
        name: "medium_priority".to_string(),
        priority: 50,
        should_match: true,
    }));
    
    // Rules should be evaluated in priority order (lower = higher priority)
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let results = engine.evaluate(&event);
    
    // Should have 3 results
    assert_eq!(results.len(), 3);
    
    // All should match
    assert!(results.iter().all(|r| matches!(r, RuleResult::Match)));
}

#[test]
fn test_rule_evaluation_single() {
    let mut engine = RuleEngine::new();
    
    engine.register_rule(Box::new(TestRule {
        name: "match_rule".to_string(),
        priority: 10,
        should_match: true,
    }));
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let results = engine.evaluate(&event);
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], RuleResult::Match));
}

#[test]
fn test_rule_evaluation_multiple() {
    let mut engine = RuleEngine::new();
    
    engine.register_rule(Box::new(TestRule {
        name: "match_rule".to_string(),
        priority: 10,
        should_match: true,
    }));
    
    engine.register_rule(Box::new(TestRule {
        name: "no_match_rule".to_string(),
        priority: 20,
        should_match: false,
    }));
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let results = engine.evaluate(&event);
    assert_eq!(results.len(), 2);
    
    // Check results
    let matches: Vec<_> = results.iter()
        .filter(|r| matches!(r, RuleResult::Match))
        .collect();
    let no_matches: Vec<_> = results.iter()
        .filter(|r| matches!(r, RuleResult::NoMatch))
        .collect();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(no_matches.len(), 1);
}

#[test]
fn test_rule_removal() {
    let mut engine = RuleEngine::new();
    
    engine.register_rule(Box::new(TestRule {
        name: "rule1".to_string(),
        priority: 10,
        should_match: true,
    }));
    
    engine.register_rule(Box::new(TestRule {
        name: "rule2".to_string(),
        priority: 20,
        should_match: true,
    }));
    
    assert_eq!(engine.rule_count(), 2);
    
    engine.remove_rule("rule1");
    assert_eq!(engine.rule_count(), 1);
    
    engine.remove_rule("rule2");
    assert_eq!(engine.rule_count(), 0);
}

#[test]
fn test_rule_enable_disable() {
    let mut engine = RuleEngine::new();
    
    engine.register_rule(Box::new(TestRule {
        name: "toggle_rule".to_string(),
        priority: 10,
        should_match: true,
    }));
    
    // Rule should be enabled by default
    assert!(engine.is_rule_enabled("toggle_rule"));
    
    // Disable rule
    engine.disable_rule("toggle_rule");
    assert!(!engine.is_rule_enabled("toggle_rule"));
    
    // Re-enable rule
    engine.enable_rule("toggle_rule");
    assert!(engine.is_rule_enabled("toggle_rule"));
}

#[test]
fn test_rule_evaluation_with_disabled_rule() {
    let mut engine = RuleEngine::new();
    
    engine.register_rule(Box::new(TestRule {
        name: "disabled_rule".to_string(),
        priority: 10,
        should_match: true,
    }));
    
    engine.disable_rule("disabled_rule");
    
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    // Disabled rules should not be evaluated
    let results = engine.evaluate(&event);
    assert!(results.is_empty());
}

#[test]
fn test_clear_all_rules() {
    let mut engine = RuleEngine::new();
    
    for i in 0..5 {
        engine.register_rule(Box::new(TestRule {
            name: format!("rule_{}", i),
            priority: i * 10,
            should_match: true,
        }));
    }
    
    assert_eq!(engine.rule_count(), 5);
    
    engine.clear_all_rules();
    assert_eq!(engine.rule_count(), 0);
}
