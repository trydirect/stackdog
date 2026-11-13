//! Rule engine
//!
//! Manages and evaluates security rules

use crate::events::security::SecurityEvent;
use crate::rules::result::RuleEvaluationResult;
use crate::rules::rule::{Rule, RuleResult};

/// Rule engine for evaluating security rules
pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
    enabled_rules: std::collections::HashSet<String>,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enabled_rules: std::collections::HashSet::new(),
        }
    }

    /// Register a rule with the engine
    pub fn register_rule(&mut self, rule: Box<dyn Rule>) {
        let name = rule.name().to_string();
        self.enabled_rules.insert(name);
        self.rules.push(rule);
        // Sort by priority after adding
        self.rules.sort_by_key(|r| r.priority());
    }

    /// Remove a rule by name
    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name() != name);
        self.enabled_rules.remove(name);
    }

    /// Evaluate all rules against an event
    pub fn evaluate(&self, event: &SecurityEvent) -> Vec<RuleResult> {
        self.rules
            .iter()
            .filter(|rule| {
                // Only evaluate enabled rules
                self.enabled_rules.contains(rule.name()) && rule.enabled()
            })
            .map(|rule| rule.evaluate(event))
            .collect()
    }

    /// Evaluate with detailed results
    pub fn evaluate_detailed(&self, event: &SecurityEvent) -> Vec<RuleEvaluationResult> {
        self.rules
            .iter()
            .filter(|rule| self.enabled_rules.contains(rule.name()) && rule.enabled())
            .map(|rule| {
                let result = rule.evaluate(event);
                RuleEvaluationResult::new(rule.name().to_string(), event.clone(), result)
            })
            .collect()
    }

    /// Get the number of registered rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Clear all rules
    pub fn clear_all_rules(&mut self) {
        self.rules.clear();
        self.enabled_rules.clear();
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, name: &str) {
        self.enabled_rules.insert(name.to_string());
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, name: &str) {
        self.enabled_rules.remove(name);
    }

    /// Check if a rule is enabled
    pub fn is_rule_enabled(&self, name: &str) -> bool {
        self.enabled_rules.contains(name)
    }

    /// Get all rule names
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name()).collect()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = RuleEngine::new();
        assert_eq!(engine.rule_count(), 0);
    }
}
