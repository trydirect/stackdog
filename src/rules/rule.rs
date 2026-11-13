//! Rule trait
//!
//! Defines the Rule trait for security rules

use crate::events::security::SecurityEvent;

/// Result of rule evaluation
#[derive(Debug, Clone, PartialEq)]
pub enum RuleResult {
    Match,
    NoMatch,
    Error(String),
}

impl RuleResult {
    /// Check if this is a match
    pub fn is_match(&self) -> bool {
        matches!(self, RuleResult::Match)
    }

    /// Check if this is no match
    pub fn is_no_match(&self) -> bool {
        matches!(self, RuleResult::NoMatch)
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        matches!(self, RuleResult::Error(_))
    }
}

impl std::fmt::Display for RuleResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleResult::Match => write!(f, "Match"),
            RuleResult::NoMatch => write!(f, "NoMatch"),
            RuleResult::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Trait for security rules
pub trait Rule: Send + Sync {
    /// Evaluate the rule against an event
    fn evaluate(&self, event: &SecurityEvent) -> RuleResult;

    /// Get the rule name
    fn name(&self) -> &str;

    /// Get the rule priority (lower = higher priority)
    fn priority(&self) -> u32 {
        100
    }

    /// Check if the rule is enabled
    fn enabled(&self) -> bool {
        true
    }
}
