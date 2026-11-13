//! Rule results
//!
//! Types for rule evaluation results and severity

use crate::events::security::SecurityEvent;
use crate::rules::rule::RuleResult;

/// Severity levels for rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 20,
    Medium = 40,
    High = 70,
    Critical = 90,
}

impl Severity {
    /// Create severity from score (0-100)
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Severity::Info,
            20..=39 => Severity::Low,
            40..=69 => Severity::Medium,
            70..=89 => Severity::High,
            90..=100 => Severity::Critical,
            _ => Severity::Info,
        }
    }

    /// Get the numeric score for this severity
    pub fn score(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 20,
            Severity::Medium => 40,
            Severity::High => 70,
            Severity::Critical => 90,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Result of evaluating a single rule
#[derive(Debug, Clone)]
pub struct RuleEvaluationResult {
    rule_name: String,
    event: SecurityEvent,
    result: RuleResult,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl RuleEvaluationResult {
    /// Create a new evaluation result
    pub fn new(rule_name: String, event: SecurityEvent, result: RuleResult) -> Self {
        Self {
            rule_name,
            event,
            result,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get the rule name
    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }

    /// Get the event
    pub fn event(&self) -> &SecurityEvent {
        &self.event
    }

    /// Get the result
    pub fn result(&self) -> &RuleResult {
        &self.result
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        self.timestamp
    }

    /// Check if the rule matched
    pub fn matched(&self) -> bool {
        self.result.is_match()
    }

    /// Check if the rule did not match
    pub fn not_matched(&self) -> bool {
        self.result.is_no_match()
    }

    /// Check if there was an error
    pub fn has_error(&self) -> bool {
        self.result.is_error()
    }
}

/// Calculate aggregate severity from multiple severities
pub fn calculate_aggregate_severity(severities: &[Severity]) -> Severity {
    if severities.is_empty() {
        return Severity::Info;
    }

    // Return the highest severity
    *severities.iter().max().unwrap_or(&Severity::Info)
}

/// Calculate aggregate severity from rule results
pub fn calculate_severity_from_results(
    results: &[RuleEvaluationResult],
    base_severities: &[Severity],
) -> Severity {
    let matched_severities: Vec<Severity> = results
        .iter()
        .filter(|r| r.matched())
        .enumerate()
        .map(|(i, _)| base_severities.get(i).copied().unwrap_or(Severity::Medium))
        .collect();

    calculate_aggregate_severity(&matched_severities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(0), Severity::Info);
        assert_eq!(Severity::from_score(25), Severity::Low);
        assert_eq!(Severity::from_score(50), Severity::Medium);
        assert_eq!(Severity::from_score(80), Severity::High);
        assert_eq!(Severity::from_score(95), Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::High), "High");
    }

    #[test]
    fn test_aggregate_severity_empty() {
        let result = calculate_aggregate_severity(&[]);
        assert_eq!(result, Severity::Info);
    }

    #[test]
    fn test_aggregate_severity_single() {
        let severities = vec![Severity::High];
        let result = calculate_aggregate_severity(&severities);
        assert_eq!(result, Severity::High);
    }

    #[test]
    fn test_aggregate_severity_multiple() {
        let severities = vec![Severity::Low, Severity::Medium, Severity::High];
        let result = calculate_aggregate_severity(&severities);
        assert_eq!(result, Severity::High);
    }
}
