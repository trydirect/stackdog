//! Signature matcher
//!
//! Advanced signature matching with multi-event pattern detection

use crate::events::security::SecurityEvent;
use crate::events::syscall::SyscallType;
use crate::rules::signatures::SignatureDatabase;
use chrono::{DateTime, Utc};

/// Pattern match definition
#[derive(Debug, Clone)]
pub struct PatternMatch {
    syscalls: Vec<SyscallType>,
    time_window: Option<u64>, // Seconds
    description: String,
}

impl PatternMatch {
    /// Create a new pattern match
    pub fn new() -> Self {
        Self {
            syscalls: Vec::new(),
            time_window: None,
            description: String::new(),
        }
    }

    /// Add a syscall to the pattern
    pub fn with_syscall(mut self, syscall: SyscallType) -> Self {
        self.syscalls.push(syscall);
        self
    }

    /// Add next syscall in sequence
    pub fn then_syscall(mut self, syscall: SyscallType) -> Self {
        self.syscalls.push(syscall);
        self
    }

    /// Set time window for pattern (in seconds)
    pub fn within_seconds(mut self, seconds: u64) -> Self {
        self.time_window = Some(seconds);
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Get syscalls in pattern
    pub fn syscalls(&self) -> &[SyscallType] {
        &self.syscalls
    }

    /// Get time window
    pub fn time_window(&self) -> Option<u64> {
        self.time_window
    }

    /// Get description
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Default for PatternMatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Match result
#[derive(Debug, Clone)]
pub struct MatchResult {
    matches: Vec<String>,
    is_match: bool,
    confidence: f64,
}

impl MatchResult {
    /// Create a new match result
    pub fn new(matches: Vec<String>, is_match: bool, confidence: f64) -> Self {
        Self {
            matches,
            is_match,
            confidence,
        }
    }

    /// Create empty (no match) result
    pub fn no_match() -> Self {
        Self {
            matches: Vec::new(),
            is_match: false,
            confidence: 0.0,
        }
    }

    /// Get matched signatures
    pub fn matches(&self) -> &[String] {
        &self.matches
    }

    /// Check if matched
    pub fn is_match(&self) -> bool {
        self.is_match
    }

    /// Get confidence score (0.0 - 1.0)
    pub fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl std::fmt::Display for MatchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_match {
            write!(
                f,
                "Match ({} signatures, confidence: {:.2})",
                self.matches.len(),
                self.confidence
            )
        } else {
            write!(f, "NoMatch")
        }
    }
}

/// Signature matcher with advanced pattern detection
pub struct SignatureMatcher {
    db: SignatureDatabase,
    patterns: Vec<PatternMatch>,
}

impl SignatureMatcher {
    /// Create a new signature matcher
    pub fn new() -> Self {
        Self {
            db: SignatureDatabase::new(),
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to match
    pub fn add_pattern(&mut self, pattern: PatternMatch) {
        self.patterns.push(pattern);
    }

    /// Match a single event against signatures
    pub fn match_single(&self, event: &SecurityEvent) -> MatchResult {
        let signatures = self.db.detect(event);

        if signatures.is_empty() {
            return MatchResult::no_match();
        }

        let matches: Vec<String> = signatures.iter().map(|s| s.name().to_string()).collect();

        // Calculate confidence based on severity
        let avg_severity =
            signatures.iter().map(|s| s.severity() as f64).sum::<f64>() / signatures.len() as f64;

        let confidence = avg_severity / 100.0;

        MatchResult::new(matches, true, confidence)
    }

    /// Match a sequence of events against patterns
    pub fn match_sequence(&self, events: &[SecurityEvent]) -> MatchResult {
        if events.is_empty() {
            return MatchResult::no_match();
        }

        for pattern in &self.patterns {
            if self.matches_pattern(pattern, events) {
                return MatchResult::new(
                    vec![pattern.description().to_string()],
                    true,
                    0.9, // High confidence for pattern match
                );
            }
        }

        // Also check individual events
        let mut all_matches = Vec::new();
        for event in events {
            let result = self.match_single(event);
            if result.is_match() {
                all_matches.extend(result.matches().iter().cloned());
            }
        }

        if all_matches.is_empty() {
            MatchResult::no_match()
        } else {
            MatchResult::new(all_matches, true, 0.7)
        }
    }

    /// Check if events match a pattern
    fn matches_pattern(&self, pattern: &PatternMatch, events: &[SecurityEvent]) -> bool {
        // Need at least as many events as pattern syscalls
        if events.len() < pattern.syscalls().len() {
            return false;
        }

        // Check if pattern syscalls appear in order
        let mut event_idx = 0;
        let mut matched_syscalls = 0;
        let mut first_match_time: Option<DateTime<Utc>> = None;

        for required_syscall in pattern.syscalls() {
            while event_idx < events.len() {
                if let SecurityEvent::Syscall(syscall_event) = &events[event_idx] {
                    if &syscall_event.syscall_type == required_syscall {
                        // Record first match time
                        if first_match_time.is_none() {
                            first_match_time = Some(syscall_event.timestamp);
                        }

                        matched_syscalls += 1;
                        event_idx += 1;
                        break;
                    }
                }
                event_idx += 1;
            }
        }

        // Check if all syscalls matched
        if matched_syscalls != pattern.syscalls().len() {
            return false;
        }

        // Check time window if specified
        if let Some(window) = pattern.time_window() {
            if let (Some(first), Some(SecurityEvent::Syscall(last_event))) =
                (first_match_time, events.last())
            {
                let elapsed = last_event.timestamp - first;
                if elapsed.num_seconds() > window as i64 {
                    return false;
                }
            }
        }

        true
    }

    /// Get signature database
    pub fn database(&self) -> &SignatureDatabase {
        &self.db
    }

    /// Get patterns
    pub fn patterns(&self) -> &[PatternMatch] {
        &self.patterns
    }

    /// Clear patterns
    pub fn clear_patterns(&mut self) {
        self.patterns.clear();
    }
}

impl Default for SignatureMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_match_builder() {
        let pattern = PatternMatch::new()
            .with_syscall(SyscallType::Execve)
            .then_syscall(SyscallType::Connect)
            .within_seconds(60)
            .with_description("Test pattern");

        assert_eq!(pattern.syscalls().len(), 2);
        assert_eq!(pattern.time_window(), Some(60));
        assert_eq!(pattern.description(), "Test pattern");
    }

    #[test]
    fn test_match_result_display() {
        let result = MatchResult::new(vec!["sig1".to_string()], true, 0.8);
        assert!(format!("{}", result).contains("Match"));

        let no_result = MatchResult::no_match();
        assert!(format!("{}", no_result).contains("NoMatch"));
    }
}
