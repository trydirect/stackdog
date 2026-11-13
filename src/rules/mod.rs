//! Rules module
//!
//! Contains the rule engine for security rule evaluation

pub mod builtin;
pub mod engine;
pub mod result;
pub mod rule;
pub mod signature_matcher;
pub mod signatures;
pub mod stats;
pub mod threat_scorer;

/// Marker struct for module tests
pub struct RulesMarker;

// Re-export commonly used types
pub use engine::RuleEngine;
pub use result::{RuleEvaluationResult, Severity};
pub use rule::{Rule, RuleResult};
pub use signature_matcher::{MatchResult, PatternMatch, SignatureMatcher};
pub use signatures::{Signature, SignatureDatabase, ThreatCategory};
pub use stats::{DetectionStats, StatsTracker};
pub use threat_scorer::{ScoringConfig, ThreatScore, ThreatScorer};
