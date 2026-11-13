//! Detection statistics
//!
//! Tracks detection metrics and statistics

use crate::events::security::SecurityEvent;
use chrono::{DateTime, Utc};

/// Detection statistics
#[derive(Debug, Clone)]
pub struct DetectionStats {
    events_processed: u64,
    signatures_matched: u64,
    false_positives: u64,
    true_positives: u64,
    start_time: DateTime<Utc>,
    last_updated: DateTime<Utc>,
}

impl DetectionStats {
    /// Create new detection stats
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            events_processed: 0,
            signatures_matched: 0,
            false_positives: 0,
            true_positives: 0,
            start_time: now,
            last_updated: now,
        }
    }

    /// Record an event being processed
    pub fn record_event(&mut self) {
        self.events_processed += 1;
        self.last_updated = Utc::now();
    }

    /// Record a signature match
    pub fn record_match(&mut self) {
        self.signatures_matched += 1;
        self.true_positives += 1;
        self.last_updated = Utc::now();
    }

    /// Record a false positive
    pub fn record_false_positive(&mut self) {
        self.false_positives += 1;
        self.last_updated = Utc::now();
    }

    /// Get events processed count
    pub fn events_processed(&self) -> u64 {
        self.events_processed
    }

    /// Get signatures matched count
    pub fn signatures_matched(&self) -> u64 {
        self.signatures_matched
    }

    /// Get false positives count
    pub fn false_positives(&self) -> u64 {
        self.false_positives
    }

    /// Get true positives count
    pub fn true_positives(&self) -> u64 {
        self.true_positives
    }

    /// Get start time
    pub fn start_time(&self) -> DateTime<Utc> {
        self.start_time
    }

    /// Get last updated time
    pub fn last_updated(&self) -> DateTime<Utc> {
        self.last_updated
    }

    /// Calculate detection rate (matches / events)
    pub fn detection_rate(&self) -> f64 {
        if self.events_processed == 0 {
            return 0.0;
        }

        self.signatures_matched as f64 / self.events_processed as f64
    }

    /// Calculate false positive rate
    pub fn false_positive_rate(&self) -> f64 {
        let total_matches = self.true_positives + self.false_positives;
        if total_matches == 0 {
            return 0.0;
        }

        self.false_positives as f64 / total_matches as f64
    }

    /// Calculate precision (true positives / all matches)
    pub fn precision(&self) -> f64 {
        let total_matches = self.true_positives + self.false_positives;
        if total_matches == 0 {
            return 1.0; // No matches = no false positives
        }

        self.true_positives as f64 / total_matches as f64
    }

    /// Get uptime duration
    pub fn uptime(&self) -> chrono::Duration {
        self.last_updated - self.start_time
    }

    /// Get events per second
    pub fn events_per_second(&self) -> f64 {
        let uptime_secs = self.uptime().num_seconds() as f64;
        if uptime_secs <= 0.0 {
            return 0.0;
        }

        self.events_processed as f64 / uptime_secs
    }
}

impl Default for DetectionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DetectionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DetectionStats {{ events: {}, matches: {}, rate: {:.1}%, fp_rate: {:.1}% }}",
            self.events_processed,
            self.signatures_matched,
            self.detection_rate() * 100.0,
            self.false_positive_rate() * 100.0
        )
    }
}

/// Stats tracker for real-time tracking
pub struct StatsTracker {
    stats: DetectionStats,
}

impl StatsTracker {
    /// Create a new stats tracker
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            stats: DetectionStats::new(),
        })
    }

    /// Record an event with match result
    pub fn record_event(&mut self, _event: &SecurityEvent, matched: bool) {
        self.stats.record_event();
        if matched {
            self.stats.record_match();
        }
    }

    /// Get current stats
    pub fn stats(&self) -> &DetectionStats {
        &self.stats
    }

    /// Get mutable stats
    pub fn stats_mut(&mut self) -> &mut DetectionStats {
        &mut self.stats
    }

    /// Reset stats
    pub fn reset(&mut self) {
        self.stats = DetectionStats::new();
    }
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new().expect("Failed to create StatsTracker")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_stats_creation() {
        let stats = DetectionStats::new();
        assert_eq!(stats.events_processed(), 0);
        assert_eq!(stats.signatures_matched(), 0);
    }

    #[test]
    fn test_detection_stats_recording() {
        let mut stats = DetectionStats::new();

        stats.record_event();
        stats.record_event();
        stats.record_match();

        assert_eq!(stats.events_processed(), 2);
        assert_eq!(stats.signatures_matched(), 1);
    }

    #[test]
    fn test_detection_rate() {
        let mut stats = DetectionStats::new();

        for _ in 0..10 {
            stats.record_event();
        }
        for _ in 0..3 {
            stats.record_match();
        }

        assert!((stats.detection_rate() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_false_positive_rate() {
        let mut stats = DetectionStats::new();

        stats.record_match(); // true positive
        stats.record_match(); // true positive
        stats.record_false_positive();

        assert!((stats.false_positive_rate() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_stats_display() {
        let mut stats = DetectionStats::new();
        stats.record_event();
        stats.record_match();

        let display = format!("{}", stats);
        assert!(display.contains("events"));
        assert!(display.contains("matches"));
    }
}
