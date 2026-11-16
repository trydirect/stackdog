//! Alert deduplication
//!
//! Deduplicates alerts based on fingerprint and time window

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::alerting::alert::Alert;

/// Deduplication configuration
#[derive(Debug, Clone)]
pub struct DedupConfig {
    enabled: bool,
    window_seconds: u64,
    aggregation: bool,
}

impl DedupConfig {
    /// Create a new config with given values
    pub fn new(enabled: bool, window_seconds: u64, aggregation: bool) -> Self {
        Self {
            enabled,
            window_seconds,
            aggregation,
        }
    }

    /// Set enabled
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set window seconds
    pub fn with_window_seconds(mut self, seconds: u64) -> Self {
        self.window_seconds = seconds;
        self
    }

    /// Set aggregation
    pub fn with_aggregation(mut self, aggregation: bool) -> Self {
        self.aggregation = aggregation;
        self
    }

    /// Check if enabled
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Get window seconds
    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    /// Check if aggregation enabled
    pub fn aggregation_enabled(&self) -> bool {
        self.aggregation
    }
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self::new(true, 300, true)
    }
}

/// Fingerprint for deduplication
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Create new fingerprint
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Get value
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Deduplication result
#[derive(Debug, Clone)]
pub struct DedupResult {
    pub is_duplicate: bool,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
}

/// Alert deduplicator
pub struct AlertDeduplicator {
    config: DedupConfig,
    fingerprints: HashMap<Fingerprint, FingerprintEntry>,
    stats: DedupStats,
}

#[derive(Debug, Clone)]
struct FingerprintEntry {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    count: u32,
}

#[derive(Debug, Clone, Default)]
struct DedupStats {
    total_checked: u64,
    duplicates_found: u64,
}

impl AlertDeduplicator {
    /// Create new deduplicator
    pub fn new(config: DedupConfig) -> Self {
        Self {
            config,
            fingerprints: HashMap::new(),
            stats: DedupStats::default(),
        }
    }

    /// Calculate fingerprint for alert
    pub fn calculate_fingerprint(&self, alert: &Alert) -> Fingerprint {
        Fingerprint::new(alert.fingerprint())
    }

    /// Check if alert is duplicate
    pub fn is_duplicate(&mut self, alert: &Alert) -> bool {
        if !self.config.enabled {
            return false;
        }

        let fingerprint = self.calculate_fingerprint(alert);
        let now = Utc::now();

        if let Some(entry) = self.fingerprints.get(&fingerprint) {
            // Check if within window
            let elapsed = now - entry.last_seen;
            if elapsed.num_seconds() as u64 <= self.config.window_seconds {
                return true;
            }
        }

        // Not a duplicate or window expired
        self.fingerprints.insert(
            fingerprint,
            FingerprintEntry {
                first_seen: now,
                last_seen: now,
                count: 1,
            },
        );

        false
    }

    /// Check if a raw key is duplicate (bypasses Alert fingerprinting).
    /// Useful when the caller wants to dedup on a subset of alert fields.
    pub fn is_duplicate_key(&mut self, key: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let fingerprint = Fingerprint::new(key.to_string());
        let now = Utc::now();

        if let Some(entry) = self.fingerprints.get(&fingerprint) {
            let elapsed = now - entry.last_seen;
            if elapsed.num_seconds() as u64 <= self.config.window_seconds {
                return true;
            }
        }

        self.fingerprints.insert(
            fingerprint,
            FingerprintEntry {
                first_seen: now,
                last_seen: now,
                count: 1,
            },
        );

        false
    }

    /// Check alert and return result with count
    pub fn check(&mut self, alert: &Alert) -> DedupResult {
        self.stats.total_checked += 1;

        if !self.config.enabled {
            return DedupResult {
                is_duplicate: false,
                count: 1,
                first_seen: Utc::now(),
            };
        }

        let fingerprint = self.calculate_fingerprint(alert);
        let now = Utc::now();

        if let Some(entry) = self.fingerprints.get_mut(&fingerprint) {
            let elapsed = now - entry.last_seen;

            if elapsed.num_seconds() as u64 <= self.config.window_seconds {
                // Duplicate within window
                entry.count += 1;
                entry.last_seen = now;
                self.stats.duplicates_found += 1;

                return DedupResult {
                    is_duplicate: true,
                    count: entry.count,
                    first_seen: entry.first_seen,
                };
            } else {
                // Window expired, reset
                *entry = FingerprintEntry {
                    first_seen: now,
                    last_seen: now,
                    count: 1,
                };
            }
        } else {
            // New fingerprint
            self.fingerprints.insert(
                fingerprint,
                FingerprintEntry {
                    first_seen: now,
                    last_seen: now,
                    count: 1,
                },
            );
        }

        DedupResult {
            is_duplicate: false,
            count: 1,
            first_seen: now,
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> DedupStatsPublic {
        DedupStatsPublic {
            total_checked: self.stats.total_checked,
            duplicates_found: self.stats.duplicates_found,
        }
    }

    /// Clear old fingerprints
    pub fn clear_expired(&mut self) {
        let now = Utc::now();
        let window = self.config.window_seconds;

        self.fingerprints.retain(|_, entry| {
            let elapsed = now - entry.last_seen;
            elapsed.num_seconds() as u64 <= window
        });
    }
}

/// Public deduplication stats
#[derive(Debug, Clone, Default)]
pub struct DedupStatsPublic {
    pub total_checked: u64,
    pub duplicates_found: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_config_default() {
        let config = DedupConfig::default();
        assert!(config.enabled());
        assert_eq!(config.window_seconds(), 300);
    }

    #[test]
    fn test_fingerprint_display() {
        let fp = Fingerprint::new("test".to_string());
        assert_eq!(format!("{}", fp), "test");
    }
}
