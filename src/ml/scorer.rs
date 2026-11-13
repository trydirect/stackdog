//! Threat scoring
//!
//! Calculates threat scores from ML output

use anyhow::{ensure, Result};

/// Threat score levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatScore {
    Normal,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatScore {
    fn elevate(self) -> Self {
        match self {
            ThreatScore::Normal => ThreatScore::Low,
            ThreatScore::Low => ThreatScore::Medium,
            ThreatScore::Medium => ThreatScore::High,
            ThreatScore::High | ThreatScore::Critical => ThreatScore::Critical,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoreThresholds {
    pub low: f64,
    pub medium: f64,
    pub high: f64,
    pub critical: f64,
}

impl Default for ScoreThresholds {
    fn default() -> Self {
        Self {
            low: 0.30,
            medium: 0.50,
            high: 0.75,
            critical: 0.90,
        }
    }
}

/// Threat scorer
pub struct Scorer {
    thresholds: ScoreThresholds,
    drift_weight: f64,
}

impl Scorer {
    pub fn new() -> Result<Self> {
        Self::with_thresholds(ScoreThresholds::default())
    }

    pub fn with_thresholds(thresholds: ScoreThresholds) -> Result<Self> {
        ensure!(
            thresholds.low >= 0.0
                && thresholds.low <= thresholds.medium
                && thresholds.medium <= thresholds.high
                && thresholds.high <= thresholds.critical
                && thresholds.critical <= 1.0,
            "invalid score thresholds"
        );

        Ok(Self {
            thresholds,
            drift_weight: 0.35,
        })
    }

    pub fn with_drift_weight(mut self, weight: f64) -> Self {
        self.drift_weight = weight.clamp(0.0, 1.0);
        self
    }

    pub fn combined_score(&self, anomaly_score: f64, drift_score: Option<f64>) -> f64 {
        let anomaly = anomaly_score.clamp(0.0, 1.0);
        match drift_score {
            Some(drift) => {
                let drift = drift.clamp(0.0, 1.0);
                ((1.0 - self.drift_weight) * anomaly + self.drift_weight * drift).clamp(0.0, 1.0)
            }
            None => anomaly,
        }
    }

    pub fn score(&self, anomaly_score: f64, drift_score: Option<f64>) -> ThreatScore {
        let combined = self.combined_score(anomaly_score, drift_score);

        if combined >= self.thresholds.critical {
            ThreatScore::Critical
        } else if combined >= self.thresholds.high {
            ThreatScore::High
        } else if combined >= self.thresholds.medium {
            ThreatScore::Medium
        } else if combined >= self.thresholds.low {
            ThreatScore::Low
        } else {
            ThreatScore::Normal
        }
    }

    pub fn aggregate(&self, scores: &[ThreatScore]) -> ThreatScore {
        let Some(mut aggregate) = scores.iter().copied().max() else {
            return ThreatScore::Normal;
        };

        let elevated_count = scores
            .iter()
            .filter(|score| **score >= ThreatScore::Medium)
            .count();

        if elevated_count >= 3 {
            aggregate = aggregate.elevate();
        }

        aggregate
    }

    pub fn threshold_exceeded(&self, score: ThreatScore, threshold: ThreatScore) -> bool {
        score >= threshold
    }
}

impl Default for Scorer {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_score_calculation() {
        let scorer = Scorer::new().unwrap();
        assert_eq!(scorer.score(0.15, None), ThreatScore::Normal);
        assert_eq!(scorer.score(0.35, None), ThreatScore::Low);
        assert_eq!(scorer.score(0.60, None), ThreatScore::Medium);
        assert_eq!(scorer.score(0.80, None), ThreatScore::High);
        assert_eq!(scorer.score(0.95, None), ThreatScore::Critical);
    }

    #[test]
    fn test_score_aggregation() {
        let scorer = Scorer::new().unwrap();
        let aggregated = scorer.aggregate(&[
            ThreatScore::Low,
            ThreatScore::Medium,
            ThreatScore::High,
            ThreatScore::Medium,
        ]);

        assert_eq!(aggregated, ThreatScore::Critical);
    }

    #[test]
    fn test_threshold_detection() {
        let scorer = Scorer::new().unwrap();
        assert!(scorer.threshold_exceeded(ThreatScore::High, ThreatScore::Medium));
        assert!(!scorer.threshold_exceeded(ThreatScore::Low, ThreatScore::High));
    }
}
