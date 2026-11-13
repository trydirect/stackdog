//! Baseline learning

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::events::security::SecurityEvent;
use crate::ml::features::SecurityFeatures;

const FEATURE_NAMES: [&str; 4] = [
    "syscall_rate",
    "network_rate",
    "unique_processes",
    "privileged_calls",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureSummary {
    pub syscall_rate: f64,
    pub network_rate: f64,
    pub unique_processes: f64,
    pub privileged_calls: f64,
}

impl FeatureSummary {
    pub fn from_vector(vector: [f64; 4]) -> Self {
        Self {
            syscall_rate: vector[0],
            network_rate: vector[1],
            unique_processes: vector[2],
            privileged_calls: vector[3],
        }
    }

    pub fn as_vector(&self) -> [f64; 4] {
        [
            self.syscall_rate,
            self.network_rate,
            self.unique_processes,
            self.privileged_calls,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureBaseline {
    pub sample_count: u64,
    pub mean: FeatureSummary,
    pub stddev: FeatureSummary,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaselineDrift {
    pub score: f64,
    pub deviating_features: Vec<String>,
}

/// Baseline learner
pub struct BaselineLearner {
    baselines: HashMap<String, RunningFeatureStats>,
    deviation_threshold: f64,
}

#[derive(Debug, Clone)]
struct RunningFeatureStats {
    sample_count: u64,
    mean: [f64; 4],
    m2: [f64; 4],
    last_updated: DateTime<Utc>,
}

impl Default for RunningFeatureStats {
    fn default() -> Self {
        Self {
            sample_count: 0,
            mean: [0.0; 4],
            m2: [0.0; 4],
            last_updated: Utc::now(),
        }
    }
}

impl RunningFeatureStats {
    fn observe(&mut self, values: [f64; 4]) {
        self.sample_count += 1;
        let count = self.sample_count as f64;

        for (idx, value) in values.iter().enumerate() {
            let delta = value - self.mean[idx];
            self.mean[idx] += delta / count;
            let delta2 = value - self.mean[idx];
            self.m2[idx] += delta * delta2;
        }

        self.last_updated = Utc::now();
    }

    fn stddev(&self) -> [f64; 4] {
        if self.sample_count < 2 {
            return [0.0; 4];
        }

        let denominator = (self.sample_count - 1) as f64;
        let mut result = [0.0; 4];

        for (idx, value) in result.iter_mut().enumerate() {
            *value = (self.m2[idx] / denominator).sqrt();
        }

        result
    }

    fn to_baseline(&self) -> FeatureBaseline {
        FeatureBaseline {
            sample_count: self.sample_count,
            mean: FeatureSummary::from_vector(self.mean),
            stddev: FeatureSummary::from_vector(self.stddev()),
            last_updated: self.last_updated,
        }
    }
}

impl BaselineLearner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            baselines: HashMap::new(),
            deviation_threshold: 3.0,
        })
    }

    pub fn with_deviation_threshold(mut self, threshold: f64) -> Self {
        self.deviation_threshold = threshold.max(0.5);
        self
    }

    pub fn observe(&mut self, scope: impl Into<String>, features: &SecurityFeatures) {
        let entry = self.baselines.entry(scope.into()).or_default();
        entry.observe(features.as_vector());
    }

    pub fn observe_events(
        &mut self,
        scope: impl Into<String>,
        events: &[SecurityEvent],
        window_seconds: f64,
    ) -> SecurityFeatures {
        let features = SecurityFeatures::from_events(events, window_seconds);
        self.observe(scope, &features);
        features
    }

    pub fn baseline(&self, scope: &str) -> Option<FeatureBaseline> {
        self.baselines
            .get(scope)
            .map(RunningFeatureStats::to_baseline)
    }

    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.baselines.keys().map(String::as_str)
    }

    pub fn detect_drift(&self, scope: &str, features: &SecurityFeatures) -> Option<BaselineDrift> {
        let baseline = self.baselines.get(scope)?;
        if baseline.sample_count < 2 {
            return None;
        }

        let values = features.as_vector();
        let means = baseline.mean;
        let stddevs = baseline.stddev();
        let mut total_deviation = 0.0;
        let mut deviating_features = Vec::new();

        for idx in 0..FEATURE_NAMES.len() {
            let deviation = if stddevs[idx] > f64::EPSILON {
                (values[idx] - means[idx]).abs() / stddevs[idx]
            } else {
                let scale = means[idx].abs().max(1.0);
                (values[idx] - means[idx]).abs() / scale
            };

            total_deviation += deviation;
            if deviation >= self.deviation_threshold {
                deviating_features.push(FEATURE_NAMES[idx].to_string());
            }
        }

        Some(BaselineDrift {
            score: total_deviation / FEATURE_NAMES.len() as f64,
            deviating_features,
        })
    }
}

impl Default for BaselineLearner {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::security::SecurityEvent;
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::Utc;

    fn feature(syscall_rate: f64, network_rate: f64, unique_processes: u32) -> SecurityFeatures {
        SecurityFeatures {
            syscall_rate,
            network_rate,
            unique_processes,
            privileged_calls: 0,
        }
    }

    #[test]
    fn test_baseline_collection() {
        let mut learner = BaselineLearner::new().unwrap();
        learner.observe("global", &feature(10.0, 2.0, 3));
        learner.observe("global", &feature(12.0, 2.5, 4));

        let baseline = learner.baseline("global").unwrap();
        assert_eq!(baseline.sample_count, 2);
        assert_eq!(baseline.mean.syscall_rate, 11.0);
        assert_eq!(baseline.mean.unique_processes, 3.5);
    }

    #[test]
    fn test_drift_detection_flags_outlier() {
        let mut learner = BaselineLearner::new()
            .unwrap()
            .with_deviation_threshold(2.0);
        learner.observe("global", &feature(10.0, 2.0, 3));
        learner.observe("global", &feature(11.0, 2.1, 3));
        learner.observe("global", &feature(9.5, 1.9, 2));

        let drift = learner
            .detect_drift("global", &feature(25.0, 9.0, 12))
            .unwrap();

        assert!(drift.score > 2.0);
        assert!(drift
            .deviating_features
            .contains(&"syscall_rate".to_string()));
        assert!(drift
            .deviating_features
            .contains(&"network_rate".to_string()));
    }

    #[test]
    fn test_observe_events_extracts_features_before_learning() {
        let mut learner = BaselineLearner::new().unwrap();
        let events = vec![
            SecurityEvent::Syscall(SyscallEvent::new(1, 0, SyscallType::Execve, Utc::now())),
            SecurityEvent::Syscall(SyscallEvent::new(1, 0, SyscallType::Connect, Utc::now())),
        ];

        let features = learner.observe_events("container:abc", &events, 1.0);
        let baseline = learner.baseline("container:abc").unwrap();

        assert_eq!(features.syscall_rate, 2.0);
        assert_eq!(baseline.sample_count, 1);
    }
}
