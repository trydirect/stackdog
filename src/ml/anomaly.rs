//! Anomaly detection
//!
//! Detects anomalies in security events

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::baselines::learning::{BaselineDrift, BaselineLearner};
use crate::events::security::SecurityEvent;
use crate::ml::features::SecurityFeatures;
use crate::ml::models::isolation_forest::{IsolationForestConfig, IsolationForestModel};
use crate::ml::scorer::{Scorer, ThreatScore};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub anomaly_threshold: f64,
    pub drift_threshold: f64,
    pub drift_weight: f64,
    pub forest: IsolationForestConfig,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 0.65,
            drift_threshold: 3.0,
            drift_weight: 0.35,
            forest: IsolationForestConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyAssessment {
    pub anomaly_score: f64,
    pub drift_score: Option<f64>,
    pub combined_score: f64,
    pub threat_score: ThreatScore,
    pub is_anomalous: bool,
    pub reasons: Vec<String>,
}

/// Anomaly detector
pub struct AnomalyDetector {
    config: DetectorConfig,
    model: IsolationForestModel,
    baseline_learner: BaselineLearner,
    scorer: Scorer,
}

impl AnomalyDetector {
    pub fn new() -> Result<Self> {
        Self::with_config(DetectorConfig::default())
    }

    pub fn with_config(config: DetectorConfig) -> Result<Self> {
        let baseline_learner =
            BaselineLearner::new()?.with_deviation_threshold(config.drift_threshold);
        let scorer = Scorer::new()?.with_drift_weight(config.drift_weight);

        Ok(Self {
            model: IsolationForestModel::with_config(config.forest.clone()),
            baseline_learner,
            scorer,
            config,
        })
    }

    pub fn train(&mut self, training_data: &[SecurityFeatures]) -> Result<()> {
        ensure!(!training_data.is_empty(), "training data cannot be empty");
        self.model.fit(training_data);
        Ok(())
    }

    pub fn learn_baseline(&mut self, scope: &str, samples: &[SecurityFeatures]) {
        for sample in samples {
            self.baseline_learner.observe(scope.to_string(), sample);
        }
    }

    pub fn assess(&self, scope: &str, features: &SecurityFeatures) -> Result<AnomalyAssessment> {
        let anomaly_score = self.model.score(features);
        let drift = self.baseline_learner.detect_drift(scope, features);
        Ok(self.build_assessment(anomaly_score, drift))
    }

    pub fn assess_events(
        &self,
        scope: &str,
        events: &[SecurityEvent],
        window_seconds: f64,
    ) -> Result<AnomalyAssessment> {
        let features = SecurityFeatures::from_events(events, window_seconds);
        self.assess(scope, &features)
    }

    pub fn model(&self) -> &IsolationForestModel {
        &self.model
    }

    fn build_assessment(
        &self,
        anomaly_score: f64,
        drift: Option<BaselineDrift>,
    ) -> AnomalyAssessment {
        let mut reasons = Vec::new();
        if anomaly_score >= self.config.anomaly_threshold {
            reasons.push(format!("isolation_forest_score={anomaly_score:.3}"));
        }

        let drift_score = drift.as_ref().map(|drift| normalize_drift(drift.score));
        if let Some(drift) = drift
            .as_ref()
            .filter(|drift| !drift.deviating_features.is_empty())
        {
            reasons.push(format!(
                "baseline_drift={:.3} [{}]",
                drift.score,
                drift.deviating_features.join(", ")
            ));
        }

        let combined_score = self.scorer.combined_score(anomaly_score, drift_score);
        let threat_score = self.scorer.score(anomaly_score, drift_score);
        let is_anomalous =
            combined_score >= self.config.anomaly_threshold || drift_score.unwrap_or(0.0) > 0.50;

        AnomalyAssessment {
            anomaly_score,
            drift_score,
            combined_score,
            threat_score,
            is_anomalous,
            reasons,
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

fn normalize_drift(score: f64) -> f64 {
    if score <= 0.0 {
        0.0
    } else {
        (score / (score + 3.0)).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature(syscall_rate: f64, network_rate: f64, unique_processes: u32) -> SecurityFeatures {
        SecurityFeatures {
            syscall_rate,
            network_rate,
            unique_processes,
            privileged_calls: 0,
        }
    }

    #[test]
    fn test_training_requires_samples() {
        let mut detector = AnomalyDetector::new().unwrap();
        assert!(detector.train(&[]).is_err());
    }

    #[test]
    fn test_detector_flags_real_outlier() {
        let mut detector = AnomalyDetector::with_config(DetectorConfig {
            anomaly_threshold: 0.55,
            ..DetectorConfig::default()
        })
        .unwrap();
        let baseline = vec![
            feature(10.0, 2.0, 3),
            feature(10.5, 2.1, 3),
            feature(9.8, 1.9, 2),
            feature(10.2, 2.0, 3),
            feature(10.1, 2.2, 3),
        ];

        detector.train(&baseline).unwrap();
        detector.learn_baseline("global", &baseline);

        let assessment = detector.assess("global", &feature(28.0, 9.0, 12)).unwrap();

        assert!(assessment.is_anomalous);
        assert!(assessment.combined_score >= 0.55);
        assert!(assessment.threat_score >= ThreatScore::Medium);
        assert!(!assessment.reasons.is_empty());
    }
}
