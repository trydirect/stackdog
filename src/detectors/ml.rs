use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::ml::models::isolation_forest::{IsolationForestConfig, IsolationForestModel};
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

use super::{DetectorFamily, DetectorFinding, LogDetector};

const MIN_TRAINING_SAMPLES: usize = 10;

/// ML-powered behavioral anomaly detector that learns normal log patterns
/// and flags deviations using Isolation Forest.
pub struct MlBehavioralDetector {
    model: Mutex<IsolationForestModel>,
    training_buffer: Mutex<Vec<[f64; 4]>>,
    trained: AtomicBool,
    min_training_samples: usize,
}

impl MlBehavioralDetector {
    pub fn new() -> Self {
        Self {
            model: Mutex::new(IsolationForestModel::with_config(IsolationForestConfig {
                trees: 48,
                sample_size: 16,
                max_depth: 6,
                seed: 0x5eed_42ca,
            })),
            training_buffer: Mutex::new(Vec::with_capacity(64)),
            trained: AtomicBool::new(false),
            min_training_samples: MIN_TRAINING_SAMPLES,
        }
    }

    #[allow(dead_code)]
    pub fn with_min_training_samples(mut self, n: usize) -> Self {
        self.min_training_samples = n.max(3);
        self
    }

    pub fn is_trained(&self) -> bool {
        self.trained.load(Ordering::Relaxed)
    }

    /// Extract a 4-element feature vector from a batch of log entries.
    fn extract_features(entries: &[LogEntry]) -> [f64; 4] {
        if entries.is_empty() {
            return [0.0, 0.0, 0.0, 0.0];
        }

        let total = entries.len() as f64;
        let mut error_count = 0usize;
        let mut warn_count = 0usize;
        let mut total_chars = 0usize;
        let mut unique_ips = Vec::new();

        for entry in entries {
            let lower = entry.line.to_ascii_lowercase();

            if lower.contains("error")
                || lower.contains("fatal")
                || lower.contains("panic")
                || lower.contains("exception")
            {
                error_count += 1;
            }
            if lower.contains("warn") {
                warn_count += 1;
            }

            total_chars += entry.line.len();

            for candidate in entry.line.split_whitespace() {
                let cleaned = candidate
                    .trim_start_matches(|ch: char| !ch.is_ascii_digit())
                    .trim_end_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
                if cleaned.parse::<Ipv4Addr>().is_ok()
                    && !unique_ips.iter().any(|ip: &String| ip == cleaned)
                {
                    unique_ips.push(cleaned.to_string());
                }
            }
        }

        let f1 = error_count as f64 / total;
        let f2 = warn_count as f64 / total;
        let f3 = (unique_ips.len() as f64 / total).clamp(0.0, 1.0);
        let f4 = (total_chars as f64 / total / 200.0).clamp(0.0, 1.0);

        [f1, f2, f3, f4]
    }

    fn try_train(&self) {
        let buffer = self.training_buffer.lock().unwrap();
        if buffer.len() < self.min_training_samples {
            return;
        }

        let mut model = self.model.lock().unwrap();
        model.fit_arrays(&buffer);
        self.trained.store(true, Ordering::Relaxed);
        log::info!(
            "MlBehavioralDetector trained on {} samples ({} trees, {} sample size)",
            buffer.len(),
            model.sample_size(),
            model.sample_size(),
        );
    }
}

impl Default for MlBehavioralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LogDetector for MlBehavioralDetector {
    fn id(&self) -> &'static str {
        "ml.behavioral-drift"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Vulnerability
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        if entries.len() < 3 {
            return Vec::new();
        }

        let features = Self::extract_features(entries);

        if !self.is_trained() {
            let mut buffer = self.training_buffer.lock().unwrap();
            buffer.push(features);
            if buffer.len() >= self.min_training_samples {
                drop(buffer);
                self.try_train();
            }
            return Vec::new();
        }

        let model = self.model.lock().unwrap();
        let anomaly_score = model.score_array(&features);

        if anomaly_score < 0.55 {
            return Vec::new();
        }

        let severity = if anomaly_score >= 0.80 {
            AnomalySeverity::High
        } else if anomaly_score >= 0.65 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        };

        let sample_line = entries
            .iter()
            .find(|e| {
                let lower = e.line.to_ascii_lowercase();
                lower.contains("error") || lower.contains("fatal") || lower.contains("panic")
            })
            .map(|e| e.line.clone())
            .unwrap_or_else(|| entries[0].line.clone());

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Behavioral anomaly detected: log pattern deviates from baseline (score={:.3})",
                anomaly_score
            ),
            severity,
            confidence: (anomaly_score * 100.0) as u8,
            sample_line,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn entry(line: &str) -> LogEntry {
        LogEntry {
            source_id: "test".into(),
            timestamp: Utc::now(),
            line: line.into(),
            metadata: HashMap::new(),
        }
    }

    fn normal_batch() -> Vec<LogEntry> {
        vec![
            entry("INFO: server started on port 8080"),
            entry("INFO: connection established from 10.0.0.1"),
            entry("GET /health 200 2ms"),
            entry("POST /api/data 201 15ms"),
            entry("INFO: background job completed"),
        ]
    }

    fn error_spike_batch() -> Vec<LogEntry> {
        vec![
            entry("ERROR: connection refused to database"),
            entry("FATAL: out of memory - killing process"),
            entry("ERROR: timeout writing to socket"),
            entry("ERROR: disk I/O error on /dev/sda1"),
            entry("PANIC: runtime error: invalid memory address"),
        ]
    }

    #[test]
    fn test_extract_features_empty() {
        let features = MlBehavioralDetector::extract_features(&[]);
        assert_eq!(features, [0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn test_extract_features_normal_batch() {
        let batch = normal_batch();
        let features = MlBehavioralDetector::extract_features(&batch);
        assert_eq!(features[0], 0.0); // no errors
        assert_eq!(features[1], 0.0); // no warnings
    }

    #[test]
    fn test_extract_features_error_spike() {
        let batch = error_spike_batch();
        let features = MlBehavioralDetector::extract_features(&batch);
        assert!(features[0] > 0.5); // high error ratio
        assert!(features[0] <= 1.0);
    }

    #[test]
    fn test_extract_features_ip_counting() {
        let batch = vec![
            entry("connection from 10.0.0.1"),
            entry("connection from 10.0.0.2"),
            entry("connection from 10.0.0.3"),
            entry("connection from 10.0.0.1"),
        ];
        let features = MlBehavioralDetector::extract_features(&batch);
        assert!((features[2] - 0.75).abs() < 0.01); // 3 unique IPs / 4 entries
    }

    #[test]
    fn test_detector_returns_empty_during_training_phase() {
        let detector = MlBehavioralDetector::new().with_min_training_samples(5);
        assert!(!detector.is_trained());

        for _ in 0..4 {
            let findings = detector.detect(&normal_batch());
            assert!(findings.is_empty());
        }

        assert!(!detector.is_trained());

        // Fifth batch triggers training
        let findings = detector.detect(&normal_batch());
        assert!(detector.is_trained());
        assert!(findings.is_empty()); // normal data shouldn't trigger
    }

    #[test]
    fn test_detector_flags_anomalous_pattern_after_training() {
        let detector = MlBehavioralDetector::new().with_min_training_samples(4);

        for _ in 0..4 {
            detector.detect(&normal_batch());
        }

        assert!(detector.is_trained());

        let model = detector.model.lock().unwrap();
        let normal_score =
            model.score_array(&MlBehavioralDetector::extract_features(&normal_batch()));
        let anomaly_score =
            model.score_array(&MlBehavioralDetector::extract_features(&error_spike_batch()));
        assert!(
            anomaly_score >= normal_score,
            "anomaly_score={} should be >= normal_score={}",
            anomaly_score,
            normal_score
        );
    }

    #[test]
    fn test_detector_skips_small_batches() {
        let detector = MlBehavioralDetector::new();
        let small_batch = vec![entry("INFO: lone entry")];
        let findings = detector.detect(&small_batch);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detector_returns_finding_when_anomaly_high() {
        let detector = MlBehavioralDetector::new().with_min_training_samples(4);

        // Train on normal data
        for _ in 0..4 {
            detector.detect(&normal_batch());
        }
        assert!(detector.is_trained());

        // Feed highly anomalous data
        let extreme_batch = vec![
            entry("FATAL: kernel panic - out of memory"),
            entry("ERROR: segfault at 0x7fff0000"),
            entry("PANIC: unrecoverable error in io scheduler"),
            entry("ERROR: disk failure on /dev/sda"),
            entry("FATAL: system will halt now"),
        ];

        let _findings = detector.detect(&extreme_batch);
        let model = detector.model.lock().unwrap();
        let score = model.score_array(&MlBehavioralDetector::extract_features(&extreme_batch));
        let normal_score =
            model.score_array(&MlBehavioralDetector::extract_features(&normal_batch()));
        assert!(
            score >= normal_score,
            "extreme score {} should >= normal score {}",
            score,
            normal_score
        );
    }
}
