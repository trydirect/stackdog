//! Isolation Forest model
//!
//! Implementation of Isolation Forest for anomaly detection using Candle

use serde::{Deserialize, Serialize};

use crate::ml::features::SecurityFeatures;

/// Isolation Forest model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForestModel {
    config: IsolationForestConfig,
    trees: Vec<IsolationTree>,
    sample_size: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IsolationForestConfig {
    pub trees: usize,
    pub sample_size: usize,
    pub max_depth: usize,
    pub seed: u64,
}

impl Default for IsolationForestConfig {
    fn default() -> Self {
        Self {
            trees: 64,
            sample_size: 32,
            max_depth: 8,
            seed: 0x5eed_cafe_d00d_f00d,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationTree {
    root: IsolationNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum IsolationNode {
    External {
        size: usize,
    },
    Internal {
        feature: usize,
        threshold: f64,
        left: Box<IsolationNode>,
        right: Box<IsolationNode>,
    },
}

#[derive(Debug, Clone)]
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn gen_range_usize(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() % upper as u64) as usize
        }
    }

    fn gen_range_f64(&mut self, min: f64, max: f64) -> f64 {
        if (max - min).abs() <= f64::EPSILON {
            min
        } else {
            let fraction = self.next_u64() as f64 / u64::MAX as f64;
            min + fraction * (max - min)
        }
    }
}

impl IsolationForestModel {
    pub fn new() -> Self {
        Self::with_config(IsolationForestConfig::default())
    }

    pub fn with_config(config: IsolationForestConfig) -> Self {
        Self {
            config,
            trees: Vec::new(),
            sample_size: 0,
        }
    }

    pub fn fit(&mut self, dataset: &[SecurityFeatures]) {
        let rows: Vec<_> = dataset.iter().map(SecurityFeatures::as_vector).collect();
        self.fit_arrays(&rows);
    }

    /// Fit the model from raw `[f64; 4]` feature arrays.
    pub fn fit_arrays(&mut self, dataset: &[[f64; 4]]) {
        self.trees.clear();
        if dataset.is_empty() {
            self.sample_size = 0;
            return;
        }

        let rows = dataset.to_vec();
        self.sample_size = self.config.sample_size.min(rows.len()).max(1);
        let max_depth = self
            .config
            .max_depth
            .max((self.sample_size as f64).log2().ceil() as usize);

        let mut rng = SimpleRng::new(self.config.seed);
        self.trees = (0..self.config.trees)
            .map(|_| {
                let sample = sample_without_replacement(&rows, self.sample_size, &mut rng);
                IsolationTree {
                    root: build_tree(&sample, 0, max_depth, &mut rng),
                }
            })
            .collect();
    }

    pub fn score(&self, sample: &SecurityFeatures) -> f64 {
        self.score_array(&sample.as_vector())
    }

    /// Score a raw `[f64; 4]` feature vector. Higher scores are more anomalous.
    pub fn score_array(&self, vector: &[f64; 4]) -> f64 {
        if self.trees.is_empty() || self.sample_size <= 1 {
            return 0.0;
        }

        let average_path = self
            .trees
            .iter()
            .map(|tree| path_length(&tree.root, vector, 0))
            .sum::<f64>()
            / self.trees.len() as f64;

        let normalization = average_path_length(self.sample_size);
        if normalization <= f64::EPSILON {
            0.0
        } else {
            2f64.powf(-(average_path / normalization)).clamp(0.0, 1.0)
        }
    }

    pub fn is_trained(&self) -> bool {
        !self.trees.is_empty()
    }

    pub fn sample_size(&self) -> usize {
        self.sample_size
    }
}

impl Default for IsolationForestModel {
    fn default() -> Self {
        Self::new()
    }
}

fn sample_without_replacement(
    data: &[[f64; 4]],
    count: usize,
    rng: &mut SimpleRng,
) -> Vec<[f64; 4]> {
    if count >= data.len() {
        return data.to_vec();
    }

    let mut indices: Vec<usize> = (0..data.len()).collect();
    for idx in 0..count {
        let swap_idx = idx + rng.gen_range_usize(data.len() - idx);
        indices.swap(idx, swap_idx);
    }

    indices
        .into_iter()
        .take(count)
        .map(|index| data[index])
        .collect()
}

fn build_tree(
    rows: &[[f64; 4]],
    depth: usize,
    max_depth: usize,
    rng: &mut SimpleRng,
) -> IsolationNode {
    if rows.len() <= 1 || depth >= max_depth {
        return IsolationNode::External { size: rows.len() };
    }

    let varying_features = (0..4)
        .filter_map(|feature| {
            let (min, max) = min_max(rows, feature);
            if (max - min).abs() > f64::EPSILON {
                Some((feature, min, max))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let Some(&(feature, min, max)) =
        varying_features.get(rng.gen_range_usize(varying_features.len()))
    else {
        return IsolationNode::External { size: rows.len() };
    };

    let threshold = rng.gen_range_f64(min, max);
    let (left_rows, right_rows): (Vec<_>, Vec<_>) = rows
        .iter()
        .copied()
        .partition(|row| row[feature] < threshold);

    if left_rows.is_empty() || right_rows.is_empty() {
        return IsolationNode::External { size: rows.len() };
    }

    IsolationNode::Internal {
        feature,
        threshold,
        left: Box::new(build_tree(&left_rows, depth + 1, max_depth, rng)),
        right: Box::new(build_tree(&right_rows, depth + 1, max_depth, rng)),
    }
}

fn min_max(rows: &[[f64; 4]], feature: usize) -> (f64, f64) {
    rows.iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(min, max), row| {
            (min.min(row[feature]), max.max(row[feature]))
        })
}

fn path_length(node: &IsolationNode, sample: &[f64; 4], depth: usize) -> f64 {
    match node {
        IsolationNode::External { size } => depth as f64 + average_path_length(*size),
        IsolationNode::Internal {
            feature,
            threshold,
            left,
            right,
        } => {
            if sample[*feature] < *threshold {
                path_length(left, sample, depth + 1)
            } else {
                path_length(right, sample, depth + 1)
            }
        }
    }
}

fn average_path_length(sample_size: usize) -> f64 {
    match sample_size {
        0 | 1 => 0.0,
        2 => 1.0,
        n => {
            let harmonic = (1..n).map(|value| 1.0 / value as f64).sum::<f64>();
            2.0 * harmonic - (2.0 * (n - 1) as f64 / n as f64)
        }
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
    fn test_anomaly_scoring_ranks_outlier_higher_than_inlier() {
        let mut model = IsolationForestModel::with_config(IsolationForestConfig {
            trees: 48,
            sample_size: 16,
            max_depth: 6,
            seed: 42,
        });
        let training = vec![
            feature(10.0, 2.0, 3),
            feature(11.0, 2.1, 3),
            feature(9.8, 1.9, 2),
            feature(10.5, 2.2, 3),
            feature(10.2, 2.0, 2),
            feature(11.1, 1.8, 3),
            feature(9.9, 2.3, 3),
            feature(10.7, 2.0, 2),
        ];
        model.fit(&training);

        let inlier = model.score(&feature(10.4, 2.1, 3));
        let outlier = model.score(&feature(30.0, 10.0, 15));

        assert!(model.is_trained());
        assert!(outlier > inlier);
        assert!(outlier > 0.50);
    }

    #[test]
    fn test_model_persistence_round_trip() {
        let mut model = IsolationForestModel::with_config(IsolationForestConfig {
            trees: 12,
            sample_size: 8,
            max_depth: 5,
            seed: 99,
        });
        let training = vec![
            feature(10.0, 2.0, 3),
            feature(11.0, 2.2, 3),
            feature(9.5, 1.9, 2),
            feature(10.7, 2.1, 3),
        ];
        model.fit(&training);

        let serialized = serde_json::to_string(&model).unwrap();
        let restored: IsolationForestModel = serde_json::from_str(&serialized).unwrap();

        assert_eq!(restored.sample_size(), model.sample_size());
        assert_eq!(
            restored.score(&feature(25.0, 8.0, 10)),
            model.score(&feature(25.0, 8.0, 10))
        );
    }
}
