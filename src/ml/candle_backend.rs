//! Candle ML backend
//!
//! Provides ML inference using Candle (HuggingFace Rust framework)

use anyhow::Result;

use crate::ml::features::SecurityFeatures;

/// Candle ML backend
pub struct CandleBackend {
    input_size: usize,
}

impl CandleBackend {
    pub fn new() -> Result<Self> {
        Ok(Self { input_size: 4 })
    }

    pub fn input_size(&self) -> usize {
        self.input_size
    }

    pub fn feature_vector(&self, features: &SecurityFeatures) -> Vec<f32> {
        features
            .as_vector()
            .into_iter()
            .map(|value| value as f32)
            .collect()
    }

    pub fn batch_feature_vectors(&self, batch: &[SecurityFeatures]) -> Vec<Vec<f32>> {
        batch
            .iter()
            .map(|features| self.feature_vector(features))
            .collect()
    }

    pub fn is_enabled(&self) -> bool {
        cfg!(feature = "ml")
    }

    #[cfg(feature = "ml")]
    pub fn tensor_from_features(&self, features: &SecurityFeatures) -> Result<candle_core::Tensor> {
        let data = self.feature_vector(features);
        Ok(candle_core::Tensor::from_vec(
            data,
            (1, self.input_size),
            &candle_core::Device::Cpu,
        )?)
    }

    #[cfg(feature = "ml")]
    pub fn tensor_from_batch(&self, batch: &[SecurityFeatures]) -> Result<candle_core::Tensor> {
        let data = self
            .batch_feature_vectors(batch)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        Ok(candle_core::Tensor::from_vec(
            data,
            (batch.len(), self.input_size),
            &candle_core::Device::Cpu,
        )?)
    }
}

impl Default for CandleBackend {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_vector_conversion() {
        let backend = CandleBackend::new().unwrap();
        let features = SecurityFeatures {
            syscall_rate: 4.0,
            network_rate: 1.5,
            unique_processes: 2,
            privileged_calls: 1,
        };

        assert_eq!(backend.input_size(), 4);
        assert_eq!(backend.feature_vector(&features), vec![4.0, 1.5, 2.0, 1.0]);
    }
}
