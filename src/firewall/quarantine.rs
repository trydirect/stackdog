//! Container quarantine
//!
//! Isolates compromised containers

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::firewall::nftables::{NfChain, NfTable, NfTablesBackend};

/// Quarantine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineState {
    Quarantined,
    Released,
    Failed,
}

/// Quarantine information
#[derive(Debug, Clone)]
pub struct QuarantineInfo {
    pub container_id: String,
    pub quarantined_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub state: QuarantineState,
    pub reason: Option<String>,
}

/// Container quarantine manager
pub struct QuarantineManager {
    #[cfg(target_os = "linux")]
    nft: Option<NfTablesBackend>,

    states: Arc<RwLock<HashMap<String, QuarantineInfo>>>,
    table_name: String,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let nft = NfTablesBackend::new().ok();

            Ok(Self {
                nft,
                states: Arc::new(RwLock::new(HashMap::new())),
                table_name: "inet_stackdog_quarantine".to_string(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Quarantine only available on Linux");
        }
    }

    /// Quarantine a container
    pub fn quarantine(&mut self, container_id: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Check if already quarantined
            {
                let states = self.states.read().unwrap();
                if let Some(info) = states.get(container_id) {
                    if info.state == QuarantineState::Quarantined {
                        anyhow::bail!("Container already quarantined");
                    }
                }
            }

            // Setup nftables table if needed
            self.setup_quarantine_table()?;

            // Get container IP (would need Docker API integration)
            // For now, log the action
            log::info!("Quarantining container: {}", container_id);

            // Add to states
            let info = QuarantineInfo {
                container_id: container_id.to_string(),
                quarantined_at: Utc::now(),
                released_at: None,
                state: QuarantineState::Quarantined,
                reason: None,
            };

            {
                let mut states = self.states.write().unwrap();
                states.insert(container_id.to_string(), info);
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Quarantine only available on Linux");
        }
    }

    /// Release a container from quarantine
    pub fn release(&mut self, container_id: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Check if quarantined
            {
                let states = self.states.read().unwrap();
                if let Some(info) = states.get(container_id) {
                    if info.state != QuarantineState::Quarantined {
                        anyhow::bail!("Container not quarantined");
                    }
                } else {
                    anyhow::bail!("Container not found in quarantine");
                }
            }

            // Remove nftables rules (would need container IP)
            log::info!("Releasing container from quarantine: {}", container_id);

            // Update state
            {
                let mut states = self.states.write().unwrap();
                if let Some(info) = states.get_mut(container_id) {
                    info.released_at = Some(Utc::now());
                    info.state = QuarantineState::Released;
                }
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Quarantine only available on Linux");
        }
    }

    /// Rollback quarantine (release and cleanup)
    pub fn rollback(&mut self, container_id: &str) -> Result<()> {
        self.release(container_id)
    }

    /// Get quarantine state for a container
    pub fn get_state(&self, container_id: &str) -> Option<QuarantineState> {
        let states = self.states.read().unwrap();
        states.get(container_id).map(|info| info.state)
    }

    /// Get all quarantined containers
    pub fn get_quarantined_containers(&self) -> Vec<String> {
        let states = self.states.read().unwrap();
        states
            .iter()
            .filter(|(_, info)| info.state == QuarantineState::Quarantined)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get quarantine info for a container
    pub fn get_quarantine_info(&self, container_id: &str) -> Option<QuarantineInfo> {
        let states = self.states.read().unwrap();
        states.get(container_id).cloned()
    }

    /// Setup quarantine nftables table
    #[cfg(target_os = "linux")]
    fn setup_quarantine_table(&mut self) -> Result<()> {
        if let Some(ref nft) = self.nft {
            let table = NfTable::new("inet", &self.table_name);

            // Try to create table (may already exist)
            let _ = nft.create_table(&table);

            // Create input chain
            let input_chain = NfChain::new(&table, "quarantine_input", "filter");
            let _ = nft.create_chain(&input_chain);

            // Create output chain
            let output_chain = NfChain::new(&table, "quarantine_output", "filter");
            let _ = nft.create_chain(&output_chain);
        }

        Ok(())
    }

    /// Get quarantine statistics
    pub fn get_stats(&self) -> QuarantineStats {
        let states = self.states.read().unwrap();

        let mut currently_quarantined = 0;
        let mut released = 0;
        let mut failed = 0;

        for info in states.values() {
            match info.state {
                QuarantineState::Quarantined => currently_quarantined += 1,
                QuarantineState::Released => released += 1,
                QuarantineState::Failed => failed += 1,
            }
        }

        QuarantineStats {
            currently_quarantined,
            total_quarantined: states.len() as u64,
            released,
            failed,
        }
    }
}

impl Default for QuarantineManager {
    fn default() -> Self {
        Self::new().expect("Failed to create QuarantineManager")
    }
}

/// Quarantine statistics
#[derive(Debug, Clone, Default)]
pub struct QuarantineStats {
    pub currently_quarantined: u64,
    pub total_quarantined: u64,
    pub released: u64,
    pub failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_state_variants() {
        let _quarantined = QuarantineState::Quarantined;
        let _released = QuarantineState::Released;
        let _failed = QuarantineState::Failed;
    }

    #[test]
    fn test_quarantine_info_creation() {
        let info = QuarantineInfo {
            container_id: "test123".to_string(),
            quarantined_at: Utc::now(),
            released_at: None,
            state: QuarantineState::Quarantined,
            reason: Some("Test".to_string()),
        };

        assert_eq!(info.container_id, "test123");
        assert_eq!(info.state, QuarantineState::Quarantined);
    }
}
