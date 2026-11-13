//! Feature extraction for ML
//!
//! Extracts features from security events for anomaly detection

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::events::security::SecurityEvent;
use crate::events::syscall::SyscallType;

/// Security features for ML model
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub syscall_rate: f64,
    pub network_rate: f64,
    pub unique_processes: u32,
    pub privileged_calls: u32,
}

impl SecurityFeatures {
    pub fn new() -> Self {
        Self {
            syscall_rate: 0.0,
            network_rate: 0.0,
            unique_processes: 0,
            privileged_calls: 0,
        }
    }

    /// Build a feature vector from a batch of security events observed over a window.
    pub fn from_events(events: &[SecurityEvent], window_seconds: f64) -> Self {
        if events.is_empty() {
            return Self::default();
        }

        let effective_window = if window_seconds > 0.0 {
            window_seconds
        } else {
            1.0
        };

        let mut syscall_count = 0usize;
        let mut network_count = 0usize;
        let mut unique_processes = HashSet::new();
        let mut privileged_calls = 0u32;

        for event in events {
            match event {
                SecurityEvent::Syscall(syscall) => {
                    syscall_count += 1;
                    unique_processes.insert(syscall.pid);

                    if matches!(
                        syscall.syscall_type,
                        SyscallType::Ptrace
                            | SyscallType::Setuid
                            | SyscallType::Setgid
                            | SyscallType::Mount
                            | SyscallType::Umount
                    ) {
                        privileged_calls += 1;
                    }

                    if matches!(
                        syscall.syscall_type,
                        SyscallType::Connect
                            | SyscallType::Accept
                            | SyscallType::Bind
                            | SyscallType::Listen
                            | SyscallType::Socket
                            | SyscallType::Sendto
                    ) {
                        network_count += 1;
                    }
                }
                SecurityEvent::Network(_) => {
                    network_count += 1;
                }
                SecurityEvent::Container(_) | SecurityEvent::Alert(_) => {}
            }
        }

        Self {
            syscall_rate: syscall_count as f64 / effective_window,
            network_rate: network_count as f64 / effective_window,
            unique_processes: unique_processes.len() as u32,
            privileged_calls,
        }
    }

    pub fn as_vector(&self) -> [f64; 4] {
        [
            self.syscall_rate,
            self.network_rate,
            self.unique_processes as f64,
            self.privileged_calls as f64,
        ]
    }

    pub fn from_vector(vector: [f64; 4]) -> Self {
        Self {
            syscall_rate: vector[0],
            network_rate: vector[1],
            unique_processes: vector[2].round().max(0.0) as u32,
            privileged_calls: vector[3].round().max(0.0) as u32,
        }
    }
}

impl Default for SecurityFeatures {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::security::{NetworkEvent, SecurityEvent};
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::Utc;

    #[test]
    fn test_feature_vector_creation_from_events() {
        let events = vec![
            SecurityEvent::Syscall(SyscallEvent::new(100, 0, SyscallType::Execve, Utc::now())),
            SecurityEvent::Syscall(SyscallEvent::new(100, 0, SyscallType::Connect, Utc::now())),
            SecurityEvent::Syscall(SyscallEvent::new(200, 0, SyscallType::Ptrace, Utc::now())),
            SecurityEvent::Network(NetworkEvent {
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "198.51.100.12".to_string(),
                src_port: 40000,
                dst_port: 443,
                protocol: "tcp".to_string(),
                timestamp: Utc::now(),
                container_id: Some("abc".to_string()),
            }),
        ];

        let features = SecurityFeatures::from_events(&events, 2.0);

        assert_eq!(features.syscall_rate, 1.5);
        assert_eq!(features.network_rate, 1.0);
        assert_eq!(features.unique_processes, 2);
        assert_eq!(features.privileged_calls, 1);
    }

    #[test]
    fn test_feature_vector_round_trip() {
        let features = SecurityFeatures {
            syscall_rate: 12.5,
            network_rate: 3.0,
            unique_processes: 7,
            privileged_calls: 2,
        };

        assert_eq!(
            SecurityFeatures::from_vector(features.as_vector()),
            features
        );
    }
}
