//! Stackdog Security Library
//!
//! Security platform for Docker containers and Linux servers
//!
//! ## Features
//!
//! - **eBPF-based syscall monitoring** - Real-time event collection
//! - **Event enrichment** - Container detection, process info
//! - **Rule engine** - Signature-based detection
//! - **Threat scoring** - ML-ready scoring system
//! - **Alert system** - Multi-channel notifications
//! - **Firewall integration** - nftables/iptables, container quarantine
//! - **Automated response** - Threat response automation

#![allow(unused_must_use)]

// External crates
extern crate log;
extern crate serde;
extern crate serde_json;

// Docker (Linux only)
#[cfg(target_os = "linux")]
extern crate bollard;

// Optional eBPF (Linux only)
#[cfg(all(target_os = "linux", feature = "ebpf"))]
extern crate aya;

// Optional ML
#[cfg(feature = "ml")]
extern crate candle_core;
#[cfg(feature = "ml")]
extern crate candle_nn;

// Security modules - Core
pub mod alerting;
pub mod events;
pub mod models;
pub mod rules;

// Security modules - Linux-specific
#[cfg(target_os = "linux")]
pub mod firewall;

// Security modules - Collectors (cross-platform; Linux-specific internals are gated within)
pub mod collectors;

// Optional modules
pub mod baselines;
pub mod correlator;
pub mod database;
pub mod detectors;
pub mod docker;
pub mod ip_ban;
pub mod ml;
pub mod response;

// Configuration
pub mod config;

// API
pub mod api;

// Log sniffing
pub mod sniff;

// AI tool-use
pub mod tools;

// Re-export commonly used types
pub use events::security::{AlertEvent, ContainerEvent, NetworkEvent, SecurityEvent};
pub use events::syscall::{SyscallEvent, SyscallType};

// Alerting
pub use alerting::{Alert, AlertSeverity, AlertStatus, AlertType};
pub use alerting::{AlertManager, AlertStats};
pub use alerting::{NotificationChannel, NotificationConfig};
#[cfg(target_os = "linux")]
pub use response::{ActionPipeline, PipelineAction, PipelinePlan};

// Linux-specific
pub use collectors::{EbpfLoader, SyscallMonitor};
#[cfg(target_os = "linux")]
pub use firewall::{QuarantineManager, QuarantineState};
#[cfg(target_os = "linux")]
pub use firewall::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};

// Rules
pub use rules::{DetectionStats, StatsTracker};
pub use rules::{MatchResult, PatternMatch, SignatureMatcher};
pub use rules::{Rule, RuleEngine, RuleResult};
pub use rules::{ScoringConfig, ThreatScore, ThreatScorer};
pub use rules::{Signature, SignatureDatabase, ThreatCategory};
