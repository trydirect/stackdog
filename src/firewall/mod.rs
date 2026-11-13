//! Firewall module
//!
//! Manages firewall rules (nftables/iptables) and container quarantine

pub mod backend;
pub mod iptables;
pub mod nftables;
pub mod quarantine;
pub mod response;

/// Marker struct for module tests
pub struct FirewallMarker;

// Re-export commonly used types
pub use backend::{FirewallBackend, FirewallChain, FirewallRule, FirewallTable};
pub use iptables::{IptChain, IptRule, IptablesBackend};
pub use nftables::{NfChain, NfRule, NfTable, NfTablesBackend};
pub use quarantine::{QuarantineInfo, QuarantineManager, QuarantineState};
pub use response::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};
