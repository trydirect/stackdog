//! Firewall backend trait
//!
//! Abstracts firewall operations for different backends

use anyhow::Result;

/// Firewall backend trait
pub trait FirewallBackend: Send + Sync {
    /// Initialize the backend
    fn initialize(&mut self) -> Result<()>;

    /// Check if backend is available
    fn is_available(&self) -> bool;

    /// Block an IP address
    fn block_ip(&self, ip: &str) -> Result<()>;

    /// Unblock an IP address
    fn unblock_ip(&self, ip: &str) -> Result<()>;

    /// Addresses currently blocked by Stackdog rules.
    ///
    /// Only rules carrying the Stackdog marker are claimed: an untagged DROP
    /// rule cannot be told apart from one an operator wrote, and removing those
    /// on a hunch is how a firewall cleanup becomes an outage.
    fn list_banned_ips(&self) -> Result<Vec<String>>;

    /// Block a port
    fn block_port(&self, port: u16) -> Result<()>;

    /// Unblock a port
    fn unblock_port(&self, port: u16) -> Result<()>;

    /// Block all traffic for a container
    fn block_container(&self, container_id: &str) -> Result<()>;

    /// Unblock all traffic for a container
    fn unblock_container(&self, container_id: &str) -> Result<()>;

    /// Get backend name
    fn name(&self) -> &str;
}

/// Firewall rule
#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub chain: String,
    pub rule_spec: String,
    pub table: String,
}

impl FirewallRule {
    pub fn new(
        chain: impl Into<String>,
        rule_spec: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        Self {
            chain: chain.into(),
            rule_spec: rule_spec.into(),
            table: table.into(),
        }
    }
}

/// Firewall table
#[derive(Debug, Clone)]
pub struct FirewallTable {
    pub family: String,
    pub name: String,
}

impl FirewallTable {
    pub fn new(family: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            name: name.into(),
        }
    }
}

/// Firewall chain
#[derive(Debug, Clone)]
pub struct FirewallChain {
    pub table: FirewallTable,
    pub name: String,
    pub chain_type: String,
}

impl FirewallChain {
    pub fn new(
        table: FirewallTable,
        name: impl Into<String>,
        chain_type: impl Into<String>,
    ) -> Self {
        Self {
            table,
            name: name.into(),
            chain_type: chain_type.into(),
        }
    }
}
