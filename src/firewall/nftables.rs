//! nftables backend
//!
//! Manages nftables firewall rules

use anyhow::{Context, Result};
use std::process::Command;

use crate::firewall::backend::FirewallBackend;

/// nftables table
#[derive(Debug, Clone)]
pub struct NfTable {
    pub family: String,
    pub name: String,
}

impl NfTable {
    pub fn new(family: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for NfTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.family, self.name)
    }
}

/// nftables chain
#[derive(Debug, Clone)]
pub struct NfChain {
    pub table: NfTable,
    pub name: String,
    pub chain_type: String,
}

impl NfChain {
    pub fn new(table: &NfTable, name: impl Into<String>, chain_type: impl Into<String>) -> Self {
        Self {
            table: table.clone(),
            name: name.into(),
            chain_type: chain_type.into(),
        }
    }
}

/// nftables rule
#[derive(Debug, Clone)]
pub struct NfRule {
    pub chain: NfChain,
    pub rule_spec: String,
}

impl NfRule {
    pub fn new(chain: &NfChain, rule_spec: impl Into<String>) -> Self {
        Self {
            chain: chain.clone(),
            rule_spec: rule_spec.into(),
        }
    }
}

/// nftables backend
pub struct NfTablesBackend {
    available: bool,
}

impl NfTablesBackend {
    fn run_nft(&self, args: &[&str], context: &str) -> Result<()> {
        let output = Command::new("nft")
            .args(args)
            .output()
            .context(context.to_string())?;

        if !output.status.success() {
            anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
        }

        Ok(())
    }

    fn base_table(&self) -> NfTable {
        NfTable::new("inet", "stackdog")
    }

    fn ensure_filter_table(&self) -> Result<()> {
        let table = self.base_table();
        let _ = self.run_nft(
            &["add", "table", &table.family, &table.name],
            "Failed to ensure nftables table",
        );
        let _ = self.run_nft(
            &[
                "add",
                "chain",
                &table.family,
                &table.name,
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            "Failed to ensure nftables input chain",
        );
        let _ = self.run_nft(
            &[
                "add",
                "chain",
                &table.family,
                &table.name,
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            "Failed to ensure nftables output chain",
        );
        let _ = self.run_nft(
            &[
                "add",
                "chain",
                &table.family,
                &table.name,
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            "Failed to ensure nftables forward chain",
        );
        Ok(())
    }

    fn input_and_forward_chains(&self) -> [NfChain; 2] {
        [
            NfChain::new(&self.base_table(), "input", "filter"),
            NfChain::new(&self.base_table(), "forward", "filter"),
        ]
    }

    fn delete_rule_by_handle(&self, chain: &NfChain, handle: &str) -> Result<()> {
        self.run_nft(
            &[
                "delete",
                "rule",
                &chain.table.family,
                &chain.table.name,
                &chain.name,
                "handle",
                handle,
            ],
            "Failed to delete nftables rule by handle",
        )
    }

    fn find_rule_handle(rules: &[String], rule_spec: &str) -> Option<String> {
        rules.iter().find_map(|line| {
            let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
            if !normalized.contains(rule_spec) {
                return None;
            }

            line.rsplit_once("# handle ")
                .map(|(_, handle)| handle.trim().to_string())
        })
    }

    fn ensure_ip_drop_rule(&self, chain: &NfChain, ip: &str) -> Result<()> {
        let rule_spec = format!("ip saddr {} drop", ip);
        if Self::find_rule_handle(&self.list_rules(chain)?, &rule_spec).is_some() {
            return Ok(());
        }

        self.run_nft(
            &[
                "add",
                "rule",
                &chain.table.family,
                &chain.table.name,
                &chain.name,
                "ip",
                "saddr",
                ip,
                "drop",
            ],
            "Failed to add nftables rule",
        )
    }

    fn delete_ip_drop_rule_if_present(&self, chain: &NfChain, ip: &str) -> Result<()> {
        let rule_spec = format!("ip saddr {} drop", ip);
        if Self::find_rule_handle(&self.list_rules(chain)?, &rule_spec).is_none() {
            return Ok(());
        }

        let rule = NfRule::new(chain, rule_spec.to_string());
        self.delete_rule(&rule)
    }

    /// Create a new nftables backend
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // Check if nft command is available
            let available = Command::new("nft")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !available {
                anyhow::bail!("nft command not available");
            }

            Ok(Self { available: true })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("nftables only available on Linux");
        }
    }

    /// Create a table
    pub fn create_table(&self, table: &NfTable) -> Result<()> {
        let table_str = table.to_string();
        let output = Command::new("nft")
            .args(["add", "table", &table_str])
            .output()
            .context("Failed to create nftables table")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create table: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Delete a table
    pub fn delete_table(&self, table: &NfTable) -> Result<()> {
        let table_str = table.to_string();
        let output = Command::new("nft")
            .args(["delete", "table", &table_str])
            .output()
            .context("Failed to delete nftables table")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to delete table: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Create a chain
    pub fn create_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!(
            "add chain {} {} {{ type {} hook input priority 0; }}",
            chain.table, chain.name, chain.chain_type
        );

        let output = Command::new("nft")
            .args(["-c", &cmd])
            .output()
            .context("Failed to create nftables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Delete a chain
    pub fn delete_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!("delete chain {} {}", chain.table, chain.name);

        let output = Command::new("nft")
            .args(["-c", &cmd])
            .output()
            .context("Failed to delete nftables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to delete chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Add a rule
    pub fn add_rule(&self, rule: &NfRule) -> Result<()> {
        let cmd = format!(
            "add rule {} {} {}",
            rule.chain.table, rule.chain.name, rule.rule_spec
        );

        let output = Command::new("nft")
            .args(["-c", &cmd])
            .output()
            .context("Failed to add nftables rule")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to add rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Delete a rule
    pub fn delete_rule(&self, rule: &NfRule) -> Result<()> {
        let rules = self.list_rules(&rule.chain)?;
        let handle = Self::find_rule_handle(&rules, &rule.rule_spec).ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to delete rule: no matching handle found for '{}'",
                rule.rule_spec
            )
        })?;
        self.delete_rule_by_handle(&rule.chain, &handle)
    }

    /// Batch add multiple rules
    pub fn batch_add_rules(&self, rules: &[NfRule]) -> Result<()> {
        for rule in rules {
            self.add_rule(rule)?;
        }
        Ok(())
    }

    /// Flush a chain
    pub fn flush_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!("flush chain {} {}", chain.table, chain.name);

        let output = Command::new("nft")
            .args(["-c", &cmd])
            .output()
            .context("Failed to flush nftables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to flush chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// List rules in a chain
    pub fn list_rules(&self, chain: &NfChain) -> Result<Vec<String>> {
        let output = Command::new("nft")
            .args([
                "-a",
                "list",
                "chain",
                &chain.table.family,
                &chain.table.name,
                &chain.name,
            ])
            .output()
            .context("Failed to list nftables rules")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to list rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        Ok(rules)
    }
}

impl FirewallBackend for NfTablesBackend {
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn block_ip(&self, ip: &str) -> Result<()> {
        self.ensure_filter_table()?;
        for chain in self.input_and_forward_chains() {
            self.ensure_ip_drop_rule(&chain, ip)?;
        }
        Ok(())
    }

    fn unblock_ip(&self, ip: &str) -> Result<()> {
        self.ensure_filter_table()?;
        for chain in self.input_and_forward_chains() {
            self.delete_ip_drop_rule_if_present(&chain, ip)?;
        }
        Ok(())
    }

    fn block_port(&self, port: u16) -> Result<()> {
        self.ensure_filter_table()?;
        let port = port.to_string();
        self.run_nft(
            &[
                "add", "rule", "inet", "stackdog", "output", "tcp", "dport", &port, "drop",
            ],
            "Failed to block port with nftables",
        )
    }

    fn unblock_port(&self, port: u16) -> Result<()> {
        self.ensure_filter_table()?;
        let chain = NfChain::new(&self.base_table(), "output", "filter");
        let rule = NfRule::new(&chain, format!("tcp dport {} drop", port));
        self.delete_rule(&rule)
    }

    fn block_container(&self, container_id: &str) -> Result<()> {
        anyhow::bail!(
            "Container-specific nftables blocking is not implemented yet for {}",
            container_id
        )
    }

    fn unblock_container(&self, container_id: &str) -> Result<()> {
        anyhow::bail!(
            "Container-specific nftables unblocking is not implemented yet for {}",
            container_id
        )
    }

    fn name(&self) -> &str {
        "nftables"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_table_creation() {
        let table = NfTable::new("inet", "stackdog_test");
        assert_eq!(table.family, "inet");
        assert_eq!(table.name, "stackdog_test");
    }

    #[test]
    fn test_nf_chain_creation() {
        let table = NfTable::new("inet", "stackdog_test");
        let chain = NfChain::new(&table, "input", "filter");
        assert_eq!(chain.name, "input");
        assert_eq!(chain.chain_type, "filter");
    }

    #[test]
    fn test_block_container_is_explicitly_unsupported() {
        let backend = NfTablesBackend { available: true };
        let result = backend.block_container("container-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_rule_handle_matches_ip_rule() {
        let rules = vec![
            "table inet stackdog {".to_string(),
            "    chain input {".to_string(),
            "        type filter hook input priority filter; policy accept;".to_string(),
            "        ip saddr 172.17.0.1 drop # handle 7".to_string(),
            "    }".to_string(),
            "}".to_string(),
        ];

        let handle = NfTablesBackend::find_rule_handle(&rules, "ip saddr 172.17.0.1 drop");

        assert_eq!(handle.as_deref(), Some("7"));
    }

    #[test]
    fn test_find_rule_handle_matches_port_rule_with_spacing() {
        let rules = vec!["        tcp   dport   443   drop   # handle 12".to_string()];

        let handle = NfTablesBackend::find_rule_handle(&rules, "tcp dport 443 drop");

        assert_eq!(handle.as_deref(), Some("12"));
    }

    #[test]
    fn test_find_rule_handle_returns_none_for_missing_rule() {
        let rules = vec!["ip saddr 192.0.2.1 drop # handle 4".to_string()];

        let handle = NfTablesBackend::find_rule_handle(&rules, "ip saddr 198.51.100.9 drop");

        assert!(handle.is_none());
    }

    #[test]
    fn test_input_and_forward_chains_cover_host_and_forwarded_traffic() {
        let backend = NfTablesBackend { available: true };
        let chains = backend.input_and_forward_chains();
        assert_eq!(chains[0].name, "input");
        assert_eq!(chains[1].name, "forward");
    }
}
