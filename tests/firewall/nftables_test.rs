//! nftables tests
//!
//! Tests for nftables firewall backend

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::firewall::nftables::{NfTablesBackend, NfTable, NfChain, NfRule};

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_table_creation() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        let table = NfTable::new("inet", "stackdog_test");
        let result = backend.create_table(&table);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.delete_table(&table);
    }

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_chain_creation() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        let table = NfTable::new("inet", "stackdog_test");
        let _ = backend.create_table(&table);
        
        let chain = NfChain::new(&table, "input_test", "filter");
        let result = backend.create_chain(&chain);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.delete_chain(&chain);
        let _ = backend.delete_table(&table);
    }

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_rule_addition() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        // Setup
        let table = NfTable::new("inet", "stackdog_test");
        let _ = backend.create_table(&table);
        let chain = NfChain::new(&table, "input_test", "filter");
        let _ = backend.create_chain(&chain);
        
        // Add rule
        let rule = NfRule::new(&chain, "tcp dport 22 drop");
        let result = backend.add_rule(&rule);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.flush_chain(&chain);
        let _ = backend.delete_chain(&chain);
        let _ = backend.delete_table(&table);
    }

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_rule_removal() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        // Setup
        let table = NfTable::new("inet", "stackdog_test");
        let _ = backend.create_table(&table);
        let chain = NfChain::new(&table, "input_test", "filter");
        let _ = backend.create_chain(&chain);
        
        let rule = NfRule::new(&chain, "tcp dport 22 drop");
        let _ = backend.add_rule(&rule);
        
        // Remove rule
        let result = backend.delete_rule(&rule);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.delete_chain(&chain);
        let _ = backend.delete_table(&table);
    }

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_batch_update() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        let table = NfTable::new("inet", "stackdog_test");
        let _ = backend.create_table(&table);
        let chain = NfChain::new(&table, "input_test", "filter");
        let _ = backend.create_chain(&chain);
        
        // Batch add multiple rules
        let rules = vec![
            NfRule::new(&chain, "tcp dport 22 drop"),
            NfRule::new(&chain, "tcp dport 23 drop"),
            NfRule::new(&chain, "tcp dport 3389 drop"),
        ];
        
        let result = backend.batch_add_rules(&rules);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.flush_chain(&chain);
        let _ = backend.delete_chain(&chain);
        let _ = backend.delete_table(&table);
    }

    #[test]
    #[ignore = "requires root and nftables"]
    fn test_nft_list_rules() {
        let backend = NfTablesBackend::new().expect("Failed to create backend");
        
        let table = NfTable::new("inet", "stackdog_test");
        let _ = backend.create_table(&table);
        let chain = NfChain::new(&table, "input_test", "filter");
        let _ = backend.create_chain(&chain);
        
        let rule = NfRule::new(&chain, "tcp dport 22 drop");
        let _ = backend.add_rule(&rule);
        
        // List rules
        let rules = backend.list_rules(&chain);
        
        assert!(rules.is_ok());
        assert!(rules.unwrap().len() > 0);
        
        // Cleanup
        let _ = backend.flush_chain(&chain);
        let _ = backend.delete_chain(&chain);
        let _ = backend.delete_table(&table);
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::firewall::nftables::NfTablesBackend;

    #[test]
    fn test_nft_not_available_on_non_linux() {
        let result = NfTablesBackend::new();
        assert!(result.is_err());
    }
}
