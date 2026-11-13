//! iptables tests
//!
//! Tests for iptables firewall backend

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::firewall::iptables::{IptablesBackend, IptChain, IptRule};

    #[test]
    #[ignore = "requires root and iptables"]
    fn test_ipt_rule_addition() {
        let backend = IptablesBackend::new().expect("Failed to create backend");
        
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, "-p tcp --dport 22 -j DROP");
        
        let result = backend.add_rule(&rule);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.delete_rule(&rule);
    }

    #[test]
    #[ignore = "requires root and iptables"]
    fn test_ipt_rule_removal() {
        let backend = IptablesBackend::new().expect("Failed to create backend");
        
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, "-p tcp --dport 22 -j DROP");
        
        // Add first
        let _ = backend.add_rule(&rule);
        
        // Remove
        let result = backend.delete_rule(&rule);
        
        assert!(result.is_ok());
    }

    #[test]
    #[ignore = "requires root and iptables"]
    fn test_ipt_chain_creation() {
        let backend = IptablesBackend::new().expect("Failed to create backend");
        
        let chain = IptChain::new("filter", "STACKDOG_TEST");
        let result = backend.create_chain(&chain);
        
        assert!(result.is_ok());
        
        // Cleanup
        let _ = backend.flush_chain(&chain);
        let _ = backend.delete_chain(&chain);
    }

    #[test]
    #[ignore = "requires root and iptables"]
    fn test_ipt_list_rules() {
        let backend = IptablesBackend::new().expect("Failed to create backend");
        
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, "-p tcp --dport 22 -j DROP");
        let _ = backend.add_rule(&rule);
        
        // List rules
        let rules = backend.list_rules(&chain);
        
        assert!(rules.is_ok());
        
        // Cleanup
        let _ = backend.delete_rule(&rule);
    }

    #[test]
    #[ignore = "requires root and iptables"]
    fn test_ipt_flush_chain() {
        let backend = IptablesBackend::new().expect("Failed to create backend");
        
        let chain = IptChain::new("filter", "STACKDOG_TEST");
        let _ = backend.create_chain(&chain);
        
        // Add rules
        let rule1 = IptRule::new(&chain, "-j DROP");
        let rule2 = IptRule::new(&chain, "-j REJECT");
        let _ = backend.add_rule(&rule1);
        let _ = backend.add_rule(&rule2);
        
        // Flush
        let result = backend.flush_chain(&chain);
        
        assert!(result.is_ok());
        
        // Verify empty
        let rules = backend.list_rules(&chain);
        assert!(rules.is_ok());
        assert_eq!(rules.unwrap().len(), 0);
        
        // Cleanup
        let _ = backend.delete_chain(&chain);
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::firewall::iptables::IptablesBackend;

    #[test]
    fn test_ipt_not_available_on_non_linux() {
        let result = IptablesBackend::new();
        assert!(result.is_err());
    }
}
