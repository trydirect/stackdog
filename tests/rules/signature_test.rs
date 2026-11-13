//! Signature tests
//!
//! Tests for threat signature detection

use stackdog::rules::signatures::{Signature, SignatureDatabase, ThreatCategory};
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use stackdog::events::security::SecurityEvent;
use chrono::Utc;

#[test]
fn test_signature_creation() {
    let sig = Signature::new(
        "test_sig",
        "Test signature",
        50,
        ThreatCategory::Suspicious,
        vec![SyscallType::Execve],
    );
    
    assert_eq!(sig.name(), "test_sig");
    assert_eq!(sig.description(), "Test signature");
    assert_eq!(sig.severity(), 50);
    assert_eq!(sig.category(), &ThreatCategory::Suspicious);
}

#[test]
fn test_signature_matching() {
    let sig = Signature::new(
        "test_sig",
        "Test signature",
        50,
        ThreatCategory::Suspicious,
        vec![SyscallType::Execve, SyscallType::Connect],
    );
    
    assert!(sig.matches(&SyscallType::Execve));
    assert!(sig.matches(&SyscallType::Connect));
    assert!(!sig.matches(&SyscallType::Openat));
}

#[test]
fn test_builtin_signatures_exist() {
    let db = SignatureDatabase::new();
    
    // Should have built-in signatures
    assert!(db.signature_count() > 0);
}

#[test]
fn test_crypto_miner_signature() {
    let db = SignatureDatabase::new();
    
    // Find crypto miner signatures
    let crypto_sigs = db.get_signatures_by_category(&ThreatCategory::CryptoMiner);
    
    // Should have at least one crypto miner signature
    assert!(!crypto_sigs.is_empty());
    
    // Check severity is high
    for sig in crypto_sigs {
        assert!(sig.severity() >= 70);
    }
}

#[test]
fn test_container_escape_signature() {
    let db = SignatureDatabase::new();
    
    // Find container escape signatures
    let escape_sigs = db.get_signatures_by_category(&ThreatCategory::ContainerEscape);
    
    // Should have at least one container escape signature
    assert!(!escape_sigs.is_empty());
    
    // Check severity is critical
    for sig in escape_sigs {
        assert!(sig.severity() >= 90);
    }
}

#[test]
fn test_network_scanner_signature() {
    let db = SignatureDatabase::new();
    
    // Find network scanner signatures
    let scanner_sigs = db.get_signatures_by_category(&ThreatCategory::NetworkScanner);
    
    // Should have at least one network scanner signature
    assert!(!scanner_sigs.is_empty());
}

#[test]
fn test_privilege_escalation_signature() {
    let db = SignatureDatabase::new();
    
    // Find privilege escalation signatures
    let priv_sigs = db.get_signatures_by_category(&ThreatCategory::PrivilegeEscalation);
    
    // Should have at least one privilege escalation signature
    assert!(!priv_sigs.is_empty());
}

#[test]
fn test_signature_database_add() {
    let mut db = SignatureDatabase::new();
    let initial_count = db.signature_count();
    
    let custom_sig = Signature::new(
        "custom_sig",
        "Custom signature",
        60,
        ThreatCategory::Suspicious,
        vec![SyscallType::Ptrace],
    );
    
    db.add_signature(custom_sig);
    assert_eq!(db.signature_count(), initial_count + 1);
}

#[test]
fn test_signature_database_remove() {
    let mut db = SignatureDatabase::new();
    
    let custom_sig = Signature::new(
        "to_remove",
        "Signature to remove",
        60,
        ThreatCategory::Suspicious,
        vec![SyscallType::Ptrace],
    );
    
    db.add_signature(custom_sig);
    let count_with_sig = db.signature_count();
    
    db.remove_signature("to_remove");
    assert_eq!(db.signature_count(), count_with_sig - 1);
}

#[test]
fn test_signature_detection_execve() {
    let db = SignatureDatabase::new();
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Execve, Utc::now(),
    ));
    
    let matches = db.detect(&event);
    // Should match some signatures
    assert!(!matches.is_empty());
}

#[test]
fn test_signature_detection_ptrace() {
    let db = SignatureDatabase::new();
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234, 1000, SyscallType::Ptrace, Utc::now(),
    ));
    
    let matches = db.detect(&event);
    // Ptrace should match suspicious activity signatures
    assert!(!matches.is_empty());
}

#[test]
fn test_threat_category_variants() {
    // Test all threat category variants exist
    let _suspicious = ThreatCategory::Suspicious;
    let _crypto_miner = ThreatCategory::CryptoMiner;
    let _container_escape = ThreatCategory::ContainerEscape;
    let _network_scanner = ThreatCategory::NetworkScanner;
    let _privilege_escalation = ThreatCategory::PrivilegeEscalation;
    let _data_exfiltration = ThreatCategory::DataExfiltration;
    let _malware = ThreatCategory::Malware;
}
