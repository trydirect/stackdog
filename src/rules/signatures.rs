//! Threat signatures
//!
//! Known threat patterns and signatures for detection

use crate::events::security::SecurityEvent;
use crate::events::syscall::SyscallType;

/// Threat categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    Suspicious,
    CryptoMiner,
    ContainerEscape,
    NetworkScanner,
    PrivilegeEscalation,
    DataExfiltration,
    Malware,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::Suspicious => write!(f, "Suspicious"),
            ThreatCategory::CryptoMiner => write!(f, "CryptoMiner"),
            ThreatCategory::ContainerEscape => write!(f, "ContainerEscape"),
            ThreatCategory::NetworkScanner => write!(f, "NetworkScanner"),
            ThreatCategory::PrivilegeEscalation => write!(f, "PrivilegeEscalation"),
            ThreatCategory::DataExfiltration => write!(f, "DataExfiltration"),
            ThreatCategory::Malware => write!(f, "Malware"),
        }
    }
}

/// A threat signature
pub struct Signature {
    name: String,
    description: String,
    severity: u8,
    category: ThreatCategory,
    syscall_patterns: Vec<SyscallType>,
}

impl Signature {
    /// Create a new signature
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        severity: u8,
        category: ThreatCategory,
        syscall_patterns: Vec<SyscallType>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            severity,
            category,
            syscall_patterns,
        }
    }

    /// Get the signature name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the severity (0-100)
    pub fn severity(&self) -> u8 {
        self.severity
    }

    /// Get the category
    pub fn category(&self) -> &ThreatCategory {
        &self.category
    }

    /// Check if a syscall matches this signature
    pub fn matches(&self, syscall_type: &SyscallType) -> bool {
        self.syscall_patterns.contains(syscall_type)
    }
}

/// Known threat signatures database
pub struct SignatureDatabase {
    signatures: Vec<Signature>,
}

impl SignatureDatabase {
    /// Create a new signature database with known threats
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::new(),
        };

        // Load built-in signatures
        db.load_builtin_signatures();
        db
    }

    /// Load built-in threat signatures
    fn load_builtin_signatures(&mut self) {
        // Crypto miner detection - execve + setuid pattern
        self.signatures.push(Signature::new(
            "crypto_miner_execve",
            "Detects execve syscall commonly used by crypto miners",
            70,
            ThreatCategory::CryptoMiner,
            vec![SyscallType::Execve, SyscallType::Setuid],
        ));

        // Container escape - ptrace + mount pattern
        self.signatures.push(Signature::new(
            "container_escape_ptrace",
            "Detects ptrace syscall associated with container escape attempts",
            95,
            ThreatCategory::ContainerEscape,
            vec![SyscallType::Ptrace],
        ));

        self.signatures.push(Signature::new(
            "container_escape_mount",
            "Detects mount syscall associated with container escape attempts",
            90,
            ThreatCategory::ContainerEscape,
            vec![SyscallType::Mount],
        ));

        // Network scanner - connect + bind pattern
        self.signatures.push(Signature::new(
            "network_scanner_connect",
            "Detects connect syscall commonly used by network scanners",
            60,
            ThreatCategory::NetworkScanner,
            vec![SyscallType::Connect],
        ));

        self.signatures.push(Signature::new(
            "network_scanner_bind",
            "Detects bind syscall commonly used by network scanners",
            50,
            ThreatCategory::NetworkScanner,
            vec![SyscallType::Bind],
        ));

        // Privilege escalation - setuid + setgid pattern
        self.signatures.push(Signature::new(
            "privilege_escalation_setuid",
            "Detects setuid syscall associated with privilege escalation",
            85,
            ThreatCategory::PrivilegeEscalation,
            vec![SyscallType::Setuid, SyscallType::Setgid],
        ));

        // Data exfiltration - connect pattern
        self.signatures.push(Signature::new(
            "data_exfiltration_network",
            "Detects network activity potentially associated with data exfiltration",
            75,
            ThreatCategory::DataExfiltration,
            vec![SyscallType::Connect, SyscallType::Sendto],
        ));

        // Malware indicators
        self.signatures.push(Signature::new(
            "malware_execve_tmp",
            "Detects execution from temporary directories",
            80,
            ThreatCategory::Malware,
            vec![SyscallType::Execve],
        ));

        // Suspicious activity
        self.signatures.push(Signature::new(
            "suspicious_execveat",
            "Detects execveat syscall which is less common",
            50,
            ThreatCategory::Suspicious,
            vec![SyscallType::Execveat],
        ));

        self.signatures.push(Signature::new(
            "suspicious_openat",
            "Detects openat syscall for file access monitoring",
            40,
            ThreatCategory::Suspicious,
            vec![SyscallType::Openat],
        ));
    }

    /// Get all signatures
    pub fn get_signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get signature count
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Add a custom signature
    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    /// Remove a signature by name
    pub fn remove_signature(&mut self, name: &str) {
        self.signatures.retain(|sig| sig.name() != name);
    }

    /// Get signatures by category
    pub fn get_signatures_by_category(&self, category: &ThreatCategory) -> Vec<&Signature> {
        self.signatures
            .iter()
            .filter(|sig| sig.category() == category)
            .collect()
    }

    /// Find signatures that match a syscall
    pub fn find_matching(&self, syscall_type: &SyscallType) -> Vec<&Signature> {
        self.signatures
            .iter()
            .filter(|sig| sig.matches(syscall_type))
            .collect()
    }

    /// Detect threats in an event
    pub fn detect(&self, event: &SecurityEvent) -> Vec<&Signature> {
        match event {
            SecurityEvent::Syscall(syscall_event) => {
                self.find_matching(&syscall_event.syscall_type)
            }
            _ => Vec::new(),
        }
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(sig.severity(), 50);
    }

    #[test]
    fn test_threat_category_display() {
        assert_eq!(format!("{}", ThreatCategory::Suspicious), "Suspicious");
        assert_eq!(format!("{}", ThreatCategory::CryptoMiner), "CryptoMiner");
    }
}
