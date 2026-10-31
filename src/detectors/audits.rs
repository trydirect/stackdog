use std::fs;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::sniff::analyzer::AnomalySeverity;

use super::{DetectorFamily, DetectorFinding};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerPosture {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub network_mode: Option<String>,
    pub pid_mode: Option<String>,
    pub cap_add: Vec<String>,
    pub mounts: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigAssessmentMonitor;

#[derive(Debug, Clone, Default)]
pub struct PackageInventoryMonitor;

#[derive(Debug, Clone, Default)]
pub struct DockerPostureMonitor;

impl ConfigAssessmentMonitor {
    pub fn detect(&self, configured_paths: &[String]) -> Result<Vec<DetectorFinding>> {
        let mut findings = Vec::new();
        let targets = config_paths(configured_paths);

        for path in targets {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if !path.exists() {
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    log::debug!(
                        "Skipping unreadable config assessment target {}: {}",
                        path.display(),
                        error
                    );
                    continue;
                }
            };
            let path_str = path.to_string_lossy().into_owned();
            match file_name {
                "sshd_config" => findings.extend(check_sshd_config(&path_str, &content)),
                "sudoers" => findings.extend(check_sudoers(&path_str, &content)),
                "daemon.json" => findings.extend(check_docker_daemon_config(&path_str, &content)),
                _ => {}
            }
        }

        Ok(findings)
    }
}

impl PackageInventoryMonitor {
    pub fn detect(&self, configured_paths: &[String]) -> Result<Vec<DetectorFinding>> {
        let mut findings = Vec::new();

        for path in inventory_paths(configured_paths) {
            if !path.exists() {
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    log::debug!(
                        "Skipping unreadable package inventory target {}: {}",
                        path.display(),
                        error
                    );
                    continue;
                }
            };
            let path_str = path.to_string_lossy().into_owned();
            let packages = match path.file_name().and_then(|name| name.to_str()) {
                Some("status") => parse_dpkg_status(&content),
                Some("installed") => parse_apk_installed(&content),
                _ => parse_dpkg_status(&content),
            };

            for (package, version) in packages {
                if let Some(finding) = check_package_advisory(&path_str, &package, &version) {
                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }
}

impl DockerPostureMonitor {
    pub fn detect(&self, postures: &[ContainerPosture]) -> Vec<DetectorFinding> {
        let mut findings = Vec::new();

        for posture in postures {
            let mut issues = Vec::new();
            if posture.privileged {
                issues.push("privileged mode");
            }
            if posture.network_mode.as_deref() == Some("host") {
                issues.push("host network");
            }
            if posture.pid_mode.as_deref() == Some("host") {
                issues.push("host PID namespace");
            }
            if posture
                .cap_add
                .iter()
                .any(|cap| matches!(cap.as_str(), "SYS_ADMIN" | "NET_ADMIN" | "SYS_PTRACE"))
            {
                issues.push("dangerous capabilities");
            }
            if posture
                .mounts
                .iter()
                .any(|mount| mount.contains("/var/run/docker.sock"))
            {
                issues.push("docker socket mount");
            }
            if posture.mounts.iter().any(|mount| {
                mount.contains("/etc:") && (mount.ends_with(":rw") || !mount.contains(":ro"))
            }) {
                issues.push("writable /etc mount");
            }

            if issues.is_empty() {
                continue;
            }

            let severity = if posture.privileged
                || posture
                    .mounts
                    .iter()
                    .any(|mount| mount.contains("/var/run/docker.sock"))
            {
                AnomalySeverity::Critical
            } else {
                AnomalySeverity::High
            };

            findings.push(DetectorFinding {
                detector_id: "container.posture-risk".into(),
                family: DetectorFamily::Container,
                description: format!(
                    "Container {} has risky posture: {}",
                    posture.name,
                    issues.join(", ")
                ),
                severity,
                confidence: 90,
                sample_line: format!("{} ({})", posture.name, posture.container_id),
            });
        }

        findings
    }
}

fn config_paths(configured_paths: &[String]) -> Vec<std::path::PathBuf> {
    if configured_paths.is_empty() {
        default_existing_paths(&[
            "/etc/ssh/sshd_config",
            "/etc/sudoers",
            "/etc/docker/daemon.json",
        ])
    } else {
        configured_paths
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    }
}

fn inventory_paths(configured_paths: &[String]) -> Vec<std::path::PathBuf> {
    if configured_paths.is_empty() {
        default_existing_paths(&["/var/lib/dpkg/status", "/lib/apk/db/installed"])
    } else {
        configured_paths
            .iter()
            .map(std::path::PathBuf::from)
            .collect()
    }
}

fn default_existing_paths(paths: &[&str]) -> Vec<std::path::PathBuf> {
    paths
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|path| path.exists())
        .collect()
}

fn check_sshd_config(path: &str, content: &str) -> Vec<DetectorFinding> {
    let mut findings = Vec::new();
    let normalized = uncommented_lines(content);

    if normalized
        .iter()
        .any(|line| line.eq_ignore_ascii_case("PermitRootLogin yes"))
    {
        findings.push(DetectorFinding {
            detector_id: "config.ssh-root-login".into(),
            family: DetectorFamily::Configuration,
            description: format!("sshd_config allows direct root login: {}", path),
            severity: AnomalySeverity::High,
            confidence: 92,
            sample_line: path.into(),
        });
    }

    if normalized
        .iter()
        .any(|line| line.eq_ignore_ascii_case("PasswordAuthentication yes"))
    {
        findings.push(DetectorFinding {
            detector_id: "config.ssh-password-auth".into(),
            family: DetectorFamily::Configuration,
            description: format!("sshd_config enables password authentication: {}", path),
            severity: AnomalySeverity::Medium,
            confidence: 84,
            sample_line: path.into(),
        });
    }

    findings
}

fn check_sudoers(path: &str, content: &str) -> Vec<DetectorFinding> {
    uncommented_lines(content)
        .iter()
        .filter(|line| line.contains("NOPASSWD: ALL"))
        .map(|_| DetectorFinding {
            detector_id: "config.sudoers-nopasswd".into(),
            family: DetectorFamily::Configuration,
            description: format!("sudoers grants passwordless full sudo access: {}", path),
            severity: AnomalySeverity::High,
            confidence: 91,
            sample_line: path.into(),
        })
        .collect()
}

fn check_docker_daemon_config(path: &str, content: &str) -> Vec<DetectorFinding> {
    let mut findings = Vec::new();

    let parsed = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(value) => value,
        Err(_) => {
            findings.push(DetectorFinding {
                detector_id: "config.docker-invalid-json".into(),
                family: DetectorFamily::Configuration,
                description: format!("Docker daemon config is not valid JSON: {}", path),
                severity: AnomalySeverity::Medium,
                confidence: 80,
                sample_line: path.into(),
            });
            return findings;
        }
    };

    if parsed
        .get("icc")
        .and_then(|value| value.as_bool())
        .unwrap_or(true)
    {
        findings.push(DetectorFinding {
            detector_id: "config.docker-icc".into(),
            family: DetectorFamily::Configuration,
            description: format!(
                "Docker daemon config allows inter-container communication: {}",
                path
            ),
            severity: AnomalySeverity::Medium,
            confidence: 82,
            sample_line: path.into(),
        });
    }

    if parsed.get("userns-remap").is_none() {
        findings.push(DetectorFinding {
            detector_id: "config.docker-userns".into(),
            family: DetectorFamily::Configuration,
            description: format!(
                "Docker daemon config does not enable user namespace remapping: {}",
                path
            ),
            severity: AnomalySeverity::Medium,
            confidence: 78,
            sample_line: path.into(),
        });
    }

    findings
}

fn uncommented_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn parse_dpkg_status(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();

    for stanza in content.split("\n\n") {
        let mut package = None;
        let mut version = None;

        for line in stanza.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                package = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value.trim().to_string());
            }
        }

        if let (Some(package), Some(version)) = (package, version) {
            packages.push((package, version));
        }
    }

    packages
}

pub(crate) fn parse_apk_installed(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut package = None;
    let mut version = None;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("P:") {
            package = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("V:") {
            version = Some(value.trim().to_string());
        } else if line.trim().is_empty() {
            if let (Some(package), Some(version)) = (package.take(), version.take()) {
                packages.push((package, version));
            }
        }
    }

    if let (Some(package), Some(version)) = (package, version) {
        packages.push((package, version));
    }

    packages
}

fn check_package_advisory(path: &str, package: &str, version: &str) -> Option<DetectorFinding> {
    let advisories: [(&str, &[&str], AnomalySeverity); 4] = [
        ("openssl", &["1.0.", "1.1.0"], AnomalySeverity::High),
        (
            "openssh-server",
            &["7.", "8.0", "8.1"],
            AnomalySeverity::High,
        ),
        ("sudo", &["1.8."], AnomalySeverity::Medium),
        ("bash", &["4.3"], AnomalySeverity::Medium),
    ];

    advisories
        .into_iter()
        .find_map(|(name, risky_prefixes, severity)| {
            (package == name
                && risky_prefixes
                    .iter()
                    .any(|prefix| version.starts_with(prefix)))
            .then(|| DetectorFinding {
                detector_id: "vuln.legacy-package".into(),
                family: DetectorFamily::Vulnerability,
                description: format!(
                    "Legacy package version detected in {}: {} {}",
                    path, package, version
                ),
                severity,
                confidence: 83,
                sample_line: format!("{} {}", package, version),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_config_assessment_detects_insecure_sshd_and_sudoers() {
        let dir = tempfile::tempdir().unwrap();
        let sshd = dir.path().join("sshd_config");
        let sudoers = dir.path().join("sudoers");
        fs::write(&sshd, "PermitRootLogin yes\nPasswordAuthentication yes\n").unwrap();
        fs::write(&sudoers, "admin ALL=(ALL) NOPASSWD: ALL\n").unwrap();

        let monitor = ConfigAssessmentMonitor;
        let findings = monitor
            .detect(&[
                sshd.to_string_lossy().into_owned(),
                sudoers.to_string_lossy().into_owned(),
            ])
            .unwrap();

        let ids = findings
            .iter()
            .map(|finding| finding.detector_id.as_str())
            .collect::<HashSet<_>>();
        assert!(ids.contains("config.ssh-root-login"));
        assert!(ids.contains("config.ssh-password-auth"));
        assert!(ids.contains("config.sudoers-nopasswd"));
    }

    #[test]
    fn test_config_assessment_detects_docker_daemon_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = dir.path().join("daemon.json");
        fs::write(&daemon, r#"{"icc": true}"#).unwrap();

        let monitor = ConfigAssessmentMonitor;
        let findings = monitor
            .detect(&[daemon.to_string_lossy().into_owned()])
            .unwrap();

        let ids = findings
            .iter()
            .map(|finding| finding.detector_id.as_str())
            .collect::<HashSet<_>>();
        assert!(ids.contains("config.docker-icc"));
        assert!(ids.contains("config.docker-userns"));
    }

    #[test]
    fn test_package_inventory_detects_legacy_versions() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        fs::write(
            &status,
            "Package: openssl\nVersion: 1.0.2u-1\n\nPackage: sudo\nVersion: 1.8.31-1\n",
        )
        .unwrap();

        let monitor = PackageInventoryMonitor;
        let findings = monitor
            .detect(&[status.to_string_lossy().into_owned()])
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| finding.detector_id == "vuln.legacy-package"));
    }

    #[test]
    fn test_docker_posture_monitor_summarizes_risky_container_settings() {
        let monitor = DockerPostureMonitor;
        let findings = monitor.detect(&[ContainerPosture {
            container_id: "abc123".into(),
            name: "web".into(),
            image: "nginx:latest".into(),
            privileged: true,
            network_mode: Some("host".into()),
            pid_mode: Some("host".into()),
            cap_add: vec!["SYS_ADMIN".into()],
            mounts: vec!["/var/run/docker.sock:/var/run/docker.sock:rw".into()],
        }]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_id, "container.posture-risk");
        assert_eq!(findings[0].family, DetectorFamily::Container);
        assert!(findings[0].description.contains("privileged mode"));
    }
}
