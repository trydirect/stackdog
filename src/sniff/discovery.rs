//! Log source discovery
//!
//! Scans for log sources across Docker containers, system log files,
//! and user-configured custom paths.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Type of log source
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogSourceType {
    DockerContainer,
    SystemLog,
    CustomFile,
}

impl std::fmt::Display for LogSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSourceType::DockerContainer => write!(f, "DockerContainer"),
            LogSourceType::SystemLog => write!(f, "SystemLog"),
            LogSourceType::CustomFile => write!(f, "CustomFile"),
        }
    }
}

impl std::str::FromStr for LogSourceType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "DockerContainer" => LogSourceType::DockerContainer,
            "SystemLog" => LogSourceType::SystemLog,
            _ => LogSourceType::CustomFile,
        })
    }
}

/// A discovered log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub id: String,
    pub source_type: LogSourceType,
    /// File path (for system/custom) or container ID (for Docker)
    pub path_or_id: String,
    pub name: String,
    pub discovered_at: DateTime<Utc>,
    /// Byte offset for incremental reads (files only)
    pub last_read_position: u64,
}

impl LogSource {
    pub fn new(source_type: LogSourceType, path_or_id: String, name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_type,
            path_or_id,
            name,
            discovered_at: Utc::now(),
            last_read_position: 0,
        }
    }
}

/// Well-known system log paths to probe
const SYSTEM_LOG_PATHS: &[&str] = &[
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/daemon.log",
    "/var/log/secure",
];

/// Discover system log files that exist and are readable
pub fn discover_system_logs() -> Vec<LogSource> {
    log::debug!("Probing {} system log paths", SYSTEM_LOG_PATHS.len());
    let sources: Vec<LogSource> = SYSTEM_LOG_PATHS
        .iter()
        .filter(|path| {
            let exists = Path::new(path).exists();
            log::trace!("System log {} — exists: {}", path, exists);
            exists
        })
        .map(|path| {
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            LogSource::new(LogSourceType::SystemLog, path.to_string(), name)
        })
        .collect();
    log::debug!("Discovered {} system log sources", sources.len());
    sources
}

/// Register user-configured custom log file paths
pub fn discover_custom_sources(paths: &[String]) -> Vec<LogSource> {
    log::debug!("Checking {} custom source paths", paths.len());
    paths
        .iter()
        .filter(|path| {
            let exists = Path::new(path.as_str()).exists();
            if exists {
                log::debug!("Custom source found: {}", path);
            } else {
                log::debug!("Custom source not found (skipped): {}", path);
            }
            exists
        })
        .map(|path| {
            let name = Path::new(path.as_str())
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("custom")
                .to_string();
            LogSource::new(LogSourceType::CustomFile, path.clone(), name)
        })
        .collect()
}

/// Label that marks a container as one Stackdog should not read logs from.
///
/// Declaring it in docker-compose is more reliable than inferring our own ID
/// from `/proc`, since it survives any cgroup layout, network mode, or runtime:
///
/// ```yaml
/// labels:
///   com.trydirect.stackdog.ignore: "true"
/// ```
pub const IGNORE_LABEL: &str = "com.trydirect.stackdog.ignore";

/// Whether a container's labels ask Stackdog to skip it.
fn is_ignored_by_label(labels: &std::collections::HashMap<String, String>) -> bool {
    labels
        .get(IGNORE_LABEL)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Extract a 64-hex container ID from a /proc line, if one is present.
fn extract_container_id(line: &str) -> Option<String> {
    line.split(|ch: char| !ch.is_ascii_hexdigit())
        .find(|token| token.len() == 64)
        .map(str::to_string)
}

/// Pull our container ID out of /proc/self/mountinfo contents.
///
/// Lines mentioning `/containers/` are preferred: Docker bind-mounts
/// `/var/lib/docker/containers/<id>/resolv.conf` and friends, so those carry the
/// real container ID. Plain 64-hex tokens elsewhere in the file can be overlay
/// layer hashes, which would be the wrong ID.
fn container_id_from_mountinfo(contents: &str) -> Option<String> {
    contents
        .lines()
        .filter(|line| line.contains("/containers/"))
        .find_map(extract_container_id)
        .or_else(|| contents.lines().find_map(extract_container_id))
}

/// Best-effort detection of the container Stackdog itself runs in.
///
/// Reading the hostname is not enough: under `network_mode: host` the container
/// inherits the host's hostname instead of its own short ID.
///
/// Two sources are consulted, because neither covers every setup:
/// `/proc/self/cgroup` carries the ID under cgroup v1 and under v2 with a host
/// cgroup namespace, but collapses to a bare `0::/` under v2 with the private
/// namespace Docker now defaults to. `/proc/self/mountinfo` still names the ID
/// there. Both live under `/proc/self`, which a process can always read for
/// itself, and neither is in Docker's masked-path list.
///
/// Returns `None` outside containers, and when detection fails; set
/// `STACKDOG_SELF_CONTAINER_ID` to pin the ID by hand in that case.
pub fn self_container_id() -> Option<String> {
    if let Ok(id) = std::env::var("STACKDOG_SELF_CONTAINER_ID") {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Some(id);
        }
    }

    if let Ok(contents) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(id) = contents.lines().find_map(extract_container_id) {
            return Some(id);
        }
    }

    if let Ok(contents) = std::fs::read_to_string("/proc/self/mountinfo") {
        if let Some(id) = container_id_from_mountinfo(&contents) {
            return Some(id);
        }
    }

    None
}

/// Discover Docker container log sources
///
/// Skips Stackdog's own container: reading our own stdout feeds every internal
/// error back into the analyzer, which then reports it as a finding.
pub async fn discover_docker_sources() -> Result<Vec<LogSource>> {
    use crate::docker::DockerClient;

    let client = match DockerClient::new().await {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Docker not available for log discovery: {}", e);
            return Ok(Vec::new());
        }
    };

    let containers = client.list_containers(false).await?;
    let self_id = self_container_id();
    if self_id.is_none() {
        log::debug!(
            "Could not determine own container ID; if Stackdog runs in Docker its own logs \
             will be analyzed as a source. Set the {} label on the container, or \
             STACKDOG_SELF_CONTAINER_ID, to prevent that.",
            IGNORE_LABEL
        );
    }
    let sources = containers
        .into_iter()
        .filter(|c| {
            if is_ignored_by_label(&c.labels) {
                log::debug!(
                    "Skipping container {} — {} label is set",
                    c.name,
                    IGNORE_LABEL
                );
                return false;
            }
            match &self_id {
                Some(self_id) => {
                    let is_self = self_id.starts_with(&c.id) || c.id.starts_with(self_id.as_str());
                    if is_self {
                        log::debug!("Skipping own container {} in log discovery", c.id);
                    }
                    !is_self
                }
                None => true,
            }
        })
        .map(|c| {
            let name = format!("docker:{}", c.name);
            LogSource::new(LogSourceType::DockerContainer, c.id, name)
        })
        .collect();

    Ok(sources)
}

/// Run full discovery across all source types
pub async fn discover_all(extra_paths: &[String]) -> Result<Vec<LogSource>> {
    let mut sources = Vec::new();

    // System logs
    let sys = discover_system_logs();
    log::debug!("System log discovery: {} sources", sys.len());
    sources.extend(sys);

    // Custom paths
    let custom = discover_custom_sources(extra_paths);
    log::debug!("Custom source discovery: {} sources", custom.len());
    sources.extend(custom);

    // Docker containers
    match discover_docker_sources().await {
        Ok(docker_sources) => {
            log::debug!("Docker discovery: {} containers", docker_sources.len());
            sources.extend(docker_sources);
        }
        Err(e) => log::warn!("Docker discovery failed: {}", e),
    }

    log::debug!("Total discovered sources: {}", sources.len());
    for s in &sources {
        log::debug!("  [{:?}] {} — {}", s.source_type, s.name, s.path_or_id);
    }

    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ignored_by_label_accepts_truthy_values() {
        for value in ["true", "TRUE", "1", " yes ", "on"] {
            let labels =
                std::collections::HashMap::from([(IGNORE_LABEL.to_string(), value.to_string())]);
            assert!(
                is_ignored_by_label(&labels),
                "expected {value} to be truthy"
            );
        }
    }

    #[test]
    fn test_is_ignored_by_label_ignores_other_values_and_labels() {
        let off =
            std::collections::HashMap::from([(IGNORE_LABEL.to_string(), "false".to_string())]);
        assert!(!is_ignored_by_label(&off));

        let unrelated = std::collections::HashMap::from([(
            "com.docker.compose.service".to_string(),
            "stackdog".to_string(),
        )]);
        assert!(!is_ignored_by_label(&unrelated));

        assert!(!is_ignored_by_label(&std::collections::HashMap::new()));
    }

    #[test]
    fn test_container_id_from_mountinfo_prefers_container_path() {
        // Overlay layer hashes appear first and are not container IDs.
        let mountinfo = "\
1234 1200 0:100 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
1250 1234 0:60 /containers/6b55165e7b09f91066e8acfd833c69f9b3cf441b948971c93d7f5a15c621ce7f/resolv.conf /etc/resolv.conf rw - ext4 /dev/vda1 rw\n";

        assert_eq!(
            container_id_from_mountinfo(mountinfo).as_deref(),
            Some("6b55165e7b09f91066e8acfd833c69f9b3cf441b948971c93d7f5a15c621ce7f")
        );
    }

    #[test]
    fn test_container_id_from_mountinfo_returns_none_on_host() {
        let mountinfo = "25 30 0:23 / /proc rw,nosuid,nodev,noexec - proc proc rw\n";
        assert_eq!(container_id_from_mountinfo(mountinfo), None);
    }

    #[test]
    fn test_extract_container_id_from_proc_lines() {
        // cgroup v1
        assert_eq!(
            extract_container_id(
                "11:devices:/docker/a70b8c987795e1f3aa1c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f"
            )
            .as_deref(),
            Some("a70b8c987795e1f3aa1c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f")
        );

        // cgroup v2 / systemd scope
        assert_eq!(
            extract_container_id(
                "0::/system.slice/docker-a70b8c987795e1f3aa1c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f.scope"
            )
            .as_deref(),
            Some("a70b8c987795e1f3aa1c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f")
        );

        // Nothing container-shaped on a plain host
        assert_eq!(extract_container_id("0::/init.scope"), None);
        assert_eq!(extract_container_id("12:pids:/user.slice"), None);
    }
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_source_type_display() {
        assert_eq!(
            LogSourceType::DockerContainer.to_string(),
            "DockerContainer"
        );
        assert_eq!(LogSourceType::SystemLog.to_string(), "SystemLog");
        assert_eq!(LogSourceType::CustomFile.to_string(), "CustomFile");
    }

    #[test]
    fn test_log_source_type_from_str() {
        assert_eq!(
            "DockerContainer".parse::<LogSourceType>().unwrap(),
            LogSourceType::DockerContainer
        );
        assert_eq!(
            "SystemLog".parse::<LogSourceType>().unwrap(),
            LogSourceType::SystemLog
        );
        assert_eq!(
            "CustomFile".parse::<LogSourceType>().unwrap(),
            LogSourceType::CustomFile
        );
        assert_eq!(
            "anything".parse::<LogSourceType>().unwrap(),
            LogSourceType::CustomFile
        );
    }

    #[test]
    fn test_log_source_new() {
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog".into(),
        );
        assert_eq!(source.source_type, LogSourceType::SystemLog);
        assert_eq!(source.path_or_id, "/var/log/syslog");
        assert_eq!(source.name, "syslog");
        assert_eq!(source.last_read_position, 0);
        assert!(!source.id.is_empty());
    }

    #[test]
    fn test_discover_custom_sources_existing_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "test log line").unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        let sources = discover_custom_sources(std::slice::from_ref(&path));
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_type, LogSourceType::CustomFile);
        assert_eq!(sources[0].path_or_id, path);
    }

    #[test]
    fn test_discover_custom_sources_nonexistent_file() {
        let sources = discover_custom_sources(&["/nonexistent/path/log.txt".into()]);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_discover_custom_sources_mixed() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "log").unwrap();
        let existing = tmp.path().to_string_lossy().to_string();

        let sources = discover_custom_sources(&[existing.clone(), "/does/not/exist.log".into()]);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path_or_id, existing);
    }

    #[test]
    fn test_discover_system_logs_returns_only_existing() {
        let sources = discover_system_logs();
        for source in &sources {
            assert_eq!(source.source_type, LogSourceType::SystemLog);
            assert!(Path::new(&source.path_or_id).exists());
        }
    }

    #[test]
    fn test_log_source_serialization() {
        let source = LogSource::new(
            LogSourceType::DockerContainer,
            "abc123def456".into(),
            "docker:myapp".into(),
        );
        let json = serde_json::to_string(&source).unwrap();
        let deserialized: LogSource = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_type, LogSourceType::DockerContainer);
        assert_eq!(deserialized.path_or_id, "abc123def456");
        assert_eq!(deserialized.name, "docker:myapp");
    }
}
