//! SSHole (CVE-2026-123158): OpenSSH authentication bypass on musl.
//!
//! SSHole lets an unauthenticated attacker log into accounts that carry a `*`
//! in the password field (password-disabled accounts such as root or alpine)
//! by sending an oversized password: 257 to 1024 bytes make the hash attempt
//! fail, and OpenSSH without PAM reads that failure as the same `*` the
//! account stores. It affects Linux systems that run OpenSSH on musl with PAM
//! disabled, including Alpine's default server configuration. Fixed in
//! OpenSSH 10.6p2 (10.6_p2 on Alpine).
//!
//! Two halves, same shape as the PHP2Shell work:
//!
//! - [`SshVersionMonitor`] flags OpenSSH builds that predate the fix on musl
//!   systems (`vuln.sshole`). A version names no attacker, so it alerts and
//!   never bans.
//! - [`SshPasswordLoginDetector`] watches logs for password logins to key-only
//!   accounts (`ssh.password-login`). That is what a successful SSHole login
//!   looks like, and Alpine's own guidance is to hunt exactly these lines. The
//!   line carries the client address, so it feeds the ban engine.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::detectors::audits::parse_apk_installed;
use crate::detectors::php_shell::{under_host_root, ContainerFilesystem};
use crate::detectors::{DetectorFamily, DetectorFinding, LogDetector};
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

pub const VERSION_DETECTOR_ID: &str = "vuln.sshole";
pub const PASSWORD_LOGIN_DETECTOR_ID: &str = "ssh.password-login";

const CVES: &str = "CVE-2026-123158";

/// First fixed upstream release: 10.6p2.
const FIXED: (u32, u32, u32) = (10, 6, 2);

/// Accounts whose password field is `*` by default, so a password login to
/// them is either a misconfiguration or SSHole. Alpine's advisory names these
/// two; `STACKDOG_SSHOLE_KEYONLY_USERS` extends the list.
pub const DEFAULT_KEYONLY_USERS: &[&str] = &["root", "alpine"];

/// Findings per pass. Each one is an offense, like the PHP2Shell attempts.
const MAX_FINDINGS: usize = 50;

/// Packages that carry the sshd that checks passwords without PAM (Alpine's
/// default flavor). The PAM and krb5 flavors are built `--with-pam` and are
/// not affected; their packages are `openssh-server-pam` and
/// `openssh-server-krb5`.
const VULNERABLE_SERVER_PACKAGES: &[&str] = &["openssh-server", "openssh"];

/// Only the musl distribution uses this package database, and musl is the
/// half of the vulnerable configuration we can see from disk.
const APK_DATABASE: &str = "lib/apk/db/installed";

/// `10.6_p2`, `10.6p2`, `OpenSSH_10.6p2`, `9.3_p2-r0` -> (10, 6, 2).
pub fn upstream_ssh_version(version: &str) -> Option<(u32, u32, u32)> {
    let without_epoch = version.split_once(':').map_or(version, |(_, rest)| rest);
    let start = without_epoch.find(|c: char| c.is_ascii_digit())?;
    let rest = &without_epoch[start..];

    let major_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    let major: u32 = rest[..major_len].parse().ok()?;
    let rest = &rest[major_len..];
    let rest = rest.strip_prefix('.')?;

    let minor_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    let minor: u32 = rest[..minor_len].parse().ok()?;
    let suffix = &rest[minor_len..];

    // The portable release number: "p2" upstream, "_p2" on Alpine. Absent
    // means the first portable release of that series.
    let p = suffix
        .find('p')
        .and_then(|index| {
            suffix[index + 1..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or(0);

    Some((major, minor, p))
}

/// Whether an OpenSSH build predates the SSHole fix.
pub fn predates_fix(version: &str) -> Option<bool> {
    upstream_ssh_version(version).map(|parsed| parsed < FIXED)
}

/// A package database parsed from a file, kept while the file does not change.
struct CachedPackages {
    modified: SystemTime,
    size: u64,
    packages: Vec<(String, String)>,
}

#[derive(Default)]
pub struct SshVersionMonitor {
    cache: Mutex<HashMap<PathBuf, CachedPackages>>,
}

impl SshVersionMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        containers: &[ContainerFilesystem],
        host_root: Option<&str>,
    ) -> Vec<DetectorFinding> {
        let mut installs = self.installs_under("host", &under_host_root(host_root, "/"));

        for container in containers {
            if let Some(merged_dir) = &container.merged_dir {
                installs.extend(
                    self.installs_under(&container.name, &under_host_root(host_root, merged_dir)),
                );
            }
        }

        findings(&installs)
    }

    fn installs_under(&self, owner: &str, root: &Path) -> Vec<(String, String, String)> {
        self.packages(&root.join(APK_DATABASE))
            .into_iter()
            .filter(|(name, _)| VULNERABLE_SERVER_PACKAGES.contains(&name.as_str()))
            .map(|(name, version)| (owner.to_string(), name, version))
            .collect()
    }

    fn packages(&self, path: &Path) -> Vec<(String, String)> {
        let Ok(metadata) = std::fs::metadata(path) else {
            return Vec::new();
        };
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(path) {
                if cached.modified == modified && cached.size == size {
                    return cached.packages.clone();
                }
            }
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        let packages = parse_apk_installed(&content);

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                path.to_path_buf(),
                CachedPackages {
                    modified,
                    size,
                    packages: packages.clone(),
                },
            );
        }
        packages
    }
}

/// One finding per exposed `(owner, version)`.
pub fn findings(installs: &[(String, String, String)]) -> Vec<DetectorFinding> {
    let mut seen = HashSet::new();
    let mut findings = Vec::new();

    for (owner, name, version) in installs {
        if !seen.insert((owner.as_str(), version.as_str())) {
            continue;
        }
        if predates_fix(version) != Some(true) {
            continue;
        }

        findings.push(DetectorFinding {
            detector_id: VERSION_DETECTOR_ID.into(),
            family: DetectorFamily::Vulnerability,
            description: format!(
                "SSHole authentication bypass ({CVES}): OpenSSH {version} on {owner} ({name}) predates the 10.6p2 fix. This is the vulnerable configuration: musl, passwords checked without PAM. An oversized password logs the attacker into accounts whose password field is `*` (root, alpine). Upgrade to 10.6p2, 10.6_p2 on Alpine, and restart sshd"
            ),
            severity: AnomalySeverity::Critical,
            confidence: 92,
            sample_line: format!("{owner} package {name} {version}"),
        });
    }

    findings
}

/// Password logins to accounts that should never accept one. That is either a
/// misconfiguration or the signature of a successful SSHole login.
pub struct SshPasswordLoginDetector {
    keyonly_users: Vec<String>,
}

impl SshPasswordLoginDetector {
    pub fn new() -> Self {
        Self {
            keyonly_users: keyonly_users(),
        }
    }

    #[cfg(test)]
    fn with_users(users: &[&str]) -> Self {
        Self {
            keyonly_users: users.iter().map(|user| user.to_string()).collect(),
        }
    }
}

impl Default for SshPasswordLoginDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// `root`, `alpine`, plus whatever the operator runs key-only.
pub fn keyonly_users() -> Vec<String> {
    let configured = std::env::var("STACKDOG_SSHOLE_KEYONLY_USERS").ok();
    configured
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|users| !users.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_KEYONLY_USERS
                .iter()
                .map(|user| user.to_string())
                .collect()
        })
}

impl LogDetector for SshPasswordLoginDetector {
    fn id(&self) -> &'static str {
        PASSWORD_LOGIN_DETECTOR_ID
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Execution
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        // Identical lines are separate logins, and the registry drops findings
        // with identical samples, so repeats are numbered to count as the
        // offenses they are.
        let mut seen: HashMap<String, usize> = HashMap::new();

        entries
            .iter()
            .filter_map(|entry| {
                let account = password_login_account(&entry.line)?;
                if !self
                    .keyonly_users
                    .iter()
                    .any(|user| user.eq_ignore_ascii_case(account))
                {
                    return None;
                }

                let count = seen.entry(entry.line.clone()).or_insert(0);
                *count += 1;
                let sample_line = if *count > 1 {
                    format!("{} (repeat {})", entry.line, count)
                } else {
                    entry.line.clone()
                };

                Some(DetectorFinding {
                    detector_id: PASSWORD_LOGIN_DETECTOR_ID.into(),
                    family: DetectorFamily::Execution,
                    description: format!(
                        "Password login to key-only account {account}. SSHole ({CVES}) logs in exactly this way, and a successful login is a foothold, not a failed attempt. If nobody should use passwords here, treat the host as compromised: check users, authorized_keys and doas, then upgrade OpenSSH to 10.6p2 and restart sshd"
                    ),
                    severity: AnomalySeverity::High,
                    confidence: 85,
                    sample_line,
                })
            })
            .take(MAX_FINDINGS)
            .collect()
    }
}

/// The account an "Accepted password for <account> from ..." line names.
fn password_login_account(line: &str) -> Option<&str> {
    let lower = line.to_ascii_lowercase();
    let marker = "accepted password for ";
    let start = lower.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',')
        .unwrap_or(rest.len());
    let account = &rest[..end];
    (!account.is_empty()).then_some(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_version_parsing() {
        assert_eq!(upstream_ssh_version("10.6_p2-r0"), Some((10, 6, 2)));
        assert_eq!(upstream_ssh_version("10.6p2"), Some((10, 6, 2)));
        assert_eq!(upstream_ssh_version("OpenSSH_10.6p2"), Some((10, 6, 2)));
        assert_eq!(upstream_ssh_version("9.3_p2-r0"), Some((9, 3, 2)));
        assert_eq!(upstream_ssh_version("1:9.2p1-2+deb12u5"), Some((9, 2, 1)));
        assert_eq!(upstream_ssh_version("10.6"), Some((10, 6, 0)));
        assert_eq!(upstream_ssh_version("not-a-version"), None);
    }

    #[test]
    fn test_versions_before_the_fix_are_exposed() {
        assert_eq!(predates_fix("10.6_p1-r0"), Some(true));
        assert_eq!(predates_fix("10.6_p2-r0"), Some(false));
        assert_eq!(predates_fix("9.3_p2-r0"), Some(true));
        assert_eq!(predates_fix("10.7p1"), Some(false));
        assert_eq!(predates_fix("garbage"), None);
    }

    fn monitor_with(root: &Path, packages: &str) -> Vec<DetectorFinding> {
        let apk = root.join("lib/apk/db");
        std::fs::create_dir_all(&apk).unwrap();
        std::fs::write(apk.join("installed"), packages).unwrap();
        SshVersionMonitor::new().detect(&[], root.to_str())
    }

    #[test]
    fn test_old_openssh_on_musl_is_reported_and_the_fix_is_not() {
        let root = tempfile::tempdir().unwrap();
        let found = monitor_with(
            root.path(),
            "P:openssh-server\nV:10.6_p1-r0\n\nP:openssh-keygen\nV:10.6_p1-r0\n\n",
        );
        assert_eq!(found.len(), 1, "{found:#?}");
        assert_eq!(found[0].detector_id, VERSION_DETECTOR_ID);
        assert_eq!(found[0].severity, AnomalySeverity::Critical);
        assert!(found[0].description.contains("10.6_p1-r0"));
        assert!(found[0].description.contains("restart sshd"));

        let patched = tempfile::tempdir().unwrap();
        assert!(monitor_with(patched.path(), "P:openssh-server\nV:10.6_p2-r0\n\n").is_empty());
    }

    #[test]
    fn test_pam_flavour_and_glibc_systems_are_not_reported() {
        // The PAM flavor checks passwords through PAM: not affected.
        let root = tempfile::tempdir().unwrap();
        assert!(monitor_with(root.path(), "P:openssh-server-pam\nV:9.3_p2-r0\n\n").is_empty());

        // A dpkg system is glibc-based: not affected, and unread anyway.
        let glibc = tempfile::tempdir().unwrap();
        let dpkg = glibc.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&dpkg).unwrap();
        std::fs::write(
            dpkg.join("status"),
            "Package: openssh-server\nVersion: 1:9.2p1-2+deb12u5\n\n",
        )
        .unwrap();
        assert!(SshVersionMonitor::new()
            .detect(&[], glibc.path().to_str())
            .is_empty());
    }

    fn entries(lines: &[&str]) -> Vec<LogEntry> {
        lines
            .iter()
            .map(|line| LogEntry {
                source_id: "sshd".into(),
                timestamp: Utc::now(),
                line: (*line).into(),
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_password_login_to_keyonly_account_is_reported() {
        let detector = SshPasswordLoginDetector::with_users(&["root", "alpine"]);
        let found = detector.detect(&entries(&[
            "Nov  6 10:00:00 host sshd[123]: Accepted password for root from 89.116.89.18 port 51234 ssh2",
            "Nov  6 10:00:01 host sshd[124]: Accepted password for alpine from 89.116.89.18 port 51236 ssh2",
        ]));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].detector_id, PASSWORD_LOGIN_DETECTOR_ID);
        assert!(found[0].sample_line.contains("89.116.89.18"));
    }

    #[test]
    fn test_ordinary_ssh_lines_are_not_reported() {
        let detector = SshPasswordLoginDetector::with_users(&["root", "alpine"]);
        let found = detector.detect(&entries(&[
            // A password user that is not on the key-only list.
            "Nov  6 10:00:00 host sshd[123]: Accepted password for deploy from 203.0.113.9 port 51234 ssh2",
            // Key logins are the normal case.
            "Nov  6 10:00:01 host sshd[124]: Accepted publickey for root from 203.0.113.9 port 51236 ssh2",
            // Failures belong to the brute-force detector.
            "Nov  6 10:00:02 host sshd[125]: Failed password for root from 203.0.113.9 port 51238 ssh2",
            // A PAM-based login is not the SSHole path.
            "Nov  6 10:00:03 host sshd[126]: Accepted keyboard-interactive/pam for root from 203.0.113.9 port 51240 ssh2",
        ]));
        assert_eq!(found.len(), 0, "{found:#?}");
    }

    #[test]
    fn test_each_login_line_is_its_own_offense() {
        let detector = SshPasswordLoginDetector::with_users(&["root"]);
        let line = "Nov  6 10:00:00 host sshd[123]: Accepted password for root from 89.116.89.18 port 51234 ssh2";
        let found = detector.detect(&entries(&[line; 5]));
        assert_eq!(found.len(), 5);
    }
}
