//! PHP2Shell exposure and PHP worker crashes.
//!
//! PHP2Shell (CVE-2026-109618, CVE-2026-109619) is unauthenticated remote code
//! execution in the PHP interpreter itself. Nothing in a log line or a file on
//! disk marks the attack reliably, so this module answers two narrower
//! questions:
//!
//! - which PHP builds on the host and in running containers predate the fixed
//!   releases (`vuln.php2shell`);
//! - whether PHP workers keep crashing, which is what memory-corruption
//!   attempts tend to leave behind (`php.worker-crash`).
//!
//! Neither names a client address, so neither ever bans.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::detectors::audits::{parse_apk_installed, parse_dpkg_status};
use crate::detectors::php_shell::{under_host_root, ContainerFilesystem};
use crate::detectors::{DetectorFamily, DetectorFinding, LogDetector};
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

pub const VERSION_DETECTOR_ID: &str = "vuln.php2shell";
pub const CRASH_DETECTOR_ID: &str = "php.worker-crash";

const CVES: &str = "CVE-2026-109618, CVE-2026-109619";

/// First fixed release per supported branch, published 2026-10-21. Branches
/// older than the oldest listed one get no fix from the PHP project.
const FIXED_RELEASES: &[(u32, u32, u32)] = &[(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)];

/// Package databases, relative to a filesystem root.
const PACKAGE_DATABASES: &[&str] = &["var/lib/dpkg/status", "lib/apk/db/installed"];

/// Crashes in one batch of log lines before it is worth an alert. A single
/// segfault is usually a buggy extension; a run of them is not.
const CRASH_THRESHOLD: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// An upstream build older than the fix for its branch.
    Vulnerable {
        fixed_in: Option<String>,
    },
    /// A distribution package older than the upstream fix. Distributions
    /// backport fixes without changing the upstream number, so only the
    /// vendor's advisory can say.
    CheckVendor {
        fixed_in: Option<String>,
    },
    Patched,
}

/// Where a PHP version was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSource {
    /// `PHP_VERSION` in a container's environment: official images build
    /// PHP from upstream source.
    ImageEnv,
    /// A distribution package (`php8.2-common` 8.2.20-1~deb12u1).
    Package { name: String },
}

/// The PHP2Shell exposure of `version`, or None if it is not a PHP version.
pub fn exposure(version: &str, from_distro_package: bool) -> Option<Exposure> {
    let (major, minor, patch) = upstream_version(version)?;

    if (major, minor) > (8, 5) {
        return Some(Exposure::Patched);
    }

    let fixed = FIXED_RELEASES
        .iter()
        .find(|(fixed_major, fixed_minor, _)| (*fixed_major, *fixed_minor) == (major, minor));

    match fixed {
        Some(&(_, _, fixed_patch)) if patch >= fixed_patch => Some(Exposure::Patched),
        Some(&(fixed_major, fixed_minor, fixed_patch)) => {
            let fixed_in = Some(format!("{}.{}.{}", fixed_major, fixed_minor, fixed_patch));
            Some(if from_distro_package {
                Exposure::CheckVendor { fixed_in }
            } else {
                Exposure::Vulnerable { fixed_in }
            })
        }
        None => Some(if from_distro_package {
            Exposure::CheckVendor { fixed_in: None }
        } else {
            Exposure::Vulnerable { fixed_in: None }
        }),
    }
}

/// `8.3.30` out of `8.3.30`, `1:8.2.20-1~deb12u1` or `8.3.12-1+ubuntu22.04.1+deb.sury.org+1`.
fn upstream_version(version: &str) -> Option<(u32, u32, u32)> {
    let without_epoch = version.split_once(':').map_or(version, |(_, rest)| rest);
    let numeric: String = without_epoch
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = numeric.split('.').filter(|part| !part.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// The package that carries the PHP core version: `php8.2-common` (Debian,
/// Ubuntu), `php83-common` or `php83` (Alpine). On Alpine every SAPI and
/// extension depends on `php83-common`, not on `php83`, so `apk add php83-fpm`
/// installs no `php83`. Meta-packages such as `php` carry the distribution's
/// own numbering, not PHP's.
fn is_php_core_package(name: &str) -> bool {
    if let Some(branch) = name
        .strip_prefix("php")
        .and_then(|rest| rest.strip_suffix("-common"))
    {
        return is_branch(branch, true) || is_branch(branch, false);
    }
    name.strip_prefix("php")
        .map(|branch| is_branch(branch, false))
        .unwrap_or(false)
}

fn is_branch(text: &str, dotted: bool) -> bool {
    if dotted {
        matches!(text.split_once('.'), Some((major, minor))
            if !major.is_empty() && !minor.is_empty()
                && major.chars().all(|c| c.is_ascii_digit())
                && minor.chars().all(|c| c.is_ascii_digit()))
    } else {
        text.len() >= 2 && text.chars().all(|c| c.is_ascii_digit())
    }
}

/// A PHP installation found on the host or in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpInstall {
    /// `host` or the container name.
    pub owner: String,
    pub version: String,
    pub source: VersionSource,
}

/// A parsed package database and the file state it was parsed from.
struct CachedPackages {
    modified: SystemTime,
    size: u64,
    packages: Vec<(String, String)>,
}

#[derive(Default)]
pub struct PhpVersionMonitor {
    /// Parsed package databases keyed by path, reused while the file's
    /// modification time and size stay the same.
    cache: Mutex<HashMap<PathBuf, CachedPackages>>,
}

impl PhpVersionMonitor {
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
            if let Some(version) = &container.php_version {
                installs.push(PhpInstall {
                    owner: container.name.clone(),
                    version: version.clone(),
                    source: VersionSource::ImageEnv,
                });
            }
            if let Some(merged_dir) = &container.merged_dir {
                installs.extend(
                    self.installs_under(&container.name, &under_host_root(host_root, merged_dir)),
                );
            }
        }

        findings(&installs)
    }

    fn installs_under(&self, owner: &str, root: &Path) -> Vec<PhpInstall> {
        PACKAGE_DATABASES
            .iter()
            .flat_map(|database| self.packages(&root.join(database)))
            .filter(|(name, _)| is_php_core_package(name))
            .map(|(name, version)| PhpInstall {
                owner: owner.to_string(),
                version,
                source: VersionSource::Package { name },
            })
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
        let packages = if path.ends_with("installed") {
            parse_apk_installed(&content)
        } else {
            parse_dpkg_status(&content)
        };

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
pub fn findings(installs: &[PhpInstall]) -> Vec<DetectorFinding> {
    let mut seen = HashSet::new();
    let mut findings = Vec::new();

    for install in installs {
        if !seen.insert((install.owner.as_str(), install.version.as_str())) {
            continue;
        }
        let from_package = matches!(install.source, VersionSource::Package { .. });
        let Some(exposure) = exposure(&install.version, from_package) else {
            continue;
        };
        let source = match &install.source {
            VersionSource::ImageEnv => "image PHP_VERSION".to_string(),
            VersionSource::Package { name } => format!("package {}", name),
        };
        let upgrade = |fixed_in: &Option<String>| {
            match fixed_in {
            Some(fixed) => format!("upgrade to {} or later", fixed),
            None => "this branch gets no fix from the PHP project; move to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later".to_string(),
        }
        };

        let (description, severity, confidence) = match &exposure {
            Exposure::Patched => continue,
            Exposure::Vulnerable { fixed_in } => (
                format!(
                    "PHP {} on {} is exposed to PHP2Shell unauthenticated remote code execution ({}): {}",
                    install.version, install.owner, CVES, upgrade(fixed_in)
                ),
                AnomalySeverity::Critical,
                95,
            ),
            Exposure::CheckVendor { fixed_in } => (
                format!(
                    "PHP {} on {} predates the upstream PHP2Shell fixes ({}). Distribution packages may carry a backported fix: check your vendor's advisory, or {}",
                    install.version, install.owner, CVES, upgrade(fixed_in)
                ),
                AnomalySeverity::Medium,
                60,
            ),
        };

        findings.push(DetectorFinding {
            detector_id: VERSION_DETECTOR_ID.into(),
            family: DetectorFamily::Vulnerability,
            description,
            severity,
            confidence,
            sample_line: format!("{} {} {}", install.owner, source, install.version),
        });
    }

    findings
}

/// PHP workers dying on memory faults, from php-fpm and Apache error logs.
pub struct PhpWorkerCrashDetector;

impl LogDetector for PhpWorkerCrashDetector {
    fn id(&self) -> &'static str {
        CRASH_DETECTOR_ID
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Execution
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let crashes: Vec<&LogEntry> = entries
            .iter()
            .filter(|entry| is_worker_crash(&entry.line))
            .collect();

        if crashes.len() < CRASH_THRESHOLD {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: CRASH_DETECTOR_ID.into(),
            family: DetectorFamily::Execution,
            description: format!(
                "PHP worker processes crashed {} times on memory faults. Repeated crashes are what attempts against PHP memory bugs such as PHP2Shell ({}) leave behind; check the PHP version and the requests at those times",
                crashes.len(),
                CVES
            ),
            severity: if crashes.len() >= 10 {
                AnomalySeverity::High
            } else {
                AnomalySeverity::Medium
            },
            confidence: 65,
            sample_line: crashes[0].line.clone(),
        }]
    }
}

/// php-fpm: `[pool www] child 123 exited on signal 11 (SIGSEGV) after ...`
/// (php-src sapi/fpm/fpm/fpm_children.c). Apache: `child pid 123 exit signal
/// Segmentation fault (11)` (httpd os/unix/unixd.c, AH00051/AH00052).
fn is_worker_crash(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let fpm = lower.contains("child ")
        && lower.contains("exited on signal")
        && ["(sigsegv", "(sigbus", "(sigabrt", "(sigill"]
            .iter()
            .any(|signal| lower.contains(signal));
    let apache = lower.contains("child pid")
        && [
            "exit signal segmentation fault",
            "exit signal bus error",
            "exit signal aborted",
            "exit signal illegal instruction",
        ]
        .iter()
        .any(|signal| lower.contains(signal));
    fpm || apache
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_upstream_builds_below_the_fix_are_vulnerable() {
        assert_eq!(
            exposure("8.3.30", false),
            Some(Exposure::Vulnerable {
                fixed_in: Some("8.3.36".into())
            })
        );
        assert_eq!(exposure("8.3.36", false), Some(Exposure::Patched));
        assert_eq!(exposure("8.4.27", false), Some(Exposure::Patched));
        assert_eq!(
            exposure("8.5.11", false),
            Some(Exposure::Vulnerable {
                fixed_in: Some("8.5.12".into())
            })
        );
        assert_eq!(exposure("8.6.0", false), Some(Exposure::Patched));
        assert_eq!(
            exposure("8.1.31", false),
            Some(Exposure::Vulnerable { fixed_in: None })
        );
        assert_eq!(
            exposure("7.4.33", false),
            Some(Exposure::Vulnerable { fixed_in: None })
        );
        assert_eq!(exposure("not-a-version", false), None);
    }

    #[test]
    fn test_distro_packages_below_the_fix_need_the_vendor_advisory() {
        assert_eq!(
            exposure("8.2.20-1~deb12u1", true),
            Some(Exposure::CheckVendor {
                fixed_in: Some("8.2.35".into())
            })
        );
        assert_eq!(
            exposure("8.3.36-1+ubuntu24.04.1+deb.sury.org+1", true),
            Some(Exposure::Patched)
        );
        assert_eq!(
            exposure("1:8.1.2-1ubuntu2.20", true),
            Some(Exposure::CheckVendor { fixed_in: None })
        );
    }

    #[test]
    fn test_only_core_packages_carry_the_php_version() {
        assert!(is_php_core_package("php8.2-common"));
        assert!(is_php_core_package("php83"));
        assert!(is_php_core_package("php83-common"));
        assert!(!is_php_core_package("php"));
        assert!(!is_php_core_package("php-common"));
        assert!(!is_php_core_package("php8.2-mysql"));
        assert!(!is_php_core_package("php83-fpm"));
        assert!(!is_php_core_package("phpmyadmin"));
    }

    #[test]
    fn test_findings_per_owner_and_version() {
        let installs = vec![
            PhpInstall {
                owner: "wordpress".into(),
                version: "8.3.30".into(),
                source: VersionSource::ImageEnv,
            },
            PhpInstall {
                owner: "wordpress".into(),
                version: "8.3.30".into(),
                source: VersionSource::ImageEnv,
            },
            PhpInstall {
                owner: "host".into(),
                version: "8.2.20-1~deb12u1".into(),
                source: VersionSource::Package {
                    name: "php8.2-common".into(),
                },
            },
            PhpInstall {
                owner: "shop".into(),
                version: "8.4.27".into(),
                source: VersionSource::ImageEnv,
            },
        ];

        let found = findings(&installs);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].severity, AnomalySeverity::Critical);
        assert!(found[0].description.contains("upgrade to 8.3.36"));
        assert_eq!(found[1].severity, AnomalySeverity::Medium);
        assert!(found[1].description.contains("vendor"));
        assert!(found
            .iter()
            .all(|finding| !crate::ip_ban::gate::names_confirmed_attack(&finding.description)));
    }

    #[test]
    fn test_monitor_reads_package_databases_under_a_root() {
        // The host root is a temp dir; the container's MergedDir sits under it,
        // as it does when Stackdog runs with the host mounted at /host.
        let host = tempfile::tempdir().unwrap();
        let dpkg = host.path().join("overlay/abc/merged/var/lib/dpkg");
        std::fs::create_dir_all(&dpkg).unwrap();
        std::fs::write(
            dpkg.join("status"),
            "Package: php\nVersion: 2:8.2+93\n\nPackage: php8.2-common\nVersion: 8.2.20-1~deb12u1\n\nPackage: php8.2-fpm\nVersion: 8.2.20-1~deb12u1\n",
        )
        .unwrap();

        let container = ContainerFilesystem {
            name: "legacy".into(),
            merged_dir: Some("/overlay/abc/merged".into()),
            php_version: Some("8.4.20".into()),
            ..Default::default()
        };
        let monitor = PhpVersionMonitor::new();
        let found = monitor.detect(&[container], host.path().to_str());

        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found
            .iter()
            .any(|f| f.description.contains("PHP 8.4.20 on legacy")));
        assert!(found
            .iter()
            .any(|f| f.description.contains("PHP 8.2.20-1~deb12u1 on legacy")));
    }

    #[test]
    fn test_alpine_common_package_alone_is_read() {
        // `apk add php83-fpm php83-mysqli` installs php83-common, not php83.
        let host = tempfile::tempdir().unwrap();
        let apk = host.path().join("lib/apk/db");
        std::fs::create_dir_all(&apk).unwrap();
        std::fs::write(
            apk.join("installed"),
            "P:php83-common\nV:8.3.13-r0\n\nP:php83-fpm\nV:8.3.13-r0\n\nP:php83-pecl-redis\nV:6.1.0-r0\n",
        )
        .unwrap();

        let found = PhpVersionMonitor::new().detect(&[], host.path().to_str());
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].description.contains("PHP 8.3.13-r0 on host"));
        assert!(found[0].description.contains("8.3.36"));
    }

    fn crash_entries(lines: &[&str]) -> Vec<LogEntry> {
        lines
            .iter()
            .map(|line| LogEntry {
                source_id: "php-fpm".into(),
                timestamp: Utc::now(),
                line: (*line).into(),
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_worker_crashes_need_a_run() {
        let fpm = "[31-Oct-2026 10:00:00] WARNING: [pool www] child 4121 exited on signal 11 (SIGSEGV - core dumped) after 0.412000 seconds from start";
        let apache = "[Sat Oct 31 10:00:00.123 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 4122 exit signal Segmentation fault (11)";
        let graceful = "[31-Oct-2026 10:00:00] NOTICE: [pool www] child 4123 exited on signal 3 (SIGQUIT) after 30.0 seconds from start";

        assert!(PhpWorkerCrashDetector
            .detect(&crash_entries(&[fpm, apache, graceful]))
            .is_empty());

        let found = PhpWorkerCrashDetector.detect(&crash_entries(&[fpm, apache, fpm, graceful]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector_id, CRASH_DETECTOR_ID);
        assert!(!crate::ip_ban::gate::names_confirmed_attack(
            &found[0].description
        ));
    }
}
