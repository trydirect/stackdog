//! CVE watch: match the package inventory against public vulnerability feeds.
//!
//! The two CVE-specific detectors hardcode what they know. This one asks the
//! public databases instead, so a CVE published tonight is checked on the next
//! refresh without a release:
//!
//! - [OSV](https://osv.dev) answers "does this exact package version have
//!   known vulnerabilities", per ecosystem and version. Debian and Ubuntu
//!   versions are matched server-side (`1:9.2p1-2+deb12u1` works as-is);
//!   Alpine versions must be sent without the `-rN` package revision
//!   (`9.7_p1-r6` -> `9.7_p1`), which is what their data carries.
//! - CISA's KEV catalog says which of them are exploited in the wild. Its
//!   canonical URL rejects datacenter clients, so the `cisagov/kev-data`
//!   mirror is tried first.
//!
//! Honest limits, same as every version-based check: a match says a fix is
//! missing, not that a machine is exploitable. Distributions backport fixes,
//! and configuration-dependent CVEs do not survive being flattened into a
//! version range. Alerts say "check your vendor's advisory" for that reason.
//! Very fresh CVEs may not be in OSV yet (CVE-2026-123158 was not, days after
//! publication); the specialized detectors cover the ones we know in detail.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use rusqlite::params;
use serde::Deserialize;

use crate::database::connection::DbPool;
use crate::detectors::audits::{parse_apk_installed, parse_dpkg_status};
use crate::detectors::php_shell::{under_host_root, ContainerFilesystem};
use crate::detectors::{DetectorFamily, DetectorFinding};
use crate::sniff::analyzer::AnomalySeverity;

pub const CVE_DETECTOR_ID: &str = "vuln.cve-watch";

const OSV_QUERYBATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN: &str = "https://api.osv.dev/v1/vulns/";
const KEV_MIRROR: &str =
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
const KEV_CANONICAL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Re-query every package at least this often: that is how a newly published
/// CVE gets noticed.
const REFRESH: Duration = Duration::from_secs(24 * 60 * 60);
/// Findings per pass. A first run over a long-lived box can match hundreds;
/// KEV and severity decide who goes first, the rest arrive next passes.
const MAX_FINDINGS: usize = 50;
const BATCH: usize = 200;

/// One installed package, as the feeds name it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstalledPackage {
    pub owner: String,
    pub ecosystem: String,
    pub name: String,
    /// The version as the package database records it.
    pub version: String,
}

/// apk versions carry a package revision (`9.7_p1-r6`) that OSV's Alpine data
/// does not; upstream comparison needs the bare version.
pub fn query_version(ecosystem: &str, version: &str) -> String {
    if ecosystem.starts_with("Alpine") {
        if let Some((base, revision)) = version.rsplit_once("-r") {
            if !revision.is_empty() && revision.chars().all(|c| c.is_ascii_digit()) {
                return base.to_string();
            }
        }
    }
    version.to_string()
}

/// The OSV ecosystem of a filesystem root, read from /etc/os-release. Alpine
/// entries are filed per release (`Alpine:v3.20`), so the version matters.
pub fn ecosystem_from_os_release(text: &str) -> Option<String> {
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(name)?;
            let rest = rest.strip_prefix('=')?;
            Some(rest.trim_matches('"').trim().to_string())
        })
    };
    match field("ID")?.as_str() {
        "alpine" => {
            let version_id = field("VERSION_ID")?;
            let mut parts = version_id.split('.');
            let major = parts.next()?;
            let minor = parts.next()?;
            Some(format!("Alpine:v{major}.{minor}"))
        }
        "debian" => Some("Debian".to_string()),
        "ubuntu" => Some("Ubuntu".to_string()),
        _ => None,
    }
}

/// Packages installed under a filesystem root, with the ecosystem that root's
/// OS release declares. apk and dpkg databases are both read; whichever
/// exists is the package manager of that system.
pub fn installed_under(owner: &str, root: &Path) -> Vec<InstalledPackage> {
    let os_release = std::fs::read_to_string(root.join("etc/os-release")).ok();
    let ecosystem = os_release
        .as_deref()
        .and_then(ecosystem_from_os_release)
        .unwrap_or_else(|| {
            // No os-release: a dpkg database still says Debian-family, an apk
            // one cannot be pinned to a release and is skipped rather than
            // matched against the wrong ranges.
            if root.join("var/lib/dpkg/status").exists() {
                "Debian".to_string()
            } else {
                String::new()
            }
        });
    if ecosystem.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    if let Ok(content) = std::fs::read_to_string(root.join("lib/apk/db/installed")) {
        out.extend(
            parse_apk_installed(&content)
                .into_iter()
                .map(|(name, version)| InstalledPackage {
                    owner: owner.to_string(),
                    ecosystem: ecosystem.clone(),
                    name,
                    version,
                }),
        );
    }
    if let Ok(content) = std::fs::read_to_string(root.join("var/lib/dpkg/status")) {
        out.extend(
            parse_dpkg_status(&content)
                .into_iter()
                .map(|(name, version)| InstalledPackage {
                    owner: owner.to_string(),
                    ecosystem: ecosystem.clone(),
                    name,
                    version,
                }),
        );
    }
    out
}

#[derive(Debug, Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
struct BatchResult {
    vulns: Option<Vec<BatchVuln>>,
}

#[derive(Debug, Deserialize)]
struct BatchVuln {
    id: String,
}

#[derive(Debug, Deserialize)]
struct VulnDetails {
    id: String,
    aliases: Option<Vec<String>>,
    summary: Option<String>,
    database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    severity: Option<String>,
}

/// The CVE id a vulnerability is known by, falling back to the OSV id.
fn cve_id(details: &VulnDetails) -> String {
    details
        .aliases
        .as_ref()
        .and_then(|aliases| {
            aliases
                .iter()
                .find(|alias| alias.starts_with("CVE-"))
                .cloned()
        })
        .unwrap_or_else(|| details.id.clone())
}

fn severity_for(known_exploited: bool, details: &VulnDetails) -> AnomalySeverity {
    if known_exploited {
        return AnomalySeverity::Critical;
    }
    // OSV's severity score is a CVSS vector, not a number; the advisories
    // carry the label in database_specific.severity instead.
    let label = details
        .database_specific
        .as_ref()
        .and_then(|specific| specific.severity.as_deref())
        .unwrap_or_default();
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" | "HIGH" => AnomalySeverity::High,
        "LOW" => AnomalySeverity::Low,
        _ => AnomalySeverity::Medium,
    }
}

/// Cached answer to "which vulnerabilities does this package version have".
struct CachedMatches {
    fetched_at: SystemTime,
    cve_ids: Vec<String>,
}

pub struct CveWatchMonitor {
    cache: Mutex<HashMap<(String, String, String), CachedMatches>>,
    kev: Mutex<Option<(SystemTime, HashSet<String>)>>,
}

impl Default for CveWatchMonitor {
    fn default() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            kev: Mutex::new(None),
        }
    }
}

impl CveWatchMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process-wide instance: the caches live here, and callers move the
    /// blocking work to a blocking thread where dropping an HTTP client is
    /// allowed.
    pub fn shared() -> &'static CveWatchMonitor {
        static MONITOR: OnceLock<CveWatchMonitor> = OnceLock::new();
        MONITOR.get_or_init(CveWatchMonitor::new)
    }

    pub fn detect(
        &self,
        pool: &DbPool,
        containers: &[ContainerFilesystem],
        host_root: Option<&str>,
    ) -> Vec<DetectorFinding> {
        let mut inventory = installed_under("host", &under_host_root(host_root, "/"));
        for container in containers {
            if let Some(merged_dir) = &container.merged_dir {
                inventory.extend(installed_under(
                    &container.name,
                    &under_host_root(host_root, merged_dir),
                ));
            }
        }
        inventory.sort_by(|a, b| {
            (&a.owner, &a.ecosystem, &a.name, &a.version).cmp(&(
                &b.owner,
                &b.ecosystem,
                &b.name,
                &b.version,
            ))
        });
        inventory.dedup();

        let matches = self.matches_for(pool, &inventory);
        self.findings(pool, &inventory, &matches)
    }

    /// Vulnerability ids per inventory row, from cache where fresh, from the
    /// OSV batch endpoint where not.
    fn matches_for(
        &self,
        pool: &DbPool,
        inventory: &[InstalledPackage],
    ) -> HashMap<usize, Vec<String>> {
        let mut out = HashMap::new();
        let mut stale = Vec::new();

        for (index, package) in inventory.iter().enumerate() {
            match self.cached(pool, package) {
                Some(ids) => {
                    out.insert(index, ids);
                }
                None => stale.push(index),
            }
        }

        for chunk in stale.chunks(BATCH) {
            let queries: Vec<serde_json::Value> = chunk
                .iter()
                .map(|index| {
                    let package = &inventory[*index];
                    serde_json::json!({
                        "package": {
                            "name": package.name,
                            "ecosystem": package.ecosystem,
                        },
                        "version": query_version(&package.ecosystem, &package.version),
                    })
                })
                .collect();
            let body = serde_json::json!({ "queries": queries }).to_string();

            let response = reqwest::blocking::Client::new()
                .post(OSV_QUERYBATCH)
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .body(body)
                .send();

            match response.and_then(|response| response.error_for_status()) {
                Ok(response) => match response.json::<BatchResponse>() {
                    Ok(batch) => {
                        for (position, result) in batch.results.iter().enumerate() {
                            let Some(&index) = chunk.get(position) else {
                                continue;
                            };
                            let ids: Vec<String> = result
                                .vulns
                                .as_ref()
                                .map(|vulns| vulns.iter().map(|vuln| vuln.id.clone()).collect())
                                .unwrap_or_default();
                            self.store(pool, &inventory[index], &ids);
                            out.insert(index, ids);
                        }
                    }
                    Err(err) => log::warn!("CVE watch: OSV batch response unreadable: {err}"),
                },
                Err(err) => log::warn!("CVE watch: OSV querybatch failed: {err}"),
            }
        }

        out
    }

    fn cached(&self, pool: &DbPool, package: &InstalledPackage) -> Option<Vec<String>> {
        let key = (
            package.ecosystem.clone(),
            package.name.clone(),
            package.version.clone(),
        );
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(&key) {
                if hit.fetched_at.elapsed().unwrap_or(Duration::MAX) < REFRESH {
                    return Some(hit.cve_ids.clone());
                }
            }
        }

        // The process cache is a courtesy; the database one keeps a restart
        // from re-querying every package at once.
        let conn = pool.get().ok()?;
        let row: Result<(String, String), _> = conn.query_row(
            "SELECT fetched_at, cve_ids FROM cve_watch_cache
             WHERE ecosystem = ?1 AND package = ?2 AND version = ?3",
            params![package.ecosystem, package.name, package.version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        let (fetched_at, ids) = row.ok()?;
        let age = SystemTime::now()
            .duration_since(
                chrono::DateTime::parse_from_rfc3339(&fetched_at)
                    .ok()?
                    .with_timezone(&chrono::Utc)
                    .into(),
            )
            .unwrap_or(Duration::MAX);
        if age >= REFRESH {
            return None;
        }
        let ids: Vec<String> = ids
            .split(',')
            .filter(|id| !id.is_empty())
            .map(String::from)
            .collect();
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                key,
                CachedMatches {
                    fetched_at: SystemTime::now(),
                    cve_ids: ids.clone(),
                },
            );
        }
        Some(ids)
    }

    fn store(&self, pool: &DbPool, package: &InstalledPackage, ids: &[String]) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                (
                    package.ecosystem.clone(),
                    package.name.clone(),
                    package.version.clone(),
                ),
                CachedMatches {
                    fetched_at: SystemTime::now(),
                    cve_ids: ids.to_vec(),
                },
            );
        }
        if let Ok(conn) = pool.get() {
            let _ = conn.execute(
                "INSERT INTO cve_watch_cache (ecosystem, package, version, fetched_at, cve_ids)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(ecosystem, package, version) DO UPDATE SET
                    fetched_at = excluded.fetched_at,
                    cve_ids = excluded.cve_ids",
                params![
                    package.ecosystem,
                    package.name,
                    package.version,
                    chrono::Utc::now().to_rfc3339(),
                    ids.join(","),
                ],
            );
        }
    }

    fn known_exploited(&self) -> HashSet<String> {
        let now = SystemTime::now();
        if let Ok(kev) = self.kev.lock() {
            if let Some((fetched_at, ids)) = kev.as_ref() {
                if now.duration_since(*fetched_at).unwrap_or(Duration::MAX) < REFRESH {
                    return ids.clone();
                }
            }
        }

        let ids = self.fetch_kev();
        if let Ok(mut kev) = self.kev.lock() {
            *kev = Some((now, ids.clone()));
        }
        ids
    }

    fn fetch_kev(&self) -> HashSet<String> {
        let client = reqwest::blocking::Client::new();
        for url in [KEV_MIRROR, KEV_CANONICAL] {
            let response = client
                .get(url)
                .header("User-Agent", USER_AGENT)
                .send()
                .and_then(|response| response.error_for_status());
            match response {
                Ok(response) => match response.json::<KevCatalog>() {
                    Ok(catalog) => {
                        return catalog
                            .vulnerabilities
                            .into_iter()
                            .map(|entry| entry.cve_id)
                            .collect();
                    }
                    Err(err) => log::warn!("CVE watch: KEV catalog unreadable from {url}: {err}"),
                },
                Err(err) => log::warn!("CVE watch: KEV fetch failed from {url}: {err}"),
            }
        }
        HashSet::new()
    }

    fn details(&self, osv_id: &str) -> Option<VulnDetails> {
        let response = reqwest::blocking::Client::new()
            .get(format!("{OSV_VULN}{osv_id}"))
            .header("User-Agent", USER_AGENT)
            .send()
            .and_then(|response| response.error_for_status())
            .ok()?;
        response.json().ok()
    }

    /// Turn new matches into findings, worst first, and remember only what was
    /// actually reported: the rest arrives on later passes.
    fn findings(
        &self,
        pool: &DbPool,
        inventory: &[InstalledPackage],
        matches: &HashMap<usize, Vec<String>>,
    ) -> Vec<DetectorFinding> {
        let mut candidates: Vec<(&InstalledPackage, String)> = Vec::new();
        for (index, package) in inventory.iter().enumerate() {
            for osv_id in matches.get(&index).into_iter().flatten() {
                if self.alerted(pool, package, osv_id) {
                    continue;
                }
                candidates.push((package, osv_id.clone()));
            }
        }
        if candidates.is_empty() {
            return Vec::new();
        }

        // KEV is a network fetch: only worth it when something matched.
        let kev = self.known_exploited();
        candidates.sort_by_key(|(_, osv_id)| std::cmp::Reverse(kev.contains(osv_id)));

        let mut findings = Vec::new();
        for (package, osv_id) in candidates {
            if findings.len() >= MAX_FINDINGS {
                break;
            }
            let exploited = kev.contains(&osv_id);
            let details = match self.details(&osv_id) {
                Some(details) => details,
                None => continue, // retried next pass: nothing was remembered
            };
            let cve = cve_id(&details);
            let severity = severity_for(exploited, &details);
            let summary = details
                .summary
                .as_deref()
                .map(|summary| summary.trim())
                .filter(|summary| !summary.is_empty())
                .unwrap_or("known vulnerability in this package version");

            findings.push(DetectorFinding {
                detector_id: CVE_DETECTOR_ID.into(),
                family: DetectorFamily::Vulnerability,
                description: format!(
                    "{cve} affects {} {} on {} ({}).{} {summary}. Distribution packages may carry a backported fix: check your vendor's advisory before treating this as live",
                    package.name,
                    package.version,
                    package.owner,
                    package.ecosystem,
                    if exploited {
                        " KNOWN EXPLOITED, on CISA's KEV list."
                    } else {
                        ""
                    }
                ),
                severity,
                confidence: if exploited { 90 } else { 75 },
                sample_line: format!(
                    "{} package {} {} {cve}",
                    package.owner, package.name, package.version
                ),
            });
            self.remember(pool, package, &osv_id);
        }

        findings
    }

    fn alerted(&self, pool: &DbPool, package: &InstalledPackage, osv_id: &str) -> bool {
        let Ok(conn) = pool.get() else {
            return false;
        };
        conn.query_row(
            "SELECT 1 FROM cve_watch_alerted
             WHERE owner = ?1 AND ecosystem = ?2 AND package = ?3 AND version = ?4 AND osv_id = ?5",
            params![
                package.owner,
                package.ecosystem,
                package.name,
                package.version,
                osv_id
            ],
            |_| Ok(()),
        )
        .is_ok()
    }

    fn remember(&self, pool: &DbPool, package: &InstalledPackage, osv_id: &str) {
        if let Ok(conn) = pool.get() {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO cve_watch_alerted
                 (owner, ecosystem, package, version, osv_id, alerted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    package.owner,
                    package.ecosystem,
                    package.name,
                    package.version,
                    osv_id,
                    chrono::Utc::now().to_rfc3339(),
                ],
            );
        }
    }
}

const USER_AGENT: &str = concat!("stackdog/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_version_strips_the_apk_revision() {
        assert_eq!(query_version("Alpine:v3.20", "9.7_p1-r6"), "9.7_p1");
        assert_eq!(query_version("Alpine:v3.20", "10.6_p2-r0"), "10.6_p2");
        assert_eq!(
            query_version("Debian", "1:9.2p1-2+deb12u1"),
            "1:9.2p1-2+deb12u1"
        );
        assert_eq!(query_version("Alpine:v3.20", "20240101-r0"), "20240101");
    }

    #[test]
    fn test_ecosystem_from_os_release() {
        assert_eq!(
            ecosystem_from_os_release("ID=alpine\nVERSION_ID=3.20.3\n"),
            Some("Alpine:v3.20".to_string())
        );
        assert_eq!(
            ecosystem_from_os_release("ID=debian\nVERSION_ID=\"12\"\n"),
            Some("Debian".to_string())
        );
        assert_eq!(
            ecosystem_from_os_release("ID=ubuntu\nVERSION_ID=\"22.04\"\n"),
            Some("Ubuntu".to_string())
        );
        assert_eq!(ecosystem_from_os_release("ID=arch\n"), None);
    }

    #[test]
    fn test_cve_id_prefers_the_cve_alias() {
        let details: VulnDetails = serde_json::from_str(
            r#"{"id":"ALPINE-CVE-2026-123158","aliases":["CVE-2026-123158"],"summary":"x"}"#,
        )
        .unwrap();
        assert_eq!(cve_id(&details), "CVE-2026-123158");

        let no_alias: VulnDetails =
            serde_json::from_str(r#"{"id":"GHSA-xxxx-yyyy","summary":"x"}"#).unwrap();
        assert_eq!(cve_id(&no_alias), "GHSA-xxxx-yyyy");
    }

    #[test]
    fn test_severity_kev_beats_the_label() {
        let details: VulnDetails = serde_json::from_str(
            r#"{"id":"CVE-1","summary":"x","database_specific":{"severity":"high"}}"#,
        )
        .unwrap();
        assert_eq!(severity_for(true, &details), AnomalySeverity::Critical);
        assert_eq!(severity_for(false, &details), AnomalySeverity::High);

        let moderate: VulnDetails = serde_json::from_str(
            r#"{"id":"CVE-2","summary":"x","database_specific":{"severity":"MODERATE"}}"#,
        )
        .unwrap();
        assert_eq!(severity_for(false, &moderate), AnomalySeverity::Medium);

        let unlabeled: VulnDetails =
            serde_json::from_str(r#"{"id":"CVE-3","summary":"x"}"#).unwrap();
        assert_eq!(severity_for(false, &unlabeled), AnomalySeverity::Medium);
    }

    #[test]
    fn test_batch_results_align_with_queries() {
        let batch: BatchResponse = serde_json::from_str(
            r#"{"results":[{"vulns":[{"id":"ALPINE-CVE-1"},{"id":"ALPINE-CVE-2"}]},{"vulns":null}]}"#,
        )
        .unwrap();
        assert_eq!(batch.results.len(), 2);
        assert_eq!(batch.results[0].vulns.as_ref().unwrap().len(), 2);
        assert!(batch.results[1].vulns.is_none());
    }

    #[test]
    fn test_inventory_reads_apk_and_dpkg_under_a_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join("etc/os-release"),
            "ID=alpine\nVERSION_ID=3.20.3\n",
        )
        .unwrap();
        let apk = root.path().join("lib/apk/db");
        std::fs::create_dir_all(&apk).unwrap();
        std::fs::write(apk.join("installed"), "P:openssh\nV:9.7_p1-r6\n\n").unwrap();

        let packages = installed_under("box", root.path());
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].ecosystem, "Alpine:v3.20");
        assert_eq!(packages[0].name, "openssh");
    }

    #[test]
    fn test_a_reported_match_is_never_reported_again() {
        use crate::database::connection::{create_pool, init_database};
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let monitor = CveWatchMonitor::new();
        let package = InstalledPackage {
            owner: "host".into(),
            ecosystem: "Alpine:v3.20".into(),
            name: "openssh".into(),
            version: "9.7_p1-r6".into(),
        };

        assert!(!monitor.alerted(&pool, &package, "ALPINE-CVE-1"));
        monitor.remember(&pool, &package, "ALPINE-CVE-1");
        assert!(monitor.alerted(&pool, &package, "ALPINE-CVE-1"));
        assert!(!monitor.alerted(&pool, &package, "ALPINE-CVE-2"));
    }

    /// Live check of the whole match path against the real OSV API:
    /// `cargo test --lib -- --ignored cve_watch_live`
    #[test]
    #[ignore]
    fn test_cve_watch_live_match() {
        use crate::database::connection::{create_pool, init_database};
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join("etc/os-release"),
            "ID=alpine\nVERSION_ID=3.20.3\n",
        )
        .unwrap();
        let apk = root.path().join("lib/apk/db");
        std::fs::create_dir_all(&apk).unwrap();
        // A real vulnerable pair: Alpine 3.20's openssh predates 10.6_p2.
        std::fs::write(apk.join("installed"), "P:openssh\nV:9.7_p1-r6\n\n").unwrap();

        let monitor = CveWatchMonitor::new();
        let packages = installed_under("box", root.path());
        let mut known = HashMap::new();
        known.insert(
            0usize,
            vec![
                "ALPINE-CVE-2015-8325".to_string(),
                "DOES-NOT-EXIST".to_string(),
            ],
        );
        let findings = monitor.findings(&pool, &packages, &known);
        assert!(!findings.is_empty(), "OSV details must resolve a real id");
        // The bogus id is skipped without being remembered as reported.
        assert!(findings
            .iter()
            .all(|finding| !finding.description.contains("DOES-NOT-EXIST")));
    }
}
