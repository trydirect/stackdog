//! NGINX2Root exposure, nginx worker crashes, and the kernel SCTP step of the
//! chain.
//!
//! NGINX2Root is a set of five memory-corruption vulnerabilities in nginx
//! (CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810,
//! CVE-2026-113425) disclosed on 2026-11-18, plus a separate, unpatched Linux
//! kernel SCTP use-after-free that escalates the nginx worker to root, including
//! from inside a Docker container. The nginx bugs are only reachable when the
//! relevant feature is enabled, so this module answers three questions the
//! running system can answer without touching the network:
//!
//! - which nginx builds on the host and in running containers predate the fixed
//!   releases, and which of the five CVEs their configuration actually exposes
//!   (`vuln.nginx2root`);
//! - whether nginx workers keep dying on memory faults, which is what the
//!   heap-corruption attempts leave behind (`nginx.worker-crash`);
//! - whether the kernel SCTP path the root-escalation uses is reachable
//!   (`kernel.sctp-exposed`).
//!
//! None of these name a client address: the exploit's control frames are not
//! logged as requests, so none of them ever bans.
//!
//! Version rules follow the F5/nginx.org advisories of 2026-11-18 and Xint's
//! write-up; the fixed releases are nginx 1.30.7 (stable) and 1.31.9 (mainline).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use regex::Regex;

use crate::detectors::audits::{parse_apk_installed, parse_dpkg_status};
use crate::detectors::php2shell::VersionSource;
use crate::detectors::php_shell::{under_host_root, ContainerFilesystem};
use crate::detectors::{DetectorFamily, DetectorFinding, LogDetector};
use crate::events::syscall::{SyscallEvent, SyscallType};
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

pub const EXPOSURE_DETECTOR_ID: &str = "vuln.nginx2root";
pub const CRASH_DETECTOR_ID: &str = "nginx.worker-crash";
pub const SCTP_DETECTOR_ID: &str = "kernel.sctp-exposed";
pub const SCTP_SOCKET_DETECTOR_ID: &str = "kernel.sctp-socket";
pub const SPRAY_DETECTOR_ID: &str = "nginx.http2-spray";
pub const WORKER_EXEC_DETECTOR_ID: &str = "web.worker-exec";

/// IPPROTO_SCTP: the protocol number an SCTP socket is created with.
const IPPROTO_SCTP: u32 = 132;

/// The five NGINX2Root CVEs, for the descriptions.
const CVES: &str =
    "CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425";

/// First fixed release per upstream track: stable 1.30.7, mainline 1.31.9.
const FIXED_STABLE: (u32, u32, u32) = (1, 30, 7);
const FIXED_MAINLINE: (u32, u32, u32) = (1, 31, 9);

/// Package databases, relative to a filesystem root.
const PACKAGE_DATABASES: &[&str] = &["var/lib/dpkg/status", "lib/apk/db/installed"];

/// Crashes in one batch of log lines before it is worth an alert. A single
/// worker segfault is usually a flaky module; a run of them is a memory
/// corruption attempt grooming the heap.
const CRASH_THRESHOLD: usize = 3;

/// Findings per pass for the exposure check, so a fleet of nginx containers
/// cannot turn one advisory into a flood.
const MAX_EXPOSURE_FINDINGS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// A source or image build older than the fix for its track.
    Vulnerable {
        fixed_in: String,
    },
    /// A distribution package older than the upstream fix. Distributions
    /// backport fixes without changing the upstream number, so only the
    /// vendor's advisory can say.
    CheckVendor {
        fixed_in: String,
    },
    Patched,
}

/// `1.31.8` out of `1.31.8`, `1:1.31.8-1~bookworm` or `1.26.3-r0`. nginx has no
/// epoch and no patch suffix beyond the distribution revision, so the leading
/// `major.minor.patch` is the upstream version.
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

/// The NGINX2Root exposure of `version`, or None if it is not a nginx version.
///
/// nginx keeps two live tracks: odd minors are mainline (1.31.x, fixed at
/// 1.31.9) and even minors are stable (1.30.x, fixed at 1.30.7). A version is
/// fixed when it reaches the fix on its own track, so the comparison is
/// per-track rather than one linear threshold: 1.31.0 is mainline and still
/// vulnerable even though it sorts above 1.30.7.
pub fn exposure(version: &str, from_distro_package: bool) -> Option<Exposure> {
    let (major, minor, patch) = upstream_version(version)?;

    if major > 1 {
        return Some(Exposure::Patched);
    }
    if major < 1 {
        return Some(triage(
            "1.30.7 (stable) or 1.31.9 (mainline)".to_string(),
            from_distro_package,
        ));
    }

    // major == 1. Odd minor = mainline, even minor = stable.
    let fixed = if minor % 2 == 1 {
        FIXED_MAINLINE
    } else {
        FIXED_STABLE
    };
    if (minor, patch) >= (fixed.1, fixed.2) {
        return Some(Exposure::Patched);
    }

    // Name the fix for the version's own track when it is on one of the two
    // fixed tracks; otherwise point at both.
    let fixed_in = if minor == fixed.1 {
        format!("{}.{}.{}", fixed.0, fixed.1, fixed.2)
    } else {
        "1.30.7 (stable) or 1.31.9 (mainline)".to_string()
    };
    Some(triage(fixed_in, from_distro_package))
}

fn triage(fixed_in: String, from_distro_package: bool) -> Exposure {
    if from_distro_package {
        Exposure::CheckVendor { fixed_in }
    } else {
        Exposure::Vulnerable { fixed_in }
    }
}

/// Package databases carry the server binary: `nginx` (Debian, Ubuntu, Alpine,
/// nginx.org) and the split Debian builds. `nginx-common`, `nginx-doc` and the
/// module packages either carry no binary or follow the same version, so they
/// are left out to keep one finding per install.
fn is_nginx_server_package(name: &str) -> bool {
    matches!(
        name,
        "nginx" | "nginx-core" | "nginx-full" | "nginx-light" | "nginx-extras"
    )
}

/// What an nginx build's configuration reaches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NginxFeatures {
    /// `http2 on` or `listen ... http2` (CVE-2026-123007, CVE-2026-123633).
    pub http2: bool,
    /// Requests are proxied to a backend (CVE-2026-123633, CVE-2026-121810).
    pub proxy_pass_backend: bool,
    /// `http3 on` or `listen ... quic` (CVE-2026-121810).
    pub http3: bool,
    /// A `mail` block with `proxy on` (CVE-2026-113425).
    pub mail_proxy: bool,
    /// `proxy_pass` with a variable, plus an SSI or mirror subrequest
    /// (CVE-2026-123634).
    pub proxy_pass_variable_subrequest: bool,
}

/// The features a configuration exposes, read from its text. nginx config is
/// free-form, so this is a whole-text scan: it answers "is this feature on
/// anywhere the server will load", not "which server block". That is the right
/// granularity for exposure, because a feature reachable in any loaded block is
/// reachable by an attacker. This runs a handful of times per pass, so the
/// patterns are compiled inline rather than cached.
pub fn config_features(content: &str) -> NginxFeatures {
    let lower = content.to_ascii_lowercase();
    let listen = Regex::new(r"\blisten\b[^;]*").expect("valid regex");
    let proxy_pass = Regex::new(r"\bproxy_pass\b[^;]*").expect("valid regex");

    let listen_with = |needle: &str| {
        listen
            .captures_iter(&lower)
            .any(|directive| directive[0].contains(needle))
    };

    let http2 = contains(&lower, r"\bhttp2\s+on\b") || listen_with("http2");
    let http3 = contains(&lower, r"\bhttp3\s+on\b") || listen_with("quic");

    let proxy_pass_backend = proxy_pass.is_match(&lower);
    let proxy_pass_variable = proxy_pass
        .captures_iter(&lower)
        .any(|directive| directive[0].contains('$'));
    let subrequest = contains(&lower, r"\bssi\s+on\b") || contains(&lower, r"\bmirror\b");
    let proxy_pass_variable_subrequest = proxy_pass_variable && subrequest;

    let mail_proxy = (contains(&lower, r"\bmail\s*\{") && contains(&lower, r"\bproxy\s+on\b"))
        || contains(&lower, r"\bauth_http\b");

    NginxFeatures {
        http2,
        proxy_pass_backend,
        http3,
        mail_proxy,
        proxy_pass_variable_subrequest,
    }
}

fn contains(haystack: &str, pattern: &str) -> bool {
    Regex::new(pattern).expect("valid regex").is_match(haystack)
}

/// Which of the five CVEs a configuration reaches, with the mitigation that
/// closes it until the build is upgraded.
fn applicable_cves(features: &NginxFeatures) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut out = Vec::new();
    if features.http2 {
        out.push((
            "CVE-2026-123007",
            "HTTP/2 is enabled",
            "set http2 off, or remove http2 from the listen directives",
        ));
    }
    if features.http2 && features.proxy_pass_backend {
        out.push((
            "CVE-2026-123633",
            "HTTP/2 is enabled and requests are proxied to a backend",
            "set http2 off, or remove http2 from the listen directives",
        ));
    }
    if features.http3 {
        out.push((
            "CVE-2026-121810",
            "HTTP/3 (QUIC) listeners are enabled",
            "remove the quic/http3 listeners, or set http3 off",
        ));
    }
    if features.mail_proxy {
        out.push((
            "CVE-2026-113425",
            "the mail proxy is enabled",
            "bind mail listeners to loopback, or firewall them to trusted networks",
        ));
    }
    if features.proxy_pass_variable_subrequest {
        out.push((
            "CVE-2026-123634",
            "proxy_pass builds the upstream from a variable and an SSI or mirror subrequest resolves the same name",
            "point proxy_pass at a fixed upstream group",
        ));
    }
    out
}

/// A nginx installation found on the host or in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxInstall {
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
pub struct NginxExposureMonitor {
    /// Parsed package databases keyed by path, reused while the file's
    /// modification time and size stay the same.
    cache: Mutex<HashMap<PathBuf, CachedPackages>>,
}

impl NginxExposureMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &self,
        containers: &[ContainerFilesystem],
        host_root: Option<&str>,
    ) -> Vec<DetectorFinding> {
        let mut findings = self.scan_root("host", &under_host_root(host_root, "/"));

        for container in containers {
            let mut installs = Vec::new();
            let mut features = NginxFeatures::default();
            if let Some(merged_dir) = &container.merged_dir {
                let root = under_host_root(host_root, merged_dir);
                installs.extend(self.installs_under(&container.name, &root));
                features = config_features(&nginx_config_text(&root));
            }
            // Official nginx images set NGINX_VERSION even when the image was
            // built from source and carries no package.
            if let Some(version) = &container.nginx_version {
                installs.push(NginxInstall {
                    owner: container.name.clone(),
                    version: version.clone(),
                    source: VersionSource::ImageEnv,
                });
            }
            if !installs.is_empty() {
                findings.extend(findings_for(&container.name, &installs, &features));
            }
        }

        findings.truncate(MAX_EXPOSURE_FINDINGS);
        findings
    }

    fn scan_root(&self, owner: &str, root: &Path) -> Vec<DetectorFinding> {
        let installs = self.installs_under(owner, root);
        if installs.is_empty() {
            return Vec::new();
        }
        let features = config_features(&nginx_config_text(root));
        findings_for(owner, &installs, &features)
    }

    fn installs_under(&self, owner: &str, root: &Path) -> Vec<NginxInstall> {
        PACKAGE_DATABASES
            .iter()
            .flat_map(|database| self.packages(&root.join(database)))
            .filter(|(name, _)| is_nginx_server_package(name))
            .map(|(name, version)| NginxInstall {
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

/// The nginx configuration a root loads: `nginx.conf` plus everything under the
/// directories it commonly includes. Reads are best-effort: a missing directory
/// is simply empty.
fn nginx_config_text(root: &Path) -> String {
    let dir = root.join("etc/nginx");
    let mut text = String::new();
    push_file(&mut text, &dir.join("nginx.conf"));
    for sub in ["conf.d", "sites-enabled", "sites-available"] {
        if let Ok(entries) = std::fs::read_dir(dir.join(sub)) {
            for entry in entries.flatten() {
                push_file(&mut text, &entry.path());
            }
        }
    }
    text
}

fn push_file(text: &mut String, path: &Path) {
    if let Ok(content) = std::fs::read_to_string(path) {
        text.push_str(&content);
        text.push('\n');
    }
}

/// One finding per exposed `(owner, CVE)`. The configuration decides which CVEs
/// are reachable; the build decides how sure we are.
pub fn findings_for(
    owner: &str,
    installs: &[NginxInstall],
    features: &NginxFeatures,
) -> Vec<DetectorFinding> {
    let mut versions = Vec::new();
    let mut worst: Option<Exposure> = None;
    let mut seen = HashSet::new();

    for install in installs {
        if !seen.insert((install.owner.as_str(), install.version.as_str())) {
            continue;
        }
        let from_package = matches!(install.source, VersionSource::Package { .. });
        let Some(exposure) = exposure(&install.version, from_package) else {
            continue;
        };
        versions.push(install.version.clone());
        // Worst wins: Vulnerable > CheckVendor > Patched.
        worst = Some(match (&worst, &exposure) {
            (Some(Exposure::Vulnerable { fixed_in }), _) => Exposure::Vulnerable {
                fixed_in: fixed_in.clone(),
            },
            (_, Exposure::Vulnerable { fixed_in }) => Exposure::Vulnerable {
                fixed_in: fixed_in.clone(),
            },
            (Some(Exposure::CheckVendor { fixed_in }), _) => Exposure::CheckVendor {
                fixed_in: fixed_in.clone(),
            },
            (_, Exposure::CheckVendor { fixed_in }) => Exposure::CheckVendor {
                fixed_in: fixed_in.clone(),
            },
            (_, next) => next.clone(),
        });
    }

    let version_label = if versions.is_empty() {
        "an nginx build".to_string()
    } else {
        format!("nginx {}", versions.join(", "))
    };

    let cves = applicable_cves(features);

    // A source or image build is the high-confidence case; a distribution
    // package may carry a backported fix, so it is only a lead. With no version
    // we can still report a feature we can see is on. A patched build reports
    // nothing at all.
    let (severity, confidence, fixed_in, framing) = match &worst {
        Some(Exposure::Patched) => return Vec::new(),
        Some(Exposure::Vulnerable { fixed_in }) => (
            AnomalySeverity::Critical,
            95,
            fixed_in.clone(),
            "vulnerable",
        ),
        Some(Exposure::CheckVendor { fixed_in }) => {
            (AnomalySeverity::Medium, 60, fixed_in.clone(), "lead")
        }
        None => {
            if cves.is_empty() {
                return Vec::new();
            }
            (
                AnomalySeverity::Medium,
                55,
                "1.30.7 (stable) or 1.31.9 (mainline)".to_string(),
                "unknown",
            )
        }
    };

    // A build below the fix with no readable config still matters: we cannot
    // say which of the five applies, so say that instead of staying quiet.
    if cves.is_empty() {
        return vec![DetectorFinding {
            detector_id: EXPOSURE_DETECTOR_ID.into(),
            family: DetectorFamily::Vulnerability,
            description: format!(
                "NGINX2Root: {} on {} predates the nginx fixes ({}). No configuration was readable to say which of the five apply, so assume the enabled features are exposed: upgrade to {} and restart nginx",
                version_label, owner, CVES, fixed_in
            ),
            severity,
            confidence,
            sample_line: format!("{} {} unverified-config", owner, version_label),
        }];
    }

    cves.into_iter()
        .map(|(cve, feature, mitigation)| {
            let description = match framing {
                "vulnerable" => format!(
                    "NGINX2Root {} on {}: {} ({}). {} Upgrade to {} and restart nginx",
                    cve, owner, version_label, feature, mitigation, fixed_in
                ),
                "lead" => format!(
                    "NGINX2Root {} on {}: {} ({}). Distribution packages may carry a backported fix: check your vendor's advisory. {}, or upgrade to {} and restart nginx",
                    cve, owner, version_label, feature, mitigation, fixed_in
                ),
                _ => format!(
                    "NGINX2Root {} on {}: {} ({}), and no package version was found to confirm the fix. {} Verify the build is {} or later",
                    cve, owner, version_label, feature, mitigation, fixed_in
                ),
            };
            DetectorFinding {
                detector_id: EXPOSURE_DETECTOR_ID.into(),
                family: DetectorFamily::Vulnerability,
                description,
                severity: severity.clone(),
                confidence,
                sample_line: format!("{} {} {}", owner, version_label, cve),
            }
        })
        .collect()
}

/// nginx workers dying on memory faults, from the nginx error log.
pub struct NginxWorkerCrashDetector;

impl LogDetector for NginxWorkerCrashDetector {
    fn id(&self) -> &'static str {
        CRASH_DETECTOR_ID
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Execution
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let crashes: Vec<&LogEntry> = entries
            .iter()
            .filter(|entry| is_nginx_worker_crash(&entry.line))
            .collect();

        if crashes.len() < CRASH_THRESHOLD {
            return Vec::new();
        }

        vec![DetectorFinding {
            detector_id: CRASH_DETECTOR_ID.into(),
            family: DetectorFamily::Execution,
            description: format!(
                "nginx workers crashed {} times on memory faults. Repeated worker crashes are what attempts against the NGINX2Root memory-corruption bugs ({}) leave behind; check the nginx version and the connections at those times",
                crashes.len(),
                CVES
            ),
            severity: if crashes.len() >= 10 {
                AnomalySeverity::High
            } else {
                AnomalySeverity::Medium
            },
            confidence: 70,
            sample_line: crashes[0].line.clone(),
        }]
    }
}

/// nginx: `2026/11/18 12:00:00 [alert] 31#0: worker process 32 exited on signal
/// 11 (SIGSEGV)` (src/os/unix/ngx_process_cycle.c). nginx names the signal and
/// may append `- core dumped`.
fn is_nginx_worker_crash(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("worker process")
        && lower.contains("exited on signal")
        && [
            "(sigsegv",
            "(sigbus",
            "(sigabrt",
            "(sigill",
            "signal 11",
            "signal 7",
            "signal 6",
            "signal 4",
        ]
        .iter()
        .any(|signal| lower.contains(signal))
}

/// Whether a web-server worker process executed a program (`web.worker-exec`).
///
/// A web worker (nginx, Apache, php-fpm) serves requests; it does not exec a
/// program as part of normal operation. When one does, the process has almost
/// certainly been hijacked - the classic end state of a remote-code-execution
/// exploit such as NGINX2Root (CVE-2026-123007). This is the "programs started
/// by an nginx worker" indicator, matched on the process that calls exec, which
/// the eBPF collector captures at syscall entry before exec replaces it.
///
/// It reads syscall events, which come from the eBPF collector. That source is
/// not yet started by the `serve` runtime (see `detect_syscall_anomalies`), so
/// this is ready to consume events the moment the collector is wired in.
pub struct WebWorkerExecMonitor;

/// Comms of processes that serve web traffic and should never exec a program.
const WEB_WORKERS: &[&str] = &[
    "nginx",
    "httpd",
    "apache2",
    "php-fpm",
    "lighttpd",
    "caddy",
    "openresty",
];

impl WebWorkerExecMonitor {
    pub fn detect(&self, events: &[SyscallEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter(|event| {
                matches!(
                    event.syscall_type,
                    SyscallType::Execve | SyscallType::Execveat
                )
            })
            .filter(|event| {
                event
                    .comm
                    .as_deref()
                    .is_some_and(|comm| WEB_WORKERS.contains(&comm))
            })
            .map(|event| {
                let comm = event.comm.as_deref().unwrap_or("web worker");
                let program = event
                    .exec_details()
                    .and_then(|(filename, _args, _argc)| filename.clone())
                    .unwrap_or_else(|| "an unknown program".to_string());
                DetectorFinding {
                    detector_id: WORKER_EXEC_DETECTOR_ID.into(),
                    family: DetectorFamily::Execution,
                    description: format!(
                        "A web server worker ({}) executed {}. Web workers do not run programs, so this is a strong sign the process was hijacked by remote code execution (e.g. NGINX2Root, {}); identify the command and the connection, and isolate the host or container",
                        comm, program, CVES
                    ),
                    severity: AnomalySeverity::Critical,
                    confidence: 90,
                    sample_line: format!("pid {} {} exec {}", event.pid, comm, program),
                }
            })
            .collect()
    }
}

/// Whether a web-worker or container process created an SCTP socket
/// (`kernel.sctp-socket`).
///
/// The unpatched Linux kernel SCTP use-after-free is what the NGINX2Root chain
/// uses to turn the nginx worker into root, including out of a Docker
/// container. Creating an SCTP socket is the first step of that escalation.
/// SCTP from an ordinary host process is legitimate (telecom, VoIP), so this
/// only fires where SCTP is surprising: a web-server worker, or anything inside
/// a container. Like `web.worker-exec`, it reads eBPF syscall events.
pub struct SctpSocketMonitor;

impl SctpSocketMonitor {
    pub fn detect(&self, events: &[SyscallEvent]) -> Vec<DetectorFinding> {
        events
            .iter()
            .filter_map(|event| {
                if event.syscall_type != SyscallType::Socket {
                    return None;
                }
                let (_domain, _type_, protocol) = event.socket_details()?;
                if protocol != IPPROTO_SCTP {
                    return None;
                }
                let comm = event.comm.as_deref().unwrap_or("unknown");
                let is_worker = WEB_WORKERS.contains(&comm);
                let in_container = event.container_id.is_some();
                if !is_worker && !in_container {
                    return None;
                }
                let (severity, who) = if is_worker {
                    (AnomalySeverity::Critical, "a web server worker")
                } else {
                    (AnomalySeverity::High, "a container process")
                };
                Some(DetectorFinding {
                    detector_id: SCTP_SOCKET_DETECTOR_ID.into(),
                    family: DetectorFamily::Execution,
                    description: format!(
                        "{} ({}) created an SCTP socket. SCTP is the path the NGINX2Root chain uses to escalate the nginx worker to root through an unpatched Linux kernel use-after-free ({}); isolate the host or container, and block the sctp module if it is not needed",
                        who, comm, CVES
                    ),
                    severity,
                    confidence: 85,
                    sample_line: format!("pid {} {} socket sctp", event.pid, comm),
                })
            })
            .collect()
    }
}

/// The HTTP/2 heap-spray footprint (`nginx.http2-spray`).
///
/// The CVE-2026-123007 exploit drives the heap over HTTP/2 with control frames
/// that are never logged as requests. At the workload level that shows up as a
/// lot of inbound data moving while the access log stays quiet: received bytes
/// grow, the request count does not. This is a heuristic read of that mismatch,
/// not a per-connection measurement (Docker reports per-container totals, not
/// per connection), so it is a review signal rather than a certainty: a large
/// single upload can look similar. Correlate with `nginx.worker-crash` and
/// `web.worker-exec` to tell an attack from a big download.
#[derive(Debug, Clone)]
pub struct Http2SprayMonitor {
    /// Inbound bytes in one window before the mismatch is worth reporting.
    min_inbound_bytes: u64,
    /// Inbound bytes per logged request above which the traffic and the log
    /// disagree. A web server rarely serves a request that carries this much
    /// inbound data and logs nothing about it.
    max_bytes_per_request: u64,
}

impl Default for Http2SprayMonitor {
    fn default() -> Self {
        Self {
            min_inbound_bytes: 16 * 1024 * 1024,
            max_bytes_per_request: 512 * 1024,
        }
    }
}

impl Http2SprayMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(&self, observations: &[TrafficWindow]) -> Vec<DetectorFinding> {
        observations
            .iter()
            .filter_map(|traffic| {
                if traffic.inbound_bytes < self.min_inbound_bytes {
                    return None;
                }
                // Inbound with nothing logged is the invisible-frame signature.
                // Otherwise a huge amount of data per logged request says the
                // bytes and the log disagree.
                let bytes_per_request = traffic
                    .inbound_bytes
                    .checked_div(traffic.request_count)
                    .unwrap_or(u64::MAX);
                if bytes_per_request <= self.max_bytes_per_request {
                    return None;
                }
                let (severity, why) = if traffic.request_count == 0 {
                    (
                        AnomalySeverity::High,
                        "received data but logged no requests".to_string(),
                    )
                } else {
                    (
                        AnomalySeverity::Medium,
                        format!(
                            "carried {} inbound bytes per logged request",
                            bytes_per_request
                        ),
                    )
                };
                Some(DetectorFinding {
                    detector_id: SPRAY_DETECTOR_ID.into(),
                    family: DetectorFamily::Web,
                    description: format!(
                        "{} moved {} inbound bytes in a window while logging only {} request(s): it {}. The CVE-2026-123007 HTTP/2 heap spray looks like this because its control frames are never logged; check for nginx worker crashes and outbound connections, and treat a one-off large upload as benign",
                        traffic.owner, traffic.inbound_bytes, traffic.request_count, why
                    ),
                    severity,
                    confidence: 55,
                    sample_line: format!(
                        "{} inbound_bytes={} requests={}",
                        traffic.owner, traffic.inbound_bytes, traffic.request_count
                    ),
                })
            })
            .collect()
    }
}

/// One workload's traffic over a window: bytes received and requests logged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficWindow {
    pub owner: String,
    pub inbound_bytes: u64,
    pub request_count: u64,
}

/// Whether the kernel SCTP path the NGINX2Root root-escalation uses is
/// reachable: the `sctp` module is loaded on the host.
///
/// The kernel bug is unpatched, so the only mitigation is to stop the module
/// loading (`install sctp /bin/false`). A loaded module is the concrete,
/// actionable state: the use-after-free path is live here. A module that is
/// merely loadable is not reported, because that is the default everywhere and
/// would only add noise. The kernel is shared, so this is host-level only.
pub struct KernelSctpMonitor;

impl KernelSctpMonitor {
    pub fn detect(&self, host_root: Option<&str>) -> Vec<DetectorFinding> {
        let root = under_host_root(host_root, "/");
        if !module_loaded(&root) {
            return Vec::new();
        }

        let blocked = sctp_blocked(&root);
        let (severity, confidence, advice) = if blocked {
            (
                AnomalySeverity::Low,
                60,
                "a modprobe.d rule blocks sctp, but the module is already loaded; a rule only stops it loading, so `rmmod sctp` (or reboot) to drop it",
            )
        } else {
            (
                AnomalySeverity::High,
                85,
                "on hosts that do not need SCTP, block it until the kernel fix lands: `echo 'install sctp /bin/false' > /etc/modprobe.d/zz-block-sctp.conf`",
            )
        };

        vec![DetectorFinding {
            detector_id: SCTP_DETECTOR_ID.into(),
            family: DetectorFamily::Configuration,
            description: format!(
                "The Linux kernel SCTP module is loaded and reachable. The NGINX2Root chain uses an unpatched SCTP use-after-free to escalate the nginx worker to root, including out of a Docker container. {}",
                advice
            ),
            severity,
            confidence,
            sample_line: format!("{} proc/modules sctp", root.display()),
        }]
    }
}

fn module_loaded(root: &Path) -> bool {
    std::fs::read_to_string(root.join("proc/modules"))
        .map(|content| {
            content
                .lines()
                .any(|line| line.split_whitespace().next() == Some("sctp"))
        })
        .unwrap_or(false)
}

fn sctp_blocked(root: &Path) -> bool {
    let dir = root.join("etc/modprobe.d");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("conf") {
            return false;
        }
        std::fs::read_to_string(&path)
            .map(|content| {
                content.lines().any(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower.contains("sctp")
                        && (lower.contains("install sctp /bin/false")
                            || lower.contains("install sctp /bin/true")
                            || lower.contains("blacklist sctp"))
                })
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::events::syscall::SyscallDetails;

    fn entries(lines: &[&str]) -> Vec<LogEntry> {
        lines
            .iter()
            .map(|line| LogEntry {
                source_id: "nginx".into(),
                timestamp: Utc::now(),
                line: (*line).into(),
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_upstream_builds_below_the_fix_are_vulnerable() {
        assert_eq!(
            exposure("1.31.8", false),
            Some(Exposure::Vulnerable {
                fixed_in: "1.31.9".to_string()
            })
        );
        assert_eq!(
            exposure("1.30.6", false),
            Some(Exposure::Vulnerable {
                fixed_in: "1.30.7".to_string()
            })
        );
        assert_eq!(
            exposure("1.9.5", false),
            Some(Exposure::Vulnerable {
                fixed_in: "1.30.7 (stable) or 1.31.9 (mainline)".to_string()
            })
        );
    }

    #[test]
    fn test_fixed_tracks_are_patched() {
        assert_eq!(exposure("1.31.9", false), Some(Exposure::Patched));
        assert_eq!(exposure("1.30.7", false), Some(Exposure::Patched));
        // A mainline release after the fix sorts above 1.30.7 but is its own
        // track: 1.31.0 is still vulnerable, 1.32.x and 1.31.10 are not.
        assert_eq!(
            exposure("1.31.0", false),
            Some(Exposure::Vulnerable {
                fixed_in: "1.31.9".to_string()
            })
        );
        assert_eq!(exposure("1.32.0", false), Some(Exposure::Patched));
        assert_eq!(exposure("1.31.10", false), Some(Exposure::Patched));
    }

    #[test]
    fn test_distribution_packages_only_lead() {
        assert_eq!(
            exposure("1:1.31.8-1~bookworm", true),
            Some(Exposure::CheckVendor {
                fixed_in: "1.31.9".to_string()
            })
        );
        assert_eq!(
            exposure("1.22.1-9+deb12u2", true),
            Some(Exposure::CheckVendor {
                fixed_in: "1.30.7 (stable) or 1.31.9 (mainline)".to_string()
            })
        );
    }

    #[test]
    fn test_non_versions_are_ignored() {
        assert_eq!(exposure("latest", false), None);
        assert_eq!(exposure("", false), None);
    }

    #[test]
    fn test_feature_detection_finds_each_cve() {
        let http2 = config_features("server {\n  listen 443 ssl http2;\n}\n");
        assert!(http2.http2);
        assert!(!http2.http3);

        let http2_directive = config_features("server {\n  listen 443 ssl;\n  http2 on;\n}\n");
        assert!(http2_directive.http2);

        let http3 = config_features("server {\n  listen 443 quic;\n  http3 on;\n}\n");
        assert!(http3.http3);

        let mail = config_features("mail {\n  proxy on;\n  auth_http localhost:9000/auth;\n}\n");
        assert!(mail.mail_proxy);

        let resolver =
            config_features("location / {\n  proxy_pass http://$backend;\n  mirror /m;\n}\n");
        assert!(resolver.proxy_pass_variable_subrequest);

        // A fixed upstream with no subrequest does not reach the resolver bug.
        let fixed_upstream =
            config_features("location / {\n  proxy_pass http://backend;\n  mirror /m;\n}\n");
        assert!(!fixed_upstream.proxy_pass_variable_subrequest);

        let plain = config_features("server {\n  listen 80;\n  root /var/www;\n}\n");
        assert_eq!(plain, NginxFeatures::default());
    }

    #[test]
    fn test_applicable_cves_map_features_to_mitigations() {
        let features = NginxFeatures {
            http2: true,
            proxy_pass_backend: true,
            http3: true,
            mail_proxy: true,
            proxy_pass_variable_subrequest: true,
        };
        let cves: Vec<&str> = applicable_cves(&features)
            .into_iter()
            .map(|c| c.0)
            .collect();
        assert!(cves.contains(&"CVE-2026-123007"));
        assert!(cves.contains(&"CVE-2026-123633"));
        assert!(cves.contains(&"CVE-2026-121810"));
        assert!(cves.contains(&"CVE-2026-113425"));
        assert!(cves.contains(&"CVE-2026-123634"));

        // HTTP/2 without a backend proxy drops the HTTP/2+proxy CVE but keeps
        // the flow-control one.
        let http2_only = NginxFeatures {
            http2: true,
            ..NginxFeatures::default()
        };
        let cves: Vec<&str> = applicable_cves(&http2_only)
            .into_iter()
            .map(|c| c.0)
            .collect();
        assert!(cves.contains(&"CVE-2026-123007"));
        assert!(!cves.contains(&"CVE-2026-123633"));
    }

    #[test]
    fn test_vulnerable_build_with_http2_names_the_cve() {
        let installs = vec![NginxInstall {
            owner: "host".into(),
            version: "1.31.8".into(),
            source: VersionSource::ImageEnv,
        }];
        let features = NginxFeatures {
            http2: true,
            proxy_pass_backend: true,
            ..NginxFeatures::default()
        };
        let findings = findings_for("host", &installs, &features);
        let text: Vec<&str> = findings.iter().map(|f| f.description.as_str()).collect();
        assert!(text.iter().any(|d| d.contains("CVE-2026-123007")));
        assert!(text.iter().any(|d| d.contains("CVE-2026-123633")));
        assert!(findings
            .iter()
            .all(|f| f.severity == AnomalySeverity::Critical));
    }

    #[test]
    fn test_patched_build_reports_nothing() {
        let installs = vec![NginxInstall {
            owner: "host".into(),
            version: "1.31.9".into(),
            source: VersionSource::ImageEnv,
        }];
        let features = NginxFeatures {
            http2: true,
            ..NginxFeatures::default()
        };
        assert!(findings_for("host", &installs, &features).is_empty());
    }

    #[test]
    fn test_vulnerable_build_without_readable_config_still_warns() {
        let installs = vec![NginxInstall {
            owner: "host".into(),
            version: "1.31.8".into(),
            source: VersionSource::ImageEnv,
        }];
        let findings = findings_for("host", &installs, &NginxFeatures::default());
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .description
            .contains("No configuration was readable"));
        assert!(findings[0].description.contains("1.31.9"));
    }

    #[test]
    fn test_worker_crash_detects_nginx_signal_faults() {
        assert!(is_nginx_worker_crash(
            "2026/11/18 12:00:00 [alert] 31#0: worker process 32 exited on signal 11 (SIGSEGV)"
        ));
        assert!(is_nginx_worker_crash(
            "2026/11/18 12:00:00 [alert] 31#0: worker process 32 exited on signal 11 (SIGSEGV - core dumped)"
        ));
        // A graceful shutdown is not a crash.
        assert!(!is_nginx_worker_crash(
            "2026/11/18 12:00:00 [alert] 31#0: worker process 32 exited on signal 3 (SIGQUIT)"
        ));
        assert!(!is_nginx_worker_crash(
            "2026/11/18 12:00:00 [notice] start worker process 33"
        ));
    }

    #[test]
    fn test_crash_detector_needs_a_run_of_faults() {
        let detector = NginxWorkerCrashDetector;
        let crash = "2026/11/18 [alert] 1#0: worker process 2 exited on signal 11 (SIGSEGV)";
        assert!(detector.detect(&entries(&[crash, crash])).is_empty());
        assert_eq!(detector.detect(&entries(&[crash, crash, crash])).len(), 1);
    }

    #[test]
    fn test_sctp_monitor_reports_only_when_loaded() {
        let dir = std::env::temp_dir().join(format!("stackdog-sctp-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("proc")).unwrap();
        std::fs::create_dir_all(dir.join("etc/modprobe.d")).unwrap();

        // Not loaded: nothing.
        std::fs::write(dir.join("proc/modules"), "overlay 1 0 - Live 0x0\n").unwrap();
        let root = dir.to_string_lossy().into_owned();
        assert!(KernelSctpMonitor.detect(Some(&root)).is_empty());

        // Loaded and unblocked: high severity.
        std::fs::write(
            dir.join("proc/modules"),
            "sctp 123 1 - Live 0x0\noverlay 1 0 - Live 0x0\n",
        )
        .unwrap();
        let findings = KernelSctpMonitor.detect(Some(&root));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, AnomalySeverity::High);

        // Loaded but blocked: low severity, still worth knowing.
        std::fs::write(
            dir.join("etc/modprobe.d/zz-block-sctp.conf"),
            "install sctp /bin/false\n",
        )
        .unwrap();
        let findings = KernelSctpMonitor.detect(Some(&root));
        assert_eq!(findings[0].severity, AnomalySeverity::Low);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn exec_event(comm: &str, filename: &str) -> SyscallEvent {
        SyscallEvent::builder()
            .pid(1000)
            .uid(101)
            .syscall_type(SyscallType::Execve)
            .comm(Some(comm.to_string()))
            .details(Some(SyscallDetails::Exec {
                filename: Some(filename.to_string()),
                args: vec![filename.to_string()],
                argc: 1,
            }))
            .build()
    }

    #[test]
    fn test_web_worker_exec_flags_compromised_worker() {
        let monitor = WebWorkerExecMonitor;
        let events = vec![
            exec_event("nginx", "/bin/sh"),
            exec_event("bash", "/bin/ls"),
        ];
        let findings = monitor.detect(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("nginx"));
        assert!(findings[0].description.contains("/bin/sh"));
        assert_eq!(findings[0].severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_web_worker_exec_ignores_non_exec_and_non_workers() {
        let monitor = WebWorkerExecMonitor;
        let connect = SyscallEvent::builder()
            .syscall_type(SyscallType::Connect)
            .comm(Some("nginx".into()))
            .build();
        let events = vec![connect, exec_event("postgres", "/bin/true")];
        assert!(monitor.detect(&events).is_empty());
    }

    fn socket_event(comm: &str, protocol: u32, container: Option<&str>) -> SyscallEvent {
        SyscallEvent::builder()
            .syscall_type(SyscallType::Socket)
            .comm(Some(comm.to_string()))
            .container_id(container.map(|c| c.to_string()))
            .details(Some(SyscallDetails::Socket {
                domain: 2,
                type_: 1,
                protocol,
            }))
            .build()
    }

    #[test]
    fn test_sctp_socket_flags_worker_and_container() {
        let monitor = SctpSocketMonitor;
        let events = vec![
            socket_event("nginx", 132, None),
            socket_event("app", 132, Some("c1")),
            socket_event("app", 132, None),
            socket_event("nginx", 6, None),
        ];
        let findings = monitor.detect(&events);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| {
            f.severity == AnomalySeverity::Critical && f.description.contains("web server worker")
        }));
        assert!(findings.iter().any(|f| {
            f.severity == AnomalySeverity::High && f.description.contains("container process")
        }));
    }

    fn window(owner: &str, inbound_bytes: u64, request_count: u64) -> TrafficWindow {
        TrafficWindow {
            owner: owner.to_string(),
            inbound_bytes,
            request_count,
        }
    }

    #[test]
    fn test_http2_spray_flags_invisible_and_mismatched_traffic() {
        let monitor = Http2SprayMonitor::default();
        let observations = vec![
            window("nginx", 64 * 1024 * 1024, 0),
            window("nginx", 64 * 1024 * 1024, 4),
            window("nginx", 1024, 0),
            window("nginx", 64 * 1024 * 1024, 512),
        ];
        let findings = monitor.detect(&observations);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == AnomalySeverity::High));
        assert!(findings
            .iter()
            .any(|f| f.severity == AnomalySeverity::Medium));
        // The high-severity one is the zero-request case.
        assert!(findings
            .iter()
            .any(|f| f.severity == AnomalySeverity::High
                && f.description.contains("logged no requests")));
    }
}
