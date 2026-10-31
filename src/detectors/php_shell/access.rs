//! Requests to PHP shells, read from access logs.
//!
//! Banning a visitor of an infected *legitimate* page would ban the site's
//! audience: a backdoor injected into `index.php` is fetched by everyone. So a
//! request is grounds for a ban only when it can come from nobody but the
//! attacker:
//!
//! - any request to a flagged file in an upload directory — no visitor has a
//!   reason to execute an upload;
//! - a request with parameters (query string or POST) to a flagged file that
//!   is not a common entry point — that is someone driving the shell;
//! - a POST to any PHP file in an upload directory, flagged or not yet.
//!
//! Other requests to flagged files raise an alert-only finding.

use std::collections::HashSet;

use crate::detectors::http_request::{extract_request, HttpRequest};
use crate::detectors::{DetectorFamily, DetectorFinding, LogDetector};
use crate::ip_ban::engine::IpBanEngine;
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

use super::{in_upload_dir, FlaggedFile, FlaggedFiles, PHP_EXTENSIONS};

pub const ACCESS_DETECTOR_ID: &str = "web.php-shell-access";
/// Alert-only: a flagged file was requested in a way visitors also do.
pub const REQUEST_DETECTOR_ID: &str = "php.shell-request";

/// One finding per client per pass is enough to count an offense; more only
/// floods the alert channel.
const MAX_FINDINGS: usize = 20;

/// Files every visitor of a PHP site requests, with parameters.
const COMMON_ENTRY_POINTS: &[&str] = &[
    "index.php",
    "wp-login.php",
    "wp-cron.php",
    "xmlrpc.php",
    "admin-ajax.php",
    "admin-post.php",
    "admin.php",
    "login.php",
    "wp-comments-post.php",
];

pub struct PhpShellAccessDetector {
    flagged: FlaggedFiles,
}

impl PhpShellAccessDetector {
    pub fn new(flagged: FlaggedFiles) -> Self {
        Self { flagged }
    }
}

enum Verdict {
    Ban(&'static str),
    Alert,
}

impl LogDetector for PhpShellAccessDetector {
    fn id(&self) -> &'static str {
        ACCESS_DETECTOR_ID
    }

    fn family(&self) -> DetectorFamily {
        DetectorFamily::Web
    }

    fn detect(&self, entries: &[LogEntry]) -> Vec<DetectorFinding> {
        let flagged = match self.flagged.read() {
            Ok(flagged) => flagged.clone(),
            Err(_) => return Vec::new(),
        };

        let mut seen = HashSet::new();
        let mut findings = Vec::new();

        for entry in entries {
            if findings.len() >= MAX_FINDINGS {
                break;
            }
            let Some(request) = extract_request(&entry.line) else {
                continue;
            };
            let Some(verdict) = judge(&request, &flagged) else {
                continue;
            };

            let client = IpBanEngine::extract_ip_candidates(&entry.line)
                .into_iter()
                .next()
                .unwrap_or_default();
            let detector_id = match verdict {
                Verdict::Ban(_) => ACCESS_DETECTOR_ID,
                Verdict::Alert => REQUEST_DETECTOR_ID,
            };
            if !seen.insert((detector_id, client)) {
                continue;
            }

            findings.push(match verdict {
                Verdict::Ban(reason) => DetectorFinding {
                    detector_id: ACCESS_DETECTOR_ID.into(),
                    family: DetectorFamily::Web,
                    description: format!(
                        "PHP shell access: {} {} ({})",
                        request.method, request.path, reason
                    ),
                    severity: AnomalySeverity::Critical,
                    confidence: 92,
                    sample_line: entry.line.clone(),
                },
                Verdict::Alert => DetectorFinding {
                    detector_id: REQUEST_DETECTOR_ID.into(),
                    family: DetectorFamily::Web,
                    description: format!(
                        "Request to a file flagged as a PHP shell: {} {}",
                        request.method, request.path
                    ),
                    severity: AnomalySeverity::High,
                    confidence: 70,
                    sample_line: entry.line.clone(),
                },
            });
        }

        findings
    }
}

fn judge(request: &HttpRequest, flagged: &[FlaggedFile]) -> Option<Verdict> {
    let file_name = request.path.rsplit('/').next().unwrap_or_default();
    if file_name.is_empty() {
        return None;
    }

    if let Some(file) = flagged
        .iter()
        .find(|file| same_file(&file.logical_path, &request.path))
    {
        if file.in_upload_dir {
            return Some(Verdict::Ban("flagged file in an upload directory"));
        }
        if request.has_parameters() && !COMMON_ENTRY_POINTS.contains(&file_name) {
            return Some(Verdict::Ban("parameters sent to a flagged file"));
        }
        return Some(Verdict::Alert);
    }

    if request.method == "POST" && is_php(file_name) && in_upload_dir(&request.path) {
        return Some(Verdict::Ban("POST to PHP in an upload directory"));
    }

    None
}

/// The file at `logical_path` (`/var/www/html/up/x.php`) is what a request
/// for `request_path` (`/up/x.php`) executes. The docroot is not known, so
/// the URL must be a suffix of the file path on a segment boundary.
fn same_file(logical_path: &str, request_path: &str) -> bool {
    let request_path = request_path.trim_end_matches('/');
    if request_path.is_empty() {
        return false;
    }
    let request_path = if request_path.starts_with('/') {
        request_path.to_string()
    } else {
        format!("/{}", request_path)
    };
    logical_path == request_path || logical_path.ends_with(&request_path)
}

fn is_php(file_name: &str) -> bool {
    file_name
        .rsplit_once('.')
        .map(|(_, ext)| PHP_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

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

    fn detector(files: &[(&str, bool)]) -> PhpShellAccessDetector {
        PhpShellAccessDetector::new(Arc::new(RwLock::new(
            files
                .iter()
                .map(|(path, upload)| FlaggedFile {
                    logical_path: (*path).into(),
                    in_upload_dir: *upload,
                })
                .collect(),
        )))
    }

    fn line(ip: &str, method: &str, target: &str) -> String {
        format!(
            r#"{ip} - - [31/Oct/2026:10:00:00 +0000] "{method} {target} HTTP/1.1" 200 5 "-" "x""#
        )
    }

    #[test]
    fn test_any_request_to_flagged_upload_bans() {
        let detector = detector(&[("/var/www/html/wp-content/uploads/x.php", true)]);
        let findings = detector.detect(&entries(&[&line(
            "203.0.113.9",
            "GET",
            "/wp-content/uploads/x.php",
        )]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_id, ACCESS_DETECTOR_ID);
    }

    #[test]
    fn test_parameters_to_flagged_file_ban() {
        let detector = detector(&[("/var/www/html/shell.php", false)]);
        let found = detector.detect(&entries(&[&line("203.0.113.9", "GET", "/shell.php?c=id")]));
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);

        let found = detector.detect(&entries(&[&line("203.0.113.9", "GET", "/shell.php")]));
        assert_eq!(found[0].detector_id, REQUEST_DETECTOR_ID);
    }

    #[test]
    fn test_visitors_of_infected_entry_point_are_not_banned() {
        let detector = detector(&[("/var/www/html/index.php", false)]);
        let found = detector.detect(&entries(&[&line("198.51.100.7", "GET", "/index.php?p=42")]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector_id, REQUEST_DETECTOR_ID);
        assert!(!found[0]
            .description
            .to_ascii_lowercase()
            .contains("webshell"));
    }

    #[test]
    fn test_post_to_php_in_uploads_bans_without_scan() {
        let detector = detector(&[]);
        let found = detector.detect(&entries(&[&line(
            "203.0.113.9",
            "POST",
            "/uploads/2026/a.php",
        )]));
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);

        assert!(detector
            .detect(&entries(&[&line(
                "203.0.113.9",
                "GET",
                "/uploads/2026/a.php"
            )]))
            .is_empty());
        assert!(detector
            .detect(&entries(&[&line(
                "203.0.113.9",
                "POST",
                "/uploads/photo.jpg"
            )]))
            .is_empty());
    }

    #[test]
    fn test_suffix_match_respects_segments() {
        assert!(same_file("/var/www/html/up/x.php", "/up/x.php"));
        assert!(!same_file("/var/www/html/backup/x.php", "/up/x.php"));
        assert!(!same_file("/var/www/html/up/x.php", "/"));
    }

    #[test]
    fn test_one_finding_per_client() {
        let detector = detector(&[("/var/www/html/uploads/x.php", true)]);
        let a = line("203.0.113.9", "POST", "/uploads/x.php");
        let b = line("203.0.113.10", "POST", "/uploads/x.php");
        let found = detector.detect(&entries(&[&a, &a, &b]));
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_stacker_agent_poll_is_ignored() {
        let detector = detector(&[("/var/www/html/uploads/x.php", true)]);
        let found = detector.detect(&entries(&[
            r#"{"msg":"[AUTHENTICATE AGENT VIA X-AGENT-ID AND BEARER TOKEN - START]","req":"\nServiceRequest HTTP/1.1 GET:/api/v1/agent/commands/wait/deployment_1\n  query: ?\"timeout=10\"\n"}"#,
        ]));
        assert!(found.is_empty());
    }
}
