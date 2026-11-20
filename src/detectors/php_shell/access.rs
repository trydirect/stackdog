//! Requests to PHP shells, read from access logs.
//!
//! Banning a visitor of an infected *legitimate* page would ban the site's
//! audience: a backdoor injected into `index.php` is fetched by everyone. So a
//! request is grounds for a ban only when it can come from nobody but the
//! attacker:
//!
//! - any request to a flagged PHP file in an upload directory, with the upload
//!   directory in the URL. No visitor has a reason to execute an upload;
//! - a request with parameters (query string or POST) to a flagged PHP file
//!   that is not a common entry point: that is someone driving the shell;
//! - a POST to any PHP file under an `uploads/` URL, flagged or not yet.
//!
//! A PHP file is any name with a PHP extension in it, `x.php.jpg` included:
//! a misconfigured Apache (`AddHandler php-script .php`) executes that too,
//! and the name is what a double-extension upload leaves behind.
//!
//! The URL side of "upload directory" is only `uploads/`: `/images/`,
//! `/files/` and `/tmp/` are ordinary URL trees with real PHP endpoints.
//!
//! A flagged non-PHP file is never grounds for a ban. A polyglot image with
//! PHP inside is served as plain bytes to every visitor of the page it is
//! embedded in, so the requests it collects are the audience. It stays an
//! alert, like the file scan that flagged it.
//!
//! Other requests to flagged files raise an alert-only finding.

use std::collections::HashSet;

use crate::detectors::http_request::{extract_request, HttpRequest};
use crate::detectors::{DetectorFamily, DetectorFinding, LogDetector};
use crate::ip_ban::engine::IpBanEngine;
use crate::sniff::analyzer::AnomalySeverity;
use crate::sniff::reader::LogEntry;

use super::{is_php_name, FlaggedFile, FlaggedFiles};

pub const ACCESS_DETECTOR_ID: &str = "web.php-shell-access";
/// Alert-only: a flagged file was requested in a way visitors also do.
pub const REQUEST_DETECTOR_ID: &str = "web.php-shell-request";

/// One finding per client per pass is enough to count an offense; more only
/// floods the alert channel.
const MAX_FINDINGS: usize = 20;

/// URL segments that mark an upload directory. Narrower than the scanner's
/// list, because a ban rests on it.
const URL_UPLOAD_DIR_SEGMENTS: &[&str] = &["uploads"];

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
    let path = script_path(&request.path);
    let file_name = path.rsplit('/').next().unwrap_or_default();
    if file_name.is_empty() {
        return None;
    }
    let url_in_uploads = in_url_upload_dir(&path);

    if let Some(file) = flagged
        .iter()
        .find(|file| same_file(&file.logical_path, &file.root_logical, &path))
    {
        // The URL must carry the upload directory itself: a suffix match of
        // `/index.php` against `.../uploads/index.php` is the front page.
        // Only a PHP file executes a request: a flagged polyglot image is
        // served as plain bytes to whoever loads the page it is embedded in,
        // so a ban here would ban the audience. Non-PHP flagged files fall
        // through to the alert below.
        if is_php(file_name) && file.in_upload_dir && url_in_uploads {
            return Some(Verdict::Ban("flagged file in an upload directory"));
        }
        if is_php(file_name)
            && request.has_parameters()
            && !COMMON_ENTRY_POINTS.contains(&file_name)
        {
            return Some(Verdict::Ban("parameters sent to a flagged file"));
        }
        return Some(Verdict::Alert);
    }

    if request.method == "POST" && is_php(file_name) && url_in_uploads {
        return Some(Verdict::Ban("POST to PHP in an upload directory"));
    }

    None
}

/// The script a request executes. Segments are normalised the way the web
/// server resolves them (`//`, `.`, `..`), and anything after the first PHP
/// segment is PATH_INFO: `/up/x.php/cmd` and `/up/x.php/` both run `x.php`.
fn script_path(request_path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in request_path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => {
                segments.push(segment);
                if is_php(segment) {
                    break;
                }
            }
        }
    }
    format!("/{}", segments.join("/"))
}

fn in_url_upload_dir(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .rev()
        .skip(1) // the file name itself
        .any(|segment| URL_UPLOAD_DIR_SEGMENTS.contains(&segment))
}

/// The file at `logical_path` (`/var/www/html/up/x.php`) is what a request
/// for `request_path` (`/up/x.php`) executes. The docroot is not known, so
/// the URL must be a suffix of the file path on a segment boundary.
///
/// A suffix that leaves a `uploads/` segment out (`/x.php` against
/// `.../uploads/2026/x.php`) names some other file: a docroot does not sit
/// inside the site's own uploads directory. Only the part of the docroot
/// below the scan root counts, for the same reason the file scan judges
/// upload directories inside the root only: where the root itself sits says
/// nothing. A site served from `/srv/uploads/site` is not "in uploads", and
/// requests to its files still match.
fn same_file(logical_path: &str, root_logical: &str, request_path: &str) -> bool {
    let request_path = request_path.trim_end_matches('/');
    if request_path.is_empty() {
        return false;
    }
    let request_path = if request_path.starts_with('/') {
        request_path.to_string()
    } else {
        format!("/{}", request_path)
    };
    let Some(docroot) = logical_path.strip_suffix(request_path.as_str()) else {
        return false;
    };
    // The docroot is a prefix of the file path and the root is a prefix of
    // the file path, so one is a prefix of the other. A docroot above the
    // root leaves nothing below it to judge.
    let below_root = docroot
        .strip_prefix(root_logical.trim_end_matches('/'))
        .unwrap_or("");
    !below_root
        .to_ascii_lowercase()
        .split('/')
        .any(|segment| URL_UPLOAD_DIR_SEGMENTS.contains(&segment))
}

fn is_php(file_name: &str) -> bool {
    is_php_name(file_name)
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
                    root_logical: "/var/www/html".into(),
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
    fn test_flagged_upload_does_not_ban_a_same_named_docroot_file() {
        let detector = detector(&[
            ("/var/www/html/wp-content/uploads/index.php", true),
            ("/var/www/html/wp-content/uploads/2026/x.php", true),
        ]);
        for target in ["/index.php", "/x.php", "/x.php?a=1", "/index.php?p=42"] {
            let found = detector.detect(&entries(&[&line("198.51.100.7", "GET", target)]));
            assert!(found.is_empty(), "{target} is another file");
        }
        let found = detector.detect(&entries(&[&line(
            "203.0.113.9",
            "GET",
            "/wp-content/uploads/index.php",
        )]));
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);
    }

    #[test]
    fn test_post_to_php_under_ordinary_url_trees_does_not_ban() {
        let detector = detector(&[]);
        for target in [
            "/images/thumb.php",
            "/files/download.php",
            "/tmp/x.php",
            "/upload/index.php",
        ] {
            assert!(
                detector
                    .detect(&entries(&[&line("198.51.100.7", "POST", target)]))
                    .is_empty(),
                "{target} must not ban"
            );
        }
    }

    #[test]
    fn test_path_info_and_trailing_slash_reach_the_script() {
        let detector = detector(&[("/var/www/html/uploads/x.php", true)]);
        for (method, target) in [
            ("GET", "/uploads/x.php/"),
            ("POST", "/uploads/x.php/cmd"),
            ("GET", "/uploads//./x.php"),
            ("GET", "/static/../uploads/x.php"),
        ] {
            let found = detector.detect(&entries(&[&line("203.0.113.9", method, target)]));
            assert_eq!(found.len(), 1, "{method} {target}");
            assert_eq!(
                found[0].detector_id, ACCESS_DETECTOR_ID,
                "{method} {target}"
            );
        }

        let found = self::detector(&[]).detect(&entries(&[&line(
            "203.0.113.9",
            "POST",
            "/uploads/y.PHP/z",
        )]));
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);
    }

    #[test]
    fn test_flagged_polyglot_image_never_bans_visitors() {
        // A polyglot GIF (PHP inside an image) is flagged by the file scan,
        // but every request to it is a browser loading a picture. Those are
        // visitors: alert only.
        let detector = detector(&[("/var/www/html/wp-content/uploads/2026/avatar.gif", true)]);
        for (method, target) in [
            ("GET", "/wp-content/uploads/2026/avatar.gif"),
            ("GET", "/wp-content/uploads/2026/avatar.gif?v=2"),
            ("POST", "/wp-content/uploads/2026/avatar.gif"),
        ] {
            let found = detector.detect(&entries(&[&line("203.0.113.9", method, target)]));
            assert_eq!(found.len(), 1, "{method} {target}");
            assert_eq!(
                found[0].detector_id, REQUEST_DETECTOR_ID,
                "{method} {target}"
            );
        }
    }

    #[test]
    fn test_suffix_match_respects_segments() {
        assert!(same_file(
            "/var/www/html/up/x.php",
            "/var/www/html",
            "/up/x.php"
        ));
        assert!(!same_file(
            "/var/www/html/backup/x.php",
            "/var/www/html",
            "/up/x.php"
        ));
        assert!(!same_file("/var/www/html/up/x.php", "/var/www/html", "/"));
        assert!(same_file(
            "/var/www/html/uploads/x.php",
            "/var/www/html",
            "/uploads/x.php"
        ));
        assert!(!same_file(
            "/var/www/html/uploads/x.php",
            "/var/www/html",
            "/x.php"
        ));
    }

    #[test]
    fn test_root_own_path_is_not_an_upload_directory() {
        // The site is served from a directory the host happens to call
        // uploads: requests to its files still match their flagged file.
        assert!(same_file(
            "/srv/uploads/site/x.php",
            "/srv/uploads/site",
            "/x.php"
        ));
        assert!(same_file(
            "/srv/uploads/site/y.php",
            "/srv/uploads/site",
            "/site/y.php"
        ));
        // What the rule still rejects: the URL dropped the site's own uploads
        // tree.
        assert!(!same_file(
            "/var/www/html/uploads/2026/x.php",
            "/var/www/html",
            "/x.php"
        ));
    }

    #[test]
    fn test_double_extension_name_counts_as_php() {
        // `AddHandler php-script .php` makes Apache execute x.php.jpg, so
        // that name is an attack artifact, not an image.
        let detector = detector(&[("/var/www/html/uploads/x.php.jpg", true)]);
        let found = detector.detect(&entries(&[&line(
            "203.0.113.9",
            "POST",
            "/uploads/x.php.jpg",
        )]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);

        // Unflagged is enough for the POST rule, same as x.php.
        let unflagged = self::detector(&[]);
        let found = unflagged.detect(&entries(&[&line(
            "203.0.113.9",
            "POST",
            "/uploads/x.php.jpg",
        )]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector_id, ACCESS_DETECTOR_ID);
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
