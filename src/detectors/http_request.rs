//! Extract the HTTP request a log line records.
//!
//! Web detectors used to match their indicators anywhere in a line. An
//! application that logs whole requests — headers, bodies, its own
//! middleware names — then trips them on its own traffic: stacker's agent
//! long-poll lines carried enough header text to read as webshell probing.
//! Detectors that are about the URL should look at the URL only.

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    /// Percent-decoded, lowercased path without the query string.
    pub path: String,
    /// Percent-decoded, lowercased query string without the leading `?`.
    pub query: String,
}

impl HttpRequest {
    pub fn has_parameters(&self) -> bool {
        !self.query.is_empty() || self.method == "POST"
    }
}

const METHODS: &str = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS";

fn combined_format() -> &'static Regex {
    // nginx/apache combined and common formats: "GET /path?q HTTP/1.1"
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(r#""({METHODS}) (\S+) HTTP/[0-9.]+""#)).expect("valid regex")
    })
}

fn method_colon_format() -> &'static Regex {
    // actix ServiceRequest debug output, as stacker logs it: "GET:/api/v1/..."
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!(r#"\b({METHODS}):(/[^\s"\\]*)"#)).expect("valid regex"))
}

fn bare_format() -> &'static Regex {
    // Plain "GET /path" without quotes, as many app loggers write it.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(r#"(?:^|[\s\[\]|])({METHODS}) (/[^\s"\\]*)"#)).expect("valid regex")
    })
}

/// The request a log line records, if it records one.
pub fn extract_request(line: &str) -> Option<HttpRequest> {
    let captures = combined_format()
        .captures(line)
        .or_else(|| method_colon_format().captures(line))
        .or_else(|| bare_format().captures(line))?;

    let method = captures.get(1)?.as_str().to_ascii_uppercase();
    let raw_target = captures.get(2)?.as_str();
    let raw_target = strip_scheme_and_host(raw_target);

    let (raw_path, raw_query) = match raw_target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (raw_target, ""),
    };

    Some(HttpRequest {
        method,
        path: percent_decode(raw_path).to_ascii_lowercase(),
        query: percent_decode(raw_query).to_ascii_lowercase(),
    })
}

/// A proxy log can record an absolute URI: "GET http://host/path HTTP/1.1".
fn strip_scheme_and_host(target: &str) -> &str {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = target.strip_prefix(scheme) {
            return rest.find('/').map(|index| &rest[index..]).unwrap_or("/");
        }
    }
    target
}

/// Decode `%XX` escapes and `+` once. Attackers encode `cmd%3Did`; a second
/// pass would turn literal `%25` in a legitimate URL into something it isn't.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        decoded.push(high << 4 | low);
                        index += 3;
                    }
                    _ => {
                        decoded.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extracts_combined_log_format() {
        let request = extract_request(
            r#"203.0.113.9 - - [31/Oct/2026:10:00:00 +0000] "GET /wp-content/uploads/x.php?cmd=id HTTP/1.1" 200 12 "-" "curl/8""#,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/wp-content/uploads/x.php");
        assert_eq!(request.query, "cmd=id");
    }

    #[test]
    fn test_extracts_actix_service_request_format() {
        let request = extract_request(
            r#"{"req":"\nServiceRequest HTTP/1.1 GET:/api/v1/agent/commands/wait/deployment_1\n  query: ?\"timeout=10\"\n"}"#,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/v1/agent/commands/wait/deployment_1");
        assert_eq!(request.query, "");
    }

    #[test]
    fn test_decodes_percent_escapes_once() {
        let request =
            extract_request(r#""POST /shell.php?c%3Dwhoami%26x=%2541 HTTP/1.1""#).unwrap();
        assert_eq!(request.query, "c=whoami&x=%41");
    }

    #[test]
    fn test_strips_absolute_uri() {
        let request = extract_request(r#""GET http://example.com/a.php?x=1 HTTP/1.1""#).unwrap();
        assert_eq!(request.path, "/a.php");
    }

    #[test]
    fn test_line_without_request_yields_none() {
        assert!(extract_request("sshd[1]: Failed password for root from 203.0.113.9").is_none());
        assert!(extract_request("worker: ran /bin/sh -c cleanup").is_none());
    }

    #[test]
    fn test_truncated_escape_is_kept_literally() {
        let request = extract_request(r#""GET /a?b=%4 HTTP/1.1""#).unwrap();
        assert_eq!(request.query, "b=%4");
    }
}
