//! Detector tools — re-run built-in detectors on demand

use crate::detectors::DetectorRegistry;
use crate::sniff::reader::LogEntry;
use crate::tools::types::{tool_def, ToolDef, ToolResult};
use chrono::Utc;

pub fn definitions() -> Vec<ToolDef> {
    vec![tool_def(
        "run_detectors",
        "Run built-in security detectors on a set of log lines. Use to validate findings or check if specific lines match known attack patterns.",
        serde_json::json!({
            "type": "object",
            "properties": {
                "lines": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Log lines to analyze"
                }
            },
            "required": ["lines"]
        }),
    )]
}

pub fn execute_run_detectors(detectors: &DetectorRegistry, args: &str) -> ToolResult {
    let lines: Vec<String> = match serde_json::from_str::<serde_json::Value>(args) {
        Ok(v) => match v["lines"].as_array() {
            Some(arr) => arr
                .iter()
                .filter_map(|l| l.as_str().map(String::from))
                .collect(),
            None => return ToolResult::error("run_detectors", "Missing 'lines' array"),
        },
        Err(e) => return ToolResult::error("run_detectors", &format!("Invalid args: {}", e)),
    };

    if lines.is_empty() {
        return ToolResult::success("run_detectors", serde_json::json!({ "findings": [] }));
    }

    let entries: Vec<LogEntry> = lines
        .into_iter()
        .map(|line| LogEntry {
            source_id: "tool-input".into(),
            timestamp: Utc::now(),
            line,
            metadata: Default::default(),
        })
        .collect();

    let anomalies = detectors.detect_log_anomalies(&entries);

    let findings: Vec<serde_json::Value> = anomalies
        .into_iter()
        .map(|a| {
            serde_json::json!({
                "detector_id": a.detector_id,
                "description": a.description,
                "severity": format!("{}", a.severity),
                "sample_line": a.sample_line,
            })
        })
        .collect();

    ToolResult::success(
        "run_detectors",
        serde_json::json!({ "findings": findings, "count": findings.len() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_detectors_with_attack_lines() {
        let detectors = DetectorRegistry::default();
        let args = r#"{"lines": [
            "GET /search?q=' OR 1=1 -- HTTP/1.1",
            "GET /search?q=UNION SELECT * FROM users-- HTTP/1.1",
            "GET /search?q=1; DROP TABLE users-- HTTP/1.1"
        ]}"#;

        let result = execute_run_detectors(&detectors, args);
        assert!(result.content.contains("sqli-probe"));
    }

    #[test]
    fn test_run_detectors_with_clean_lines() {
        let detectors = DetectorRegistry::default();
        let args = r#"{"lines": [
            "GET /index.html HTTP/1.1 200",
            "GET /about HTTP/1.1 200"
        ]}"#;

        let result = execute_run_detectors(&detectors, args);
        assert!(result.content.contains(r#""count":0"#));
    }

    #[test]
    fn test_run_detectors_empty_lines() {
        let detectors = DetectorRegistry::default();
        let result = execute_run_detectors(&detectors, r#"{"lines": []}"#);
        assert!(result.content.contains("findings"));
    }
}
