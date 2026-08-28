//! AI-powered log analysis engine
//!
//! Provides log summarization and anomaly detection via two backends:
//! - OpenAI-compatible API (works with OpenAI, Ollama, vLLM, etc.)
//! - Local Candle inference (requires `ml` feature)

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::sniff::reader::LogEntry;

const MAX_PROMPT_LINES: usize = 200;
const MAX_PROMPT_CHARS: usize = 16_000;
const MAX_LINE_CHARS: usize = 500;

/// Summary produced by AI analysis of log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSummary {
    pub source_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_entries: usize,
    pub summary_text: String,
    pub error_count: usize,
    pub warning_count: usize,
    pub key_events: Vec<String>,
    pub anomalies: Vec<LogAnomaly>,
}

/// An anomaly detected in log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnomaly {
    pub description: String,
    pub severity: AnomalySeverity,
    pub sample_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detector_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detector_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

/// Severity of a detected anomaly
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalySeverity::Low => write!(f, "Low"),
            AnomalySeverity::Medium => write!(f, "Medium"),
            AnomalySeverity::High => write!(f, "High"),
            AnomalySeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Trait for AI-powered log analysis
#[async_trait]
pub trait LogAnalyzer: Send + Sync {
    /// Summarize a batch of log entries
    async fn summarize(&self, entries: &[LogEntry]) -> Result<LogSummary>;
}

/// OpenAI-compatible API backend (works with OpenAI, Ollama, vLLM, etc.)
pub struct OpenAiAnalyzer {
    api_url: String,
    api_key: Option<String>,
    model: String,
    max_tokens: u32,
    client: reqwest::Client,
}

impl OpenAiAnalyzer {
    fn push_selected_index(
        selected_indices: &mut Vec<usize>,
        seen: &mut HashSet<usize>,
        idx: usize,
        total_entries: usize,
    ) {
        if idx < total_entries && seen.insert(idx) {
            selected_indices.push(idx);
        }
    }

    pub fn new(
        api_url: String,
        api_key: Option<String>,
        model: String,
        timeout_secs: u64,
        max_tokens: u32,
    ) -> Self {
        let mut builder = reqwest::Client::builder();
        if timeout_secs > 0 {
            builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
        }
        let client = builder.build().unwrap_or_else(|err| {
            log::warn!(
                "Failed to build HTTP client with {}s timeout ({}), falling back to default",
                timeout_secs,
                err
            );
            reqwest::Client::new()
        });

        Self {
            api_url,
            api_key,
            model,
            max_tokens,
            client,
        }
    }

    fn build_prompt(entries: &[LogEntry]) -> String {
        let prompt_entries = Self::select_prompt_entries(entries);
        let included_count = prompt_entries.len();
        let included_chars: usize = prompt_entries.iter().map(|line| line.len()).sum();
        let was_truncated = included_count < entries.len();
        let truncation_note = if was_truncated {
            format!(
                "Only {} of {} entries are included below to keep the request bounded. \
                 Prioritize the included lines when identifying anomalies, but keep the full batch size in mind.\n",
                included_count,
                entries.len()
            )
        } else {
            String::new()
        };
        let log_block = prompt_entries.join("\n");

        format!(
            "Analyze these log entries and provide a JSON response with:\n\
             1. \"summary\": A concise summary of what happened\n\
             2. \"error_count\": Number of errors found\n\
             3. \"warning_count\": Number of warnings found\n\
             4. \"key_events\": Array of important events (max 5)\n\
             5. \"anomalies\": Array of objects with \"description\", \"severity\" (Low/Medium/High/Critical), \"sample_line\"\n\n\
             Respond ONLY with valid JSON, no markdown.\n\n\
             Batch metadata:\n\
             - total_entries: {}\n\
             - included_entries: {}\n\
             - included_characters: {}\n\
             {}\
             Log entries:\n{}",
            entries.len(),
            included_count,
            included_chars,
            truncation_note,
            log_block
        )
    }

    fn select_prompt_entries(entries: &[LogEntry]) -> Vec<String> {
        if entries.is_empty() {
            return Vec::new();
        }

        let mut selected_indices = Vec::new();
        let mut seen = HashSet::new();

        for (idx, entry) in entries.iter().enumerate() {
            if Self::is_priority_line(&entry.line) {
                Self::push_selected_index(&mut selected_indices, &mut seen, idx, entries.len());
            }
        }

        let recent_window_start = entries.len().saturating_sub(MAX_PROMPT_LINES);
        for idx in recent_window_start..entries.len() {
            Self::push_selected_index(&mut selected_indices, &mut seen, idx, entries.len());
        }

        if selected_indices.len() < MAX_PROMPT_LINES {
            let stride = (entries.len() / MAX_PROMPT_LINES.max(1)).max(1);
            let mut idx = 0;
            while idx < entries.len() && selected_indices.len() < MAX_PROMPT_LINES {
                Self::push_selected_index(&mut selected_indices, &mut seen, idx, entries.len());
                idx += stride;
            }
        }

        selected_indices.sort_unstable();

        let mut prompt_entries = Vec::new();
        let mut total_chars = 0;

        for idx in selected_indices {
            if prompt_entries.len() >= MAX_PROMPT_LINES {
                break;
            }

            let line = Self::truncate_line(&entries[idx].line);
            let next_chars = if prompt_entries.is_empty() {
                line.len()
            } else {
                total_chars + 1 + line.len()
            };

            if next_chars > MAX_PROMPT_CHARS {
                break;
            }

            total_chars = next_chars;
            prompt_entries.push(line);
        }

        if prompt_entries.is_empty() {
            prompt_entries.push(Self::truncate_line(&entries[entries.len() - 1].line));
        }

        prompt_entries
    }

    fn is_priority_line(line: &str) -> bool {
        let lower = line.to_ascii_lowercase();
        [
            "error",
            "warn",
            "fatal",
            "panic",
            "exception",
            "denied",
            "unauthorized",
            "failed",
            "timeout",
            "attack",
            "anomaly",
        ]
        .iter()
        .any(|pattern| lower.contains(pattern))
    }

    fn truncate_line(line: &str) -> String {
        let truncated: String = line.chars().take(MAX_LINE_CHARS).collect();
        if truncated.len() == line.len() {
            truncated
        } else {
            format!("{}...[truncated]", truncated)
        }
    }
}

/// Response structure from the LLM
#[derive(Debug, Deserialize)]
struct LlmAnalysis {
    summary: Option<String>,
    error_count: Option<usize>,
    warning_count: Option<usize>,
    key_events: Option<Vec<String>>,
    anomalies: Option<Vec<LlmAnomaly>>,
}

#[derive(Debug, Deserialize)]
struct LlmAnomaly {
    description: Option<String>,
    severity: Option<String>,
    sample_line: Option<String>,
}

/// OpenAI chat completion response
#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Extract JSON from LLM response, handling markdown fences, preamble text, etc.
fn extract_json(content: &str) -> &str {
    let trimmed = content.trim();

    // Try ```json ... ``` fence
    if let Some(start) = trimmed.find("```json") {
        let after_fence = &trimmed[start + 7..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }

    // Try ``` ... ``` fence (no language tag)
    if let Some(start) = trimmed.find("```") {
        let after_fence = &trimmed[start + 3..];
        if let Some(end) = after_fence.find("```") {
            return after_fence[..end].trim();
        }
    }

    // Try to find raw JSON object
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            if end > start {
                return &trimmed[start..=end];
            }
        }
    }

    trimmed
}

/// Attempt to repair truncated JSON by closing open braces/brackets and
/// trimming incomplete trailing string values.  Returns `None` if the
/// input doesn't look like JSON at all.
fn repair_truncated_json(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let start = trimmed.find('{')?;
    let json = &trimmed[start..];

    // Already valid — nothing to repair.
    if serde_json::from_str::<serde_json::Value>(json).is_ok() {
        return None;
    }

    // Count unmatched openers to decide how many closers we need.
    let mut depth: i32 = 0; // braces
    let mut bracket_depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;

    for ch in json.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            _ => {}
        }
    }

    // If we're inside a string when we ran out of input, close it first.
    let mut repair = String::from(json);
    if in_string {
        repair.push('"');
    }

    // Close any incomplete array entries with a trailing `]` if needed.
    // (We don't try to be perfect — just enough for serde to parse the
    // fields that *were* fully written.)
    for _ in 0..bracket_depth.max(0) {
        repair.push(']');
    }
    for _ in 0..depth.max(0) {
        repair.push('}');
    }

    // If the last meaningful token before our closers is a trailing comma
    // or colon, strip it — serde will reject `{"a":}` or `{"a":1,}`.
    // We do a simple scan from the end ignoring the closers we just added.
    let closers_len =
        (bracket_depth.max(0) as usize) + (depth.max(0) as usize) + if in_string { 1 } else { 0 };
    let body_end = repair.len() - closers_len;
    let body = &repair[..body_end];
    let trimmed_body = body.trim_end();
    if trimmed_body.ends_with(',') || trimmed_body.ends_with(':') {
        let new_body = &trimmed_body[..trimmed_body.len() - 1];
        repair = format!("{}{}", new_body.trim_end(), &repair[body_end..]);
    }

    // Only return the repair if it actually parses.
    if serde_json::from_str::<serde_json::Value>(&repair).is_ok() {
        Some(repair)
    } else {
        None
    }
}

/// Parse LLM severity string to enum
fn parse_severity(s: &str) -> AnomalySeverity {
    match s.to_lowercase().as_str() {
        "critical" => AnomalySeverity::Critical,
        "high" => AnomalySeverity::High,
        "medium" => AnomalySeverity::Medium,
        _ => AnomalySeverity::Low,
    }
}

/// Parse the LLM JSON response into a LogSummary
fn parse_llm_response(source_id: &str, entries: &[LogEntry], raw_json: &str) -> Result<LogSummary> {
    log::debug!(
        "Parsing LLM response ({} bytes) for source {}",
        raw_json.len(),
        source_id
    );
    log::trace!("Raw LLM response:\n{}", raw_json);

    let analysis: LlmAnalysis = match serde_json::from_str(raw_json) {
        Ok(a) => a,
        Err(e) => {
            // Try to repair truncated JSON before giving up.
            if let Some(repaired) = repair_truncated_json(raw_json) {
                log::warn!(
                    "LLM response was truncated ({}); repaired to {} bytes",
                    e,
                    repaired.len()
                );
                serde_json::from_str(&repaired).context(format!(
                    "Failed to parse repaired LLM response. Original starts with: {}",
                    &raw_json[..raw_json.len().min(200)]
                ))?
            } else {
                return Err(e).context(format!(
                    "Failed to parse LLM response as JSON. Response starts with: {}",
                    &raw_json[..raw_json.len().min(200)]
                ));
            }
        }
    };

    log::debug!(
        "LLM analysis parsed — summary: {:?}, errors: {:?}, warnings: {:?}, anomalies: {}",
        analysis.summary.as_deref().map(|s| &s[..s.len().min(80)]),
        analysis.error_count,
        analysis.warning_count,
        analysis.anomalies.as_ref().map(|a| a.len()).unwrap_or(0),
    );

    let anomalies = analysis
        .anomalies
        .unwrap_or_default()
        .into_iter()
        .map(|a| LogAnomaly {
            description: a.description.unwrap_or_default(),
            severity: parse_severity(&a.severity.unwrap_or_default()),
            sample_line: a.sample_line.unwrap_or_default(),
            detector_id: None,
            detector_family: None,
            confidence: None,
        })
        .collect();

    let (start, end) = entry_time_range(entries);

    Ok(LogSummary {
        source_id: source_id.to_string(),
        period_start: start,
        period_end: end,
        total_entries: entries.len(),
        summary_text: analysis
            .summary
            .unwrap_or_else(|| "No summary available".into()),
        error_count: analysis.error_count.unwrap_or(0),
        warning_count: analysis.warning_count.unwrap_or(0),
        key_events: analysis.key_events.unwrap_or_default(),
        anomalies,
    })
}

/// Compute time range from entries
fn entry_time_range(entries: &[LogEntry]) -> (DateTime<Utc>, DateTime<Utc>) {
    if entries.is_empty() {
        let now = Utc::now();
        return (now, now);
    }
    let start = entries
        .iter()
        .map(|e| e.timestamp)
        .min()
        .unwrap_or_else(Utc::now);
    let end = entries
        .iter()
        .map(|e| e.timestamp)
        .max()
        .unwrap_or_else(Utc::now);
    (start, end)
}

#[async_trait]
impl LogAnalyzer for OpenAiAnalyzer {
    async fn summarize(&self, entries: &[LogEntry]) -> Result<LogSummary> {
        if entries.is_empty() {
            log::debug!("OpenAiAnalyzer: no entries to analyze, returning empty summary");
            return Ok(LogSummary {
                source_id: String::new(),
                period_start: Utc::now(),
                period_end: Utc::now(),
                total_entries: 0,
                summary_text: "No log entries to analyze".into(),
                error_count: 0,
                warning_count: 0,
                key_events: Vec::new(),
                anomalies: Vec::new(),
            });
        }

        let prompt = Self::build_prompt(entries);
        let source_id = &entries[0].source_id;

        log::debug!(
            "Sending {} entries to AI API (model: {}, url: {}, prompt_chars: {})",
            entries.len(),
            self.model,
            self.api_url,
            prompt.len()
        );
        log::trace!("Prompt:\n{}", prompt);

        let request_body = serde_json::json!({
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a log analysis assistant. Analyze logs and return structured JSON. Be concise — limit summary to 1-2 sentences, max 5 key events, max 5 anomalies."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": self.max_tokens
        });

        let url = format!("{}/chat/completions", self.api_url.trim_end_matches('/'));
        log::debug!("POST {}", url);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        if let Some(ref key) = self.api_key {
            log::debug!(
                "Using API key: {}...{}",
                &key[..key.len().min(4)],
                &key[key.len().saturating_sub(4)..]
            );
            req = req.header("Authorization", format!("Bearer {}", key));
        } else {
            log::debug!("No API key configured (using keyless access)");
        }

        let response = req
            .json(&request_body)
            .send()
            .await
            .context("Failed to send request to AI API")?;

        let status = response.status();
        log::debug!("AI API response status: {}", status);

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::debug!("AI API error body: {}", body);
            anyhow::bail!("AI API returned status {}: {}", status, body);
        }

        let raw_body = response
            .text()
            .await
            .context("Failed to read AI API response body")?;
        log::debug!("AI API response body ({} bytes)", raw_body.len());
        log::trace!("AI API raw response:\n{}", raw_body);

        let completion: ChatCompletionResponse = serde_json::from_str(&raw_body)
            .context("Failed to parse AI API response as ChatCompletion")?;

        let content = completion
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        log::debug!(
            "LLM content ({} chars): {}",
            content.len(),
            &content[..content.len().min(200)]
        );

        // Extract JSON from response — LLMs often wrap in markdown code fences
        let json_str = extract_json(&content);
        log::debug!("Extracted JSON ({} chars)", json_str.len());

        parse_llm_response(source_id, entries, json_str)
    }
}

/// Fallback local analyzer that uses pattern matching (no AI required)
pub struct PatternAnalyzer;

impl Default for PatternAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self
    }

    fn count_pattern(entries: &[LogEntry], patterns: &[&str]) -> usize {
        entries
            .iter()
            .filter(|e| {
                let lower = e.line.to_lowercase();
                patterns.iter().any(|p| lower.contains(p))
            })
            .count()
    }
}

#[async_trait]
impl LogAnalyzer for PatternAnalyzer {
    async fn summarize(&self, entries: &[LogEntry]) -> Result<LogSummary> {
        if entries.is_empty() {
            log::debug!("PatternAnalyzer: no entries to analyze");
            return Ok(LogSummary {
                source_id: String::new(),
                period_start: Utc::now(),
                period_end: Utc::now(),
                total_entries: 0,
                summary_text: "No log entries to analyze".into(),
                error_count: 0,
                warning_count: 0,
                key_events: Vec::new(),
                anomalies: Vec::new(),
            });
        }

        let source_id = &entries[0].source_id;
        let error_count =
            Self::count_pattern(entries, &["error", "err", "fatal", "panic", "exception"]);
        let warning_count = Self::count_pattern(entries, &["warn", "warning"]);
        let (start, end) = entry_time_range(entries);

        log::debug!(
            "PatternAnalyzer [{}]: {} entries, {} errors, {} warnings",
            source_id,
            entries.len(),
            error_count,
            warning_count
        );

        let mut anomalies = Vec::new();

        // Detect error spikes
        if error_count > entries.len() / 4 {
            log::debug!(
                "Error spike detected: {} errors / {} entries (threshold: >25%)",
                error_count,
                entries.len()
            );
            if let Some(sample) = entries
                .iter()
                .find(|e| e.line.to_lowercase().contains("error"))
            {
                anomalies.push(LogAnomaly {
                    description: format!(
                        "High error rate: {} errors in {} entries",
                        error_count,
                        entries.len()
                    ),
                    severity: AnomalySeverity::High,
                    sample_line: sample.line.clone(),
                    detector_id: None,
                    detector_family: None,
                    confidence: None,
                });
            }
        }

        let summary_text = format!(
            "{} log entries analyzed. {} errors, {} warnings detected.",
            entries.len(),
            error_count,
            warning_count
        );

        Ok(LogSummary {
            source_id: source_id.clone(),
            period_start: start,
            period_end: end,
            total_entries: entries.len(),
            summary_text,
            error_count,
            warning_count,
            key_events: Vec::new(),
            anomalies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_entries(lines: &[&str]) -> Vec<LogEntry> {
        lines
            .iter()
            .map(|line| LogEntry {
                source_id: "test-source".into(),
                timestamp: Utc::now(),
                line: line.to_string(),
                metadata: HashMap::new(),
            })
            .collect()
    }

    #[test]
    fn test_anomaly_severity_display() {
        assert_eq!(AnomalySeverity::Low.to_string(), "Low");
        assert_eq!(AnomalySeverity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), AnomalySeverity::Critical);
        assert_eq!(parse_severity("High"), AnomalySeverity::High);
        assert_eq!(parse_severity("MEDIUM"), AnomalySeverity::Medium);
        assert_eq!(parse_severity("low"), AnomalySeverity::Low);
        assert_eq!(parse_severity("unknown"), AnomalySeverity::Low);
    }

    #[test]
    fn test_build_prompt_contains_log_lines() {
        let entries = make_entries(&["line 1", "line 2"]);
        let prompt = OpenAiAnalyzer::build_prompt(&entries);
        assert!(prompt.contains("line 1"));
        assert!(prompt.contains("line 2"));
        assert!(prompt.contains("JSON"));
    }

    #[test]
    fn test_build_prompt_limits_included_entries() {
        let entries: Vec<LogEntry> = (0..250)
            .map(|i| LogEntry {
                source_id: "test-source".into(),
                timestamp: Utc::now(),
                line: format!("INFO line {}", i),
                metadata: HashMap::new(),
            })
            .collect();

        let prompt = OpenAiAnalyzer::build_prompt(&entries);

        assert!(prompt.contains("- total_entries: 250"));
        assert!(prompt.contains("- included_entries: 200"));
        assert!(prompt.contains("Only 200 of 250 entries are included below"));
        assert!(prompt.contains("INFO line 249"));
        assert!(!prompt.contains("INFO line 0"));
    }

    #[test]
    fn test_select_prompt_entries_preserves_priority_lines() {
        let mut entries: Vec<LogEntry> = (0..260)
            .map(|i| LogEntry {
                source_id: "test-source".into(),
                timestamp: Utc::now(),
                line: format!("INFO line {}", i),
                metadata: HashMap::new(),
            })
            .collect();
        entries[10].line = "ERROR: early failure".into();

        let selected = OpenAiAnalyzer::select_prompt_entries(&entries);

        assert_eq!(selected.len(), 200);
        assert!(selected
            .iter()
            .any(|line| line.contains("ERROR: early failure")));
    }

    #[test]
    fn test_select_prompt_entries_truncates_long_lines() {
        let long_line = "x".repeat(MAX_LINE_CHARS + 50);
        let entries = make_entries(&[&long_line]);

        let selected = OpenAiAnalyzer::select_prompt_entries(&entries);

        assert_eq!(selected.len(), 1);
        assert!(selected[0].ends_with("...[truncated]"));
        assert!(selected[0].len() > MAX_LINE_CHARS);
    }

    #[test]
    fn test_parse_llm_response_valid() {
        let entries = make_entries(&["test line"]);
        let json = r#"{
            "summary": "System running normally",
            "error_count": 0,
            "warning_count": 1,
            "key_events": ["Service started"],
            "anomalies": []
        }"#;

        let summary = parse_llm_response("src-1", &entries, json).unwrap();
        assert_eq!(summary.source_id, "src-1");
        assert_eq!(summary.summary_text, "System running normally");
        assert_eq!(summary.error_count, 0);
        assert_eq!(summary.warning_count, 1);
        assert_eq!(summary.key_events.len(), 1);
        assert!(summary.anomalies.is_empty());
    }

    #[test]
    fn test_parse_llm_response_with_anomalies() {
        let entries = make_entries(&["error: disk full"]);
        let json = r#"{
            "summary": "Disk issue detected",
            "error_count": 1,
            "warning_count": 0,
            "key_events": ["Disk full"],
            "anomalies": [
                {
                    "description": "Disk full errors detected",
                    "severity": "Critical",
                    "sample_line": "error: disk full"
                }
            ]
        }"#;

        let summary = parse_llm_response("src-1", &entries, json).unwrap();
        assert_eq!(summary.anomalies.len(), 1);
        assert_eq!(summary.anomalies[0].severity, AnomalySeverity::Critical);
        assert!(summary.anomalies[0].description.contains("Disk full"));
    }

    #[test]
    fn test_parse_llm_response_partial_fields() {
        let entries = make_entries(&["line"]);
        let json = r#"{"summary": "Minimal response"}"#;

        let summary = parse_llm_response("src-1", &entries, json).unwrap();
        assert_eq!(summary.summary_text, "Minimal response");
        assert_eq!(summary.error_count, 0);
        assert!(summary.anomalies.is_empty());
    }

    #[test]
    fn test_parse_llm_response_invalid_json() {
        let entries = make_entries(&["line"]);
        let result = parse_llm_response("src-1", &entries, "not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_json_plain() {
        let input = r#"{"summary": "ok"}"#;
        assert_eq!(extract_json(input), input);
    }

    #[test]
    fn test_extract_json_markdown_fence() {
        let input = "```json\n{\"summary\": \"ok\"}\n```";
        assert_eq!(extract_json(input), r#"{"summary": "ok"}"#);
    }

    #[test]
    fn test_extract_json_plain_fence() {
        let input = "```\n{\"summary\": \"ok\"}\n```";
        assert_eq!(extract_json(input), r#"{"summary": "ok"}"#);
    }

    #[test]
    fn test_extract_json_with_preamble() {
        let input = "Here is the analysis:\n{\"summary\": \"ok\", \"error_count\": 0}";
        assert_eq!(
            extract_json(input),
            r#"{"summary": "ok", "error_count": 0}"#
        );
    }

    #[test]
    fn test_extract_json_with_trailing_text() {
        let input = "Sure! {\"summary\": \"ok\"} Hope this helps!";
        assert_eq!(extract_json(input), r#"{"summary": "ok"}"#);
    }

    #[test]
    fn test_entry_time_range_empty() {
        let (start, end) = entry_time_range(&[]);
        assert!(end >= start);
    }

    #[test]
    fn test_entry_time_range_multiple() {
        let mut entries = make_entries(&["a", "b"]);
        entries[0].timestamp = Utc::now() - chrono::Duration::hours(1);
        let (start, end) = entry_time_range(&entries);
        assert!(end > start);
    }

    #[tokio::test]
    async fn test_pattern_analyzer_empty() {
        let analyzer = PatternAnalyzer::new();
        let summary = analyzer.summarize(&[]).await.unwrap();
        assert_eq!(summary.total_entries, 0);
        assert!(summary.summary_text.contains("No log entries"));
    }

    #[tokio::test]
    async fn test_pattern_analyzer_counts_errors() {
        let analyzer = PatternAnalyzer::new();
        let entries = make_entries(&[
            "INFO: started",
            "ERROR: connection refused",
            "WARN: disk space low",
            "ERROR: timeout",
        ]);
        let summary = analyzer.summarize(&entries).await.unwrap();
        assert_eq!(summary.total_entries, 4);
        assert_eq!(summary.error_count, 2);
        assert_eq!(summary.warning_count, 1);
    }

    #[tokio::test]
    async fn test_pattern_analyzer_detects_error_spike() {
        let analyzer = PatternAnalyzer::new();
        let entries = make_entries(&[
            "ERROR: fail 1",
            "ERROR: fail 2",
            "ERROR: fail 3",
            "INFO: ok",
        ]);
        let summary = analyzer.summarize(&entries).await.unwrap();
        assert!(!summary.anomalies.is_empty());
        assert_eq!(summary.anomalies[0].severity, AnomalySeverity::High);
    }

    #[tokio::test]
    async fn test_pattern_analyzer_no_anomaly_when_low_errors() {
        let analyzer = PatternAnalyzer::new();
        let entries = make_entries(&[
            "INFO: all good",
            "INFO: running fine",
            "INFO: healthy",
            "ERROR: one blip",
        ]);
        let summary = analyzer.summarize(&entries).await.unwrap();
        assert!(summary.anomalies.is_empty());
    }

    #[test]
    fn test_openai_analyzer_new() {
        let analyzer = OpenAiAnalyzer::new(
            "http://localhost:11434/v1".into(),
            None,
            "llama3".into(),
            300,
            2048,
        );
        assert_eq!(analyzer.api_url, "http://localhost:11434/v1");
        assert!(analyzer.api_key.is_none());
        assert_eq!(analyzer.model, "llama3");
    }

    #[tokio::test]
    async fn test_openai_analyzer_empty_entries() {
        let analyzer = OpenAiAnalyzer::new(
            "http://localhost:11434/v1".into(),
            None,
            "llama3".into(),
            300,
            2048,
        );
        let summary = analyzer.summarize(&[]).await.unwrap();
        assert_eq!(summary.total_entries, 0);
    }

    #[test]
    fn test_log_summary_serialization() {
        let summary = LogSummary {
            source_id: "test".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries: 10,
            summary_text: "All good".into(),
            error_count: 0,
            warning_count: 0,
            key_events: vec!["Started".into()],
            anomalies: vec![LogAnomaly {
                description: "Test anomaly".into(),
                severity: AnomalySeverity::Medium,
                sample_line: "WARN: something".into(),
                detector_id: None,
                detector_family: None,
                confidence: None,
            }],
        };
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: LogSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_entries, 10);
        assert_eq!(deserialized.anomalies[0].severity, AnomalySeverity::Medium);
    }

    #[test]
    fn test_repair_truncated_json_basic() {
        // Simulates a truncated LLM response — missing closing braces
        let truncated = r#"{"summary": "Multiple errors detected", "error_count": 42"#;
        let repaired = repair_truncated_json(truncated).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&repaired).unwrap();
        assert_eq!(parsed["summary"], "Multiple errors detected");
        assert_eq!(parsed["error_count"], 42);
    }

    #[test]
    fn test_repair_truncated_json_with_trailing_comma() {
        let truncated = r#"{"summary": "Test", "error_count": 5, "#;
        let repaired = repair_truncated_json(truncated).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&repaired).unwrap();
        assert_eq!(parsed["summary"], "Test");
        assert_eq!(parsed["error_count"], 5);
    }

    #[test]
    fn test_repair_truncated_json_mid_string() {
        let truncated = r#"{"summary": "Multiple failed connection at"#;
        let repaired = repair_truncated_json(truncated).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&repaired).unwrap();
        // The string value will be truncated but still parseable
        assert!(parsed["summary"].as_str().unwrap().starts_with("Multiple"));
    }

    #[test]
    fn test_repair_truncated_json_with_nested_array() {
        let truncated = r#"{"summary": "Test", "key_events": ["event1", "event2"#;
        let repaired = repair_truncated_json(truncated).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&repaired).unwrap();
        assert_eq!(parsed["key_events"][0], "event1");
        assert_eq!(parsed["key_events"][1], "event2");
    }

    #[test]
    fn test_repair_truncated_json_already_valid() {
        let valid = r#"{"summary": "OK", "error_count": 0}"#;
        assert!(repair_truncated_json(valid).is_none());
    }

    #[test]
    fn test_repair_truncated_json_not_json() {
        assert!(repair_truncated_json("this is not json at all").is_none());
    }
}
