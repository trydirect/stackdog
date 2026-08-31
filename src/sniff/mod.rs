//! Log sniffing module
//!
//! Discovers, reads, analyzes, and optionally consumes logs from
//! Docker containers, system log files, and custom sources.

pub mod analyzer;
pub mod config;
pub mod consumer;
pub mod discovery;
pub mod reader;
pub mod reporter;

use crate::alerting::{notifications::NotificationConfig, AlertSeverity};
use crate::database::connection::{create_pool, init_database, DbPool};
use crate::database::repositories::log_sources as log_sources_repo;
use crate::detectors::DetectorRegistry;
use crate::docker::DockerClient;
use crate::ip_ban::{IpBanConfig, IpBanEngine, OffenseInput};
use crate::sniff::analyzer::{LogAnalyzer, PatternAnalyzer};
use crate::sniff::config::SniffConfig;
use crate::sniff::consumer::LogConsumer;
use crate::sniff::discovery::LogSourceType;
use crate::sniff::reader::{DockerLogReader, FileLogReader, LogReader};
use crate::sniff::reporter::Reporter;
use crate::tools::ToolRegistry;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// Main orchestrator for the sniff command
pub struct SniffOrchestrator {
    config: SniffConfig,
    pool: DbPool,
    detectors: DetectorRegistry,
    reporter: Reporter,
    ip_ban: Option<IpBanEngine>,
    tool_registry: ToolRegistry,
    /// Last AI analysis time per source (prevents re-analyzing every 30s)
    last_ai_analysis: Mutex<HashMap<String, chrono::DateTime<Utc>>>,
}

impl SniffOrchestrator {
    pub fn new(config: SniffConfig) -> Result<Self> {
        let pool = create_pool(&config.database_url)?;
        init_database(&pool)?;

        let mut notification_config = NotificationConfig::from_env();
        if let Some(ref url) = config.slack_webhook {
            notification_config = notification_config.with_slack_webhook(url.clone());
        }
        if let Some(ref url) = config.webhook_url {
            notification_config = notification_config.with_webhook_url(url.clone());
        }
        if let Some(ref host) = config.smtp_host {
            notification_config = notification_config.with_smtp_host(host.clone());
        }
        if let Some(port) = config.smtp_port {
            notification_config = notification_config.with_smtp_port(port);
        }
        if let Some(ref user) = config.smtp_user {
            notification_config = notification_config.with_smtp_user(user.clone());
        }
        if let Some(ref password) = config.smtp_password {
            notification_config = notification_config.with_smtp_password(password.clone());
        }
        if !config.email_recipients.is_empty() {
            notification_config =
                notification_config.with_email_recipients(config.email_recipients.clone());
        }
        let reporter = Reporter::new(notification_config);
        let ip_ban_config = IpBanConfig::from_env();
        let ip_ban = ip_ban_config
            .enabled
            .then(|| IpBanEngine::new(pool.clone(), ip_ban_config));

        let tool_registry = ToolRegistry::new(
            pool.clone(),
            IpBanConfig::from_env(),
            DetectorRegistry::default(),
        );

        Ok(Self {
            config,
            pool,
            detectors: DetectorRegistry::default(),
            reporter,
            ip_ban,
            tool_registry,
            last_ai_analysis: Mutex::new(HashMap::new()),
        })
    }

    /// Create the appropriate AI analyzer based on config
    fn create_analyzer(&self) -> Box<dyn LogAnalyzer> {
        match self.config.ai_provider {
            config::AiProvider::OpenAi => {
                log::debug!(
                    "Creating OpenAI-compatible analyzer (model: {}, url: {})",
                    self.config.ai_model,
                    self.config.ai_api_url
                );
                Box::new(analyzer::OpenAiAnalyzer::new(
                    self.config.ai_api_url.clone(),
                    self.config.ai_api_key.clone(),
                    self.config.ai_model.clone(),
                    self.config.ai_timeout_secs,
                    self.config.ai_max_tokens,
                ))
            }
            config::AiProvider::Candle => {
                log::info!("Using pattern analyzer (Candle backend not yet implemented)");
                Box::new(PatternAnalyzer::new())
            }
        }
    }

    /// Build readers for discovered sources, restoring saved positions from DB
    fn build_readers(&self, sources: &[discovery::LogSource]) -> Vec<Box<dyn LogReader>> {
        sources
            .iter()
            .map(|source| {
                let saved =
                    log_sources_repo::get_log_source_by_path(&self.pool, &source.path_or_id)
                        .ok()
                        .flatten();
                let offset = saved.map(|s| s.last_read_position).unwrap_or(0);

                match source.source_type {
                    LogSourceType::SystemLog | LogSourceType::CustomFile => Box::new(
                        FileLogReader::new(source.id.clone(), source.path_or_id.clone(), offset),
                    )
                        as Box<dyn LogReader>,
                    LogSourceType::DockerContainer => Box::new(DockerLogReader::new(
                        source.id.clone(),
                        source.path_or_id.clone(),
                    )) as Box<dyn LogReader>,
                }
            })
            .collect()
    }

    /// Run a single sniff pass: discover → read → analyze → report → consume
    pub async fn run_once(&self) -> Result<SniffPassResult> {
        let mut result = SniffPassResult::default();

        self.report_detector_batch(
            &mut result,
            "file-integrity",
            self.config.integrity_paths.len(),
            "File integrity monitoring",
            self.detectors
                .detect_file_integrity_anomalies(&self.pool, &self.config.integrity_paths)?,
        )
        .await?;
        self.report_detector_batch(
            &mut result,
            "config-assessment",
            self.config.config_assessment_paths.len(),
            "Configuration assessment",
            self.detectors
                .detect_config_assessment_anomalies(&self.config.config_assessment_paths)?,
        )
        .await?;
        self.report_detector_batch(
            &mut result,
            "package-audit",
            self.config.package_inventory_paths.len(),
            "Package inventory audit",
            self.detectors
                .detect_package_inventory_anomalies(&self.config.package_inventory_paths)?,
        )
        .await?;

        match DockerClient::new().await {
            Ok(docker) => {
                let postures = docker.list_container_postures(true).await?;
                // Update tool registry with all postures (before filtering)
                self.tool_registry.set_postures(postures.clone());
                let filtered: Vec<_> = postures
                    .into_iter()
                    .filter(|p| !self.config.trusted_containers.iter().any(|t| t == &p.name))
                    .collect();
                self.report_detector_batch(
                    &mut result,
                    "docker-posture",
                    filtered.len(),
                    "Docker posture audit",
                    self.detectors.detect_docker_posture_anomalies(&filtered),
                )
                .await?;
            }
            Err(err) => log::debug!("Skipping Docker posture audit: {}", err),
        }

        // 1. Discover sources
        log::debug!("Step 1: discovering log sources...");
        let sources = discovery::discover_all(&self.config.extra_sources).await?;
        result.sources_found = sources.len();
        log::debug!("Discovered {} sources", sources.len());

        // Register sources in DB
        for source in &sources {
            let _ = log_sources_repo::upsert_log_source(&self.pool, source);
        }

        // 2. Build readers and analyzer
        log::debug!("Step 2: building readers and analyzer...");
        let mut readers = self.build_readers(&sources);
        let analyzer = self.create_analyzer();
        let mut consumer = if self.config.consume {
            log::debug!(
                "Consume mode enabled, output: {}",
                self.config.output_dir.display()
            );
            Some(LogConsumer::new(self.config.output_dir.clone())?)
        } else {
            None
        };

        // 3. Process each source
        let reader_count = readers.len();
        for (i, reader) in readers.iter_mut().enumerate() {
            log::debug!(
                "Step 3: reading source {}/{} ({})",
                i + 1,
                reader_count,
                reader.source_id()
            );
            let entries = reader.read_new_entries().await?;
            if entries.is_empty() {
                log::debug!("  No new entries, skipping");
                continue;
            }

            result.total_entries += entries.len();
            log::debug!("  Read {} entries", entries.len());

            // 4. Analyze
            log::debug!("Step 4: analyzing {} entries...", entries.len());

            // Run built-in detectors first (free, local)
            let detector_anomalies = self.detectors.detect_log_anomalies(&entries);
            let has_errors = entries.iter().any(|e| {
                let lower = e.line.to_lowercase();
                lower.contains("error") || lower.contains("fatal") || lower.contains("panic")
            });

            // Skip AI if no errors and no detector findings — use pattern analyzer
            let skip_ai = !has_errors && detector_anomalies.is_empty();

            // Check per-source cooldown (default 5 minutes between AI calls)
            let source_key = reader.source_id().to_string();
            let cooldown_secs = std::env::var("STACKDOG_AI_COOLDOWN_SECS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(300);
            let within_cooldown = {
                let last = self.last_ai_analysis.lock().unwrap();
                last.get(&source_key)
                    .map(|t| (Utc::now() - t).num_seconds() < cooldown_secs)
                    .unwrap_or(false)
            };

            let mut summary = if skip_ai || within_cooldown {
                if within_cooldown {
                    log::debug!("  Source {} within cooldown ({}s), using pattern analyzer", source_key, cooldown_secs);
                } else {
                    log::debug!("  No errors or detector findings, using pattern analyzer");
                }
                analyzer::PatternAnalyzer::new().summarize(&entries).await?
            } else if self.config.ai_tools_enabled {
                // Tool-use path — single call, no fallback to avoid double billing
                match analyzer.summarize_with_tools(&entries, &self.tool_registry).await {
                    Ok(summary) => {
                        self.last_ai_analysis.lock().unwrap().insert(source_key.clone(), Utc::now());
                        summary
                    }
                    Err(err) => {
                        log::warn!(
                            "AI analysis failed for {}: {}. Using pattern analyzer.",
                            reader.source_id(),
                            err
                        );
                        analyzer::PatternAnalyzer::new().summarize(&entries).await?
                    }
                }
            } else {
                match analyzer.summarize(&entries).await {
                    Ok(summary) => {
                        self.last_ai_analysis.lock().unwrap().insert(source_key.clone(), Utc::now());
                        summary
                    }
                    Err(err) => {
                        log::warn!(
                            "AI analysis failed for {}: {}. Using pattern analyzer.",
                            reader.source_id(),
                            err
                        );
                        analyzer::PatternAnalyzer::new().summarize(&entries).await?
                    }
                }
            };
            if !detector_anomalies.is_empty() {
                summary.key_events.extend(
                    detector_anomalies
                        .iter()
                        .take(5)
                        .map(|anomaly| anomaly.description.clone()),
                );
                summary.anomalies.extend(detector_anomalies);
            }
            log::debug!(
                "  Analysis complete: {} errors, {} warnings, {} anomalies",
                summary.error_count,
                summary.warning_count,
                summary.anomalies.len()
            );

            // 5. Report
            log::debug!("Step 5: reporting results...");
            let source = &sources[i];
            let report = self
                .reporter
                .report(&summary, Some(&self.pool), Some(source))
                .await?;
            result.anomalies_found += report.anomalies_reported;
            if let Some(engine) = &self.ip_ban {
                self.apply_ip_ban(&entries, source, &summary, engine)
                    .await?;
            }

            // 6. Consume (if enabled)
            if let Some(ref mut cons) = consumer {
                if i < sources.len() {
                    log::debug!("Step 6: consuming entries...");
                    let source = &sources[i];
                    let consume_result = cons
                        .consume(
                            &entries,
                            &source.name,
                            &source.source_type,
                            &source.path_or_id,
                        )
                        .await?;
                    result.bytes_freed += consume_result.bytes_freed;
                    result.entries_archived += consume_result.entries_archived;
                    log::debug!(
                        "  Consumed: {} archived, {} bytes freed",
                        consume_result.entries_archived,
                        consume_result.bytes_freed
                    );
                }
            }

            // 7. Update read position
            //
            // Keyed by path_or_id, not source_id: `LogSource::id` is a fresh UUID
            // on every discovery pass, so it never matches the stored row and the
            // offset would silently reset to 0 — re-reading the whole file forever.
            log::debug!("Step 7: saving read position ({})", reader.position());
            if let Err(err) = log_sources_repo::update_read_position(
                &self.pool,
                &source.path_or_id,
                reader.position(),
            ) {
                log::warn!(
                    "Failed to save read position for {}: {}",
                    source.path_or_id,
                    err
                );
            }
        }

        Ok(result)
    }

    async fn apply_ip_ban(
        &self,
        entries: &[reader::LogEntry],
        source: &discovery::LogSource,
        summary: &analyzer::LogSummary,
        engine: &IpBanEngine,
    ) -> Result<()> {
        self.apply_auth_log_ip_ban(entries, source, engine).await?;

        for anomaly in &summary.anomalies {
            if !should_auto_ban(anomaly) {
                continue;
            }

            let severity = match anomaly.severity {
                analyzer::AnomalySeverity::Low => crate::alerting::AlertSeverity::Low,
                analyzer::AnomalySeverity::Medium => crate::alerting::AlertSeverity::Medium,
                analyzer::AnomalySeverity::High => crate::alerting::AlertSeverity::High,
                analyzer::AnomalySeverity::Critical => crate::alerting::AlertSeverity::Critical,
            };

            // Try sample_line first, fall back to scanning entries
            let mut ips = IpBanEngine::extract_ip_candidates(&anomaly.sample_line);
            if ips.is_empty() {
                for entry in entries {
                    ips.extend(IpBanEngine::extract_ip_candidates(&entry.line));
                }
                ips.sort();
                ips.dedup();
            }

            for ip in ips {
                let target_ip = resolve_ban_target(&ip, &anomaly.sample_line, engine);
                if !is_public_routable_ipv4(&target_ip) {
                    continue;
                }

                engine
                    .record_offense(OffenseInput {
                        ip_address: target_ip,
                        source_type: "sniff".into(),
                        reason: anomaly.description.clone(),
                        severity,
                        container_id: source_container_id(source),
                        source_path: source_path(source, None),
                        sample_line: Some(anomaly.sample_line.clone()),
                    })
                    .await?;
            }
        }

        Ok(())
    }

    async fn apply_auth_log_ip_ban(
        &self,
        entries: &[reader::LogEntry],
        source: &discovery::LogSource,
        engine: &IpBanEngine,
    ) -> Result<()> {
        for entry in entries {
            let Some((reason, severity)) = ssh_auth_failure_offense(&entry.line) else {
                continue;
            };

            for ip in IpBanEngine::extract_ip_candidates(&entry.line) {
                let target_ip = resolve_ban_target(&ip, &entry.line, engine);
                if !is_public_routable_ipv4(&target_ip) {
                    continue;
                }

                engine
                    .record_offense(OffenseInput {
                        ip_address: target_ip,
                        source_type: "sniff".into(),
                        reason: reason.into(),
                        severity,
                        container_id: source_container_id(source),
                        source_path: source_path(source, Some(entry)),
                        sample_line: Some(entry.line.clone()),
                    })
                    .await?;
            }
        }

        Ok(())
    }

    async fn report_detector_batch(
        &self,
        result: &mut SniffPassResult,
        source_id: &str,
        total_entries: usize,
        label: &str,
        anomalies: Vec<analyzer::LogAnomaly>,
    ) -> Result<()> {
        if anomalies.is_empty() {
            return Ok(());
        }

        let summary = analyzer::LogSummary {
            source_id: source_id.into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries,
            summary_text: format!("{} detected {} anomaly entries", label, anomalies.len()),
            error_count: 0,
            warning_count: 0,
            key_events: anomalies
                .iter()
                .take(5)
                .map(|anomaly| anomaly.description.clone())
                .collect(),
            anomalies,
        };
        let report = self
            .reporter
            .report(&summary, Some(&self.pool), None)
            .await?;
        result.anomalies_found += report.anomalies_reported;
        Ok(())
    }

    /// Run the sniff loop (continuous or one-shot)
    pub async fn run(&self) -> Result<()> {
        log::info!("🔍 Sniff orchestrator started");

        loop {
            match self.run_once().await {
                Ok(result) => {
                    log::info!(
                        "Sniff pass: {} sources, {} entries, {} anomalies, {} bytes freed",
                        result.sources_found,
                        result.total_entries,
                        result.anomalies_found,
                        result.bytes_freed,
                    );
                }
                Err(e) => {
                    log::error!("Sniff pass failed: {}", e);
                }
            }

            if self.config.once {
                log::info!("🏁 One-shot mode: exiting after single pass");
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(self.config.interval_secs)).await;
        }

        Ok(())
    }
}

/// Result of a single sniff pass
#[derive(Debug, Clone, Default)]
pub struct SniffPassResult {
    pub sources_found: usize,
    pub total_entries: usize,
    pub anomalies_found: usize,
    pub bytes_freed: u64,
    pub entries_archived: usize,
}

fn should_auto_ban(anomaly: &analyzer::LogAnomaly) -> bool {
    if let Some(detector_id) = anomaly.detector_id.as_deref() {
        if matches!(
            detector_id,
            "web.login-bruteforce"
                | "web.path-traversal"
                | "web.archive-probe"
                | "web.sqli-probe"
                | "web.webshell-probe"
                | "file.sensitive-access"
                | "cloud.metadata-ssrf"
        ) {
            return true;
        }
    }

    let description = anomaly.description.to_ascii_lowercase();
    [
        "brute-force",
        "failed ssh login",
        "failed login attempts",
        "authentication failures",
        "invalid user",
        "path traversal",
        "credential scanning",
        "sensitive file access",
        "sql injection probing",
        "ssrf",
        "metadata access",
        // AI-generated attack descriptions
        "rejected connection",
        "coordinated attack",
        "possible attack",
        "targeting",
        "probing",
        "scanning",
        "frequent access",
    ]
    .iter()
    .any(|needle| description.contains(needle))
}

/// If `ip` is a trusted proxy, try to extract the real client IP from
/// X-Forwarded-For / X-Real-IP in the log line.  Otherwise return `ip` as-is.
fn resolve_ban_target(ip: &str, line: &str, engine: &IpBanEngine) -> String {
    let Ok(parsed) = ip.parse::<Ipv4Addr>() else {
        return ip.to_string();
    };
    if engine.config().is_trusted_proxy(&parsed) {
        if let Some(real_ip) = IpBanEngine::extract_forwarded_ip(line) {
            log::debug!(
                "Resolved proxied IP {} -> {} via X-Forwarded-For",
                ip,
                real_ip
            );
            return real_ip;
        }
    }
    ip.to_string()
}

fn ssh_auth_failure_offense(line: &str) -> Option<(&'static str, AlertSeverity)> {
    let line = line.to_ascii_lowercase();

    if line.contains("failed password for") {
        return Some(("Failed ssh login", AlertSeverity::High));
    }

    if line.contains("auth fail [preauth]") {
        return Some((
            "SSH authentication failed during preauth",
            AlertSeverity::High,
        ));
    }

    None
}

fn source_container_id(source: &discovery::LogSource) -> Option<String> {
    matches!(
        source.source_type,
        discovery::LogSourceType::DockerContainer
    )
    .then(|| source.path_or_id.clone())
}

fn source_path(source: &discovery::LogSource, entry: Option<&reader::LogEntry>) -> Option<String> {
    entry
        .and_then(|entry| entry.metadata.get("source_path").cloned())
        .or_else(|| {
            matches!(
                source.source_type,
                discovery::LogSourceType::SystemLog | discovery::LogSourceType::CustomFile
            )
            .then(|| source.path_or_id.clone())
        })
}

fn is_public_routable_ipv4(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return false;
    };

    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        || (ip.octets()[0] == 198 && ip.octets()[1] == 18)
        || (ip.octets()[0] == 198 && ip.octets()[1] == 19)
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 2)
        || (ip.octets()[0] == 198 && ip.octets()[1] == 51 && ip.octets()[2] == 100)
        || (ip.octets()[0] == 203 && ip.octets()[1] == 0 && ip.octets()[2] == 113)
        || ip.octets()[0] >= 240)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::repositories::offenses::{active_block_for_ip, find_recent_offenses};
    use crate::database::{list_alerts, AlertFilter};
    use crate::ip_ban::{IpBanConfig, IpBanEngine};
    use crate::sniff::analyzer::{AnomalySeverity, LogAnomaly, LogSummary};
    use chrono::Utc;
    #[cfg(target_os = "linux")]
    use std::process::Command;

    #[cfg(target_os = "linux")]
    fn running_as_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|stdout| stdout.trim() == "0")
            .unwrap_or(false)
    }

    fn memory_sniff_config() -> SniffConfig {
        let mut config = SniffConfig::from_env_and_args(config::SniffArgs {
            once: true,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: Some("candle"),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        config.database_url = ":memory:".into();
        config
    }

    fn make_summary(sample_line: &str, severity: analyzer::AnomalySeverity) -> LogSummary {
        LogSummary {
            source_id: "test-source".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries: 1,
            summary_text: "Suspicious login activity".into(),
            error_count: 1,
            warning_count: 0,
            key_events: vec!["Failed password attempts".into()],
            anomalies: vec![LogAnomaly {
                description: "Repeated failed ssh login".into(),
                severity,
                sample_line: sample_line.into(),
                detector_id: None,
                detector_family: None,
                confidence: None,
                suggested_action: None,
            }],
        }
    }

    fn make_detector_summary(
        description: &str,
        sample_line: &str,
        severity: analyzer::AnomalySeverity,
        detector_id: Option<&str>,
    ) -> LogSummary {
        LogSummary {
            source_id: "test-source".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries: 1,
            summary_text: description.into(),
            error_count: 1,
            warning_count: 0,
            key_events: vec![description.into()],
            anomalies: vec![LogAnomaly {
                description: description.into(),
                severity,
                sample_line: sample_line.into(),
                detector_id: detector_id.map(str::to_string),
                detector_family: None,
                confidence: None,
                suggested_action: None,
            }],
        }
    }

    fn test_log_source() -> discovery::LogSource {
        discovery::LogSource::new(
            discovery::LogSourceType::SystemLog,
            "/var/log/auth.log".into(),
            "auth.log".into(),
        )
    }

    #[test]
    fn test_sniff_pass_result_default() {
        let result = SniffPassResult::default();
        assert_eq!(result.sources_found, 0);
        assert_eq!(result.total_entries, 0);
        assert_eq!(result.anomalies_found, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_should_auto_ban_detector_backed_traversal_probe() {
        let anomaly = LogAnomaly {
            description: "Path traversal probing indicators found in 2 log entries".into(),
            severity: AnomalySeverity::High,
            sample_line: "GET /../../etc/passwd HTTP/1.1".into(),
            detector_id: Some("web.path-traversal".into()),
            detector_family: Some("Web".into()),
            confidence: Some(82),
            suggested_action: None,
        };

        assert!(should_auto_ban(&anomaly));
    }

    #[test]
    fn test_should_not_auto_ban_secret_leakage_alerts() {
        let anomaly = LogAnomaly {
            description: "Potential secret leakage detected in 1 log entries".into(),
            severity: AnomalySeverity::High,
            sample_line: "Authorization: Bearer token".into(),
            detector_id: Some("secrets.log-leakage".into()),
            detector_family: Some("Secrets".into()),
            confidence: Some(92),
            suggested_action: None,
        };

        assert!(!should_auto_ban(&anomaly));
    }

    #[test]
    fn test_is_public_routable_ipv4_skips_private_and_documentation_ranges() {
        assert!(!is_public_routable_ipv4("127.0.0.1"));
        assert!(!is_public_routable_ipv4("10.1.2.3"));
        assert!(!is_public_routable_ipv4("192.0.2.10"));
        assert!(is_public_routable_ipv4("95.163.183.214"));
    }

    #[test]
    fn test_orchestrator_creates_with_memory_db() {
        let mut config = SniffConfig::from_env_and_args(config::SniffArgs {
            once: true,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config);
        assert!(orchestrator.is_ok());
    }

    #[tokio::test]
    async fn test_orchestrator_run_once_with_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, "INFO: service started").unwrap();
            writeln!(f, "ERROR: connection failed").unwrap();
            writeln!(f, "WARN: retry in 5s").unwrap();
        }

        let mut config = SniffConfig::from_env_and_args(config::SniffArgs {
            once: true,
            consume: false,
            output: "./stackdog-logs/",
            sources: Some(&log_path.to_string_lossy()),
            interval: 30,
            ai_provider: Some("candle"),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.sources_found >= 1);
        assert!(result.total_entries >= 3);
    }

    #[tokio::test]
    async fn test_orchestrator_persists_read_position_across_passes() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("position.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, "INFO: service started").unwrap();
            writeln!(f, "ERROR: connection failed").unwrap();
        }
        let path_str = log_path.to_string_lossy().to_string();

        let mut config = SniffConfig::from_env_and_args(config::SniffArgs {
            once: true,
            consume: false,
            output: "./stackdog-logs/",
            sources: Some(&path_str),
            interval: 30,
            ai_provider: Some("candle"),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        orchestrator.run_once().await.unwrap();

        let file_len = std::fs::metadata(&log_path).unwrap().len();
        let saved = log_sources_repo::get_log_source_by_path(&orchestrator.pool, &path_str)
            .unwrap()
            .expect("source should be registered");
        assert_eq!(
            saved.last_read_position, file_len,
            "read position must persist so the next pass does not re-read the file"
        );

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(f, "WARN: retry in 5s").unwrap();
        }

        orchestrator.run_once().await.unwrap();

        let grown_len = std::fs::metadata(&log_path).unwrap().len();
        let saved = log_sources_repo::get_log_source_by_path(&orchestrator.pool, &path_str)
            .unwrap()
            .expect("source should still be registered");
        assert!(grown_len > file_len);
        assert_eq!(saved.last_read_position, grown_len);
    }

    #[tokio::test]
    async fn test_orchestrator_applies_builtin_detectors_to_log_entries() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("attacks.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, r#"GET /search?q=' OR 1=1 -- HTTP/1.1"#).unwrap();
            writeln!(
                f,
                r#"GET /search?q=UNION SELECT password FROM users HTTP/1.1"#
            )
            .unwrap();
            writeln!(f, "sendmail invoked for attachment bytes=2000000").unwrap();
            writeln!(f, "smtp delivery queued bytes=3000000").unwrap();
        }

        let mut config = SniffConfig::from_env_and_args(config::SniffArgs {
            once: true,
            consume: false,
            output: "./stackdog-logs/",
            sources: Some(&log_path.to_string_lossy()),
            interval: 30,
            ai_provider: Some("candle"),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.anomalies_found >= 2);
    }

    #[tokio::test]
    async fn test_apply_auth_log_ip_ban_records_failed_ssh_attempts() {
        use crate::sniff::discovery::{LogSource, LogSourceType};
        use crate::sniff::reader::LogEntry;
        use std::collections::HashMap;

        let orchestrator = SniffOrchestrator::new(memory_sniff_config()).unwrap();
        let engine = IpBanEngine::new(
            orchestrator.pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 10,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/auth.log".into(),
            "auth.log".into(),
        );
        let entries = (0..5)
            .map(|attempt| LogEntry {
                source_id: source.id.clone(),
                timestamp: Utc::now(),
                line: format!(
                    "Apr 18 18:14:{attempt:02} host sshd[1234]: Failed password for invalid user test from 95.163.183.214 port 500{attempt} ssh2"
                ),
                metadata: HashMap::from([(
                    "source_path".into(),
                    "/var/log/auth.log".into(),
                )]),
            })
            .collect::<Vec<_>>();

        orchestrator
            .apply_auth_log_ip_ban(&entries, &source, &engine)
            .await
            .unwrap();

        let offenses = find_recent_offenses(
            &orchestrator.pool,
            "95.163.183.214",
            "sniff",
            Utc::now() - chrono::Duration::minutes(5),
        )
        .unwrap();
        assert_eq!(offenses.len(), 5);
        assert!(offenses.iter().all(|offense| {
            offense
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.source_path.as_deref())
                == Some("/var/log/auth.log")
        }));
    }

    #[tokio::test]
    async fn test_orchestrator_reports_file_integrity_drift() {
        let dir = tempfile::tempdir().unwrap();
        let monitored = dir.path().join("app.env");
        std::fs::write(&monitored, "TOKEN=first").unwrap();

        let mut config = memory_sniff_config();
        config.integrity_paths = vec![monitored.to_string_lossy().into_owned()];

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        orchestrator.run_once().await.unwrap();

        std::fs::write(&monitored, "TOKEN=second").unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.anomalies_found >= 1);

        let alerts = list_alerts(&orchestrator.pool, AlertFilter::default())
            .await
            .unwrap();
        assert!(alerts.iter().any(|alert| {
            alert
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.extra.get("detector_id").map(String::as_str))
                == Some("integrity.file-baseline")
        }));
    }

    #[tokio::test]
    async fn test_orchestrator_reports_config_assessment_findings() {
        let dir = tempfile::tempdir().unwrap();
        let sshd = dir.path().join("sshd_config");
        std::fs::write(&sshd, "PermitRootLogin yes\nPasswordAuthentication yes\n").unwrap();

        let mut config = memory_sniff_config();
        config.config_assessment_paths = vec![sshd.to_string_lossy().into_owned()];

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.anomalies_found >= 1);

        let alerts = list_alerts(&orchestrator.pool, AlertFilter::default())
            .await
            .unwrap();
        assert!(alerts.iter().any(|alert| {
            alert
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.extra.get("detector_id").map(String::as_str))
                == Some("config.ssh-root-login")
        }));
    }

    #[tokio::test]
    async fn test_orchestrator_reports_package_inventory_findings() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        std::fs::write(
            &status,
            "Package: openssl\nVersion: 1.0.2u-1\n\nPackage: bash\nVersion: 4.3-1\n",
        )
        .unwrap();

        let mut config = memory_sniff_config();
        config.package_inventory_paths = vec![status.to_string_lossy().into_owned()];

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.anomalies_found >= 1);

        let alerts = list_alerts(&orchestrator.pool, AlertFilter::default())
            .await
            .unwrap();
        assert!(alerts.iter().any(|alert| {
            alert
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.extra.get("detector_id").map(String::as_str))
                == Some("vuln.legacy-package")
        }));
    }

    #[actix_rt::test]
    async fn test_apply_ip_ban_records_offense_metadata_from_anomaly() {
        let orchestrator = SniffOrchestrator::new(memory_sniff_config()).unwrap();
        let engine = IpBanEngine::new(
            orchestrator.pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 2,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );
        let summary = make_summary(
            "Failed password for root from 95.163.183.214 port 2222 ssh2",
            AnomalySeverity::High,
        );
        let source = test_log_source();

        orchestrator
            .apply_ip_ban(&[], &source, &summary, &engine)
            .await
            .unwrap();

        let offenses = find_recent_offenses(
            &orchestrator.pool,
            "95.163.183.214",
            "sniff",
            Utc::now() - chrono::Duration::minutes(5),
        )
        .unwrap();
        assert_eq!(offenses.len(), 1);
        assert_eq!(offenses[0].reason, "Repeated failed ssh login");
        assert_eq!(
            offenses[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.sample_line.as_deref()),
            Some("Failed password for root from 95.163.183.214 port 2222 ssh2")
        );
        assert!(active_block_for_ip(&orchestrator.pool, "95.163.183.214")
            .unwrap()
            .is_none());
    }

    #[actix_rt::test]
    async fn test_apply_ip_ban_blocks_and_emits_alert_after_repeated_anomalies() {
        let orchestrator = SniffOrchestrator::new(memory_sniff_config()).unwrap();
        let engine = IpBanEngine::new(
            orchestrator.pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 2,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );
        let summary = make_summary(
            "Failed password for root from 95.163.183.215 port 3333 ssh2",
            AnomalySeverity::Critical,
        );
        let source = test_log_source();

        orchestrator
            .apply_ip_ban(&[], &source, &summary, &engine)
            .await
            .unwrap();
        let second_attempt = orchestrator
            .apply_ip_ban(&[], &source, &summary, &engine)
            .await;

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            let error = second_attempt.unwrap_err().to_string();
            assert!(
                error.contains("Operation not permitted")
                    || error.contains("Permission denied")
                    || error.contains("you must be root")
            );
            return;
        }

        second_attempt.unwrap();

        assert!(active_block_for_ip(&orchestrator.pool, "95.163.183.215")
            .unwrap()
            .is_some());

        let alerts = list_alerts(&orchestrator.pool, AlertFilter::default())
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type.to_string(), "ThresholdExceeded");
        assert_eq!(
            alerts[0].message,
            "Blocked IP 95.163.183.215 after repeated sniff offenses"
        );
        assert_eq!(
            alerts[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.source.as_deref()),
            Some("ip_ban")
        );
        assert_eq!(
            alerts[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.reason.as_deref()),
            Some("Repeated failed ssh login")
        );
    }

    #[actix_rt::test]
    async fn test_apply_ip_ban_skips_non_bannable_anomalies() {
        let orchestrator = SniffOrchestrator::new(memory_sniff_config()).unwrap();
        let engine = IpBanEngine::new(
            orchestrator.pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );
        let summary = make_detector_summary(
            "Potential secret leakage detected in 1 log entries",
            "Client 95.163.183.214 saw secret-like output",
            AnomalySeverity::High,
            Some("secrets.log-leakage"),
        );
        let source = test_log_source();

        orchestrator
            .apply_ip_ban(&[], &source, &summary, &engine)
            .await
            .unwrap();

        let offenses = find_recent_offenses(
            &orchestrator.pool,
            "95.163.183.214",
            "sniff",
            Utc::now() - chrono::Duration::minutes(5),
        )
        .unwrap();
        assert!(offenses.is_empty());
    }

    #[actix_rt::test]
    async fn test_apply_ip_ban_skips_loopback_and_private_ips() {
        let orchestrator = SniffOrchestrator::new(memory_sniff_config()).unwrap();
        let engine = IpBanEngine::new(
            orchestrator.pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );
        let summary = make_summary(
            "Failed password for root from 127.0.0.1 port 2222 ssh2",
            AnomalySeverity::High,
        );
        let source = test_log_source();

        orchestrator
            .apply_ip_ban(&[], &source, &summary, &engine)
            .await
            .unwrap();

        let offenses = find_recent_offenses(
            &orchestrator.pool,
            "127.0.0.1",
            "sniff",
            Utc::now() - chrono::Duration::minutes(5),
        )
        .unwrap();
        assert!(offenses.is_empty());
    }
}
