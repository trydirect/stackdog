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

use crate::alerting::notifications::NotificationConfig;
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
use anyhow::Result;
use chrono::Utc;
use std::net::Ipv4Addr;

/// Main orchestrator for the sniff command
pub struct SniffOrchestrator {
    config: SniffConfig,
    pool: DbPool,
    detectors: DetectorRegistry,
    reporter: Reporter,
    ip_ban: Option<IpBanEngine>,
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

        Ok(Self {
            config,
            pool,
            detectors: DetectorRegistry::default(),
            reporter,
            ip_ban,
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
                self.report_detector_batch(
                    &mut result,
                    "docker-posture",
                    postures.len(),
                    "Docker posture audit",
                    self.detectors.detect_docker_posture_anomalies(&postures),
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
            let mut summary = analyzer.summarize(&entries).await?;
            let detector_anomalies = self.detectors.detect_log_anomalies(&entries);
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
            let report = self.reporter.report(&summary, Some(&self.pool)).await?;
            result.anomalies_found += report.anomalies_reported;
            if let Some(engine) = &self.ip_ban {
                self.apply_ip_ban(&summary, engine).await?;
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
            log::debug!("Step 7: saving read position ({})", reader.position());
            let _ = log_sources_repo::update_read_position(
                &self.pool,
                reader.source_id(),
                reader.position(),
            );
        }

        Ok(result)
    }

    async fn apply_ip_ban(
        &self,
        summary: &analyzer::LogSummary,
        engine: &IpBanEngine,
    ) -> Result<()> {
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

            for ip in IpBanEngine::extract_ip_candidates(&anomaly.sample_line) {
                if !is_public_routable_ipv4(&ip) {
                    continue;
                }

                engine
                    .record_offense(OffenseInput {
                        ip_address: ip,
                        source_type: "sniff".into(),
                        reason: anomaly.description.clone(),
                        severity,
                        container_id: None,
                        source_path: None,
                        sample_line: Some(anomaly.sample_line.clone()),
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
        let report = self.reporter.report(&summary, Some(&self.pool)).await?;
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
        if matches!(detector_id, "web.login-bruteforce" | "web.path-traversal") {
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
    ]
    .iter()
    .any(|needle| description.contains(needle))
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
            }],
        }
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
            },
        );
        let summary = make_summary(
            "Failed password for root from 95.163.183.214 port 2222 ssh2",
            AnomalySeverity::High,
        );

        orchestrator.apply_ip_ban(&summary, &engine).await.unwrap();

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
            },
        );
        let summary = make_summary(
            "Failed password for root from 95.163.183.215 port 3333 ssh2",
            AnomalySeverity::Critical,
        );

        orchestrator.apply_ip_ban(&summary, &engine).await.unwrap();
        let second_attempt = orchestrator.apply_ip_ban(&summary, &engine).await;

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
            },
        );
        let summary = make_detector_summary(
            "Potential secret leakage detected in 1 log entries",
            "Client 95.163.183.214 saw secret-like output",
            AnomalySeverity::High,
            Some("secrets.log-leakage"),
        );

        orchestrator.apply_ip_ban(&summary, &engine).await.unwrap();

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
            },
        );
        let summary = make_summary(
            "Failed password for root from 127.0.0.1 port 2222 ssh2",
            AnomalySeverity::High,
        );

        orchestrator.apply_ip_ban(&summary, &engine).await.unwrap();

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
