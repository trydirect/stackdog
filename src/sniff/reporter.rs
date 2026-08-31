//! Log analysis reporter
//!
//! Converts log summaries and anomalies into alerts, then dispatches
//! them via the existing notification channels.

use std::cell::RefCell;

use crate::alerting::alert::{Alert, AlertSeverity, AlertType};
use crate::alerting::dedup::{AlertDeduplicator, DedupConfig};
use crate::alerting::notifications::{NotificationConfig, NotificationResult};
use crate::database::connection::DbPool;
use crate::database::models::{Alert as StoredAlert, AlertMetadata};
use crate::database::repositories::alerts::create_alert;
use crate::database::repositories::log_sources;
use crate::sniff::analyzer::{AnomalySeverity, LogSummary};
use crate::sniff::discovery::{LogSource, LogSourceType};
use anyhow::Result;

/// Reports log analysis results to alert channels and persists summaries
pub struct Reporter {
    notification_config: NotificationConfig,
    deduplicator: RefCell<AlertDeduplicator>,
}

impl Reporter {
    pub fn new(notification_config: NotificationConfig) -> Self {
        Self {
            notification_config,
            deduplicator: RefCell::new(AlertDeduplicator::new(DedupConfig::default())),
        }
    }

    /// Map anomaly severity to alert severity
    fn map_severity(anomaly_severity: &AnomalySeverity) -> AlertSeverity {
        match anomaly_severity {
            AnomalySeverity::Low => AlertSeverity::Low,
            AnomalySeverity::Medium => AlertSeverity::Medium,
            AnomalySeverity::High => AlertSeverity::High,
            AnomalySeverity::Critical => AlertSeverity::Critical,
        }
    }

    /// Report a log summary: persist to DB and send anomaly alerts
    ///
    /// `source` carries the human-readable identity of the log source. It is
    /// optional because synthetic summaries (file integrity, package audit)
    /// already use a readable `source_id`.
    pub async fn report(
        &self,
        summary: &LogSummary,
        pool: Option<&DbPool>,
        source: Option<&LogSource>,
    ) -> Result<ReportResult> {
        let source_label = describe_source(&summary.source_id, source);
        let mut alerts_sent = 0;

        // Persist summary to database
        if let Some(pool) = pool {
            log::debug!(
                "Persisting summary for source {} to database",
                summary.source_id
            );
            let _ = log_sources::create_log_summary(
                pool,
                log_sources::CreateLogSummaryParams {
                    source_id: &summary.source_id,
                    summary_text: &summary.summary_text,
                    period_start: &summary.period_start.to_rfc3339(),
                    period_end: &summary.period_end.to_rfc3339(),
                    total_entries: summary.total_entries as i64,
                    error_count: summary.error_count as i64,
                    warning_count: summary.warning_count as i64,
                },
            );
        }

        // Generate alerts for anomalies
        for anomaly in &summary.anomalies {
            let alert_severity = Self::map_severity(&anomaly.severity);

            log::debug!(
                "Generating alert: severity={}, description={}",
                anomaly.severity,
                anomaly.description
            );

            let mut message = format!(
                "[Log Sniff] {} — Source: {} | Sample: {}",
                anomaly.description, source_label, anomaly.sample_line
            );
            if let Some(ref action) = anomaly.suggested_action {
                message.push_str(&format!("\nSuggested: {}", action));
            }
            let alert = Alert::new(AlertType::AnomalyDetected, alert_severity, message.clone());

            // Deduplicate by description only (ignore source_id and sample_line
            // which vary across containers and timestamps for the same finding)
            let dedup_key = format!(
                "{}:{:?}:{}",
                "AnomalyDetected", alert_severity, anomaly.description
            );
            if self.deduplicator.borrow_mut().is_duplicate_key(&dedup_key) {
                log::debug!("Suppressing duplicate alert: {}", anomaly.description);
                continue;
            }

            if let Some(pool) = pool {
                // Record the stable identity (path or container ID), not the
                // per-pass UUID in `summary.source_id`, so stored alerts can be
                // joined back to `log_sources.path_or_id`.
                let mut metadata = AlertMetadata::default()
                    .with_source(
                        source
                            .map(|s| s.path_or_id.clone())
                            .unwrap_or_else(|| summary.source_id.clone()),
                    )
                    .with_reason(anomaly.description.clone());
                if let Some(s) = source {
                    metadata.extra.insert("source_name".into(), s.name.clone());
                    metadata
                        .extra
                        .insert("source_type".into(), s.source_type.to_string());
                    if s.source_type == LogSourceType::DockerContainer {
                        metadata = metadata.with_container_id(s.path_or_id.clone());
                    }
                }
                if let Some(detector_id) = &anomaly.detector_id {
                    metadata
                        .extra
                        .insert("detector_id".into(), detector_id.clone());
                }
                if let Some(detector_family) = &anomaly.detector_family {
                    metadata
                        .extra
                        .insert("detector_family".into(), detector_family.clone());
                }
                if let Some(confidence) = anomaly.confidence {
                    metadata
                        .extra
                        .insert("detector_confidence".into(), confidence.to_string());
                }

                create_alert(
                    pool,
                    StoredAlert::new(AlertType::AnomalyDetected, alert_severity, message)
                        .with_metadata(metadata),
                )
                .await?;
            }

            // Route to appropriate notification channels (respecting minimum severity)
            if alert_severity < self.notification_config.minimum_severity() {
                continue;
            }
            let channels = self
                .notification_config
                .configured_channels_for_severity(alert_severity);
            log::debug!("Routing alert to {} notification channels", channels.len());
            for channel in &channels {
                match channel.send(&alert, &self.notification_config).await {
                    Ok(NotificationResult::Success(_)) => alerts_sent += 1,
                    Ok(NotificationResult::Failure(message)) => {
                        log::warn!("Notification channel reported failure: {}", message)
                    }
                    Err(e) => log::warn!("Failed to send notification: {}", e),
                }
            }
        }

        // Log summary to console
        log::info!(
            "📊 Log Summary [{}]: {} entries, {} errors, {} warnings, {} anomalies",
            source_label,
            summary.total_entries,
            summary.error_count,
            summary.warning_count,
            summary.anomalies.len(),
        );

        Ok(ReportResult {
            anomalies_reported: summary.anomalies.len(),
            notifications_sent: alerts_sent,
            summary_persisted: pool.is_some(),
        })
    }
}

/// Render a log source as something a human can act on: a container name, or a
/// file path. Falls back to the raw summary source id when no source is known.
fn describe_source(summary_source_id: &str, source: Option<&LogSource>) -> String {
    match source {
        Some(source) => match source.source_type {
            LogSourceType::DockerContainer => {
                let short_id: String = source.path_or_id.chars().take(12).collect();
                format!("container {} [{}]", source.name, short_id)
            }
            LogSourceType::SystemLog | LogSourceType::CustomFile => {
                format!("file {}", source.path_or_id)
            }
        },
        None => summary_source_id.to_string(),
    }
}

/// Result of a report operation
#[derive(Debug, Clone, Default)]
pub struct ReportResult {
    pub anomalies_reported: usize,
    pub notifications_sent: usize,
    pub summary_persisted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};
    use crate::database::repositories::{list_alerts, AlertFilter};
    use crate::sniff::analyzer::LogAnomaly;
    use chrono::Utc;

    fn make_summary(anomalies: Vec<LogAnomaly>) -> LogSummary {
        LogSummary {
            source_id: "test-source".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries: 100,
            summary_text: "Test summary".into(),
            error_count: 5,
            warning_count: 3,
            key_events: vec!["Service restarted".into()],
            anomalies,
        }
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Low),
            AlertSeverity::Low
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Medium),
            AlertSeverity::Medium
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::High),
            AlertSeverity::High
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Critical),
            AlertSeverity::Critical
        );
    }

    #[tokio::test]
    async fn test_report_no_anomalies() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![]);
        let result = reporter.report(&summary, None, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 0);
        assert_eq!(result.notifications_sent, 0);
        assert!(!result.summary_persisted);
    }

    #[tokio::test]
    async fn test_report_with_anomalies_sends_alerts() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![LogAnomaly {
            description: "High error rate".into(),
            severity: AnomalySeverity::High,
            sample_line: "ERROR: connection failed".into(),
            detector_id: None,
            detector_family: None,
            confidence: None,
            suggested_action: None,
        }]);

        let result = reporter.report(&summary, None, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 1);
        assert_eq!(result.notifications_sent, 1);
    }

    #[tokio::test]
    async fn test_report_persists_to_database() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![]);

        let result = reporter.report(&summary, Some(&pool), None).await.unwrap();
        assert!(result.summary_persisted);

        // Verify summary was stored
        let summaries = log_sources::list_summaries_for_source(&pool, "test-source").unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_entries, 100);
    }

    #[tokio::test]
    async fn test_report_persists_detector_metadata_in_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![LogAnomaly {
            description: "Potential SQL injection probing detected".into(),
            severity: AnomalySeverity::High,
            sample_line: "GET /search?q=UNION%20SELECT".into(),
            detector_id: Some("web.sqli-probe".into()),
            detector_family: Some("Web".into()),
            confidence: Some(84),
            suggested_action: None,
        }]);

        reporter.report(&summary, Some(&pool), None).await.unwrap();

        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        assert_eq!(alerts.len(), 1);
        let metadata = alerts[0].metadata.as_ref().unwrap();
        assert_eq!(metadata.source.as_deref(), Some("test-source"));
        assert_eq!(
            metadata.extra.get("detector_id").map(String::as_str),
            Some("web.sqli-probe")
        );
        assert_eq!(
            metadata.extra.get("detector_family").map(String::as_str),
            Some("Web")
        );
    }

    #[test]
    fn test_describe_source_renders_container_and_file() {
        let container = LogSource::new(
            LogSourceType::DockerContainer,
            "a6f2ec2d90294889".into(),
            "mailer".into(),
        );
        assert_eq!(
            describe_source("ignored", Some(&container)),
            "container mailer [a6f2ec2d9029]"
        );

        let file = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog".into(),
        );
        assert_eq!(
            describe_source("ignored", Some(&file)),
            "file /var/log/syslog"
        );

        assert_eq!(describe_source("file-integrity", None), "file-integrity");
    }

    #[tokio::test]
    async fn test_report_records_stable_source_identity() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let source = LogSource::new(
            LogSourceType::DockerContainer,
            "a6f2ec2d90294889".into(),
            "mailer".into(),
        );
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![LogAnomaly {
            description: "Multiple instances of EmptyEmailBodyError".into(),
            severity: AnomalySeverity::Critical,
            sample_line: "ERROR EmptyEmailBodyError".into(),
            detector_id: None,
            detector_family: None,
            confidence: None,
            suggested_action: None,
        }]);

        reporter
            .report(&summary, Some(&pool), Some(&source))
            .await
            .unwrap();

        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0]
            .message
            .contains("container mailer [a6f2ec2d9029]"));
        let metadata = alerts[0].metadata.as_ref().unwrap();
        assert_eq!(metadata.source.as_deref(), Some("a6f2ec2d90294889"));
        assert_eq!(metadata.container_id.as_deref(), Some("a6f2ec2d90294889"));
        assert_eq!(
            metadata.extra.get("source_name").map(String::as_str),
            Some("mailer")
        );
    }

    #[tokio::test]
    async fn test_report_multiple_anomalies() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![
            LogAnomaly {
                description: "Error spike".into(),
                severity: AnomalySeverity::Critical,
                sample_line: "FATAL: OOM".into(),
                detector_id: None,
                detector_family: None,
                confidence: None,
                suggested_action: None,
            },
            LogAnomaly {
                description: "Unusual pattern".into(),
                severity: AnomalySeverity::Low,
                sample_line: "DEBUG: retry".into(),
                detector_id: None,
                detector_family: None,
                confidence: None,
                suggested_action: None,
            },
        ]);

        let result = reporter.report(&summary, None, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 2);
        assert_eq!(result.notifications_sent, 2);
    }

    #[tokio::test]
    async fn test_reporter_new() {
        let config = NotificationConfig::default();
        let reporter = Reporter::new(config);
        // Just ensure it constructs without error
        let summary = make_summary(vec![]);
        let result = reporter.report(&summary, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_report_does_not_count_delivery_failures_as_sent() {
        let reporter = Reporter::new(
            NotificationConfig::default().with_slack_webhook("http://127.0.0.1:1".into()),
        );
        let summary = make_summary(vec![LogAnomaly {
            description: "High error rate".into(),
            severity: AnomalySeverity::High,
            sample_line: "ERROR: connection failed".into(),
            detector_id: None,
            detector_family: None,
            confidence: None,
            suggested_action: None,
        }]);

        let result = reporter.report(&summary, None, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 1);
        assert_eq!(result.notifications_sent, 1);
    }
}
