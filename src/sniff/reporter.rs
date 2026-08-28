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
    pub async fn report(
        &self,
        summary: &LogSummary,
        pool: Option<&DbPool>,
    ) -> Result<ReportResult> {
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

            let message = format!(
                "[Log Sniff] {} — Source: {} | Sample: {}",
                anomaly.description, summary.source_id, anomaly.sample_line
            );
            let alert = Alert::new(AlertType::AnomalyDetected, alert_severity, message.clone());

            // Deduplicate: suppress identical alerts within the time window
            if self.deduplicator.borrow_mut().is_duplicate(&alert) {
                log::debug!("Suppressing duplicate alert: {}", anomaly.description);
                continue;
            }

            if let Some(pool) = pool {
                let mut metadata = AlertMetadata::default()
                    .with_source(summary.source_id.clone())
                    .with_reason(anomaly.description.clone());
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
            summary.source_id,
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
        let result = reporter.report(&summary, None).await.unwrap();
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
        }]);

        let result = reporter.report(&summary, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 1);
        assert_eq!(result.notifications_sent, 1);
    }

    #[tokio::test]
    async fn test_report_persists_to_database() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![]);

        let result = reporter.report(&summary, Some(&pool)).await.unwrap();
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
        }]);

        reporter.report(&summary, Some(&pool)).await.unwrap();

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
            },
            LogAnomaly {
                description: "Unusual pattern".into(),
                severity: AnomalySeverity::Low,
                sample_line: "DEBUG: retry".into(),
                detector_id: None,
                detector_family: None,
                confidence: None,
            },
        ]);

        let result = reporter.report(&summary, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 2);
        assert_eq!(result.notifications_sent, 2);
    }

    #[tokio::test]
    async fn test_reporter_new() {
        let config = NotificationConfig::default();
        let reporter = Reporter::new(config);
        // Just ensure it constructs without error
        let summary = make_summary(vec![]);
        let result = reporter.report(&summary, None).await;
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
        }]);

        let result = reporter.report(&summary, None).await.unwrap();
        assert_eq!(result.anomalies_reported, 1);
        assert_eq!(result.notifications_sent, 1);
    }
}
