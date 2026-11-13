//! Alert repository using rusqlite

use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
use crate::database::connection::DbPool;
use crate::database::models::{Alert, AlertMetadata};
use anyhow::Result;
use rusqlite::params;
use rusqlite::types::Type;

/// Alert filter
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
}

/// Alert statistics
#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub total_count: i64,
    pub new_count: i64,
    pub acknowledged_count: i64,
    pub resolved_count: i64,
    pub false_positive_count: i64,
}

/// Severity breakdown for open security alerts.
#[derive(Debug, Clone, Default)]
pub struct SeverityBreakdown {
    pub info_count: u32,
    pub low_count: u32,
    pub medium_count: u32,
    pub high_count: u32,
    pub critical_count: u32,
}

impl SeverityBreakdown {
    pub fn weighted_penalty(&self) -> u32 {
        self.info_count
            + self.low_count.saturating_mul(4)
            + self.medium_count.saturating_mul(10)
            + self.high_count.saturating_mul(20)
            + self.critical_count.saturating_mul(35)
    }
}

/// Snapshot of current security status derived from persisted alerts.
#[derive(Debug, Clone, Default)]
pub struct SecurityStatusSnapshot {
    pub alerts_new: u32,
    pub alerts_acknowledged: u32,
    pub active_threats: u32,
    pub quarantined_containers: u32,
    pub severity_breakdown: SeverityBreakdown,
}

/// Alert summary for a single container.
#[derive(Debug, Clone, Default)]
pub struct ContainerAlertSummary {
    pub active_threats: u32,
    pub quarantined: bool,
    pub severity_breakdown: SeverityBreakdown,
    pub last_alert_at: Option<String>,
}

impl ContainerAlertSummary {
    pub fn risk_score(&self) -> u32 {
        let base = self.severity_breakdown.weighted_penalty();
        let quarantine_penalty = if self.quarantined { 25 } else { 0 };
        (base + quarantine_penalty).min(100)
    }

    pub fn security_state(&self) -> &'static str {
        if self.quarantined {
            "Quarantined"
        } else if self.active_threats > 0 {
            "AtRisk"
        } else {
            "Secure"
        }
    }
}

fn map_alert_row(row: &rusqlite::Row) -> Result<Alert, rusqlite::Error> {
    let alert_type = parse_alert_type(row.get::<_, String>(1)?, 1)?;
    let severity = parse_alert_severity(row.get::<_, String>(2)?, 2)?;
    let status = parse_alert_status(row.get::<_, String>(4)?, 4)?;
    let metadata = row
        .get::<_, Option<String>>(6)?
        .and_then(|raw| AlertMetadata::from_storage(&raw));

    Ok(Alert {
        id: row.get(0)?,
        alert_type,
        severity,
        message: row.get(3)?,
        status,
        timestamp: row.get(5)?,
        metadata,
    })
}

fn parse_alert_type(value: String, column_index: usize) -> Result<AlertType, rusqlite::Error> {
    value.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column_index,
            Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    })
}

fn parse_alert_severity(
    value: String,
    column_index: usize,
) -> Result<AlertSeverity, rusqlite::Error> {
    value.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column_index,
            Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    })
}

fn parse_alert_status(value: String, column_index: usize) -> Result<AlertStatus, rusqlite::Error> {
    value.parse().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column_index,
            Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    })
}

fn serialize_metadata(metadata: Option<&AlertMetadata>) -> Result<Option<String>> {
    match metadata {
        Some(metadata) if !metadata.is_empty() => Ok(Some(serde_json::to_string(metadata)?)),
        _ => Ok(None),
    }
}

/// Create a new alert
pub async fn create_alert(pool: &DbPool, alert: Alert) -> Result<Alert> {
    let conn = pool.get()?;
    let metadata = serialize_metadata(alert.metadata.as_ref())?;

    conn.execute(
        "INSERT INTO alerts (id, alert_type, severity, message, status, timestamp, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &alert.id,
            alert.alert_type.to_string(),
            alert.severity.to_string(),
            &alert.message,
            alert.status.to_string(),
            &alert.timestamp,
            metadata
        ],
    )?;

    Ok(alert)
}

/// List alerts with filter
pub async fn list_alerts(pool: &DbPool, filter: AlertFilter) -> Result<Vec<Alert>> {
    let conn = pool.get()?;

    let mut alerts = Vec::new();

    match (&filter.severity, &filter.status) {
        (Some(severity), Some(status)) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE severity = ?1 AND status = ?2 ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map(params![severity, status], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (Some(severity), None) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE severity = ?1 ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map(params![severity], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (None, Some(status)) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts WHERE status = ?1 ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map(params![status], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
        (None, None) => {
            let mut stmt = conn.prepare(
                "SELECT id, alert_type, severity, message, status, timestamp, metadata 
                 FROM alerts ORDER BY timestamp DESC",
            )?;
            let rows = stmt.query_map([], map_alert_row)?;
            for row in rows {
                alerts.push(row?);
            }
        }
    }

    Ok(alerts)
}

/// Get alert by ID
pub async fn get_alert(pool: &DbPool, alert_id: &str) -> Result<Option<Alert>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT id, alert_type, severity, message, status, timestamp, metadata 
         FROM alerts WHERE id = ?",
    )?;

    let result = stmt.query_row(params![alert_id], map_alert_row);

    match result {
        Ok(alert) => Ok(Some(alert)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Database error: {}", e)),
    }
}

/// Update alert status
pub async fn update_alert_status(pool: &DbPool, alert_id: &str, status: &str) -> Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "UPDATE alerts SET status = ?1 WHERE id = ?2",
        params![status, alert_id],
    )?;

    Ok(())
}

/// Get alert statistics
pub async fn get_alert_stats(pool: &DbPool) -> Result<AlertStats> {
    let conn = pool.get()?;

    let total: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0))?;
    let new: i64 = conn.query_row(
        "SELECT COUNT(*) FROM alerts WHERE status = 'New'",
        [],
        |row| row.get(0),
    )?;
    let ack: i64 = conn.query_row(
        "SELECT COUNT(*) FROM alerts WHERE status = 'Acknowledged'",
        [],
        |row| row.get(0),
    )?;
    let resolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM alerts WHERE status = 'Resolved'",
        [],
        |row| row.get(0),
    )?;
    let false_positive: i64 = conn.query_row(
        "SELECT COUNT(*) FROM alerts WHERE status = 'FalsePositive'",
        [],
        |row| row.get(0),
    )?;

    Ok(AlertStats {
        total_count: total,
        new_count: new,
        acknowledged_count: ack,
        resolved_count: resolved,
        false_positive_count: false_positive,
    })
}

/// Get a live security status snapshot from persisted alerts.
pub fn get_security_status_snapshot(pool: &DbPool) -> Result<SecurityStatusSnapshot> {
    let conn = pool.get()?;
    let snapshot = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status = 'Acknowledged' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                              THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved' AND alert_type = 'QuarantineApplied' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               AND severity = 'Info'
                              THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               AND severity = 'Low'
                              THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               AND severity = 'Medium'
                              THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               AND severity = 'High'
                              THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               AND severity = 'Critical'
                              THEN 1 ELSE 0 END), 0)
         FROM alerts",
        [],
        |row| {
            Ok(SecurityStatusSnapshot {
                alerts_new: row.get::<_, i64>(0)?.max(0) as u32,
                alerts_acknowledged: row.get::<_, i64>(1)?.max(0) as u32,
                active_threats: row.get::<_, i64>(2)?.max(0) as u32,
                quarantined_containers: row.get::<_, i64>(3)?.max(0) as u32,
                severity_breakdown: SeverityBreakdown {
                    info_count: row.get::<_, i64>(4)?.max(0) as u32,
                    low_count: row.get::<_, i64>(5)?.max(0) as u32,
                    medium_count: row.get::<_, i64>(6)?.max(0) as u32,
                    high_count: row.get::<_, i64>(7)?.max(0) as u32,
                    critical_count: row.get::<_, i64>(8)?.max(0) as u32,
                },
            })
        },
    )?;

    Ok(snapshot)
}

/// Get alert-derived security summary for a specific container.
pub fn get_container_alert_summary(
    pool: &DbPool,
    container_id: &str,
) -> Result<ContainerAlertSummary> {
    let conn = pool.get()?;
    let legacy_metadata = format!("container_id={container_id}");
    let metadata_pattern = format!("%{legacy_metadata}%");
    let summary = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND alert_type IN ('ThreatDetected', 'AnomalyDetected', 'RuleViolation', 'ThresholdExceeded')
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND alert_type = 'QuarantineApplied'
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND severity = 'Info'
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND severity = 'Low'
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND severity = 'Medium'
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND severity = 'High'
                               THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status != 'Resolved'
                               AND (
                                   (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                                   OR metadata = ?2
                                   OR metadata LIKE ?3
                               )
                                AND severity = 'Critical'
                               THEN 1 ELSE 0 END), 0),
            MAX(CASE WHEN (
                           (json_valid(metadata) AND json_extract(metadata, '$.container_id') = ?1)
                           OR metadata = ?2
                           OR metadata LIKE ?3
                         ) THEN timestamp ELSE NULL END)
         FROM alerts",
        params![container_id, legacy_metadata, metadata_pattern],
        |row| {
            Ok(ContainerAlertSummary {
                active_threats: row.get::<_, i64>(0)?.max(0) as u32,
                quarantined: row.get::<_, i64>(1)?.max(0) > 0,
                severity_breakdown: SeverityBreakdown {
                    info_count: row.get::<_, i64>(2)?.max(0) as u32,
                    low_count: row.get::<_, i64>(3)?.max(0) as u32,
                    medium_count: row.get::<_, i64>(4)?.max(0) as u32,
                    high_count: row.get::<_, i64>(5)?.max(0) as u32,
                    critical_count: row.get::<_, i64>(6)?.max(0) as u32,
                },
                last_alert_at: row.get(7)?,
            })
        },
    )?;

    Ok(summary)
}

/// Create a sample alert (for testing)
pub fn create_sample_alert() -> Alert {
    Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Suspicious activity detected",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::create_pool;
    use crate::database::connection::init_database;
    use chrono::Utc;

    #[actix_rt::test]
    async fn test_create_and_list_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let alert = create_sample_alert();
        let result = create_alert(&pool, alert.clone()).await;
        assert!(result.is_ok());

        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        assert_eq!(alerts.len(), 1);
    }

    #[actix_rt::test]
    async fn test_update_alert_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let alert = create_sample_alert();
        create_alert(&pool, alert.clone()).await.unwrap();

        update_alert_status(&pool, &alert.id, "Acknowledged")
            .await
            .unwrap();

        let updated = get_alert(&pool, &alert.id).await.unwrap().unwrap();
        assert_eq!(updated.status, AlertStatus::Acknowledged);
    }

    #[actix_rt::test]
    async fn test_get_alert_stats() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        // Create some alerts
        for _ in 0..3 {
            create_alert(&pool, create_sample_alert()).await.unwrap();
        }

        let stats = get_alert_stats(&pool).await.unwrap();
        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.new_count, 3);
    }

    #[actix_rt::test]
    async fn test_get_security_status_snapshot() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert {
                id: "a1".to_string(),
                alert_type: AlertType::ThreatDetected,
                severity: AlertSeverity::Critical,
                message: "critical".to_string(),
                status: AlertStatus::New,
                timestamp: Utc::now().to_rfc3339(),
                metadata: None,
            },
        )
        .await
        .unwrap();
        create_alert(
            &pool,
            Alert {
                id: "a2".to_string(),
                alert_type: AlertType::QuarantineApplied,
                severity: AlertSeverity::High,
                message: "q".to_string(),
                status: AlertStatus::Acknowledged,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::default().with_container_id("abc123")),
            },
        )
        .await
        .unwrap();

        let snapshot = get_security_status_snapshot(&pool).unwrap();
        assert_eq!(snapshot.alerts_new, 1);
        assert_eq!(snapshot.alerts_acknowledged, 1);
        assert_eq!(snapshot.active_threats, 1);
        assert_eq!(snapshot.quarantined_containers, 1);
        assert_eq!(snapshot.severity_breakdown.critical_count, 1);
    }

    #[actix_rt::test]
    async fn test_get_container_alert_summary() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert {
                id: "a1".to_string(),
                alert_type: AlertType::ThreatDetected,
                severity: AlertSeverity::High,
                message: "threat".to_string(),
                status: AlertStatus::New,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::default().with_container_id("abc123")),
            },
        )
        .await
        .unwrap();
        create_alert(
            &pool,
            Alert {
                id: "a2".to_string(),
                alert_type: AlertType::QuarantineApplied,
                severity: AlertSeverity::High,
                message: "quarantine".to_string(),
                status: AlertStatus::New,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::default().with_container_id("abc123")),
            },
        )
        .await
        .unwrap();

        let summary = get_container_alert_summary(&pool, "abc123").unwrap();
        assert_eq!(summary.active_threats, 1);
        assert!(summary.quarantined);
        assert_eq!(summary.security_state(), "Quarantined");
        assert!(summary.risk_score() > 0);
    }

    #[actix_rt::test]
    async fn test_get_container_alert_summary_supports_legacy_metadata() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert {
                id: "legacy-a1".to_string(),
                alert_type: AlertType::ThreatDetected,
                severity: AlertSeverity::High,
                message: "legacy threat".to_string(),
                status: AlertStatus::New,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::from_storage("container_id=legacy123").unwrap()),
            },
        )
        .await
        .unwrap();

        let summary = get_container_alert_summary(&pool, "legacy123").unwrap();
        assert_eq!(summary.active_threats, 1);
    }
}
