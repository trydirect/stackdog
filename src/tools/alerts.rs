//! Alert tools — query recent alerts and stats

use crate::database::connection::DbPool;
use crate::database::repositories::alerts::{list_alerts, AlertFilter};

use super::types::{tool_def, ToolDef, ToolResult};

pub fn definitions() -> Vec<ToolDef> {
    vec![tool_def(
        "recent_alerts",
        "Get recent security alerts. Use to check if an issue has already been reported before creating a new alert.",
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max alerts to return (default 10)"
                },
                "severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    "description": "Filter by severity (optional)"
                }
            },
        }),
    )]
}

pub async fn execute_recent_alerts(pool: &DbPool, args: &str) -> ToolResult {
    let (limit, severity) = match serde_json::from_str::<serde_json::Value>(args) {
        Ok(v) => {
            let limit = v["limit"].as_u64().unwrap_or(10) as usize;
            let severity = v["severity"].as_str().map(String::from);
            (limit, severity)
        }
        Err(e) => return ToolResult::error("recent_alerts", &format!("Invalid args: {}", e)),
    };

    let filter = AlertFilter {
        severity,
        status: None,
    };

    let alerts = match list_alerts(pool, filter).await {
        Ok(a) => a,
        Err(e) => return ToolResult::error("recent_alerts", &format!("DB error: {}", e)),
    };

    let recent: Vec<serde_json::Value> = alerts
        .into_iter()
        .take(limit)
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "alert_type": a.alert_type.to_string(),
                "severity": a.severity.to_string(),
                "status": a.status.to_string(),
                "message": a.message,
                "timestamp": a.timestamp,
            })
        })
        .collect();

    ToolResult::success(
        "recent_alerts",
        serde_json::json!({ "alerts": recent, "count": recent.len() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::alert::{AlertSeverity, AlertType};
    use crate::database::connection::{create_pool, init_database};
    use crate::database::models::Alert;
    use crate::database::repositories::alerts::create_alert;

    #[actix_rt::test]
    async fn test_recent_alerts_returns_empty_when_no_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let result = execute_recent_alerts(&pool, r#"{"limit": 5}"#).await;
        assert!(result.content.contains("[]"));
        assert!(result.content.contains(r#""count":0"#));
    }

    #[actix_rt::test]
    async fn test_recent_alerts_returns_created_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert::new(
                AlertType::AnomalyDetected,
                AlertSeverity::Critical,
                "Test alert",
            ),
        )
        .await
        .unwrap();

        let result = execute_recent_alerts(&pool, r#"{"limit": 5}"#).await;
        assert!(result.content.contains("Test alert"));
        assert!(result.content.contains(r#""count":1"#));
    }

    #[actix_rt::test]
    async fn test_recent_alerts_filters_by_severity() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert::new(
                AlertType::AnomalyDetected,
                AlertSeverity::Critical,
                "Critical alert",
            ),
        )
        .await
        .unwrap();
        create_alert(
            &pool,
            Alert::new(AlertType::AnomalyDetected, AlertSeverity::Low, "Low alert"),
        )
        .await
        .unwrap();

        let result = execute_recent_alerts(&pool, r#"{"severity": "Critical"}"#).await;
        assert!(result.content.contains("Critical alert"));
        assert!(!result.content.contains("Low alert"));
    }
}
