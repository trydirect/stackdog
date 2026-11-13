//! Threats API endpoints

use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
use crate::database::models::{Alert, AlertMetadata};
use crate::database::{list_alerts as db_list_alerts, AlertFilter, DbPool};
use crate::models::api::threats::{ThreatResponse, ThreatStatisticsResponse};
use actix_web::{web, HttpResponse, Responder};
use std::collections::HashMap;

/// Get all threats
///
/// GET /api/threats
pub async fn get_threats(pool: web::Data<DbPool>) -> impl Responder {
    match db_list_alerts(&pool, AlertFilter::default()).await {
        Ok(alerts) => {
            let threats = alerts
                .into_iter()
                .filter(|alert| is_threat_alert_type(alert.alert_type))
                .map(|alert| ThreatResponse {
                    id: alert.id,
                    r#type: alert.alert_type.to_string(),
                    severity: alert.severity.to_string(),
                    score: severity_to_score(alert.severity),
                    source: extract_source(alert.metadata.as_ref()),
                    timestamp: alert.timestamp,
                    status: alert.status.to_string(),
                })
                .collect::<Vec<_>>();

            HttpResponse::Ok().json(threats)
        }
        Err(e) => {
            log::error!("Failed to load threats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to load threats"
            }))
        }
    }
}

/// Get threat statistics
///
/// GET /api/threats/statistics
pub async fn get_threat_statistics(pool: web::Data<DbPool>) -> impl Responder {
    match db_list_alerts(&pool, AlertFilter::default()).await {
        Ok(alerts) => {
            let threats = alerts
                .into_iter()
                .filter(|alert| is_threat_alert_type(alert.alert_type))
                .collect::<Vec<_>>();
            let mut by_severity = HashMap::new();
            let mut by_type = HashMap::new();

            for alert in &threats {
                *by_severity.entry(alert.severity.to_string()).or_insert(0) += 1;
                *by_type.entry(alert.alert_type.to_string()).or_insert(0) += 1;
            }

            let stats = ThreatStatisticsResponse {
                total_threats: threats.len() as u32,
                by_severity,
                by_type,
                trend: calculate_trend(&threats),
            };

            HttpResponse::Ok().json(stats)
        }
        Err(e) => {
            log::error!("Failed to load threat statistics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to load threat statistics"
            }))
        }
    }
}

/// Configure threat routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/threats")
            .route("", web::get().to(get_threats))
            .route("/statistics", web::get().to(get_threat_statistics)),
    );
}

fn severity_to_score(severity: AlertSeverity) -> u32 {
    match severity {
        AlertSeverity::Critical => 95,
        AlertSeverity::High => 85,
        AlertSeverity::Medium => 60,
        AlertSeverity::Low => 30,
        _ => 10,
    }
}

fn extract_source(metadata: Option<&AlertMetadata>) -> String {
    metadata
        .and_then(|value| {
            value
                .source
                .as_ref()
                .or(value.container_id.as_ref())
                .or(value.reason.as_ref())
                .cloned()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_threat_alert_type(alert_type: AlertType) -> bool {
    matches!(
        alert_type,
        AlertType::ThreatDetected
            | AlertType::AnomalyDetected
            | AlertType::RuleViolation
            | AlertType::ThresholdExceeded
    )
}

fn calculate_trend(alerts: &[Alert]) -> String {
    let unresolved = alerts
        .iter()
        .filter(|alert| alert.status != AlertStatus::Resolved)
        .count();
    let resolved = alerts
        .iter()
        .filter(|alert| alert.status == AlertStatus::Resolved)
        .count();

    if unresolved > resolved {
        "increasing".to_string()
    } else if resolved > unresolved {
        "decreasing".to_string()
    } else {
        "stable".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_get_threats() {
        let pool = crate::database::create_pool(":memory:").unwrap();
        crate::database::init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/threats").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_get_threat_statistics() {
        let pool = crate::database::create_pool(":memory:").unwrap();
        crate::database::init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/threats/statistics")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
