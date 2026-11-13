//! Security API endpoints

use crate::database::repositories::offenses::{list_offenses, OffenseStatus};
use crate::database::{get_security_status_snapshot, DbPool, SecurityStatusSnapshot};
use crate::ip_ban::{IpBanConfig, IpBanEngine};
use crate::models::api::security::SecurityStatusResponse;
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

/// Upper bound on `?limit=`, so one request cannot pull the whole table.
const MAX_BAN_LIMIT: usize = 500;
const DEFAULT_BAN_LIMIT: usize = 100;

#[derive(Debug, Deserialize)]
pub struct BanQuery {
    /// active, blocked, or released. Case-insensitive; omit for all.
    status: Option<String>,
    limit: Option<usize>,
}

/// Get overall security status
///
/// GET /api/security/status
pub async fn get_security_status(pool: web::Data<DbPool>) -> impl Responder {
    match build_security_status(pool.get_ref()) {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(err) => {
            log::error!("Failed to build security status: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to build security status"
            }))
        }
    }
}

/// List IP ban offenses
///
/// GET /api/security/bans?status=blocked&limit=100
pub async fn list_bans(pool: web::Data<DbPool>, query: web::Query<BanQuery>) -> impl Responder {
    let status = match query.status.as_deref() {
        None => None,
        Some(raw) => match parse_offense_status(raw) {
            Some(status) => Some(status),
            None => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid status. Expected one of: active, blocked, released"
                }))
            }
        },
    };
    let limit = query.limit.unwrap_or(DEFAULT_BAN_LIMIT).min(MAX_BAN_LIMIT);

    match list_offenses(pool.get_ref(), status, limit) {
        Ok(offenses) => HttpResponse::Ok().json(offenses),
        Err(err) => {
            log::error!("Failed to list IP bans: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list IP bans"
            }))
        }
    }
}

/// Release an IP ban ahead of its expiry
///
/// DELETE /api/security/bans/{ip}
pub async fn delete_ban(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    let ip_address = path.into_inner();
    let engine = IpBanEngine::new(pool.get_ref().clone(), IpBanConfig::from_env());

    match engine.unban_ip(&ip_address).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "ip_address": ip_address,
            "status": "Released"
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("No active block for {}", ip_address)
        })),
        Err(err) => {
            log::error!("Failed to release ban for {}: {}", ip_address, err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to release ban"
            }))
        }
    }
}

/// Accept the lowercase spellings a URL query would realistically use.
fn parse_offense_status(raw: &str) -> Option<OffenseStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => Some(OffenseStatus::Active),
        "blocked" => Some(OffenseStatus::Blocked),
        "released" => Some(OffenseStatus::Released),
        _ => None,
    }
}

/// Configure security routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/security")
            .route("/status", web::get().to(get_security_status))
            .route("/bans", web::get().to(list_bans))
            .route("/bans/{ip}", web::delete().to(delete_ban)),
    );
}

pub(crate) fn build_security_status(pool: &DbPool) -> anyhow::Result<SecurityStatusResponse> {
    let snapshot = get_security_status_snapshot(pool)?;
    Ok(SecurityStatusResponse::from_state(
        calculate_overall_score(&snapshot),
        snapshot.active_threats,
        snapshot.quarantined_containers,
        snapshot.alerts_new,
        snapshot.alerts_acknowledged,
    ))
}

fn calculate_overall_score(snapshot: &SecurityStatusSnapshot) -> u32 {
    let penalty = snapshot.severity_breakdown.weighted_penalty()
        + snapshot.quarantined_containers.saturating_mul(25)
        + snapshot.alerts_acknowledged.saturating_mul(2);
    100u32.saturating_sub(penalty.min(100))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
    use crate::database::models::{Alert, AlertMetadata};
    use crate::database::{create_alert, create_pool, init_database};
    use actix_web::{test, App};
    use chrono::Utc;

    fn insert_blocked_offense(pool: &DbPool, ip: &str) {
        use crate::database::repositories::offenses::{
            mark_blocked, record_offense_occurrence, NewIpOffense,
        };

        record_offense_occurrence(
            pool,
            &NewIpOffense {
                id: format!("offense-{ip}"),
                ip_address: ip.to_string(),
                source_type: "sniff".into(),
                container_id: None,
                first_seen: Utc::now(),
                reason: "repeated offenses".into(),
                metadata: None,
            },
            Utc::now() - chrono::Duration::minutes(5),
        )
        .unwrap();
        mark_blocked(
            pool,
            ip,
            "sniff",
            Utc::now() + chrono::Duration::minutes(30),
        )
        .unwrap();
    }

    #[actix_rt::test]
    async fn test_list_bans_returns_offenses() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        insert_blocked_offense(&pool, "46.224.127.228");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/security/bans?status=blocked")
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["ip_address"], "46.224.127.228");
        assert_eq!(body[0]["status"], "Blocked");
    }

    #[actix_rt::test]
    async fn test_list_bans_rejects_unknown_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/security/bans?status=banned")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn test_delete_ban_returns_404_for_unknown_ip() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/api/security/bans/203.0.113.99")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::NOT_FOUND);
    }

    // `#[test]` resolves to actix_web::test here, which requires async.
    #[actix_rt::test]
    async fn test_parse_offense_status_is_case_insensitive() {
        assert_eq!(
            parse_offense_status("Blocked"),
            Some(OffenseStatus::Blocked)
        );
        assert_eq!(
            parse_offense_status(" active "),
            Some(OffenseStatus::Active)
        );
        assert_eq!(
            parse_offense_status("released"),
            Some(OffenseStatus::Released)
        );
        assert_eq!(parse_offense_status("nonsense"), None);
    }

    #[actix_rt::test]
    async fn test_get_security_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let pool_data = web::Data::new(pool);
        let app =
            test::init_service(App::new().app_data(pool_data).configure(configure_routes)).await;

        let req = test::TestRequest::get()
            .uri("/api/security/status")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_build_security_status_uses_alert_data() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        create_alert(
            &pool,
            Alert {
                id: "a1".to_string(),
                alert_type: AlertType::ThreatDetected,
                severity: AlertSeverity::High,
                message: "test".to_string(),
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
                message: "container quarantined".to_string(),
                status: AlertStatus::Acknowledged,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::default().with_container_id("abc123")),
            },
        )
        .await
        .unwrap();

        let status = build_security_status(&pool).unwrap();
        assert_eq!(status.active_threats, 1);
        assert_eq!(status.quarantined_containers, 1);
        assert_eq!(status.alerts_new, 1);
        assert_eq!(status.alerts_acknowledged, 1);
        assert!(status.overall_score < 100);
    }
}
