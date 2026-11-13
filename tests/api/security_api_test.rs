//! Security API tests

use actix_web::{test, web, App};
use serde_json::Value;
use stackdog::alerting::{AlertSeverity, AlertStatus, AlertType};
use stackdog::api::security;
use stackdog::database::models::{Alert, AlertMetadata};
use stackdog::database::{create_alert, create_pool, init_database};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_get_security_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        create_alert(
            &pool,
            Alert::new(
                AlertType::ThreatDetected,
                AlertSeverity::High,
                "Open threat",
            ),
        )
        .await
        .unwrap();
        let mut quarantine = Alert::new(
            AlertType::QuarantineApplied,
            AlertSeverity::High,
            "Container quarantined",
        )
        .with_metadata(AlertMetadata::default().with_container_id("container-1"));
        quarantine.status = AlertStatus::Acknowledged;
        create_alert(&pool, quarantine).await.unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(security::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/security/status")
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body["active_threats"], 1);
        assert_eq!(body["quarantined_containers"], 1);
        assert_eq!(body["alerts_new"], 1);
        assert_eq!(body["alerts_acknowledged"], 1);
        assert!(body["overall_score"].as_u64().unwrap() < 100);
        assert!(body["last_updated"].as_str().is_some());
    }

    #[actix_rt::test]
    async fn test_security_status_format() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(security::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/security/status")
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        for key in [
            "overall_score",
            "active_threats",
            "quarantined_containers",
            "alerts_new",
            "alerts_acknowledged",
            "last_updated",
        ] {
            assert!(body.get(key).is_some(), "missing key {key}");
        }
    }
}
