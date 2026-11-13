//! Threats API tests

use actix_web::{test, web, App};
use serde_json::Value;
use stackdog::alerting::{AlertSeverity, AlertStatus, AlertType};
use stackdog::api::threats;
use stackdog::database::models::{Alert, AlertMetadata};
use stackdog::database::{create_alert, create_pool, init_database};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_list_threats() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        create_alert(
            &pool,
            Alert::new(
                AlertType::ThresholdExceeded,
                AlertSeverity::Critical,
                "Blocked IP",
            )
            .with_metadata(AlertMetadata::default().with_source("ip_ban")),
        )
        .await
        .unwrap();
        create_alert(
            &pool,
            Alert::new(AlertType::SystemEvent, AlertSeverity::Info, "Ignore me"),
        )
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(threats::configure_routes),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/threats").to_request();
        let body: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["type"], "ThresholdExceeded");
        assert_eq!(body[0]["severity"], "Critical");
        assert_eq!(body[0]["score"], 95);
        assert_eq!(body[0]["source"], "ip_ban");
    }

    #[actix_rt::test]
    async fn test_get_threat_statistics() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let mut unresolved = Alert::new(
            AlertType::ThreatDetected,
            AlertSeverity::High,
            "Open threat",
        );
        unresolved.status = AlertStatus::New;
        create_alert(&pool, unresolved).await.unwrap();

        let mut resolved = Alert::new(
            AlertType::RuleViolation,
            AlertSeverity::Medium,
            "Resolved threat",
        );
        resolved.status = AlertStatus::Resolved;
        create_alert(&pool, resolved).await.unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(threats::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/threats/statistics")
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body["total_threats"], 2);
        assert_eq!(body["by_severity"]["High"], 1);
        assert_eq!(body["by_severity"]["Medium"], 1);
        assert_eq!(body["by_type"]["ThreatDetected"], 1);
        assert_eq!(body["by_type"]["RuleViolation"], 1);
        assert_eq!(body["trend"], "stable");
    }

    #[actix_rt::test]
    async fn test_statistics_format() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(threats::configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/threats/statistics")
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        for key in ["total_threats", "by_severity", "by_type", "trend"] {
            assert!(body.get(key).is_some(), "missing key {key}");
        }
    }
}
