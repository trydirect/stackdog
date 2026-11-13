//! Alerts API tests

use actix::Actor;
use actix_web::{test, web, App};
use serde_json::Value;
use stackdog::alerting::{AlertSeverity, AlertStatus, AlertType};
use stackdog::api::{alerts, websocket::WebSocketHub};
use stackdog::database::models::{Alert, AlertMetadata};
use stackdog::database::{create_alert, create_pool, init_database};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_list_alerts() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let mut alert = Alert::new(
            AlertType::ThreatDetected,
            AlertSeverity::High,
            "Critical test alert",
        )
        .with_metadata(AlertMetadata::default().with_source("tests"));
        alert.status = AlertStatus::New;
        create_alert(&pool, alert).await.unwrap();

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::get().uri("/api/alerts").to_request();
        let body: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["alert_type"], "ThreatDetected");
        assert_eq!(body[0]["severity"], "High");
        assert_eq!(body[0]["status"], "New");
        assert_eq!(body[0]["metadata"]["source"], "tests");
    }

    #[actix_rt::test]
    async fn test_list_alerts_filter_by_severity() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let mut high = Alert::new(AlertType::ThreatDetected, AlertSeverity::High, "High");
        high.status = AlertStatus::New;
        create_alert(&pool, high).await.unwrap();

        let mut low = Alert::new(AlertType::ThreatDetected, AlertSeverity::Low, "Low");
        low.status = AlertStatus::New;
        create_alert(&pool, low).await.unwrap();

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/api/alerts?severity=High")
            .to_request();
        let body: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["message"], "High");
    }

    #[actix_rt::test]
    async fn test_list_alerts_filter_by_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let mut new_alert = Alert::new(AlertType::ThreatDetected, AlertSeverity::High, "New alert");
        new_alert.status = AlertStatus::New;
        create_alert(&pool, new_alert).await.unwrap();

        let mut acknowledged = Alert::new(
            AlertType::RuleViolation,
            AlertSeverity::Medium,
            "Acknowledged alert",
        );
        acknowledged.status = AlertStatus::Acknowledged;
        create_alert(&pool, acknowledged).await.unwrap();

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/api/alerts?status=Acknowledged")
            .to_request();
        let body: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["status"], "Acknowledged");
        assert_eq!(body[0]["message"], "Acknowledged alert");
    }

    #[actix_rt::test]
    async fn test_get_alert_stats() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let statuses = [
            AlertStatus::New,
            AlertStatus::Acknowledged,
            AlertStatus::Resolved,
            AlertStatus::FalsePositive,
        ];
        for status in statuses {
            let mut alert = Alert::new(
                AlertType::ThreatDetected,
                AlertSeverity::High,
                format!("{status}"),
            );
            alert.status = status;
            create_alert(&pool, alert).await.unwrap();
        }

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/api/alerts/stats")
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body["total_count"], 4);
        assert_eq!(body["new_count"], 1);
        assert_eq!(body["acknowledged_count"], 1);
        assert_eq!(body["resolved_count"], 1);
        assert_eq!(body["false_positive_count"], 1);
    }

    #[actix_rt::test]
    async fn test_acknowledge_alert() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let alert = create_alert(
            &pool,
            Alert::new(
                AlertType::ThreatDetected,
                AlertSeverity::High,
                "Needs acknowledgement",
            ),
        )
        .await
        .unwrap();

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::post()
            .uri(&format!("/api/alerts/{}/acknowledge", alert.id))
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        let req = test::TestRequest::get()
            .uri("/api/alerts?status=Acknowledged")
            .to_request();
        let alerts: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body["success"], true);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["id"], alert.id);
    }

    #[actix_rt::test]
    async fn test_resolve_alert() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let alert = create_alert(
            &pool,
            Alert::new(
                AlertType::RuleViolation,
                AlertSeverity::Medium,
                "Needs resolution",
            ),
        )
        .await
        .unwrap();

        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(hub))
                .configure(alerts::configure_routes),
        )
        .await;
        let req = test::TestRequest::post()
            .uri(&format!("/api/alerts/{}/resolve", alert.id))
            .set_json(serde_json::json!({ "note": "resolved in test" }))
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;

        let req = test::TestRequest::get()
            .uri("/api/alerts?status=Resolved")
            .to_request();
        let alerts: Vec<Value> = test::call_and_read_body_json(&app, req).await;

        assert_eq!(body["success"], true);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["id"], alert.id);
    }
}
