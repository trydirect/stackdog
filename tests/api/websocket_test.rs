//! WebSocket API tests

use actix::Actor;
use actix_test::start;
use actix_web::{web, App};
use awc::ws::Frame;
use chrono::Utc;
use futures_util::StreamExt;
use serde_json::Value;
use stackdog::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
use stackdog::api::websocket::{self, WebSocketHub};
use stackdog::database::models::Alert;
use stackdog::database::{create_alert, create_pool, init_database};

async fn read_text_frame<S>(framed: &mut S) -> Value
where
    S: futures_util::Stream<Item = Result<Frame, awc::error::WsProtocolError>> + Unpin,
{
    loop {
        match framed
            .next()
            .await
            .expect("expected websocket frame")
            .expect("valid websocket frame")
        {
            Frame::Text(bytes) => {
                return serde_json::from_slice(&bytes).expect("valid websocket json");
            }
            Frame::Ping(_) | Frame::Pong(_) => continue,
            other => panic!("unexpected websocket frame: {other:?}"),
        }
    }
}

fn sample_alert(id: &str) -> Alert {
    Alert {
        id: id.to_string(),
        alert_type: AlertType::ThreatDetected,
        severity: AlertSeverity::High,
        message: format!("alert-{id}"),
        status: AlertStatus::New,
        timestamp: Utc::now().to_rfc3339(),
        metadata: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_websocket_connection_receives_initial_stats_snapshot() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        create_alert(&pool, sample_alert("a1")).await.unwrap();

        let hub = WebSocketHub::new().start();
        let pool_for_app = pool.clone();
        let hub_for_app = hub.clone();
        let server = start(move || {
            App::new()
                .app_data(web::Data::new(pool_for_app.clone()))
                .app_data(web::Data::new(hub_for_app.clone()))
                .configure(websocket::configure_routes)
        });

        let (_response, mut framed) = awc::Client::new()
            .ws(server.url("/ws"))
            .connect()
            .await
            .unwrap();

        let message = read_text_frame(&mut framed).await;
        assert_eq!(message["type"], "stats:updated");
        assert_eq!(message["payload"]["alerts_new"], 1);
    }

    #[actix_rt::test]
    async fn test_websocket_receives_broadcast_events() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let hub = WebSocketHub::new().start();
        let pool_for_app = pool.clone();
        let hub_for_app = hub.clone();
        let server = start(move || {
            App::new()
                .app_data(web::Data::new(pool_for_app.clone()))
                .app_data(web::Data::new(hub_for_app.clone()))
                .configure(websocket::configure_routes)
        });

        let (_response, mut framed) = awc::Client::new()
            .ws(server.url("/ws"))
            .connect()
            .await
            .unwrap();

        let _initial = read_text_frame(&mut framed).await;

        websocket::broadcast_event(
            &hub,
            "alert:created",
            serde_json::json!({ "id": "alert-1" }),
        )
        .await;

        let message = read_text_frame(&mut framed).await;
        assert_eq!(message["type"], "alert:created");
        assert_eq!(message["payload"]["id"], "alert-1");
    }

    #[actix_rt::test]
    async fn test_websocket_receives_broadcast_stats_updates() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let hub = WebSocketHub::new().start();
        let pool_for_app = pool.clone();
        let hub_for_app = hub.clone();
        let server = start(move || {
            App::new()
                .app_data(web::Data::new(pool_for_app.clone()))
                .app_data(web::Data::new(hub_for_app.clone()))
                .configure(websocket::configure_routes)
        });

        let (_response, mut framed) = awc::Client::new()
            .ws(server.url("/ws"))
            .connect()
            .await
            .unwrap();

        let initial = read_text_frame(&mut framed).await;
        assert_eq!(initial["type"], "stats:updated");
        assert_eq!(initial["payload"]["alerts_new"], 0);

        create_alert(&pool, sample_alert("a2")).await.unwrap();
        websocket::broadcast_stats(&hub, &pool).await.unwrap();

        let updated = read_text_frame(&mut framed).await;
        assert_eq!(updated["type"], "stats:updated");
        assert_eq!(updated["payload"]["alerts_new"], 1);
    }
}
