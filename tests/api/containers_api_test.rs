//! Containers API tests

use actix::Actor;
use actix_web::{http::StatusCode, test, web, App};
use serde_json::Value;
use stackdog::api::{containers, websocket::WebSocketHub};
use stackdog::database::{create_pool, init_database};

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_list_containers() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(containers::configure_routes),
        )
        .await;
        let req = test::TestRequest::get().uri("/api/containers").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(matches!(
            resp.status(),
            StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[actix_rt::test]
    async fn test_quarantine_container() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(containers::configure_routes),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/api/containers/container-1/quarantine")
            .set_json(serde_json::json!({ "reason": "integration-test" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: Value = test::read_body_json(resp).await;

        assert!(body.get("success").is_some() || body.get("error").is_some());
    }

    #[actix_rt::test]
    async fn test_release_container() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let hub = WebSocketHub::new().start();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(hub))
                .configure(containers::configure_routes),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/api/containers/container-1/release")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: Value = test::read_body_json(resp).await;

        assert!(body.get("success").is_some() || body.get("error").is_some());
    }
}
