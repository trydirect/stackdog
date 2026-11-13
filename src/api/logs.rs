//! Log sources and summaries API endpoints

use crate::database::connection::DbPool;
use crate::database::repositories::log_sources;
use crate::sniff::discovery::{LogSource, LogSourceType};
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

/// Query parameters for summary filtering
#[derive(Debug, Deserialize)]
pub struct SummaryQuery {
    source_id: Option<String>,
}

/// Request body for adding a custom log source
#[derive(Debug, Deserialize)]
pub struct AddSourceRequest {
    pub path: String,
    pub name: Option<String>,
}

/// List all discovered log sources
///
/// GET /api/logs/sources
pub async fn list_sources(pool: web::Data<DbPool>) -> impl Responder {
    match log_sources::list_log_sources(&pool) {
        Ok(sources) => HttpResponse::Ok().json(sources),
        Err(e) => {
            log::error!("Failed to list log sources: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list log sources"
            }))
        }
    }
}

/// Get a single log source by path
///
/// GET /api/logs/sources/{path}
pub async fn get_source(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    match log_sources::get_log_source_by_path(&pool, &path.into_inner()) {
        Ok(Some(source)) => HttpResponse::Ok().json(source),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Log source not found"
        })),
        Err(e) => {
            log::error!("Failed to get log source: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get log source"
            }))
        }
    }
}

/// Manually add a custom log source
///
/// POST /api/logs/sources
pub async fn add_source(
    pool: web::Data<DbPool>,
    body: web::Json<AddSourceRequest>,
) -> impl Responder {
    let name = body.name.clone().unwrap_or_else(|| body.path.clone());
    let source = LogSource::new(LogSourceType::CustomFile, body.path.clone(), name);

    match log_sources::upsert_log_source(&pool, &source) {
        Ok(_) => HttpResponse::Created().json(source),
        Err(e) => {
            log::error!("Failed to add log source: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add log source"
            }))
        }
    }
}

/// Delete a log source
///
/// DELETE /api/logs/sources/{path}
pub async fn delete_source(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    match log_sources::delete_log_source(&pool, &path.into_inner()) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete log source: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete log source"
            }))
        }
    }
}

/// List AI-generated log summaries
///
/// GET /api/logs/summaries
pub async fn list_summaries(
    pool: web::Data<DbPool>,
    query: web::Query<SummaryQuery>,
) -> impl Responder {
    let source_id = query.source_id.as_deref().unwrap_or("");
    if source_id.is_empty() {
        // List all summaries — check each known source
        match log_sources::list_log_sources(&pool) {
            Ok(sources) => {
                let mut all_summaries = Vec::new();
                for source in &sources {
                    if let Ok(summaries) =
                        log_sources::list_summaries_for_source(&pool, &source.path_or_id)
                    {
                        all_summaries.extend(summaries);
                    }
                }
                HttpResponse::Ok().json(all_summaries)
            }
            Err(e) => {
                log::error!("Failed to list summaries: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to list summaries"
                }))
            }
        }
    } else {
        match log_sources::list_summaries_for_source(&pool, source_id) {
            Ok(summaries) => HttpResponse::Ok().json(summaries),
            Err(e) => {
                log::error!("Failed to list summaries for source: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to list summaries"
                }))
            }
        }
    }
}

/// Configure log API routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/logs")
            .route("/sources", web::get().to(list_sources))
            .route("/sources", web::post().to(add_source))
            .route("/sources/{path:.*}", web::get().to(get_source))
            .route("/sources/{path:.*}", web::delete().to(delete_source))
            .route("/summaries", web::get().to(list_summaries)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};
    use actix_web::{test, App};

    fn setup_pool() -> DbPool {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        pool
    }

    #[actix_rt::test]
    async fn test_list_sources_empty() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/sources")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_rt::test]
    async fn test_add_source() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let body = serde_json::json!({ "path": "/var/log/test.log", "name": "Test Log" });
        let req = test::TestRequest::post()
            .uri("/api/logs/sources")
            .set_json(&body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
    }

    #[actix_rt::test]
    async fn test_add_and_list_sources() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        // Add a source
        let body = serde_json::json!({ "path": "/var/log/app.log" });
        let req = test::TestRequest::post()
            .uri("/api/logs/sources")
            .set_json(&body)
            .to_request();
        test::call_service(&app, req).await;

        // List sources
        let req = test::TestRequest::get()
            .uri("/api/logs/sources")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 1);
    }

    #[actix_rt::test]
    async fn test_get_source_not_found() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/sources/nonexistent")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_get_source_with_full_filesystem_path() {
        let pool = setup_pool();
        let source = LogSource::new(
            LogSourceType::CustomFile,
            "/var/log/app.log".into(),
            "App Log".into(),
        );
        log_sources::upsert_log_source(&pool, &source).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/sources//var/log/app.log")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["path_or_id"], "/var/log/app.log");
    }

    #[actix_rt::test]
    async fn test_delete_source() {
        let pool = setup_pool();

        // Add source directly via repository (avoids route path issues)
        let source = LogSource::new(
            LogSourceType::CustomFile,
            "test-delete.log".into(),
            "Test Delete".into(),
        );
        log_sources::upsert_log_source(&pool, &source).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/api/logs/sources/test-delete.log")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 204);
    }

    #[actix_rt::test]
    async fn test_delete_source_with_full_filesystem_path() {
        let pool = setup_pool();
        let source = LogSource::new(
            LogSourceType::CustomFile,
            "/var/log/app.log".into(),
            "App Log".into(),
        );
        log_sources::upsert_log_source(&pool, &source).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::delete()
            .uri("/api/logs/sources//var/log/app.log")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 204);

        let stored = log_sources::get_log_source_by_path(&pool, "/var/log/app.log").unwrap();
        assert!(stored.is_none());
    }

    #[actix_rt::test]
    async fn test_list_summaries_empty() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/summaries")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_rt::test]
    async fn test_list_summaries_filtered() {
        let pool = setup_pool();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .configure(configure_routes),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/logs/summaries?source_id=test-source")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}
