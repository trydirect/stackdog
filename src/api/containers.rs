//! Containers API endpoints

use crate::api::websocket::{broadcast_event, broadcast_stats, WebSocketHubHandle};
use crate::database::DbPool;
use crate::docker::client::{ContainerInfo, ContainerStats};
use crate::docker::containers::ContainerManager;
use crate::models::api::containers::{
    ContainerResponse, ContainerSecurityStatus as ApiContainerSecurityStatus, NetworkActivity,
};
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

/// Quarantine request
#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub reason: String,
}

/// Get all containers
///
/// GET /api/containers
pub async fn get_containers(pool: web::Data<DbPool>) -> impl Responder {
    // Create container manager
    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "Failed to connect to Docker"
            }));
        }
    };

    match manager.list_containers().await {
        Ok(containers) => {
            let mut response = Vec::with_capacity(containers.len());
            for container in &containers {
                let security = match manager.get_container_security_status(&container.id).await {
                    Ok(status) => status,
                    Err(err) => {
                        log::warn!(
                            "Failed to derive security status for container {}: {}",
                            container.id,
                            err
                        );
                        crate::docker::containers::ContainerSecurityStatus {
                            container_id: container.id.clone(),
                            risk_score: 0,
                            threats: 0,
                            security_state: "Unknown".to_string(),
                        }
                    }
                };

                let stats = match manager.get_container_stats(&container.id).await {
                    Ok(stats) => Some(stats),
                    Err(err) => {
                        log::warn!(
                            "Failed to load runtime stats for container {}: {}",
                            container.id,
                            err
                        );
                        None
                    }
                };

                response.push(to_container_response(container, &security, stats.as_ref()));
            }

            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            log::error!("Failed to list containers: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list containers"
            }))
        }
    }
}

fn to_container_response(
    container: &ContainerInfo,
    security: &crate::docker::containers::ContainerSecurityStatus,
    stats: Option<&ContainerStats>,
) -> ContainerResponse {
    let effective_status = if security.security_state == "Quarantined" {
        "Quarantined".to_string()
    } else {
        container.status.clone()
    };

    ContainerResponse {
        id: container.id.clone(),
        name: container.name.clone(),
        image: container.image.clone(),
        status: effective_status,
        security_status: ApiContainerSecurityStatus {
            state: security.security_state.clone(),
            threats: security.threats,
            vulnerabilities: None,
            last_scan: None,
        },
        risk_score: security.risk_score,
        network_activity: NetworkActivity {
            inbound_connections: None,
            outbound_connections: None,
            blocked_connections: None,
            received_bytes: stats.map(|stats| stats.network_rx),
            transmitted_bytes: stats.map(|stats| stats.network_tx),
            received_packets: stats.map(|stats| stats.network_rx_packets),
            transmitted_packets: stats.map(|stats| stats.network_tx_packets),
            suspicious_activity: security.threats > 0 || security.security_state == "Quarantined",
        },
        created_at: container.created.clone(),
    }
}

/// Quarantine a container
///
/// POST /api/containers/:id/quarantine
pub async fn quarantine_container(
    pool: web::Data<DbPool>,
    hub: web::Data<WebSocketHubHandle>,
    path: web::Path<String>,
    body: web::Json<QuarantineRequest>,
) -> impl Responder {
    let container_id = path.into_inner();
    let reason = body.into_inner().reason;

    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Docker"
            }));
        }
    };

    match manager.quarantine_container(&container_id, &reason).await {
        Ok(()) => {
            broadcast_event(
                hub.get_ref(),
                "container:quarantined",
                serde_json::json!({
                    "container_id": container_id,
                    "reason": reason
                }),
            )
            .await;
            let _ = broadcast_stats(hub.get_ref(), &pool).await;
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Container {} quarantined", container_id)
            }))
        }
        Err(e) => {
            log::error!("Failed to quarantine container: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to quarantine container"
            }))
        }
    }
}

/// Release a container from quarantine
///
/// POST /api/containers/:id/release
pub async fn release_container(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    let container_id = path.into_inner();

    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Docker"
            }));
        }
    };

    match manager.release_container(&container_id).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Container {} released", container_id)
        })),
        Err(e) => {
            log::error!("Failed to release container: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to release container"
            }))
        }
    }
}

/// Configure container routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/containers")
            .route("", web::get().to(get_containers))
            .route("/{id}/quarantine", web::post().to(quarantine_container))
            .route("/{id}/release", web::post().to(release_container)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};
    use crate::docker::client::ContainerStats;
    use actix_web::{test, App};

    fn sample_container() -> ContainerInfo {
        ContainerInfo {
            id: "container-1".into(),
            name: "web".into(),
            image: "nginx:latest".into(),
            status: "Running".into(),
            created: "2026-01-01T00:00:00Z".into(),
            network_settings: std::collections::HashMap::new(),
            labels: std::collections::HashMap::new(),
        }
    }

    fn sample_security() -> crate::docker::containers::ContainerSecurityStatus {
        crate::docker::containers::ContainerSecurityStatus {
            container_id: "container-1".into(),
            risk_score: 42,
            threats: 1,
            security_state: "AtRisk".into(),
        }
    }

    #[actix_rt::test]
    async fn test_to_container_response_uses_real_stats() {
        let response = to_container_response(
            &sample_container(),
            &sample_security(),
            Some(&ContainerStats {
                cpu_percent: 0.0,
                memory_usage: 0,
                memory_limit: 0,
                network_rx: 1024,
                network_tx: 2048,
                network_rx_packets: 5,
                network_tx_packets: 9,
            }),
        );

        assert_eq!(response.security_status.vulnerabilities, None);
        assert_eq!(response.security_status.last_scan, None);
        assert_eq!(response.network_activity.received_bytes, Some(1024));
        assert_eq!(response.network_activity.transmitted_bytes, Some(2048));
        assert_eq!(response.network_activity.received_packets, Some(5));
        assert_eq!(response.network_activity.transmitted_packets, Some(9));
        assert_eq!(response.network_activity.inbound_connections, None);
        assert_eq!(response.network_activity.outbound_connections, None);
    }

    #[actix_rt::test]
    async fn test_to_container_response_leaves_missing_stats_unavailable() {
        let response = to_container_response(&sample_container(), &sample_security(), None);

        assert_eq!(response.network_activity.received_bytes, None);
        assert_eq!(response.network_activity.transmitted_bytes, None);
        assert_eq!(response.network_activity.received_packets, None);
        assert_eq!(response.network_activity.transmitted_packets, None);
        assert_eq!(response.network_activity.blocked_connections, None);
    }

    #[actix_rt::test]
    async fn test_to_container_response_marks_quarantined_status_from_security_state() {
        let response = to_container_response(
            &sample_container(),
            &crate::docker::containers::ContainerSecurityStatus {
                container_id: "container-1".into(),
                risk_score: 88,
                threats: 3,
                security_state: "Quarantined".into(),
            },
            None,
        );

        assert_eq!(response.status, "Quarantined");
        assert_eq!(response.security_status.state, "Quarantined");
        assert!(response.network_activity.suspicious_activity);
    }

    #[actix_rt::test]
    async fn test_get_containers() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let pool_data = web::Data::new(pool);

        let app =
            test::init_service(App::new().app_data(pool_data).configure(configure_routes)).await;

        let req = test::TestRequest::get().uri("/api/containers").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(
            resp.status().is_success()
                || resp.status() == actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
