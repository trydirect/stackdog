//! API module
//!
//! REST API and WebSocket endpoints

pub mod alerts;
pub mod containers;
pub mod logs;
pub mod security;
pub mod threats;
pub mod websocket;

/// Marker struct for module tests
pub struct ApiMarker;

// Re-export route configurators
pub use alerts::configure_routes as configure_alerts_routes;
pub use containers::configure_routes as configure_containers_routes;
pub use logs::configure_routes as configure_logs_routes;
pub use security::configure_routes as configure_security_routes;
pub use threats::configure_routes as configure_threats_routes;
pub use websocket::configure_routes as configure_websocket_routes;

/// Configure all API routes
pub fn configure_all_routes(cfg: &mut actix_web::web::ServiceConfig) {
    configure_security_routes(cfg);
    configure_alerts_routes(cfg);
    configure_containers_routes(cfg);
    configure_threats_routes(cfg);
    configure_websocket_routes(cfg);
    configure_logs_routes(cfg);
}
