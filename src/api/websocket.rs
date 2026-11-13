//! WebSocket handler for real-time updates.

use std::collections::HashMap;
use std::time::Duration;

use actix::prelude::*;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use serde::Serialize;

use crate::api::security::build_security_status;
use crate::database::DbPool;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize)]
pub struct WsEnvelope<T> {
    pub r#type: String,
    pub payload: T,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

#[derive(Message)]
#[rtype(usize)]
struct Connect {
    addr: Recipient<WsMessage>,
}

#[derive(Message)]
#[rtype(result = "()")]
struct Disconnect {
    id: usize,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct BroadcastMessage {
    pub event_type: String,
    pub payload: serde_json::Value,
}

pub struct WebSocketHub {
    sessions: HashMap<usize, Recipient<WsMessage>>,
    next_id: usize,
}

impl WebSocketHub {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    fn broadcast_json(&self, message: &str) {
        for recipient in self.sessions.values() {
            recipient.do_send(WsMessage(message.to_string()));
        }
    }
}

impl Default for WebSocketHub {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for WebSocketHub {
    type Context = Context<Self>;
}

impl Handler<Connect> for WebSocketHub {
    type Result = usize;

    fn handle(&mut self, msg: Connect, _: &mut Self::Context) -> Self::Result {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(id, msg.addr);
        id
    }
}

impl Handler<Disconnect> for WebSocketHub {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Self::Context) {
        self.sessions.remove(&msg.id);
    }
}

impl Handler<BroadcastMessage> for WebSocketHub {
    type Result = ();

    fn handle(&mut self, msg: BroadcastMessage, _: &mut Self::Context) {
        let envelope = WsEnvelope {
            r#type: msg.event_type,
            payload: msg.payload,
        };
        if let Ok(json) = serde_json::to_string(&envelope) {
            self.broadcast_json(&json);
        }
    }
}

pub type WebSocketHubHandle = Addr<WebSocketHub>;

pub struct WebSocketSession {
    id: usize,
    heartbeat: std::time::Instant,
    hub: WebSocketHubHandle,
    pool: DbPool,
}

impl WebSocketSession {
    fn new(hub: WebSocketHubHandle, pool: DbPool) -> Self {
        Self {
            id: 0,
            heartbeat: std::time::Instant::now(),
            hub,
            pool,
        }
    }

    fn start_heartbeat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |actor, ctx| {
            if std::time::Instant::now().duration_since(actor.heartbeat) > CLIENT_TIMEOUT {
                actor.hub.do_send(Disconnect { id: actor.id });
                ctx.stop();
                return;
            }

            ctx.ping(b"");
        });
    }

    fn send_initial_snapshot(&self, ctx: &mut ws::WebsocketContext<Self>) {
        if let Ok(message) = build_stats_message(&self.pool) {
            ctx.text(message);
        }
    }
}

impl Actor for WebSocketSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.start_heartbeat(ctx);

        let address = ctx.address();
        self.hub
            .send(Connect {
                addr: address.recipient(),
            })
            .into_actor(self)
            .map(|result, actor, ctx| {
                if let Ok(id) = result {
                    actor.id = id;
                    actor.send_initial_snapshot(ctx);
                } else {
                    ctx.stop();
                }
            })
            .wait(ctx);
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        self.hub.do_send(Disconnect { id: self.id });
    }
}

impl Handler<WsMessage> for WebSocketSession {
    type Result = ();

    fn handle(&mut self, msg: WsMessage, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebSocketSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(payload)) => {
                self.heartbeat = std::time::Instant::now();
                ctx.pong(&payload);
            }
            Ok(ws::Message::Pong(_)) => {
                self.heartbeat = std::time::Instant::now();
            }
            Ok(ws::Message::Text(_)) => {}
            Ok(ws::Message::Binary(_)) => {}
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            Ok(ws::Message::Continuation(_)) => {}
            Ok(ws::Message::Nop) => {}
            Err(_) => ctx.stop(),
        }
    }
}

pub async fn websocket_handler(
    req: HttpRequest,
    stream: web::Payload,
    hub: web::Data<WebSocketHubHandle>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, Error> {
    ws::start(
        WebSocketSession::new(hub.get_ref().clone(), pool.get_ref().clone()),
        &req,
        stream,
    )
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/ws", web::get().to(websocket_handler));
}

pub async fn broadcast_event(
    hub: &WebSocketHubHandle,
    event_type: impl Into<String>,
    payload: serde_json::Value,
) {
    hub.do_send(BroadcastMessage {
        event_type: event_type.into(),
        payload,
    });
}

pub async fn broadcast_stats(hub: &WebSocketHubHandle, pool: &DbPool) -> anyhow::Result<()> {
    let message = build_stats_broadcast(pool).await?;
    hub.do_send(message);
    Ok(())
}

pub fn spawn_stats_broadcaster(hub: WebSocketHubHandle, pool: DbPool) {
    actix_rt::spawn(async move {
        let mut interval = actix_rt::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if let Err(err) = broadcast_stats(&hub, &pool).await {
                log::debug!("Failed to broadcast websocket stats: {}", err);
            }
        }
    });
}

async fn build_stats_broadcast(pool: &DbPool) -> anyhow::Result<BroadcastMessage> {
    let status = build_security_status(pool)?;
    Ok(BroadcastMessage {
        event_type: "stats:updated".to_string(),
        payload: serde_json::to_value(status)?,
    })
}

fn build_stats_message(pool: &DbPool) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&WsEnvelope {
        r#type: "stats:updated".to_string(),
        payload: build_security_status(pool)?,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
    use crate::database::models::Alert;
    use crate::database::{create_alert, create_pool, init_database};
    use chrono::Utc;

    #[actix_rt::test]
    async fn test_build_stats_message() {
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

        let message = build_stats_message(&pool).unwrap();
        assert!(message.contains("\"type\":\"stats:updated\""));
        assert!(message.contains("\"alerts_new\":1"));
    }

    #[actix_rt::test]
    async fn test_broadcast_message_serialization() {
        let envelope = WsEnvelope {
            r#type: "alert:created".to_string(),
            payload: serde_json::json!({ "id": "alert-1" }),
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(
            json,
            "{\"type\":\"alert:created\",\"payload\":{\"id\":\"alert-1\"}}"
        );
    }
}
