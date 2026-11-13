//! Docker events collector
//!
//! Streams events from Docker daemon using Bollard

use std::collections::HashMap;

use anyhow::{Context, Result};
use bollard::system::EventsOptions;
use bollard::{models::EventMessageTypeEnum, Docker};
use chrono::{TimeZone, Utc};
use futures_util::stream::StreamExt;

use crate::events::security::{ContainerEvent, ContainerEventType};

/// Docker events collector
pub struct DockerEventsCollector {
    client: Docker,
}

impl DockerEventsCollector {
    pub fn new() -> Result<Self> {
        let client =
            Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;
        Ok(Self { client })
    }

    pub async fn read_events(&self, limit: usize) -> Result<Vec<ContainerEvent>> {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        let mut stream = self.client.events(Some(EventsOptions::<String> {
            since: None,
            until: None,
            filters,
        }));

        let mut events = Vec::new();
        while events.len() < limit {
            let Some(event) = stream.next().await else {
                break;
            };

            let event = event.context("Failed to read Docker event")?;
            if !matches!(event.typ, Some(EventMessageTypeEnum::CONTAINER)) {
                continue;
            }

            if let Some(mapped) = map_container_event(event) {
                events.push(mapped);
            }
        }

        Ok(events)
    }
}

impl Default for DockerEventsCollector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

fn map_container_event(event: bollard::models::EventMessage) -> Option<ContainerEvent> {
    let actor = event.actor?;
    let container_id = actor.id?;
    let action = event.action?;
    let event_type = match action.as_str() {
        "start" => ContainerEventType::Start,
        "stop" | "die" | "kill" => ContainerEventType::Stop,
        "create" => ContainerEventType::Create,
        "destroy" | "remove" => ContainerEventType::Destroy,
        "pause" => ContainerEventType::Pause,
        "unpause" => ContainerEventType::Unpause,
        _ => return None,
    };

    let timestamp = event
        .time
        .and_then(|secs| Utc.timestamp_opt(secs, 0).single())
        .unwrap_or_else(Utc::now);
    let details = actor.attributes.and_then(|attributes| {
        if attributes.is_empty() {
            None
        } else {
            Some(
                attributes
                    .into_iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
    });

    Some(ContainerEvent {
        container_id,
        event_type,
        timestamp,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{EventActor, EventMessage};

    #[test]
    fn test_map_container_start_event() {
        let event = EventMessage {
            typ: Some(EventMessageTypeEnum::CONTAINER),
            action: Some("start".to_string()),
            actor: Some(EventActor {
                id: Some("abc123".to_string()),
                attributes: Some(HashMap::from([(
                    "name".to_string(),
                    "wordpress".to_string(),
                )])),
            }),
            time: Some(1_700_000_000),
            ..Default::default()
        };

        let mapped = map_container_event(event).unwrap();
        assert_eq!(mapped.container_id, "abc123");
        assert_eq!(mapped.event_type, ContainerEventType::Start);
        assert!(mapped
            .details
            .as_deref()
            .unwrap_or_default()
            .contains("name=wordpress"));
    }

    #[test]
    fn test_map_container_ignores_unknown_action() {
        let event = EventMessage {
            typ: Some(EventMessageTypeEnum::CONTAINER),
            action: Some("rename".to_string()),
            actor: Some(EventActor {
                id: Some("abc123".to_string()),
                attributes: None,
            }),
            ..Default::default()
        };

        assert!(map_container_event(event).is_none());
    }
}
