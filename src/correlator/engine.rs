//! Event correlation engine

use crate::events::security::SecurityEvent;
use anyhow::Result;
use chrono::Duration;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CorrelatedEventGroup {
    pub correlation_key: String,
    pub events: Vec<SecurityEvent>,
}

/// Event correlation engine
pub struct CorrelationEngine {
    window: Duration,
}

impl CorrelationEngine {
    pub fn new() -> Result<Self> {
        Ok(Self {
            window: Duration::minutes(5),
        })
    }

    pub fn correlate(&self, events: &[SecurityEvent]) -> Vec<CorrelatedEventGroup> {
        let mut grouped: HashMap<String, Vec<SecurityEvent>> = HashMap::new();

        for event in events {
            if let Some(key) = self.correlation_key(event) {
                grouped.entry(key).or_default().push(event.clone());
            }
        }

        grouped
            .into_iter()
            .filter_map(|(correlation_key, mut grouped_events)| {
                grouped_events.sort_by_key(SecurityEvent::timestamp);
                let first = grouped_events.first()?.timestamp();
                let last = grouped_events.last()?.timestamp();
                if grouped_events.len() >= 2 && (last - first) <= self.window {
                    Some(CorrelatedEventGroup {
                        correlation_key,
                        events: grouped_events,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn correlation_key(&self, event: &SecurityEvent) -> Option<String> {
        match event {
            SecurityEvent::Syscall(event) => Some(format!("pid:{}", event.pid)),
            SecurityEvent::Container(event) => Some(format!("container:{}", event.container_id)),
            SecurityEvent::Network(event) => event
                .container_id
                .as_ref()
                .map(|container_id| format!("container:{container_id}")),
            SecurityEvent::Alert(event) => event
                .source_event_id
                .as_ref()
                .map(|source_event_id| format!("source:{source_event_id}")),
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::security::{ContainerEvent, ContainerEventType, SecurityEvent};
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::{Duration, Utc};

    #[test]
    fn test_correlates_syscall_events_by_pid_within_window() {
        let engine = CorrelationEngine::new().unwrap();
        let now = Utc::now();
        let events = vec![
            SecurityEvent::Syscall(SyscallEvent::new(4242, 1000, SyscallType::Execve, now)),
            SecurityEvent::Syscall(SyscallEvent::new(
                4242,
                1000,
                SyscallType::Open,
                now + Duration::seconds(10),
            )),
            SecurityEvent::Syscall(SyscallEvent::new(7, 1000, SyscallType::Execve, now)),
        ];

        let groups = engine.correlate(&events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].correlation_key, "pid:4242");
        assert_eq!(groups[0].events.len(), 2);
    }

    #[test]
    fn test_correlates_container_events_by_container_id() {
        let engine = CorrelationEngine::new().unwrap();
        let now = Utc::now();
        let events = vec![
            SecurityEvent::Container(ContainerEvent {
                container_id: "container-1".into(),
                event_type: ContainerEventType::Start,
                timestamp: now,
                details: None,
            }),
            SecurityEvent::Container(ContainerEvent {
                container_id: "container-1".into(),
                event_type: ContainerEventType::Stop,
                timestamp: now + Duration::seconds(30),
                details: Some("manual stop".into()),
            }),
            SecurityEvent::Container(ContainerEvent {
                container_id: "container-2".into(),
                event_type: ContainerEventType::Start,
                timestamp: now,
                details: None,
            }),
        ];

        let groups = engine.correlate(&events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].correlation_key, "container:container-1");
        assert_eq!(groups[0].events.len(), 2);
    }
}
