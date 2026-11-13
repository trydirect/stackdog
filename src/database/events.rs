//! Security events database operations

use crate::events::security::SecurityEvent;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::{Arc, RwLock};

/// Events database manager
pub struct EventsDb {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
}

impl EventsDb {
    pub fn new() -> Result<Self> {
        Ok(Self {
            events: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub fn insert(&self, event: SecurityEvent) -> Result<()> {
        self.events.write().unwrap().push(event);
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SecurityEvent>> {
        Ok(self.events.read().unwrap().clone())
    }

    pub fn events_since(&self, since: DateTime<Utc>) -> Result<Vec<SecurityEvent>> {
        Ok(self
            .events
            .read()
            .unwrap()
            .iter()
            .filter(|event| event.timestamp() >= since)
            .cloned()
            .collect())
    }

    pub fn events_for_pid(&self, pid: u32) -> Result<Vec<SecurityEvent>> {
        Ok(self
            .events
            .read()
            .unwrap()
            .iter()
            .filter(|event| event.pid() == Some(pid))
            .cloned()
            .collect())
    }

    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.read().unwrap().is_empty()
    }
}

impl Default for EventsDb {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::security::{
        AlertEvent, AlertSeverity, AlertType, ContainerEvent, ContainerEventType,
    };
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::{Duration, Utc};

    #[test]
    fn test_events_db_stores_and_queries_events_since_timestamp() {
        let db = EventsDb::new().unwrap();
        let old_time = Utc::now() - Duration::minutes(10);
        let recent_time = Utc::now();

        db.insert(SecurityEvent::Alert(AlertEvent {
            alert_type: AlertType::ThreatDetected,
            severity: AlertSeverity::High,
            message: "old event".into(),
            timestamp: old_time,
            source_event_id: None,
        }))
        .unwrap();
        db.insert(SecurityEvent::Alert(AlertEvent {
            alert_type: AlertType::AnomalyDetected,
            severity: AlertSeverity::Critical,
            message: "recent event".into(),
            timestamp: recent_time,
            source_event_id: None,
        }))
        .unwrap();

        let recent = db.events_since(Utc::now() - Duration::minutes(1)).unwrap();
        assert_eq!(recent.len(), 1);
        match &recent[0] {
            SecurityEvent::Alert(event) => assert_eq!(event.message, "recent event"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn test_events_db_filters_events_by_pid() {
        let db = EventsDb::new().unwrap();
        assert!(db.is_empty());

        db.insert(SecurityEvent::Syscall(SyscallEvent::new(
            42,
            1000,
            SyscallType::Execve,
            Utc::now(),
        )))
        .unwrap();
        db.insert(SecurityEvent::Container(ContainerEvent {
            container_id: "container-1".into(),
            event_type: ContainerEventType::Start,
            timestamp: Utc::now(),
            details: None,
        }))
        .unwrap();
        db.insert(SecurityEvent::Syscall(SyscallEvent::new(
            7,
            1000,
            SyscallType::Open,
            Utc::now(),
        )))
        .unwrap();

        let pid_events = db.events_for_pid(42).unwrap();
        assert_eq!(pid_events.len(), 1);
        assert_eq!(pid_events[0].pid(), Some(42));
        assert_eq!(db.len(), 3);
        assert!(!db.is_empty());
    }
}
