//! Event stream types
//!
//! Provides event batch, filter, and iterator types for streaming operations

use crate::events::security::SecurityEvent;
use crate::events::syscall::SyscallType;
use chrono::{DateTime, Utc};

/// A batch of security events for bulk operations
#[derive(Debug, Clone, Default)]
pub struct EventBatch {
    events: Vec<SecurityEvent>,
}

impl EventBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Create a batch with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
        }
    }

    /// Add an event to the batch
    pub fn add(&mut self, event: SecurityEvent) {
        self.events.push(event);
    }

    /// Get the number of events in the batch
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get events in the batch
    pub fn events(&self) -> &[SecurityEvent] {
        &self.events
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Iterate over events
    pub fn iter(&self) -> impl Iterator<Item = &SecurityEvent> {
        self.events.iter()
    }
}

impl From<Vec<SecurityEvent>> for EventBatch {
    fn from(events: Vec<SecurityEvent>) -> Self {
        Self { events }
    }
}

impl IntoIterator for EventBatch {
    type Item = SecurityEvent;
    type IntoIter = std::vec::IntoIter<SecurityEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}

/// Filter for querying events
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    syscall_type: Option<SyscallType>,
    pid: Option<u32>,
    uid: Option<u32>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
}

impl EventFilter {
    /// Create a new filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by syscall type
    pub fn with_syscall_type(mut self, syscall_type: SyscallType) -> Self {
        self.syscall_type = Some(syscall_type);
        self
    }

    /// Filter by PID
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Filter by UID
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Filter by time range
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Check if an event matches this filter
    pub fn matches(&self, event: &SecurityEvent) -> bool {
        // Check syscall type
        if let Some(filter_type) = &self.syscall_type {
            if let SecurityEvent::Syscall(syscall_event) = event {
                if &syscall_event.syscall_type != filter_type {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check PID
        if let Some(filter_pid) = self.pid {
            if let Some(event_pid) = event.pid() {
                if event_pid != filter_pid {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check UID
        if let Some(filter_uid) = self.uid {
            if let Some(event_uid) = event.uid() {
                if event_uid != filter_uid {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check time range
        let event_time = event.timestamp();
        if let Some(start) = self.start_time {
            if event_time < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if event_time > end {
                return false;
            }
        }

        true
    }
}

/// Iterator for streaming events
pub struct EventIterator {
    events: Vec<SecurityEvent>,
    index: usize,
}

impl EventIterator {
    /// Create a new iterator from events
    pub fn new(events: Vec<SecurityEvent>) -> Self {
        Self { events, index: 0 }
    }

    /// Filter events matching the filter
    pub fn filter(self, filter: &EventFilter) -> FilteredEventIterator {
        FilteredEventIterator {
            inner: self,
            filter: filter.clone(),
        }
    }

    /// Filter events by time range
    pub fn time_range(self, start: DateTime<Utc>, end: DateTime<Utc>) -> FilteredEventIterator {
        let filter = EventFilter::new().with_time_range(start, end);
        self.filter(&filter)
    }
}

impl Iterator for EventIterator {
    type Item = SecurityEvent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.events.len() {
            let event = self.events[self.index].clone();
            self.index += 1;
            Some(event)
        } else {
            None
        }
    }
}

/// Filtered event iterator
pub struct FilteredEventIterator {
    inner: EventIterator,
    filter: EventFilter,
}

impl Iterator for FilteredEventIterator {
    type Item = SecurityEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.by_ref().find(|event| self.filter.matches(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::syscall::SyscallEvent;

    #[test]
    fn test_event_batch_new() {
        let batch = EventBatch::new();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_event_batch_add() {
        let mut batch = EventBatch::new();
        let event: SecurityEvent =
            SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now()).into();

        batch.add(event);
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_event_filter_new() {
        let filter = EventFilter::new();
        assert!(filter.syscall_type.is_none());
        assert!(filter.pid.is_none());
    }

    #[test]
    fn test_event_filter_chained() {
        let filter = EventFilter::new()
            .with_syscall_type(SyscallType::Execve)
            .with_pid(1234)
            .with_uid(1000);

        assert!(filter.syscall_type.is_some());
        assert_eq!(filter.pid, Some(1234));
        assert_eq!(filter.uid, Some(1000));
    }
}
