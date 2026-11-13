//! eBPF ring buffer
//!
//! Provides efficient event buffering from eBPF to userspace

use crate::events::syscall::SyscallEvent;

/// Ring buffer for eBPF events
pub struct EventRingBuffer {
    // TODO: Implement actual ring buffer in TASK-004
    // For now, this is a stub
    buffer: Vec<SyscallEvent>,
    capacity: usize,
}

impl EventRingBuffer {
    /// Create a new ring buffer with default capacity
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            capacity: 4096, // Default capacity
        }
    }

    /// Create a ring buffer with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Add an event to the buffer
    pub fn push(&mut self, event: SyscallEvent) {
        // If buffer is full, remove oldest events
        if self.buffer.len() >= self.capacity {
            self.buffer.remove(0);
        }
        self.buffer.push(event);
    }

    /// Get all events and clear the buffer
    pub fn drain(&mut self) -> Vec<SyscallEvent> {
        std::mem::take(&mut self.buffer)
    }

    /// Get the number of events in the buffer
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get the capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// View events without consuming them
    pub fn events(&self) -> &[SyscallEvent] {
        &self.buffer
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Default for EventRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::Utc;

    #[test]
    fn test_ring_buffer_creation() {
        let buffer = EventRingBuffer::new();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_ring_buffer_with_capacity() {
        let buffer = EventRingBuffer::with_capacity(100);
        assert_eq!(buffer.capacity(), 100);
    }

    #[test]
    fn test_ring_buffer_push() {
        let mut buffer = EventRingBuffer::new();
        let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

        buffer.push(event);
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_ring_buffer_drain() {
        let mut buffer = EventRingBuffer::new();

        for i in 0..5 {
            let event = SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now());
            buffer.push(event);
        }

        let events = buffer.drain();
        assert_eq!(events.len(), 5);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_ring_buffer_overflow() {
        let mut buffer = EventRingBuffer::with_capacity(3);

        // Push 5 events into buffer with capacity 3
        for i in 0..5 {
            let event = SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now());
            buffer.push(event);
        }

        // Should only have 3 events (oldest removed)
        assert_eq!(buffer.len(), 3);

        // The first two events should be removed
        let events = buffer.drain();
        assert_eq!(events[0].pid, 2); // First event should be pid=2
        assert_eq!(events[1].pid, 3);
        assert_eq!(events[2].pid, 4);
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut buffer = EventRingBuffer::new();

        for i in 0..3 {
            let event = SyscallEvent::new(i, 1000, SyscallType::Execve, Utc::now());
            buffer.push(event);
        }

        buffer.clear();
        assert!(buffer.is_empty());
    }
}
