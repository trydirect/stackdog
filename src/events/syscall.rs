//! Syscall event types
//!
//! Defines syscall event structures for eBPF-based monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Types of syscalls we monitor
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum SyscallType {
    // Process execution
    Execve,
    Execveat,

    // Network
    Connect,
    Accept,
    Bind,
    Listen,
    Socket,
    Sendto,

    // File operations
    Open,
    Openat,
    Close,
    Read,
    Write,

    // Security-sensitive
    Ptrace,
    Setuid,
    Setgid,

    // Mount operations
    Mount,
    Umount,

    #[default]
    Unknown,
}

/// A syscall event captured by eBPF
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub pid: u32,
    pub uid: u32,
    pub syscall_type: SyscallType,
    pub timestamp: DateTime<Utc>,
    pub container_id: Option<String>,
    pub comm: Option<String>,
    pub details: Option<SyscallDetails>,
}

/// Syscall-specific details captured by eBPF or userspace enrichment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyscallDetails {
    Exec {
        filename: Option<String>,
        args: Vec<String>,
        argc: u32,
    },
    Connect {
        dst_addr: Option<String>,
        dst_port: u16,
        family: u16,
    },
    Openat {
        path: Option<String>,
        flags: u32,
    },
    Ptrace {
        target_pid: u32,
        request: u32,
        addr: u64,
        data: u64,
    },
}

impl SyscallEvent {
    /// Create a new syscall event
    pub fn new(pid: u32, uid: u32, syscall_type: SyscallType, timestamp: DateTime<Utc>) -> Self {
        Self {
            pid,
            uid,
            syscall_type,
            timestamp,
            container_id: None,
            comm: None,
            details: None,
        }
    }

    /// Create a builder for SyscallEvent
    pub fn builder() -> SyscallEventBuilder {
        SyscallEventBuilder::new()
    }

    /// Get the PID if this is a syscall event
    pub fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    /// Get the UID if this is a syscall event
    pub fn uid(&self) -> Option<u32> {
        Some(self.uid)
    }

    /// Get exec details if this is an exec event.
    pub fn exec_details(&self) -> Option<(&Option<String>, &[String], u32)> {
        match self.details.as_ref() {
            Some(SyscallDetails::Exec {
                filename,
                args,
                argc,
            }) => Some((filename, args.as_slice(), *argc)),
            _ => None,
        }
    }

    /// Get connect destination if this is a connect event.
    pub fn connect_destination(&self) -> Option<(Option<&str>, u16)> {
        match self.details.as_ref() {
            Some(SyscallDetails::Connect {
                dst_addr, dst_port, ..
            }) => Some((dst_addr.as_deref(), *dst_port)),
            _ => None,
        }
    }
}

/// Builder for SyscallEvent
pub struct SyscallEventBuilder {
    pid: u32,
    uid: u32,
    syscall_type: SyscallType,
    timestamp: Option<DateTime<Utc>>,
    container_id: Option<String>,
    comm: Option<String>,
    details: Option<SyscallDetails>,
}

impl SyscallEventBuilder {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            syscall_type: SyscallType::default(),
            timestamp: None,
            container_id: None,
            comm: None,
            details: None,
        }
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    pub fn syscall_type(mut self, syscall_type: SyscallType) -> Self {
        self.syscall_type = syscall_type;
        self
    }

    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn container_id(mut self, container_id: Option<String>) -> Self {
        self.container_id = container_id;
        self
    }

    pub fn comm(mut self, comm: Option<String>) -> Self {
        self.comm = comm;
        self
    }

    pub fn details(mut self, details: Option<SyscallDetails>) -> Self {
        self.details = details;
        self
    }

    pub fn build(self) -> SyscallEvent {
        SyscallEvent {
            pid: self.pid,
            uid: self.uid,
            syscall_type: self.syscall_type,
            timestamp: self.timestamp.unwrap_or_else(Utc::now),
            container_id: self.container_id,
            comm: self.comm,
            details: self.details,
        }
    }
}

impl Default for SyscallEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_type_default() {
        assert_eq!(SyscallType::default(), SyscallType::Unknown);
    }

    #[test]
    fn test_syscall_event_new() {
        let event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());
        assert_eq!(event.pid, 1234);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.pid(), Some(1234));
        assert_eq!(event.uid(), Some(1000));
    }

    #[test]
    fn test_syscall_event_builder() {
        let event = SyscallEvent::builder()
            .pid(1234)
            .uid(1000)
            .syscall_type(SyscallType::Connect)
            .details(Some(SyscallDetails::Connect {
                dst_addr: Some("192.0.2.10".to_string()),
                dst_port: 587,
                family: 2,
            }))
            .build();
        assert_eq!(event.pid, 1234);
        assert_eq!(event.connect_destination(), Some((Some("192.0.2.10"), 587)));
    }

    #[test]
    fn test_exec_details_accessor() {
        let event = SyscallEvent::builder()
            .pid(1234)
            .uid(1000)
            .syscall_type(SyscallType::Execve)
            .details(Some(SyscallDetails::Exec {
                filename: Some("/usr/sbin/sendmail".to_string()),
                args: vec!["/usr/sbin/sendmail".to_string(), "-t".to_string()],
                argc: 2,
            }))
            .build();

        let (filename, args, argc) = event.exec_details().unwrap();
        assert_eq!(filename.as_deref(), Some("/usr/sbin/sendmail"));
        assert_eq!(args, ["/usr/sbin/sendmail", "-t"]);
        assert_eq!(argc, 2);
    }
}
