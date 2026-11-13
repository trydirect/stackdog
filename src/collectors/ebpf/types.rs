//! eBPF types
//!
//! Shared type definitions for eBPF programs and userspace

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{TimeZone, Utc};

/// eBPF syscall event structure
///
/// This structure is shared between eBPF programs and userspace
/// It must be C-compatible for efficient transfer via ring buffer
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EbpfSyscallEvent {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Syscall ID
    pub syscall_id: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: u64,
    /// Command name (comm)
    pub comm: [u8; 16],
    /// Union data - syscall specific
    pub data: EbpfEventData,
}

/// Event data union
#[repr(C)]
#[derive(Clone, Copy)]
pub union EbpfEventData {
    /// execve data
    pub execve: ExecveData,
    /// connect data
    pub connect: ConnectData,
    /// openat data
    pub openat: OpenatData,
    /// ptrace data
    pub ptrace: PtraceData,
    /// Raw bytes
    pub raw: [u8; 128],
}

impl std::fmt::Debug for EbpfEventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAFETY: raw is always a valid field in any union variant
        let raw = unsafe { self.raw };
        write!(f, "EbpfEventData {{ raw: {:?} }}", &raw[..])
    }
}

impl Default for EbpfEventData {
    fn default() -> Self {
        Self { raw: [0u8; 128] }
    }
}

/// execve-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecveData {
    /// Filename length
    pub filename_len: u32,
    /// Filename (first 128 bytes)
    pub filename: [u8; 128],
    /// Argument count
    pub argc: u32,
}

impl Default for ExecveData {
    fn default() -> Self {
        Self {
            filename_len: 0,
            filename: [0u8; 128],
            argc: 0,
        }
    }
}

/// connect-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectData {
    /// Destination IP (v4 or v6)
    pub dst_ip: [u8; 16],
    /// Destination port
    pub dst_port: u16,
    /// Address family (AF_INET or AF_INET6)
    pub family: u16,
}

/// openat-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenatData {
    /// File path length
    pub path_len: u32,
    /// File path (first 256 bytes)
    pub path: [u8; 256],
    /// Open flags
    pub flags: u32,
}

impl Default for OpenatData {
    fn default() -> Self {
        Self {
            path_len: 0,
            path: [0u8; 256],
            flags: 0,
        }
    }
}

/// ptrace-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PtraceData {
    /// Target PID being traced
    pub target_pid: u32,
    /// Ptrace request type
    pub request: u32,
    /// Address
    pub addr: u64,
    /// Data
    pub data: u64,
}

impl EbpfSyscallEvent {
    /// Create a new event
    pub fn new(pid: u32, uid: u32, syscall_id: u32) -> Self {
        Self {
            pid,
            uid,
            syscall_id,
            _pad: 0,
            timestamp: 0,
            comm: [0u8; 16],
            data: EbpfEventData::default(),
        }
    }

    /// Get command name as string
    pub fn comm_str(&self) -> String {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..len]).to_string()
    }

    /// Set command name
    pub fn set_comm(&mut self, comm: &[u8]) {
        let len = comm.len().min(15);
        self.comm[..len].copy_from_slice(&comm[..len]);
        self.comm[len] = 0;
    }

    /// Convert this raw eBPF event to a userspace syscall event.
    pub fn to_syscall_event(&self) -> crate::events::syscall::SyscallEvent {
        to_syscall_event(self)
    }
}

/// Convert eBPF event to userspace SyscallEvent
pub fn to_syscall_event(ebpf_event: &EbpfSyscallEvent) -> crate::events::syscall::SyscallEvent {
    use crate::events::syscall::{SyscallEvent, SyscallType};

    // Convert syscall_id to SyscallType
    let syscall_type = match ebpf_event.syscall_id {
        59 => SyscallType::Execve,  // sys_execve
        42 => SyscallType::Connect, // sys_connect
        257 => SyscallType::Openat, // sys_openat
        101 => SyscallType::Ptrace, // sys_ptrace
        _ => SyscallType::Unknown,
    };

    let mut event = SyscallEvent::new(
        ebpf_event.pid,
        ebpf_event.uid,
        syscall_type.clone(),
        timestamp_to_utc(ebpf_event.timestamp),
    );

    event.comm = Some(ebpf_event.comm_str());
    event.details = match syscall_type {
        SyscallType::Execve | SyscallType::Execveat => {
            // SAFETY: We interpret the union according to the syscall type.
            Some(exec_details(unsafe { &ebpf_event.data.execve }))
        }
        SyscallType::Connect => {
            // SAFETY: We interpret the union according to the syscall type.
            Some(connect_details(unsafe { &ebpf_event.data.connect }))
        }
        SyscallType::Openat => {
            // SAFETY: We interpret the union according to the syscall type.
            Some(openat_details(unsafe { &ebpf_event.data.openat }))
        }
        SyscallType::Ptrace => {
            // SAFETY: We interpret the union according to the syscall type.
            Some(ptrace_details(unsafe { &ebpf_event.data.ptrace }))
        }
        _ => None,
    };

    event
}

fn timestamp_to_utc(timestamp_ns: u64) -> chrono::DateTime<chrono::Utc> {
    if timestamp_ns == 0 {
        return chrono::Utc::now();
    }

    let seconds = (timestamp_ns / 1_000_000_000) as i64;
    let nanos = (timestamp_ns % 1_000_000_000) as u32;
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .unwrap_or_else(Utc::now)
}

fn exec_details(data: &ExecveData) -> crate::events::syscall::SyscallDetails {
    crate::events::syscall::SyscallDetails::Exec {
        filename: decode_string(&data.filename, Some(data.filename_len as usize)),
        args: Vec::new(),
        argc: data.argc,
    }
}

fn connect_details(data: &ConnectData) -> crate::events::syscall::SyscallDetails {
    crate::events::syscall::SyscallDetails::Connect {
        dst_addr: decode_ip(data),
        dst_port: u16::from_be(data.dst_port),
        family: data.family,
    }
}

fn openat_details(data: &OpenatData) -> crate::events::syscall::SyscallDetails {
    crate::events::syscall::SyscallDetails::Openat {
        path: decode_string(&data.path, Some(data.path_len as usize)),
        flags: data.flags,
    }
}

fn ptrace_details(data: &PtraceData) -> crate::events::syscall::SyscallDetails {
    crate::events::syscall::SyscallDetails::Ptrace {
        target_pid: data.target_pid,
        request: data.request,
        addr: data.addr,
        data: data.data,
    }
}

fn decode_string(bytes: &[u8], declared_len: Option<usize>) -> Option<String> {
    let first_nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let len = declared_len
        .unwrap_or(first_nul)
        .min(first_nul)
        .min(bytes.len());
    if len == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&bytes[..len]).to_string())
}

fn decode_ip(data: &ConnectData) -> Option<String> {
    match data.family {
        2 => Some(
            Ipv4Addr::new(
                data.dst_ip[0],
                data.dst_ip[1],
                data.dst_ip[2],
                data.dst_ip[3],
            )
            .to_string(),
        ),
        10 => Some(Ipv6Addr::from(data.dst_ip).to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::syscall::SyscallDetails;

    #[test]
    fn test_event_creation() {
        let event = EbpfSyscallEvent::new(1234, 1000, 59);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.syscall_id, 59);
    }

    #[test]
    fn test_comm_str_empty() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.comm = [0u8; 16];
        assert_eq!(event.comm_str(), "");
    }

    #[test]
    fn test_comm_str_short() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"bash");
        assert_eq!(event.comm_str(), "bash");
    }

    #[test]
    fn test_comm_str_exact_15() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"longprocessname");
        assert_eq!(event.comm_str(), "longprocessname");
    }

    #[test]
    fn test_set_comm_truncates() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"this_is_a_very_long_command_name_that_exceeds_limit");
        // Should be truncated to 15 chars + null
        assert_eq!(event.comm_str().len(), 15);
    }

    #[test]
    fn test_to_syscall_event_preserves_exec_details() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"php-fpm");
        event.timestamp = 1_700_000_000_123_456_789;
        let mut filename = [0u8; 128];
        filename[..18].copy_from_slice(b"/usr/sbin/sendmail");
        event.data = EbpfEventData {
            execve: ExecveData {
                filename_len: 18,
                filename,
                argc: 2,
            },
        };

        let converted = event.to_syscall_event();
        assert_eq!(converted.comm.as_deref(), Some("php-fpm"));
        match converted.details {
            Some(SyscallDetails::Exec { filename, argc, .. }) => {
                assert_eq!(filename.as_deref(), Some("/usr/sbin/sendmail"));
                assert_eq!(argc, 2);
            }
            other => panic!("unexpected details: {:?}", other),
        }
    }

    #[test]
    fn test_to_syscall_event_preserves_connect_details() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 42);
        event.data = EbpfEventData {
            connect: ConnectData {
                dst_ip: [192, 0, 2, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dst_port: 587u16.to_be(),
                family: 2,
            },
        };

        let converted = event.to_syscall_event();
        match converted.details {
            Some(SyscallDetails::Connect {
                dst_addr,
                dst_port,
                family,
            }) => {
                assert_eq!(dst_addr.as_deref(), Some("192.0.2.25"));
                assert_eq!(dst_port, 587);
                assert_eq!(family, 2);
            }
            other => panic!("unexpected details: {:?}", other),
        }
    }

    #[test]
    fn test_to_syscall_event_preserves_openat_details() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 257);
        let mut path = [0u8; 256];
        path[..17].copy_from_slice(b"/etc/postfix/main");
        event.data = EbpfEventData {
            openat: OpenatData {
                path_len: 17,
                path,
                flags: 0o2,
            },
        };

        let converted = event.to_syscall_event();
        match converted.details {
            Some(SyscallDetails::Openat { path, flags }) => {
                assert_eq!(path.as_deref(), Some("/etc/postfix/main"));
                assert_eq!(flags, 0o2);
            }
            other => panic!("unexpected details: {:?}", other),
        }
    }
}
