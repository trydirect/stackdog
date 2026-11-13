//! eBPF maps
//!
//! Shared maps for eBPF programs

use aya_ebpf::{macros::map, maps::RingBuf};

#[repr(C)]
#[derive(Clone, Copy)]
pub union EbpfEventData {
    pub execve: ExecveData,
    pub connect: ConnectData,
    pub openat: OpenatData,
    pub ptrace: PtraceData,
    pub raw: [u8; 264],
}

impl EbpfEventData {
    pub const fn empty() -> Self {
        Self { raw: [0u8; 264] }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfSyscallEvent {
    pub pid: u32,
    pub uid: u32,
    pub syscall_id: u32,
    pub _pad: u32,
    pub timestamp: u64,
    pub comm: [u8; 16],
    pub data: EbpfEventData,
}

impl EbpfSyscallEvent {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            uid: 0,
            syscall_id: 0,
            _pad: 0,
            timestamp: 0,
            comm: [0u8; 16],
            data: EbpfEventData::empty(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveData {
    pub filename_len: u32,
    pub filename: [u8; 128],
    pub argc: u32,
}

impl ExecveData {
    pub const fn empty() -> Self {
        Self {
            filename_len: 0,
            filename: [0u8; 128],
            argc: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectData {
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
    pub family: u16,
}

impl ConnectData {
    pub const fn empty() -> Self {
        Self {
            dst_ip: [0u8; 16],
            dst_port: 0,
            family: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenatData {
    pub path_len: u32,
    pub path: [u8; 256],
    pub flags: u32,
}

impl OpenatData {
    pub const fn empty() -> Self {
        Self {
            path_len: 0,
            path: [0u8; 256],
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceData {
    pub target_pid: u32,
    pub request: u32,
    pub addr: u64,
    pub data: u64,
}

impl PtraceData {
    pub const fn empty() -> Self {
        Self {
            target_pid: 0,
            request: 0,
            addr: 0,
            data: 0,
        }
    }
}

#[map(name = "EVENTS")]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
