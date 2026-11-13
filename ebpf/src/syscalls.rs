//! Syscall monitoring eBPF programs
//!
//! Tracepoints for monitoring security-relevant syscalls

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::tracepoint,
    programs::TracePointContext,
    EbpfContext,
};

use crate::maps::{
    ConnectData, EbpfEventData, EbpfSyscallEvent, ExecveData, OpenatData, PtraceData, EVENTS,
};

const SYSCALL_ARG_START: usize = 16;
const SYSCALL_ARG_SIZE: usize = 8;

const SYS_EXECVE: u32 = 59;
const SYS_CONNECT: u32 = 42;
const SYS_OPENAT: u32 = 257;
const SYS_PTRACE: u32 = 101;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const MAX_ARGC_SCAN: usize = 16;

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn trace_execve(ctx: TracePointContext) -> i32 {
    let _ = unsafe { try_trace_execve(&ctx) };
    0
}

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn trace_connect(ctx: TracePointContext) -> i32 {
    let _ = unsafe { try_trace_connect(&ctx) };
    0
}

#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn trace_openat(ctx: TracePointContext) -> i32 {
    let _ = unsafe { try_trace_openat(&ctx) };
    0
}

#[tracepoint(name = "sys_enter_ptrace", category = "syscalls")]
pub fn trace_ptrace(ctx: TracePointContext) -> i32 {
    let _ = unsafe { try_trace_ptrace(&ctx) };
    0
}

unsafe fn try_trace_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = read_u64_arg(ctx, 0)? as *const u8;
    let argv_ptr = read_u64_arg(ctx, 1)? as *const u64;
    let mut event = base_event(ctx, SYS_EXECVE);
    let mut data = ExecveData::empty();

    if !filename_ptr.is_null() {
        if let Ok(bytes) = bpf_probe_read_user_str_bytes(filename_ptr, &mut data.filename) {
            data.filename_len = bytes.len() as u32;
        }
    }

    data.argc = count_argv(argv_ptr).unwrap_or(0);
    event.data = EbpfEventData { execve: data };
    submit_event(&event)
}

unsafe fn try_trace_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let sockaddr_ptr = read_u64_arg(ctx, 1)? as *const u8;
    if sockaddr_ptr.is_null() {
        return Ok(());
    }

    let family = bpf_probe_read_user(sockaddr_ptr as *const u16)?;
    let mut event = base_event(ctx, SYS_CONNECT);
    let mut data = ConnectData::empty();
    data.family = family;

    if family == AF_INET {
        data.dst_port = bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)?;
        let mut addr = [0u8; 4];
        bpf_probe_read_user_buf(sockaddr_ptr.add(4), &mut addr)?;
        data.dst_ip[..4].copy_from_slice(&addr);
    } else if family == AF_INET6 {
        data.dst_port = bpf_probe_read_user(sockaddr_ptr.add(2) as *const u16)?;
        bpf_probe_read_user_buf(sockaddr_ptr.add(8), &mut data.dst_ip)?;
    }

    event.data = EbpfEventData { connect: data };
    submit_event(&event)
}

unsafe fn try_trace_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let pathname_ptr = read_u64_arg(ctx, 1)? as *const u8;
    let flags = read_u64_arg(ctx, 2)? as u32;
    let mut event = base_event(ctx, SYS_OPENAT);
    let mut data = OpenatData::empty();
    data.flags = flags;

    if !pathname_ptr.is_null() {
        if let Ok(bytes) = bpf_probe_read_user_str_bytes(pathname_ptr, &mut data.path) {
            data.path_len = bytes.len() as u32;
        }
    }

    event.data = EbpfEventData { openat: data };
    submit_event(&event)
}

unsafe fn try_trace_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let mut event = base_event(ctx, SYS_PTRACE);
    let data = PtraceData {
        request: read_u64_arg(ctx, 0)? as u32,
        target_pid: read_u64_arg(ctx, 1)? as u32,
        addr: read_u64_arg(ctx, 2)?,
        data: read_u64_arg(ctx, 3)?,
    };
    event.data = EbpfEventData { ptrace: data };
    submit_event(&event)
}

fn base_event(ctx: &TracePointContext, syscall_id: u32) -> EbpfSyscallEvent {
    let mut event = EbpfSyscallEvent::empty();
    event.pid = ctx.tgid();
    event.uid = ctx.uid();
    event.syscall_id = syscall_id;
    event.timestamp = 0;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }
    event
}

fn submit_event(event: &EbpfSyscallEvent) -> Result<(), i64> {
    EVENTS.output(event, 0)
}

fn read_u64_arg(ctx: &TracePointContext, index: usize) -> Result<u64, i64> {
    unsafe { ctx.read_at::<u64>(SYSCALL_ARG_START + index * SYSCALL_ARG_SIZE) }
}

unsafe fn count_argv(argv_ptr: *const u64) -> Result<u32, i64> {
    if argv_ptr.is_null() {
        return Ok(0);
    }

    let mut argc = 0u32;
    while argc < MAX_ARGC_SCAN as u32 {
        let arg_ptr = bpf_probe_read_user(argv_ptr.add(argc as usize))?;
        if arg_ptr == 0 {
            break;
        }
        argc += 1;
    }

    Ok(argc)
}
