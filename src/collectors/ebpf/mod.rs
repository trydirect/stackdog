//! eBPF collectors module
//!
//! Provides eBPF-based syscall monitoring using aya-rs
//!
//! Note: This module is only available on Linux with the ebpf feature enabled

pub mod container;
pub mod enrichment;
pub mod kernel;
pub mod loader;
pub mod programs;
pub mod ring_buffer;
pub mod syscall_monitor;
pub mod types;

// Re-export main types
pub use container::ContainerDetector;
pub use enrichment::EventEnricher;
pub use loader::EbpfLoader;
pub use syscall_monitor::SyscallMonitor;
pub use types::{to_syscall_event, EbpfEventData, EbpfSyscallEvent};
