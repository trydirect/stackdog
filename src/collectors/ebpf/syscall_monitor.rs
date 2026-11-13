//! Syscall monitor
//!
//! Monitors syscalls using eBPF tracepoints

use crate::collectors::ebpf::container::ContainerDetector;
use crate::collectors::ebpf::enrichment::EventEnricher;
use crate::collectors::ebpf::ring_buffer::EventRingBuffer;
use crate::events::syscall::SyscallEvent;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
use anyhow::Context;
use anyhow::Result;

/// Syscall monitor using eBPF
pub struct SyscallMonitor {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    loader: Option<super::loader::EbpfLoader>,

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    ring_buf: Option<aya::maps::RingBuf<aya::maps::MapData>>,

    running: bool,
    event_buffer: EventRingBuffer,
    _enricher: EventEnricher,
    _container_detector: Option<ContainerDetector>,
}

impl SyscallMonitor {
    /// Create a new syscall monitor
    pub fn new() -> Result<Self> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let loader =
                super::loader::EbpfLoader::new().context("Failed to create eBPF loader")?;

            let enricher = EventEnricher::new().context("Failed to create event enricher")?;

            let container_detector = ContainerDetector::new().ok();

            Ok(Self {
                loader: Some(loader),
                ring_buf: None,
                running: false,
                event_buffer: EventRingBuffer::with_capacity(8192),
                _enricher: enricher,
                _container_detector: container_detector,
            })
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            anyhow::bail!("SyscallMonitor is only available on Linux with eBPF feature");
        }
    }

    /// Start monitoring syscalls
    pub fn start(&mut self) -> Result<()> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            if self.running {
                anyhow::bail!("Monitor is already running");
            }

            if let Some(loader) = &mut self.loader {
                let ebpf_path = "target/bpfel-unknown-none/release/stackdog";
                match loader.load_program_from_file(ebpf_path) {
                    Ok(()) => {
                        loader.attach_all_programs().unwrap_or_else(|e| {
                            log::warn!("Some eBPF programs failed to attach: {}", e);
                        });
                        match loader.take_ring_buf() {
                            Ok(rb) => {
                                self.ring_buf = Some(rb);
                            }
                            Err(e) => {
                                log::warn!("Failed to get eBPF ring buffer: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "eBPF program not found at '{}': {}. \
                             Running without kernel event collection — \
                             build the eBPF crate first with `cargo build --release` \
                             in the ebpf/ directory.",
                            ebpf_path,
                            e
                        );
                    }
                }
            }

            self.running = true;
            log::info!("Syscall monitor started");
            Ok(())
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            anyhow::bail!("SyscallMonitor is only available on Linux");
        }
    }

    /// Stop monitoring syscalls
    pub fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.event_buffer.clear();
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            self.ring_buf = None;
        }
        log::info!("Syscall monitor stopped");
        Ok(())
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Poll for new events
    pub fn poll_events(&mut self) -> Vec<SyscallEvent> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            if !self.running {
                return Vec::new();
            }

            // Drain the eBPF ring buffer into the staging buffer
            if let Some(rb) = &mut self.ring_buf {
                while let Some(item) = rb.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= std::mem::size_of::<super::types::EbpfSyscallEvent>() {
                        // SAFETY: We verified the byte length matches the struct size,
                        // and EbpfSyscallEvent is #[repr(C)] with no padding surprises.
                        let raw: super::types::EbpfSyscallEvent = unsafe {
                            std::ptr::read_unaligned(
                                bytes.as_ptr() as *const super::types::EbpfSyscallEvent
                            )
                        };
                        self.event_buffer.push(raw.to_syscall_event());
                    }
                }
            }

            // Drain the staging buffer and enrich with /proc info
            let mut events = self.event_buffer.drain();
            for event in &mut events {
                let _ = self._enricher.enrich(event);
                if event.container_id.is_none() {
                    if let Some(detector) = &mut self._container_detector {
                        event.container_id = detector.detect_container(event.pid);
                    }
                }
            }

            events
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Vec::new()
        }
    }

    /// Get events without consuming them
    pub fn peek_events(&self) -> &[SyscallEvent] {
        self.event_buffer.events()
    }

    /// Get the eBPF loader
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn loader(&self) -> Option<&super::loader::EbpfLoader> {
        self.loader.as_ref()
    }

    /// Get container ID for current process
    pub fn current_container_id(&mut self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if let Some(detector) = &mut self._container_detector {
                return detector.current_container();
            }
        }
        None
    }

    /// Detect container for a specific PID
    pub fn detect_container_for_pid(&mut self, _pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if let Some(detector) = &mut self._container_detector {
                return detector.detect_container(_pid);
            }
        }
        None
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.event_buffer.len()
    }

    /// Clear event buffer
    pub fn clear_events(&mut self) {
        self.event_buffer.clear();
    }
}

impl Default for SyscallMonitor {
    fn default() -> Self {
        Self::new().expect("Failed to create SyscallMonitor")
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
impl SyscallMonitor {
    /// Stub implementation for non-Linux
    pub fn new_stub() -> Result<Self> {
        anyhow::bail!("SyscallMonitor is only available on Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_monitor_creation() {
        let result = SyscallMonitor::new();

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        assert!(result.is_ok());

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        assert!(result.is_err());
    }

    #[test]
    fn test_syscall_monitor_not_running_initially() {
        let _monitor = SyscallMonitor::new();

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let monitor = monitor.unwrap();
            assert!(!monitor.is_running());
        }
    }

    #[test]
    fn test_poll_events_empty_when_not_running() {
        let _monitor = SyscallMonitor::new();

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let mut monitor = _monitor.unwrap();
            let events = monitor.poll_events();
            assert!(events.is_empty());
        }
    }

    #[test]
    fn test_event_count() {
        let _monitor = SyscallMonitor::new();

        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let monitor = _monitor.unwrap();
            assert_eq!(monitor.event_count(), 0);
        }
    }
}
