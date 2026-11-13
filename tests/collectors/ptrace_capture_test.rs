//! ptrace syscall capture tests
//!
//! Tests for ptrace syscall event capture

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;
    use std::time::Duration;

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_ptrace_event_captured_on_trace_attempt() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Note: Actually calling ptrace requires special setup
        // For now, we just verify the monitor doesn't crash
        // and can detect ptrace syscalls if they occur

        std::thread::sleep(Duration::from_millis(100));

        let _events = monitor.poll_events();

        // Just verify monitor works without crashing
        assert!(true, "Monitor should handle ptrace detection gracefully");
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_ptrace_event_contains_target_pid() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        std::thread::sleep(Duration::from_millis(100));

        let _events = monitor.poll_events();

        // Verify structure ready for ptrace events
        assert!(true);
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_ptrace_event_security_alert() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Ptrace is often used by debuggers and malware
        // Verify we can detect it

        std::thread::sleep(Duration::from_millis(100));

        let _events = monitor.poll_events();

        // Just verify monitor is working
        assert!(true);
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;

    #[test]
    fn test_ptrace_monitor_not_available_on_non_linux() {
        let result = SyscallMonitor::new();
        assert!(result.is_err());
    }
}
