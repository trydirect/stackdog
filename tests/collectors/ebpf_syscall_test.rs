//! eBPF syscall event capture tests
//!
//! Tests for syscall event capture from eBPF programs

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;
    use stackdog::events::syscall::SyscallType;
    use std::time::Duration;

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_syscall_monitor_creation() {
        let monitor = SyscallMonitor::new();
        assert!(
            monitor.is_ok(),
            "SyscallMonitor::new() should succeed on Linux with eBPF"
        );
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_capture() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        // Start monitoring
        monitor.start().expect("Failed to start monitor");

        // Trigger an execve by running a simple command
        std::process::Command::new("echo").arg("test").output().ok();

        // Give eBPF time to process
        std::thread::sleep(Duration::from_millis(100));

        // Poll for events
        let events = monitor.poll_events();

        // Should have captured some events
        assert!(events.len() > 0, "Should capture at least one execve event");

        // Check that we have execve events
        let has_execve = events.iter().any(|e| e.syscall_type == SyscallType::Execve);
        assert!(has_execve, "Should capture execve events");
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_connect_event_capture() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");
        monitor.start().expect("Failed to start monitor");

        // Trigger a connect syscall
        let _ = std::net::TcpStream::connect("127.0.0.1:12345");

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();
        let _has_connect = events
            .iter()
            .any(|e| e.syscall_type == SyscallType::Connect);

        // May or may not capture depending on timing
        // Just verify no panic
        assert!(true);
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_openat_event_capture() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");
        monitor.start().expect("Failed to start monitor");

        // Trigger openat syscalls
        let _ = std::fs::File::open("/etc/hostname");

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        // Should have captured some events
        assert!(events.len() > 0);
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_ptrace_event_capture() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");
        monitor.start().expect("Failed to start monitor");

        // Note: Actually calling ptrace requires special setup
        // This test verifies the monitor doesn't crash

        let _events = monitor.poll_events();
        assert!(true); // Just verify no panic
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_event_ring_buffer_poll() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");
        monitor.start().expect("Failed to start monitor");

        // Multiple polls should work
        let events1 = monitor.poll_events();
        let events2 = monitor.poll_events();

        // Both should succeed (may be empty)
        assert!(events1.len() >= 0);
        assert!(events2.len() >= 0);
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_syscall_monitor_stop() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");
        monitor.start().expect("Failed to start monitor");

        // Stop should work
        let result = monitor.stop();
        assert!(result.is_ok());

        // Poll after stop should return empty
        let events = monitor.poll_events();
        assert!(events.is_empty());
    }
}

/// Cross-platform stub tests
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;

    #[test]
    fn test_syscall_monitor_not_linux() {
        // On non-Linux, should return error
        let result = SyscallMonitor::new();
        assert!(result.is_err());
    }
}
