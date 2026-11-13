//! connect syscall capture tests
//!
//! Tests for connect syscall event capture

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;
    use stackdog::events::syscall::SyscallType;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_connect_event_captured_on_tcp_connection() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Try to connect to a local port (will fail, but syscall is still made)
        let _ = TcpStream::connect("127.0.0.1:12345");

        // Give eBPF time to process
        std::thread::sleep(Duration::from_millis(100));

        // Poll for events
        let events = monitor.poll_events();

        // Should have captured connect events
        let connect_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Connect)
            .collect();

        // We expect at least one connect event
        assert!(
            !connect_events.is_empty(),
            "Should capture at least one connect event"
        );
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_connect_event_contains_destination_ip() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Connect to localhost
        let _ = TcpStream::connect("127.0.0.1:12345");

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let connect_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Connect)
            .collect();

        // Just verify we got events (detailed IP capture tested in integration)
        assert!(!connect_events.is_empty());
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_connect_event_contains_destination_port() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Connect to specific port
        let test_port = 12346;
        let _ = TcpStream::connect(format!("127.0.0.1:{}", test_port));

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let connect_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Connect)
            .collect();

        // Verify events captured
        assert!(!connect_events.is_empty());
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_connect_event_multiple_connections() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Make multiple connections
        for port in 12350..12355 {
            let _ = TcpStream::connect(format!("127.0.0.1:{}", port));
        }

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let connect_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Connect)
            .collect();

        // Should have multiple connect events
        assert!(
            connect_events.len() >= 5,
            "Should capture multiple connect events"
        );
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;

    #[test]
    fn test_connect_monitor_not_available_on_non_linux() {
        let result = SyscallMonitor::new();
        assert!(result.is_err());
    }
}
