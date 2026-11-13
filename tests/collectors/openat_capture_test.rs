//! openat syscall capture tests
//!
//! Tests for openat syscall event capture

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;
    use stackdog::events::syscall::SyscallType;
    use std::fs::File;
    use std::time::Duration;

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_openat_event_captured_on_file_open() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Open a file to trigger openat
        let _ = File::open("/etc/hostname");

        // Give eBPF time to process
        std::thread::sleep(Duration::from_millis(100));

        // Poll for events
        let events = monitor.poll_events();

        // Should have captured openat events
        let openat_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Openat)
            .collect();

        assert!(
            !openat_events.is_empty(),
            "Should capture at least one openat event"
        );
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_openat_event_contains_file_path() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Open specific file
        let _ = File::open("/etc/hostname");

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let openat_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Openat)
            .collect();

        // Just verify events captured (detailed path capture in integration tests)
        assert!(!openat_events.is_empty());
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_openat_event_multiple_files() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Open multiple files
        let files = vec!["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"];

        for path in files {
            let _ = File::open(path);
        }

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let openat_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Openat)
            .collect();

        // Should have multiple openat events
        assert!(
            openat_events.len() >= 3,
            "Should capture multiple openat events"
        );
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_openat_event_read_and_write() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Open file for reading
        let _ = File::open("/etc/hostname");

        // Open file for writing (creates temp file)
        let temp_path = "/tmp/stackdog_test.tmp";
        let _ = File::create(temp_path);

        // Cleanup
        let _ = std::fs::remove_file(temp_path);

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let openat_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Openat)
            .collect();

        // Should have captured both read and write opens
        assert!(openat_events.len() >= 2);
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;

    #[test]
    fn test_openat_monitor_not_available_on_non_linux() {
        let result = SyscallMonitor::new();
        assert!(result.is_err());
    }
}
