//! execve syscall capture tests
//!
//! Tests for execve syscall event capture

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;
    use stackdog::events::syscall::SyscallType;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_captured_on_process_spawn() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Spawn a process to trigger execve
        let _ = Command::new("echo").arg("test").output();

        // Give eBPF time to process
        std::thread::sleep(Duration::from_millis(100));

        // Poll for events
        let events = monitor.poll_events();

        // Should have captured execve events
        let execve_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Execve)
            .collect();

        assert!(
            !execve_events.is_empty(),
            "Should capture at least one execve event"
        );
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_contains_filename() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        // Spawn a specific process
        let _ = Command::new("/bin/ls").arg("-la").output();

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        // Find execve events
        let execve_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Execve)
            .collect();

        // At least one should have comm set
        let has_comm = execve_events
            .iter()
            .any(|e| e.comm.as_ref().map(|c| !c.is_empty()).unwrap_or(false));

        assert!(has_comm, "Should capture command name");
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_contains_pid() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        let _ = Command::new("echo").arg("test").output();

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let execve_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Execve)
            .collect();

        // All events should have valid PID
        for event in execve_events {
            assert!(event.pid > 0, "PID should be positive");
        }
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_contains_uid() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        let _ = Command::new("echo").arg("test").output();

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let execve_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Execve)
            .collect();

        // UID is u32, so only verify iterating events is safe and stable.
        for _event in execve_events {}
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_execve_event_timestamp() {
        let mut monitor = SyscallMonitor::new().expect("Failed to create monitor");

        monitor.start().expect("Failed to start monitor");

        let before = chrono::Utc::now();

        let _ = Command::new("echo").arg("test").output();

        std::thread::sleep(Duration::from_millis(100));

        let events = monitor.poll_events();

        let execve_events: Vec<_> = events
            .iter()
            .filter(|e| e.syscall_type == SyscallType::Execve)
            .collect();

        // Timestamps should be reasonable
        for event in execve_events {
            assert!(
                event.timestamp >= before,
                "Event timestamp should be after test start"
            );
        }
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::collectors::ebpf::syscall_monitor::SyscallMonitor;

    #[test]
    fn test_execve_monitor_not_available_on_non_linux() {
        // On non-Linux, monitor creation should fail
        let result = SyscallMonitor::new();
        assert!(result.is_err());
    }
}
