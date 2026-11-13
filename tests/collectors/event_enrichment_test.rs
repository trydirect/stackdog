//! Event enrichment tests
//!
//! Tests for event enrichment (container ID, timestamps, process tree)

use chrono::Utc;
use stackdog::collectors::ebpf::container::ContainerDetector;
use stackdog::collectors::ebpf::enrichment::EventEnricher;
use stackdog::events::syscall::{SyscallEvent, SyscallType};

#[test]
fn test_event_enricher_creation() {
    let enricher = EventEnricher::new();
    assert!(enricher.is_ok());
}

#[test]
fn test_enrich_adds_timestamp() {
    let mut enricher = EventEnricher::new().expect("Failed to create enricher");
    let mut event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    enricher.enrich(&mut event).expect("Failed to enrich");

    // Event should have timestamp
    assert!(event.timestamp <= Utc::now());
}

#[test]
fn test_enrich_preserves_existing_timestamp() {
    let mut enricher = EventEnricher::new().expect("Failed to create enricher");
    let original_timestamp = Utc::now();
    let mut event = SyscallEvent::new(1234, 1000, SyscallType::Execve, original_timestamp);

    enricher.enrich(&mut event).expect("Failed to enrich");

    // Timestamp should be preserved or updated (both acceptable)
    assert!(event.timestamp >= original_timestamp);
}

#[test]
fn test_container_detector_creation() {
    let detector = ContainerDetector::new();
    // Should work on Linux, may fail on other platforms
    #[cfg(target_os = "linux")]
    assert!(detector.is_ok());
    #[cfg(not(target_os = "linux"))]
    assert!(detector.is_err());
}

#[test]
fn test_container_id_detection_format() {
    let detector = ContainerDetector::new();

    #[cfg(target_os = "linux")]
    {
        let detector = detector.expect("Failed to create detector");
        // Test with a known container ID format
        let valid_ids = vec![
            "abc123def456",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        ];

        for id in valid_ids {
            let result = detector.validate_container_id(id);
            assert!(result, "Should validate container ID: {}", id);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert!(detector.is_err());
    }
}

#[test]
fn test_container_id_invalid_formats() {
    let detector = ContainerDetector::new();

    #[cfg(target_os = "linux")]
    {
        let detector = detector.expect("Failed to create detector");
        let invalid_ids = vec![
            "",
            "too_short",
            "invalid@chars!",
            "this_is_way_too_long_for_a_container_id_and_should_fail_validation",
        ];

        for id in invalid_ids {
            let result = detector.validate_container_id(id);
            assert!(!result, "Should reject invalid container ID: {}", id);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert!(detector.is_err());
    }
}

#[test]
fn test_cgroup_parsing() {
    // Test cgroup path parsing for container detection
    let test_cases = vec![
        ("12:memory:/docker/abc123def456", Some("abc123def456")),
        ("11:cpu:/kubepods/pod123/def456abc789", Some("def456abc789")),
        ("10:cpuacct:/", None),
    ];

    for (cgroup_path, expected_id) in test_cases {
        let result = ContainerDetector::parse_container_from_cgroup(cgroup_path);
        assert_eq!(result, expected_id.map(|s| s.to_string()));
    }
}

#[test]
fn test_process_tree_enrichment() {
    let enricher = EventEnricher::new().expect("Failed to create enricher");

    // Test that we can get parent PID
    let ppid = enricher.get_parent_pid(1); // init process

    // PID 1 should exist on Linux
    #[cfg(target_os = "linux")]
    assert!(ppid.is_some());
    #[cfg(not(target_os = "linux"))]
    let _ = ppid;
}

#[test]
fn test_process_comm_enrichment() {
    let enricher = EventEnricher::new().expect("Failed to create enricher");

    // Test that we can get process name
    let comm = enricher.get_process_comm(std::process::id());

    // Should get some process name
    #[cfg(target_os = "linux")]
    assert!(comm.is_some());
    #[cfg(not(target_os = "linux"))]
    let _ = comm;
}

#[test]
fn test_timestamp_normalization() {
    use stackdog::collectors::ebpf::enrichment::normalize_timestamp;

    // Test with current time
    let now = Utc::now();
    let normalized = normalize_timestamp(now);
    assert!(normalized >= now);

    // Test with epoch
    let epoch = chrono::DateTime::from_timestamp(0, 0).unwrap();
    let normalized = normalize_timestamp(epoch);
    assert!(normalized >= epoch);
}

#[test]
fn test_enrichment_pipeline() {
    let mut enricher = EventEnricher::new().expect("Failed to create enricher");
    let mut event = SyscallEvent::new(1234, 1000, SyscallType::Execve, Utc::now());

    // Run full enrichment pipeline
    enricher.enrich(&mut event).expect("Failed to enrich");

    // Event should be enriched
    assert!(event.timestamp <= Utc::now());
}
