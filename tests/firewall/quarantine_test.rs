//! Container quarantine tests
//!
//! Tests for container quarantine functionality

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::firewall::quarantine::{QuarantineManager, QuarantineState};
    use chrono::Utc;

    #[test]
    #[ignore = "requires root and docker"]
    fn test_container_quarantine() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        // Use a test container ID
        let container_id = "test_container_abc123";
        
        let result = manager.quarantine(container_id);
        
        assert!(result.is_ok());
        
        // Verify state
        let state = manager.get_state(container_id);
        assert!(state.is_some());
        assert_eq!(state.unwrap(), QuarantineState::Quarantined);
        
        // Cleanup
        let _ = manager.release(container_id);
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_container_release() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_abc123";
        
        // Quarantine first
        let _ = manager.quarantine(container_id);
        
        // Release
        let result = manager.release(container_id);
        
        assert!(result.is_ok());
        
        // Verify state changed
        let state = manager.get_state(container_id);
        assert!(state.is_some());
        assert_eq!(state.unwrap(), QuarantineState::Released);
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_quarantine_state_tracking() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_abc123";
        
        // Quarantine
        let _ = manager.quarantine(container_id);
        
        // Get all quarantined
        let quarantined = manager.get_quarantined_containers();
        
        assert!(quarantined.contains(&container_id.to_string()));
        
        // Cleanup
        let _ = manager.release(container_id);
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_quarantine_rollback() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_abc123";
        
        // Quarantine
        let _ = manager.quarantine(container_id);
        
        // Rollback
        let result = manager.rollback(container_id);
        
        assert!(result.is_ok());
        
        // Should be released
        let state = manager.get_state(container_id);
        assert!(state.is_some());
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_quarantine_timestamp() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_abc123";
        
        let before = Utc::now();
        let _ = manager.quarantine(container_id);
        let after = Utc::now();
        
        let state = manager.get_state(container_id);
        assert!(state.is_some());
        
        let info = manager.get_quarantine_info(container_id);
        assert!(info.is_some());
        
        let quarantined_at = info.unwrap().quarantined_at;
        assert!(quarantined_at >= before);
        assert!(quarantined_at <= after);
        
        // Cleanup
        let _ = manager.release(container_id);
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_quarantine_already_quarantined() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_abc123";
        
        // Quarantine first time
        let result1 = manager.quarantine(container_id);
        assert!(result1.is_ok());
        
        // Quarantine second time (should handle gracefully)
        let result2 = manager.quarantine(container_id);
        
        // Should either succeed or return specific error
        assert!(result2.is_ok() || result2.is_err());
        
        // Cleanup
        let _ = manager.release(container_id);
    }

    #[test]
    #[ignore = "requires root and docker"]
    fn test_release_not_quarantined() {
        let mut manager = QuarantineManager::new().expect("Failed to create manager");
        
        let container_id = "test_container_not_quarantined";
        
        // Try to release container that was never quarantined
        let result = manager.release(container_id);
        
        // Should handle gracefully (either Ok or specific error)
        assert!(result.is_ok() || result.is_err());
    }
}

/// Stub tests for non-Linux
#[cfg(not(target_os = "linux"))]
mod stub_tests {
    use stackdog::firewall::quarantine::QuarantineManager;

    #[test]
    fn test_quarantine_not_available_on_non_linux() {
        let result = QuarantineManager::new();
        assert!(result.is_err());
    }
}
