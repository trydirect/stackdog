//! Automated response tests
//!
//! Tests for automated response actions

use stackdog::firewall::response::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};
use stackdog::alerting::alert::{Alert, AlertSeverity, AlertType};

#[test]
fn test_response_action_creation() {
    let action = ResponseAction::new(
        ResponseType::BlockIP("192.168.1.100".to_string()),
        "Block malicious IP".to_string(),
    );
    
    assert_eq!(action.action_type(), ResponseType::BlockIP("192.168.1.100".to_string()));
    assert_eq!(action.description(), "Block malicious IP");
}

#[test]
fn test_response_action_execution() {
    let action = ResponseAction::new(
        ResponseType::LogAction("Test response".to_string()),
        "Test action".to_string(),
    );
    
    // Log action should always succeed
    let result = action.execute();
    assert!(result.is_ok());
}

#[test]
fn test_response_action_types() {
    let _block_ip = ResponseType::BlockIP("10.0.0.1".to_string());
    let _block_port = ResponseType::BlockPort(22);
    let _quarantine = ResponseType::QuarantineContainer("abc123".to_string());
    let _kill_process = ResponseType::KillProcess(1234);
    let _log = ResponseType::LogAction("test".to_string());
    let _alert = ResponseType::SendAlert("test".to_string());
}

#[test]
fn test_response_chain_creation() {
    let chain = ResponseChain::new("test_chain");
    
    assert_eq!(chain.name(), "test_chain");
    assert_eq!(chain.action_count(), 0);
}

#[test]
fn test_response_chain_add_action() {
    let mut chain = ResponseChain::new("test_chain");
    
    let action1 = ResponseAction::new(
        ResponseType::LogAction("Action 1".to_string()),
        "First action".to_string(),
    );
    
    let action2 = ResponseAction::new(
        ResponseType::LogAction("Action 2".to_string()),
        "Second action".to_string(),
    );
    
    chain.add_action(action1);
    chain.add_action(action2);
    
    assert_eq!(chain.action_count(), 2);
}

#[test]
fn test_response_chain_execution() {
    let mut chain = ResponseChain::new("test_chain");
    
    let action1 = ResponseAction::new(
        ResponseType::LogAction("Action 1".to_string()),
        "First action".to_string(),
    );
    
    let action2 = ResponseAction::new(
        ResponseType::LogAction("Action 2".to_string()),
        "Second action".to_string(),
    );
    
    chain.add_action(action1);
    chain.add_action(action2);
    
    let result = chain.execute();
    
    assert!(result.is_ok());
}

#[test]
fn test_response_chain_stop_on_failure() {
    let mut chain = ResponseChain::new("test_chain");
    chain.set_stop_on_failure(true);
    
    // All log actions should succeed
    let action = ResponseAction::new(
        ResponseType::LogAction("test".to_string()),
        "Test".to_string(),
    );
    
    chain.add_action(action);
    
    let result = chain.execute();
    assert!(result.is_ok());
}

#[test]
fn test_response_executor_creation() {
    let executor = ResponseExecutor::new();
    assert!(executor.is_ok());
}

#[test]
fn test_response_executor_execute() {
    let mut executor = ResponseExecutor::new().expect("Failed to create executor");
    
    let action = ResponseAction::new(
        ResponseType::LogAction("Test response".to_string()),
        "Test".to_string(),
    );
    
    let result = executor.execute(&action);
    assert!(result.is_ok());
}

#[test]
fn test_response_from_alert() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat".to_string(),
    );
    
    // Create response from alert
    let action = ResponseAction::from_alert(&alert, ResponseType::QuarantineContainer("test".to_string()));
    
    assert!(action.description().contains("Critical threat"));
}

#[test]
fn test_quarantine_response_is_explicitly_unsupported_in_sync_pipeline() {
    let action = ResponseAction::new(
        ResponseType::QuarantineContainer("test-container".to_string()),
        "Quarantine container".to_string(),
    );

    let error = action.execute().unwrap_err().to_string();
    assert!(error.contains("Docker-based container quarantine flow"));
    assert!(error.contains("test-container"));
}

#[test]
fn test_response_retry() {
    let mut action = ResponseAction::new(
        ResponseType::LogAction("Test".to_string()),
        "Test action".to_string(),
    );
    
    action.set_retry_config(3, 1000);  // 3 retries, 1000ms delay
    
    assert_eq!(action.max_retries(), 3);
    assert_eq!(action.retry_delay_ms(), 1000);
}

#[test]
fn test_response_logging() {
    use stackdog::firewall::response::ResponseLog;
    use chrono::Utc;
    
    let log = ResponseLog::new(
        "test_action".to_string(),
        true,
        Some("Success".to_string()),
    );
    
    assert_eq!(log.action_name(), "test_action");
    assert!(log.success());
    assert!(log.timestamp() <= Utc::now());
}

#[test]
fn test_response_audit_trail() {
    use stackdog::firewall::response::ResponseAudit;
    
    let mut audit = ResponseAudit::new();
    
    audit.record(
        "test_action".to_string(),
        true,
        Some("Success".to_string()),
    );
    
    let history = audit.get_history();
    assert_eq!(history.len(), 1);
}
