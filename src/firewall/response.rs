//! Automated response
//!
//! Implements automated threat response actions

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::process::Command;
use std::sync::{Arc, RwLock};

use crate::alerting::alert::Alert;
use crate::firewall::backend::FirewallBackend;
use crate::firewall::{IptablesBackend, NfTablesBackend};

/// Response action types
#[derive(Debug, Clone)]
pub enum ResponseType {
    BlockIP(String),
    BlockPort(u16),
    QuarantineContainer(String),
    KillProcess(u32),
    LogAction(String),
    SendAlert(String),
    Custom(String),
}

/// Response action
#[derive(Debug, Clone)]
pub struct ResponseAction {
    action_type: ResponseType,
    description: String,
    max_retries: u32,
    retry_delay_ms: u64,
}

impl ResponseAction {
    fn quarantine_container_error(container_id: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "Docker-based container quarantine flow is required for {} because firewall backends do not implement container-specific quarantine. Use the Docker/API quarantine path instead.",
            container_id
        )
    }

    fn preferred_backend() -> Result<Box<dyn FirewallBackend>> {
        if let Ok(mut backend) = NfTablesBackend::new() {
            backend.initialize()?;
            return Ok(Box::new(backend));
        }

        let mut backend = IptablesBackend::new()?;
        backend.initialize()?;
        Ok(Box::new(backend))
    }

    /// Create a new response action
    pub fn new(action_type: ResponseType, description: String) -> Self {
        Self {
            action_type,
            description,
            max_retries: 0,
            retry_delay_ms: 0,
        }
    }

    /// Create response from alert
    pub fn from_alert(alert: &Alert, action_type: ResponseType) -> Self {
        Self {
            action_type,
            description: format!("Response to: {}", alert.message()),
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }

    /// Set retry configuration
    pub fn set_retry_config(&mut self, max_retries: u32, retry_delay_ms: u64) {
        self.max_retries = max_retries;
        self.retry_delay_ms = retry_delay_ms;
    }

    /// Get action type
    pub fn action_type(&self) -> ResponseType {
        self.action_type.clone()
    }

    /// Get description
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get max retries
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Get retry delay
    pub fn retry_delay_ms(&self) -> u64 {
        self.retry_delay_ms
    }

    /// Execute the action
    pub fn execute(&self) -> Result<()> {
        match &self.action_type {
            ResponseType::LogAction(msg) => {
                log::info!("Response action: {}", msg);
                Ok(())
            }
            ResponseType::BlockIP(ip) => {
                let backend = Self::preferred_backend()?;
                backend.block_ip(ip)
            }
            ResponseType::BlockPort(port) => {
                let backend = Self::preferred_backend()?;
                backend.block_port(*port)
            }
            ResponseType::QuarantineContainer(id) => Err(Self::quarantine_container_error(id)),
            ResponseType::KillProcess(pid) => {
                let output = Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .output()?;
                if !output.status.success() {
                    anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
                }
                Ok(())
            }
            ResponseType::SendAlert(msg) => {
                log::info!("Would send alert: {}", msg);
                Ok(())
            }
            ResponseType::Custom(cmd) => {
                log::info!("Would execute custom command: {}", cmd);
                Ok(())
            }
        }
    }

    /// Execute with retries
    pub fn execute_with_retry(&self) -> Result<()> {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match self.execute() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        log::warn!(
                            "Action failed (attempt {}/{}), retrying...",
                            attempt + 1,
                            self.max_retries + 1
                        );
                        std::thread::sleep(std::time::Duration::from_millis(self.retry_delay_ms));
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Action failed")))
    }
}

/// Response chain for executing multiple actions
#[derive(Debug)]
pub struct ResponseChain {
    name: String,
    actions: Vec<ResponseAction>,
    stop_on_failure: bool,
}

impl ResponseChain {
    /// Create a new response chain
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            actions: Vec::new(),
            stop_on_failure: false,
        }
    }

    /// Add an action to the chain
    pub fn add_action(&mut self, action: ResponseAction) {
        self.actions.push(action);
    }

    /// Set stop on failure
    pub fn set_stop_on_failure(&mut self, stop: bool) {
        self.stop_on_failure = stop;
    }

    /// Get chain name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get action count
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Execute all actions in chain
    pub fn execute(&self) -> Result<()> {
        for (i, action) in self.actions.iter().enumerate() {
            log::debug!(
                "Executing action {}/{}: {}",
                i + 1,
                self.actions.len(),
                action.description()
            );

            match action.execute() {
                Ok(()) => {}
                Err(e) => {
                    if self.stop_on_failure {
                        log::error!("Action failed, stopping chain: {}", e);
                        return Err(e);
                    } else {
                        log::warn!("Action failed, continuing: {}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Response executor
pub struct ResponseExecutor {
    log: Arc<RwLock<Vec<ResponseLog>>>,
}

impl ResponseExecutor {
    /// Create a new response executor
    pub fn new() -> Result<Self> {
        Ok(Self {
            log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Execute a response action
    pub fn execute(&mut self, action: &ResponseAction) -> Result<()> {
        let _start = Utc::now();
        let result = action.execute();
        let _end = Utc::now();

        // Log the execution
        let log_entry = ResponseLog::new(
            action.description().to_string(),
            result.is_ok(),
            result.as_ref().err().map(|e| e.to_string()),
        );

        {
            let mut log = self.log.write().unwrap();
            log.push(log_entry);
        }

        result
    }

    /// Execute a response chain
    pub fn execute_chain(&mut self, chain: &ResponseChain) -> Result<()> {
        log::info!("Executing response chain: {}", chain.name());
        chain.execute()
    }

    /// Get execution log
    pub fn get_log(&self) -> Vec<ResponseLog> {
        let log = self.log.read().unwrap();
        log.clone()
    }

    /// Clear execution log
    pub fn clear_log(&mut self) {
        let mut log = self.log.write().unwrap();
        log.clear();
    }
}

impl Default for ResponseExecutor {
    fn default() -> Self {
        Self::new().expect("Failed to create ResponseExecutor")
    }
}

/// Response log entry
#[derive(Debug, Clone)]
pub struct ResponseLog {
    action_name: String,
    success: bool,
    error: Option<String>,
    timestamp: DateTime<Utc>,
}

impl ResponseLog {
    pub fn new(action_name: String, success: bool, error: Option<String>) -> Self {
        Self {
            action_name,
            success,
            error,
            timestamp: Utc::now(),
        }
    }

    pub fn action_name(&self) -> &str {
        &self.action_name
    }

    pub fn success(&self) -> bool {
        self.success
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

/// Response audit trail
pub struct ResponseAudit {
    history: Vec<ResponseLog>,
}

impl ResponseAudit {
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
        }
    }

    pub fn record(&mut self, action_name: String, success: bool, error: Option<String>) {
        self.history
            .push(ResponseLog::new(action_name, success, error));
    }

    pub fn get_history(&self) -> &[ResponseLog] {
        &self.history
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }
}

impl Default for ResponseAudit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_response_action_creation() {
        let action = ResponseAction::new(
            ResponseType::LogAction("test".to_string()),
            "Test action".to_string(),
        );

        assert_eq!(action.description(), "Test action");
    }

    #[test]
    fn test_response_action_execution() {
        let action = ResponseAction::new(
            ResponseType::LogAction("test".to_string()),
            "Test".to_string(),
        );

        let result = action.execute();
        assert!(result.is_ok());
    }

    #[test]
    fn test_response_chain_creation() {
        let chain = ResponseChain::new("test_chain");
        assert_eq!(chain.name(), "test_chain");
        assert_eq!(chain.action_count(), 0);
    }

    #[test]
    fn test_response_chain_execution() {
        let mut chain = ResponseChain::new("test");

        let action = ResponseAction::new(
            ResponseType::LogAction("test".to_string()),
            "Test".to_string(),
        );

        chain.add_action(action);

        let result = chain.execute();
        assert!(result.is_ok());
    }

    #[test]
    fn test_response_log_creation() {
        let log = ResponseLog::new("test_action".to_string(), true, None);

        assert!(log.success());
        assert_eq!(log.action_name(), "test_action");
    }

    #[test]
    fn test_quarantine_action_returns_actionable_error() {
        let action = ResponseAction::new(
            ResponseType::QuarantineContainer("container-1".to_string()),
            "Quarantine".to_string(),
        );

        let error = action.execute().unwrap_err().to_string();
        assert!(error.contains("Docker-based container quarantine flow"));
        assert!(error.contains("container-1"));
    }

    #[test]
    fn test_response_chain_stops_on_failure() {
        let mut chain = ResponseChain::new("stop-on-failure");
        chain.set_stop_on_failure(true);
        chain.add_action(ResponseAction::new(
            ResponseType::QuarantineContainer("container-1".to_string()),
            "Quarantine".to_string(),
        ));
        chain.add_action(ResponseAction::new(
            ResponseType::LogAction("after".to_string()),
            "After".to_string(),
        ));

        let result = chain.execute();
        assert!(result.is_err());
    }

    #[test]
    fn test_response_chain_continues_when_failure_allowed() {
        let mut chain = ResponseChain::new("continue-on-failure");
        chain.add_action(ResponseAction::new(
            ResponseType::QuarantineContainer("container-1".to_string()),
            "Quarantine".to_string(),
        ));
        chain.add_action(ResponseAction::new(
            ResponseType::LogAction("after".to_string()),
            "After".to_string(),
        ));

        let result = chain.execute();
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_with_retry_honors_retry_count() {
        let mut action = ResponseAction::new(
            ResponseType::QuarantineContainer("container-1".to_string()),
            "Quarantine".to_string(),
        );
        action.set_retry_config(2, 0);

        let started = Instant::now();
        let result = action.execute_with_retry();

        assert!(result.is_err());
        assert!(started.elapsed().as_millis() < 100);
    }

    #[test]
    fn test_response_executor_records_failed_action() {
        let mut executor = ResponseExecutor::new().unwrap();
        let action = ResponseAction::new(
            ResponseType::QuarantineContainer("container-1".to_string()),
            "Quarantine".to_string(),
        );

        let result = executor.execute(&action);
        let log = executor.get_log();

        assert!(result.is_err());
        assert_eq!(log.len(), 1);
        assert!(!log[0].success());
        assert!(log[0].error().is_some());
        assert!(log[0]
            .error()
            .unwrap()
            .contains("Docker-based container quarantine flow"));
    }
}
