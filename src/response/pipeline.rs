//! Response action pipeline

use anyhow::Result;
use std::collections::HashMap;

use crate::firewall::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};

/// A named response template that can be executed directly or converted to a chain.
#[derive(Debug, Clone)]
pub struct PipelineAction {
    name: String,
    action: ResponseAction,
}

impl PipelineAction {
    pub fn new(name: impl Into<String>, action: ResponseAction) -> Self {
        Self {
            name: name.into(),
            action,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn action(&self) -> &ResponseAction {
        &self.action
    }
}

/// A reusable response plan composed of ordered actions.
#[derive(Debug, Clone)]
pub struct PipelinePlan {
    name: String,
    actions: Vec<PipelineAction>,
    stop_on_failure: bool,
}

impl PipelinePlan {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            actions: Vec::new(),
            stop_on_failure: true,
        }
    }

    pub fn add_action(&mut self, action: PipelineAction) {
        self.actions.push(action);
    }

    pub fn set_stop_on_failure(&mut self, stop_on_failure: bool) {
        self.stop_on_failure = stop_on_failure;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn actions(&self) -> &[PipelineAction] {
        &self.actions
    }

    pub fn to_chain(&self) -> ResponseChain {
        let mut chain = ResponseChain::new(self.name.clone());
        chain.set_stop_on_failure(self.stop_on_failure);
        for action in &self.actions {
            chain.add_action(action.action.clone());
        }
        chain
    }
}

/// Action pipeline for reusable response orchestration.
pub struct ActionPipeline {
    executor: ResponseExecutor,
    plans: HashMap<String, PipelinePlan>,
}

impl ActionPipeline {
    pub fn new() -> Result<Self> {
        Ok(Self {
            executor: ResponseExecutor::new()?,
            plans: HashMap::new(),
        })
    }

    pub fn with_executor(executor: ResponseExecutor) -> Self {
        Self {
            executor,
            plans: HashMap::new(),
        }
    }

    pub fn register_plan(&mut self, plan: PipelinePlan) {
        self.plans.insert(plan.name().to_string(), plan);
    }

    pub fn get_plan(&self, name: &str) -> Option<&PipelinePlan> {
        self.plans.get(name)
    }

    pub fn has_plan(&self, name: &str) -> bool {
        self.plans.contains_key(name)
    }

    pub fn execute_plan(&mut self, name: &str) -> Result<()> {
        let plan = self
            .plans
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Response plan not found: {}", name))?;
        self.executor.execute_chain(&plan.to_chain())
    }

    pub fn execute_action(&mut self, action: &ResponseAction) -> Result<()> {
        self.executor.execute(action)
    }

    pub fn execution_log(&self) -> Vec<crate::firewall::response::ResponseLog> {
        self.executor.get_log()
    }

    pub fn clear_execution_log(&mut self) {
        self.executor.clear_log();
    }

    pub fn register_default_security_plans(&mut self) {
        let mut quarantine_plan = PipelinePlan::new("quarantine-container");
        quarantine_plan.add_action(PipelineAction::new(
            "quarantine",
            ResponseAction::new(
                ResponseType::QuarantineContainer("{{container_id}}".to_string()),
                "Quarantine compromised container".to_string(),
            ),
        ));
        self.register_plan(quarantine_plan);

        let mut block_mail_plan = PipelinePlan::new("block-mail-port");
        block_mail_plan.add_action(PipelineAction::new(
            "block-port",
            ResponseAction::new(
                ResponseType::BlockPort(25),
                "Block outbound SMTP traffic".to_string(),
            ),
        ));
        self.register_plan(block_mail_plan);
    }
}

impl Default for ActionPipeline {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_plan_builds_chain() {
        let mut plan = PipelinePlan::new("test-plan");
        plan.set_stop_on_failure(false);
        plan.add_action(PipelineAction::new(
            "log",
            ResponseAction::new(ResponseType::LogAction("ok".to_string()), "Log".to_string()),
        ));

        let chain = plan.to_chain();
        assert_eq!(chain.name(), "test-plan");
        assert_eq!(chain.action_count(), 1);
    }

    #[test]
    fn test_pipeline_registers_and_finds_plan() {
        let mut pipeline = ActionPipeline::new().unwrap();
        let plan = PipelinePlan::new("mail-abuse");

        pipeline.register_plan(plan);

        assert!(pipeline.has_plan("mail-abuse"));
        assert!(pipeline.get_plan("mail-abuse").is_some());
    }

    #[test]
    fn test_pipeline_execute_unknown_plan_fails() {
        let mut pipeline = ActionPipeline::new().unwrap();
        let result = pipeline.execute_plan("missing");
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_execute_action_records_log() {
        let mut pipeline = ActionPipeline::new().unwrap();
        let action =
            ResponseAction::new(ResponseType::LogAction("ok".to_string()), "Log".to_string());

        pipeline.execute_action(&action).unwrap();

        let log = pipeline.execution_log();
        assert_eq!(log.len(), 1);
        assert!(log[0].success());
    }

    #[test]
    fn test_pipeline_register_default_security_plans() {
        let mut pipeline = ActionPipeline::new().unwrap();
        pipeline.register_default_security_plans();

        assert!(pipeline.has_plan("quarantine-container"));
        assert!(pipeline.has_plan("block-mail-port"));
    }
}
