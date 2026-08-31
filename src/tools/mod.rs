//! AI tool-use registry
//!
//! Defines tools the AI can call during log analysis and dispatches
//! execution to the appropriate handlers.

pub mod alerts;
pub mod detectors;
pub mod docker;
pub mod ip_ban;
pub mod types;

use std::sync::RwLock;

use crate::database::connection::DbPool;
use crate::detectors::audits::ContainerPosture;
use crate::detectors::DetectorRegistry;
use crate::ip_ban::config::IpBanConfig;

use types::{ToolCall, ToolDef, ToolResult};

/// Central registry holding references to subsystems the AI can query.
pub struct ToolRegistry {
    pool: DbPool,
    ip_ban_config: IpBanConfig,
    detectors: DetectorRegistry,
    /// Pre-fetched container postures (populated each sniff pass)
    postures: RwLock<Vec<ContainerPosture>>,
}

impl ToolRegistry {
    pub fn new(pool: DbPool, ip_ban_config: IpBanConfig, detectors: DetectorRegistry) -> Self {
        Self {
            pool,
            ip_ban_config,
            detectors,
            postures: RwLock::new(Vec::new()),
        }
    }

    /// Update container postures (called each sniff pass before analysis)
    pub fn set_postures(&self, postures: Vec<ContainerPosture>) {
        *self.postures.write().unwrap() = postures;
    }

    /// All tool definitions for the OpenAI `tools` array
    pub fn definitions(&self) -> Vec<ToolDef> {
        let mut defs = Vec::new();
        defs.extend(ip_ban::definitions());
        defs.extend(docker::definitions());
        defs.extend(alerts::definitions());
        defs.extend(detectors::definitions());
        defs
    }

    /// Execute a tool call and return the result
    pub async fn execute(&self, call: &ToolCall) -> ToolResult {
        let args = &call.function.arguments;
        match call.function.name.as_str() {
            "check_ip_status" => ip_ban::execute_check_ip_status(&self.pool, args),
            "ban_ip" => ip_ban::execute_ban_ip(&self.pool, &self.ip_ban_config, args),
            "list_containers" => {
                let postures = self.postures.read().unwrap();
                docker::execute_list_containers(&postures)
            }
            "get_container_posture" => {
                let postures = self.postures.read().unwrap();
                docker::execute_get_container_posture(&postures, args)
            }
            "recent_alerts" => alerts::execute_recent_alerts(&self.pool, args).await,
            "run_detectors" => detectors::execute_run_detectors(&self.detectors, args),
            unknown => ToolResult::error(unknown, &format!("Unknown tool: {}", unknown)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};

    fn make_registry() -> ToolRegistry {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        ToolRegistry::new(pool, IpBanConfig::from_env(), DetectorRegistry::default())
    }

    #[test]
    fn test_definitions_include_all_tools() {
        let registry = make_registry();
        let defs = registry.definitions();
        let names: Vec<&str> = defs.iter().map(|d| d.function.name.as_str()).collect();
        assert!(names.contains(&"check_ip_status"));
        assert!(names.contains(&"ban_ip"));
        assert!(names.contains(&"list_containers"));
        assert!(names.contains(&"get_container_posture"));
        assert!(names.contains(&"recent_alerts"));
        assert!(names.contains(&"run_detectors"));
    }

    #[actix_rt::test]
    async fn test_execute_unknown_tool_returns_error() {
        let registry = make_registry();
        let call = ToolCall {
            id: "call_1".into(),
            call_type: "function".into(),
            function: types::FunctionCall {
                name: "nonexistent_tool".into(),
                arguments: "{}".into(),
            },
        };
        let result = registry.execute(&call).await;
        assert!(result.content.contains("Unknown tool"));
    }

    #[actix_rt::test]
    async fn test_execute_check_ip_status() {
        let registry = make_registry();
        let call = ToolCall {
            id: "call_2".into(),
            call_type: "function".into(),
            function: types::FunctionCall {
                name: "check_ip_status".into(),
                arguments: r#"{"ip_address": "1.2.3.4"}"#.into(),
            },
        };
        let result = registry.execute(&call).await;
        assert!(result.content.contains("1.2.3.4"));
        assert!(result.content.contains("banned"));
    }
}
