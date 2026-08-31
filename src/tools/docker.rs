//! Docker tools — list containers and inspect posture

use crate::detectors::audits::ContainerPosture;
use crate::tools::types::{tool_def, ToolDef, ToolResult};

pub fn definitions() -> Vec<ToolDef> {
    vec![
        tool_def(
            "list_containers",
            "List all running containers with their security posture. Use to understand the environment before analyzing alerts.",
            serde_json::json!({
                "type": "object",
                "properties": {},
            }),
        ),
        tool_def(
            "get_container_posture",
            "Get detailed security posture for a specific container: privileged mode, network mode, capabilities, mounts.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "container_name": {
                        "type": "string",
                        "description": "Name or ID of the container"
                    }
                },
                "required": ["container_name"]
            }),
        ),
    ]
}

/// Execute list_containers using pre-fetched postures (avoids async Docker connection)
pub fn execute_list_containers(postures: &[ContainerPosture]) -> ToolResult {
    let containers: Vec<serde_json::Value> = postures
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "image": p.image,
                "privileged": p.privileged,
                "network_mode": p.network_mode,
                "pid_mode": p.pid_mode,
                "cap_add": p.cap_add,
                "has_docker_socket": p.mounts.iter().any(|m: &String| m.contains("/var/run/docker.sock")),
            })
        })
        .collect();

    ToolResult::success(
        "list_containers",
        serde_json::json!({ "containers": containers }),
    )
}

/// Execute get_container_posture using pre-fetched postures
pub fn execute_get_container_posture(postures: &[ContainerPosture], args: &str) -> ToolResult {
    let name = match serde_json::from_str::<serde_json::Value>(args) {
        Ok(v) => v["container_name"].as_str().unwrap_or("").to_string(),
        Err(e) => {
            return ToolResult::error("get_container_posture", &format!("Invalid args: {}", e))
        }
    };

    match postures
        .iter()
        .find(|p| p.name == name || p.container_id == name)
    {
        Some(p) => ToolResult::success(
            "get_container_posture",
            serde_json::json!({
                "name": p.name,
                "image": p.image,
                "container_id": p.container_id,
                "privileged": p.privileged,
                "network_mode": p.network_mode,
                "pid_mode": p.pid_mode,
                "cap_add": p.cap_add,
                "mounts": p.mounts,
            }),
        ),
        None => ToolResult::error(
            "get_container_posture",
            &format!("Container '{}' not found", name),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_postures() -> Vec<ContainerPosture> {
        vec![
            ContainerPosture {
                container_id: "abc123".into(),
                name: "nginx".into(),
                image: "nginx:latest".into(),
                privileged: false,
                network_mode: Some("bridge".into()),
                pid_mode: None,
                cap_add: vec![],
                mounts: vec![],
            },
            ContainerPosture {
                container_id: "def456".into(),
                name: "redis".into(),
                image: "redis:7".into(),
                privileged: false,
                network_mode: Some("host".into()),
                pid_mode: None,
                cap_add: vec![],
                mounts: vec!["/var/run/docker.sock:/var/run/docker.sock:rw".into()],
            },
        ]
    }

    #[test]
    fn test_list_containers_returns_all() {
        let postures = sample_postures();
        let result = execute_list_containers(&postures);
        assert!(result.content.contains("nginx"));
        assert!(result.content.contains("redis"));
        assert!(result.content.contains("docker_socket"));
    }

    #[test]
    fn test_get_container_posture_found() {
        let postures = sample_postures();
        let result = execute_get_container_posture(&postures, r#"{"container_name": "redis"}"#);
        assert!(result.content.contains("host"));
        assert!(result.content.contains("docker.sock"));
    }

    #[test]
    fn test_get_container_posture_not_found() {
        let postures = sample_postures();
        let result = execute_get_container_posture(&postures, r#"{"container_name": "ghost"}"#);
        assert!(result.content.contains("error"));
        assert!(result.content.contains("not found"));
    }
}
