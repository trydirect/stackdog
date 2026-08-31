//! Tool-use types for AI function calling

use serde::{Deserialize, Serialize};

/// Definition of a tool the AI can call (maps to OpenAI function schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// A tool call requested by the AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Result of executing a tool
#[derive(Debug, Clone, Serialize)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub role: String,
    pub content: String,
}

impl ToolResult {
    pub fn success(tool_call_id: impl Into<String>, content: impl Serialize) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            role: "tool".into(),
            content: serde_json::to_string(&content).unwrap_or_else(|_| "{}".into()),
        }
    }

    pub fn error(tool_call_id: impl Into<String>, message: &str) -> Self {
        Self {
            tool_call_id: tool_call_id.into(),
            role: "tool".into(),
            content: serde_json::json!({ "error": message }).to_string(),
        }
    }
}

/// Helper to build a ToolDef with JSON Schema parameters
pub fn tool_def(
    name: &str,
    description: &str,
    parameters: serde_json::Value,
) -> ToolDef {
    ToolDef {
        tool_type: "function".into(),
        function: FunctionDef {
            name: name.into(),
            description: description.into(),
            parameters,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_def_serializes_to_openai_format() {
        let def = tool_def(
            "check_ip",
            "Check IP status",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string" }
                },
                "required": ["ip"]
            }),
        );

        let json = serde_json::to_value(&def).unwrap();
        assert_eq!(json["type"], "function");
        assert_eq!(json["function"]["name"], "check_ip");
        assert_eq!(json["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn test_tool_result_success_serialization() {
        let result = ToolResult::success("call_1", serde_json::json!({"banned": false}));
        assert_eq!(result.tool_call_id, "call_1");
        assert_eq!(result.role, "tool");
        assert!(result.content.contains("banned"));
    }

    #[test]
    fn test_tool_result_error_serialization() {
        let result = ToolResult::error("call_2", "IP not found");
        assert!(result.content.contains("error"));
        assert!(result.content.contains("IP not found"));
    }
}
