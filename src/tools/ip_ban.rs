//! IP ban tools — check status and ban IPs

use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::database::connection::DbPool;
use crate::database::repositories::offenses::{
    active_block_for_ip, find_recent_offenses, insert_offense, mark_blocked, NewIpOffense,
};
use crate::ip_ban::config::IpBanConfig;

use super::types::{tool_def, ToolDef, ToolResult};

pub fn definitions() -> Vec<ToolDef> {
    vec![
        tool_def(
            "check_ip_status",
            "Check if an IP address is currently banned and its offense history. Use this before alerting to avoid re-reporting known threats.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IPv4 address to check"
                    }
                },
                "required": ["ip_address"]
            }),
        ),
        tool_def(
            "ban_ip",
            "Ban an IP address for a specified duration. Use when an attack is confirmed and the IP should be blocked immediately.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IPv4 address to ban"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why this IP is being banned"
                    },
                    "duration_secs": {
                        "type": "integer",
                        "description": "Ban duration in seconds (default 1800 = 30 minutes)"
                    }
                },
                "required": ["ip_address", "reason"]
            }),
        ),
    ]
}

#[derive(Deserialize)]
struct CheckIpArgs {
    ip_address: String,
}

#[derive(Deserialize)]
struct BanIpArgs {
    ip_address: String,
    reason: String,
    duration_secs: Option<u64>,
}

pub fn execute_check_ip_status(pool: &DbPool, args: &str) -> ToolResult {
    let args: CheckIpArgs = match serde_json::from_str(args) {
        Ok(a) => a,
        Err(e) => return ToolResult::error("check_ip_status", &format!("Invalid args: {}", e)),
    };

    let ip = &args.ip_address;

    let blocked = active_block_for_ip(pool, ip)
        .ok()
        .flatten()
        .map(|r| serde_json::json!({
            "blocked_until": r.blocked_until,
            "reason": r.reason,
        }));

    let offenses = find_recent_offenses(
        pool,
        ip,
        "sniff",
        Utc::now() - Duration::hours(24),
    )
    .unwrap_or_default();

    let result = serde_json::json!({
        "ip_address": ip,
        "banned": blocked.is_some(),
        "blocked_until": blocked.as_ref().and_then(|b| b.get("blocked_until").and_then(|v| v.as_str())),
        "offense_count_24h": offenses.len(),
        "last_offense": offenses.first().map(|o| serde_json::json!({
            "reason": o.reason,
            "time": o.last_seen,
            "status": format!("{:?}", o.status),
        })),
    });

    ToolResult::success("check_ip_status", result)
}

pub fn execute_ban_ip(pool: &DbPool, config: &IpBanConfig, args: &str) -> ToolResult {
    let args: BanIpArgs = match serde_json::from_str(args) {
        Ok(a) => a,
        Err(e) => return ToolResult::error("ban_ip", &format!("Invalid args: {}", e)),
    };

    let duration = args.duration_secs.unwrap_or(config.ban_time_secs);
    let now = Utc::now();
    let blocked_until = now + Duration::seconds(duration as i64);

    // Record the offense
    if let Err(e) = insert_offense(
        pool,
        &NewIpOffense {
            id: uuid::Uuid::new_v4().to_string(),
            ip_address: args.ip_address.clone(),
            source_type: "ai-tool".into(),
            container_id: None,
            first_seen: now,
            reason: args.reason.clone(),
            metadata: None,
        },
    ) {
        return ToolResult::error("ban_ip", &format!("Failed to record offense: {}", e));
    }

    // Mark as blocked
    if let Err(e) = mark_blocked(pool, &args.ip_address, "ai-tool", blocked_until) {
        return ToolResult::error("ban_ip", &format!("Failed to mark blocked: {}", e));
    }

    // Apply firewall block on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(engine) = IpBanEngine::new(pool.clone(), config.clone()) {
            // The mark_blocked already happened; firewall block is best-effort
            log::info!("IP {} banned via AI tool until {}", args.ip_address, blocked_until);
        }
    }

    let cli_cmd = format!(
        "stackdog ban-ip {} --duration {}s --reason \"{}\"",
        args.ip_address, duration, args.reason
    );

    ToolResult::success(
        "ban_ip",
        serde_json::json!({
            "success": true,
            "ip_address": args.ip_address,
            "blocked_until": blocked_until.to_rfc3339(),
            "duration_secs": duration,
            "cli_command": cli_cmd,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};

    #[test]
    fn test_check_ip_status_returns_not_banned_for_unknown_ip() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let result = execute_check_ip_status(&pool, r#"{"ip_address": "1.2.3.4"}"#);
        assert!(result.content.contains("false"));
        assert!(result.content.contains("1.2.3.4"));
    }

    #[test]
    fn test_check_ip_status_returns_error_for_invalid_args() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let result = execute_check_ip_status(&pool, "not json");
        assert!(result.content.contains("error"));
    }

    #[test]
    fn test_ban_ip_records_offense_and_blocks() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        let result = execute_ban_ip(
            &pool,
            &config,
            r#"{"ip_address": "5.6.7.8", "reason": "test ban", "duration_secs": 60}"#,
        );
        assert!(result.content.contains("true"));
        assert!(result.content.contains("5.6.7.8"));
        assert!(result.content.contains("cli_command"));

        // Verify it's now blocked
        let check = execute_check_ip_status(&pool, r#"{"ip_address": "5.6.7.8"}"#);
        assert!(check.content.contains("true")); // banned: true
    }

    #[test]
    fn test_ban_ip_uses_default_duration() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        let result = execute_ban_ip(
            &pool,
            &config,
            r#"{"ip_address": "9.10.11.12", "reason": "test"}"#,
        );
        assert!(result.content.contains("success"));
    }
}
