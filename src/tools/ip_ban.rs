//! IP ban tools — check status, ban, and release IPs

use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::database::connection::DbPool;
use crate::database::repositories::offenses::{active_block_for_ip, recent_offenses_for_ip};
use crate::ip_ban::{BanOutcome, IpBanConfig, IpBanEngine, LocalIpContext};

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
            "Ban an IP address for a specified duration. Use when an attack is confirmed and the IP should be blocked immediately. Only plain public IPv4 addresses can be banned: private, local, and allowlisted addresses are refused because blocking them takes the service down.",
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
        tool_def(
            "unban_ip",
            "Release a ban early and remove the firewall rules for an IP address. Use when an address was banned by mistake or the ban is no longer justified.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IPv4 address to release"
                    }
                },
                "required": ["ip_address"]
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

    let blocked = active_block_for_ip(pool, ip).ok().flatten().map(|r| {
        serde_json::json!({
            "blocked_until": r.blocked_until,
            "reason": r.reason,
        })
    });

    // Every source type, not just "sniff": the ban check above spans them all,
    // so narrowing here could report a banned address with no offenses.
    let offenses =
        recent_offenses_for_ip(pool, ip, Utc::now() - Duration::hours(24)).unwrap_or_default();
    // The tally lives in offense_count; one row is one (ip, source_type) pair,
    // not one detection.
    let offense_count_24h: u32 = offenses.iter().map(|offense| offense.offense_count).sum();

    let result = serde_json::json!({
        "ip_address": ip,
        "banned": blocked.is_some(),
        "blocked_until": blocked.as_ref().and_then(|b| b.get("blocked_until").and_then(|v| v.as_str())),
        "offense_count_24h": offense_count_24h,
        "last_offense": offenses.first().map(|o| serde_json::json!({
            "reason": o.reason,
            "time": o.last_seen,
            "status": format!("{:?}", o.status),
        })),
    });

    ToolResult::success("check_ip_status", result)
}

pub async fn execute_ban_ip(pool: &DbPool, config: &IpBanConfig, args: &str) -> ToolResult {
    let args: BanIpArgs = match serde_json::from_str(args) {
        Ok(a) => a,
        Err(e) => return ToolResult::error("ban_ip", &format!("Invalid args: {}", e)),
    };

    let engine = IpBanEngine::new(pool.clone(), config.clone())
        .with_local_context(LocalIpContext::discover_local());

    // Through the engine: the same gate that stops the sniff path from banning
    // infrastructure stops a tool call. A raw mark_blocked here used to accept
    // any string, CIDR ranges included.
    let outcome = match engine
        .ban_now(
            &args.ip_address,
            &args.reason,
            "ai-tool",
            args.duration_secs,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return ToolResult::error("ban_ip", &format!("Failed to ban IP: {}", e)),
    };

    match outcome {
        BanOutcome::Refused(refusal) => ToolResult::error(
            "ban_ip",
            &format!("Refused to ban {}: {}", args.ip_address, refusal.reason()),
        ),
        BanOutcome::AlreadyBanned => ToolResult::success(
            "ban_ip",
            serde_json::json!({
                "success": true,
                "ip_address": args.ip_address,
                "already_banned": true,
            }),
        ),
        BanOutcome::Banned { blocked_until } => {
            log::info!(
                "IP {} banned via AI tool until {}",
                args.ip_address,
                blocked_until
            );

            let duration = args.duration_secs.unwrap_or(config.ban_time_secs);
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
    }
}

#[derive(Deserialize)]
struct UnbanIpArgs {
    ip_address: String,
}

pub async fn execute_unban_ip(pool: &DbPool, config: &IpBanConfig, args: &str) -> ToolResult {
    let args: UnbanIpArgs = match serde_json::from_str(args) {
        Ok(a) => a,
        Err(e) => return ToolResult::error("unban_ip", &format!("Invalid args: {}", e)),
    };

    let engine = IpBanEngine::new(pool.clone(), config.clone())
        .with_local_context(LocalIpContext::discover_local());

    match engine.unban_ip(&args.ip_address).await {
        Ok(true) => ToolResult::success(
            "unban_ip",
            serde_json::json!({
                "success": true,
                "ip_address": args.ip_address,
                "released": true,
            }),
        ),
        Ok(false) => ToolResult::success(
            "unban_ip",
            serde_json::json!({
                "success": true,
                "ip_address": args.ip_address,
                "released": false,
                "note": "no active ban for this address",
            }),
        ),
        Err(e) => ToolResult::error("unban_ip", &format!("Failed to release ban: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};
    use crate::database::repositories::offenses::{record_offense_occurrence, NewIpOffense};

    #[cfg(target_os = "linux")]
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|stdout| stdout.trim() == "0")
            .unwrap_or(false)
    }

    #[test]
    fn test_check_ip_status_returns_not_banned_for_unknown_ip() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let result = execute_check_ip_status(&pool, r#"{"ip_address": "1.2.3.4"}"#);
        assert!(result.content.contains("false"));
        assert!(result.content.contains("1.2.3.4"));
    }

    #[test]
    fn test_check_ip_status_reports_the_tally_not_the_row_count() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let window_start = Utc::now() - Duration::hours(24);

        // Seven detections from the sniffer plus one from the AI tool live in
        // two rows; the model must be told eight, not two.
        for _ in 0..7 {
            record_offense_occurrence(
                &pool,
                &NewIpOffense {
                    id: uuid::Uuid::new_v4().to_string(),
                    ip_address: "9.9.9.9".into(),
                    source_type: "sniff".into(),
                    container_id: None,
                    first_seen: Utc::now(),
                    reason: "ssh".into(),
                    metadata: None,
                },
                window_start,
            )
            .unwrap();
        }
        record_offense_occurrence(
            &pool,
            &NewIpOffense {
                id: uuid::Uuid::new_v4().to_string(),
                ip_address: "9.9.9.9".into(),
                source_type: "ai-tool".into(),
                container_id: None,
                first_seen: Utc::now(),
                reason: "manual".into(),
                metadata: None,
            },
            window_start,
        )
        .unwrap();

        let result = execute_check_ip_status(&pool, r#"{"ip_address": "9.9.9.9"}"#);
        let payload: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(payload["offense_count_24h"], 8);
    }

    #[test]
    fn test_check_ip_status_returns_error_for_invalid_args() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let result = execute_check_ip_status(&pool, "not json");
        assert!(result.content.contains("error"));
    }

    #[actix_rt::test]
    async fn test_ban_ip_records_offense_and_blocks() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        let result = execute_ban_ip(
            &pool,
            &config,
            r#"{"ip_address": "5.6.7.8", "reason": "test ban", "duration_secs": 60}"#,
        )
        .await;

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            assert!(
                result.content.contains("error"),
                "ban without CAP_NET_ADMIN must report the firewall failure: {}",
                result.content
            );
            return;
        }

        assert!(result.content.contains("true"));
        assert!(result.content.contains("5.6.7.8"));
        assert!(result.content.contains("cli_command"));

        // Verify it's now blocked
        let check = execute_check_ip_status(&pool, r#"{"ip_address": "5.6.7.8"}"#);
        assert!(check.content.contains("true")); // banned: true
    }

    #[actix_rt::test]
    async fn test_ban_ip_uses_default_duration() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        let result = execute_ban_ip(
            &pool,
            &config,
            r#"{"ip_address": "9.10.11.12", "reason": "test"}"#,
        )
        .await;

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            assert!(
                result.content.contains("error"),
                "ban without CAP_NET_ADMIN must report the firewall failure: {}",
                result.content
            );
            return;
        }

        assert!(result.content.contains("success"));
    }

    #[actix_rt::test]
    async fn test_ban_ip_refuses_cidr_and_infrastructure_addresses() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        // A range would drop a whole docker network; a container address would
        // drop a service peer. Neither may be banned from here. The refusal
        // happens before any firewall write, so this holds for every user.
        for ip in ["172.16.0.0/12", "10.0.0.5", "127.0.0.1", "not-an-ip"] {
            let result = execute_ban_ip(
                &pool,
                &config,
                &format!(r#"{{"ip_address": "{ip}", "reason": "test"}}"#),
            )
            .await;
            assert!(
                result.content.contains("Refused") || result.content.contains("error"),
                "{ip} must not be bannable, got: {}",
                result.content
            );
        }
    }

    #[actix_rt::test]
    async fn test_unban_ip_releases_a_ban() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let config = IpBanConfig::from_env();

        let banned = execute_ban_ip(
            &pool,
            &config,
            r#"{"ip_address": "5.6.7.8", "reason": "test", "duration_secs": 60}"#,
        )
        .await;

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            assert!(
                banned.content.contains("error"),
                "ban without CAP_NET_ADMIN must report the firewall failure: {}",
                banned.content
            );
            return;
        }

        assert!(banned.content.contains("success"));

        let released = execute_unban_ip(&pool, &config, r#"{"ip_address": "5.6.7.8"}"#).await;
        assert!(released.content.contains("released"));

        let check = execute_check_ip_status(&pool, r#"{"ip_address": "5.6.7.8"}"#);
        let payload: serde_json::Value = serde_json::from_str(&check.content).unwrap();
        assert_eq!(payload["banned"], false);
    }
}
