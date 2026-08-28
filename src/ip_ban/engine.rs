use crate::alerting::notifications::{dispatch_stored_alert, env_flag_enabled, NotificationConfig};
use crate::alerting::{AlertSeverity, AlertType};
use crate::database::models::{Alert, AlertMetadata};
use crate::database::repositories::offenses::{
    active_block_for_ip, expired_blocks, find_recent_offenses, insert_offense, mark_blocked,
    mark_released, NewIpOffense, OffenseMetadata,
};
use crate::database::{create_alert, DbPool};
use crate::ip_ban::config::IpBanConfig;
use anyhow::Result;
use chrono::{Duration, Utc};
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::firewall::backend::FirewallBackend;

#[derive(Debug, Clone)]
pub struct OffenseInput {
    pub ip_address: String,
    pub source_type: String,
    pub reason: String,
    pub severity: AlertSeverity,
    pub container_id: Option<String>,
    pub source_path: Option<String>,
    pub sample_line: Option<String>,
}

pub struct IpBanEngine {
    pool: DbPool,
    config: IpBanConfig,
}

impl IpBanEngine {
    pub fn new(pool: DbPool, config: IpBanConfig) -> Self {
        Self { pool, config }
    }

    pub fn config(&self) -> &IpBanConfig {
        &self.config
    }

    pub async fn record_offense(&self, offense: OffenseInput) -> Result<bool> {
        if active_block_for_ip(&self.pool, &offense.ip_address)?.is_some() {
            return Ok(false);
        }

        let now = Utc::now();
        insert_offense(
            &self.pool,
            &NewIpOffense {
                id: Uuid::new_v4().to_string(),
                ip_address: offense.ip_address.clone(),
                source_type: offense.source_type.clone(),
                container_id: offense.container_id.clone(),
                first_seen: now,
                reason: offense.reason.clone(),
                metadata: Some(OffenseMetadata {
                    source_path: offense.source_path.clone(),
                    sample_line: offense.sample_line.clone(),
                }),
            },
        )?;

        let recent = find_recent_offenses(
            &self.pool,
            &offense.ip_address,
            &offense.source_type,
            now - Duration::seconds(self.config.find_time_secs as i64),
        )?;

        if recent.len() as u32 >= self.config.max_retries {
            self.block_ip(&offense, now).await?;
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn unban_expired(&self) -> Result<usize> {
        let now = Utc::now();
        let expired = expired_blocks(&self.pool, now)?;
        let mut released = 0;

        for offense in expired {
            #[cfg(target_os = "linux")]
            self.with_firewall_backend(|backend| backend.unblock_ip(&offense.ip_address))?;

            mark_released(&self.pool, &offense.id)?;
            let alert = create_alert(
                &self.pool,
                Alert::new(
                    AlertType::SystemEvent,
                    AlertSeverity::Info,
                    format!("Released IP ban for {}", offense.ip_address),
                )
                .with_metadata(
                    AlertMetadata::default()
                        .with_source("ip_ban")
                        .with_reason(format!("Released expired ban for {}", offense.ip_address)),
                ),
            )
            .await?;
            self.notify_action_alert(&alert, "STACKDOG_NOTIFY_IP_BAN_ACTIONS", "ip ban release")
                .await;
            released += 1;
        }

        Ok(released)
    }

    async fn block_ip(&self, offense: &OffenseInput, now: chrono::DateTime<Utc>) -> Result<()> {
        #[cfg(target_os = "linux")]
        self.with_firewall_backend(|backend| backend.block_ip(&offense.ip_address))?;

        let blocked_until = now + Duration::seconds(self.config.ban_time_secs as i64);
        mark_blocked(
            &self.pool,
            &offense.ip_address,
            &offense.source_type,
            blocked_until,
        )?;

        let alert = create_alert(
            &self.pool,
            Alert::new(
                AlertType::ThresholdExceeded,
                offense.severity,
                format!(
                    "Blocked IP {} after repeated {} offenses",
                    offense.ip_address, offense.source_type
                ),
            )
            .with_metadata({
                let mut metadata = AlertMetadata::default()
                    .with_source("ip_ban")
                    .with_reason(offense.reason.clone());
                if let Some(container_id) = &offense.container_id {
                    metadata = metadata.with_container_id(container_id.clone());
                }
                metadata
            }),
        )
        .await?;
        self.notify_action_alert(&alert, "STACKDOG_NOTIFY_IP_BAN_ACTIONS", "ip ban")
            .await;

        Ok(())
    }

    async fn notify_action_alert(&self, alert: &Alert, env_toggle: &str, action_name: &str) {
        if !env_flag_enabled(env_toggle, true) {
            return;
        }

        let config = NotificationConfig::from_env();
        if let Err(err) = dispatch_stored_alert(alert, &config).await {
            log::warn!("Failed to send {} notification: {}", action_name, err);
        }
    }

    #[cfg(target_os = "linux")]
    fn with_firewall_backend<F>(&self, action: F) -> Result<()>
    where
        F: FnOnce(&dyn crate::firewall::FirewallBackend) -> Result<()>,
    {
        if let Ok(mut backend) = crate::firewall::NfTablesBackend::new() {
            backend.initialize()?;
            return action(&backend);
        }

        let mut backend = crate::firewall::IptablesBackend::new()?;
        backend.initialize()?;
        action(&backend)
    }

    pub fn extract_ip_candidates(line: &str) -> Vec<String> {
        line.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
            .filter(|part| !part.is_empty())
            .filter(|part| is_ipv4(part))
            .map(str::to_string)
            .collect()
    }

    /// Extract the real client IP from X-Forwarded-For / X-Real-IP headers in a
    /// log line.  Returns the first public-routable IP found, or None.
    pub fn extract_forwarded_ip(line: &str) -> Option<String> {
        let lower = line.to_ascii_lowercase();

        // Try X-Forwarded-For: client, proxy1, proxy2
        if let Some(start) = lower.find("x-forwarded-for:") {
            let after = &line[start + 16..];
            let value = after.split('"').next().unwrap_or(after);
            for candidate in value.split(',') {
                let ip = candidate.trim();
                if is_ipv4(ip) {
                    return Some(ip.to_string());
                }
            }
        }

        // Try X-Real-IP: <ip>
        if let Some(start) = lower.find("x-real-ip:") {
            let after = &line[start + 10..];
            let value = after.split('"').next().unwrap_or(after);
            let ip = value.trim();
            if is_ipv4(ip) {
                return Some(ip.to_string());
            }
        }

        None
    }
}

fn is_ipv4(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::repositories::offenses::find_recent_offenses;
    use crate::database::repositories::offenses::OffenseStatus;
    use crate::database::{create_pool, init_database, list_alerts, AlertFilter};
    use chrono::Utc;
    #[cfg(target_os = "linux")]
    use std::process::Command;

    #[cfg(target_os = "linux")]
    fn running_as_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|stdout| stdout.trim() == "0")
            .unwrap_or(false)
    }

    #[actix_rt::test]
    async fn test_extract_ip_candidates() {
        let ips = IpBanEngine::extract_ip_candidates(
            "Failed password for root from 192.0.2.4 port 51234 ssh2",
        );
        assert_eq!(ips, vec!["192.0.2.4".to_string()]);
    }

    #[actix_rt::test]
    async fn test_record_offense_blocks_after_threshold() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 2,
                find_time_secs: 300,
                ban_time_secs: 60,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );

        let first = engine
            .record_offense(OffenseInput {
                ip_address: "192.0.2.44".into(),
                source_type: "sniff".into(),
                reason: "Failed ssh login".into(),
                severity: AlertSeverity::High,
                container_id: None,
                source_path: Some("/var/log/auth.log".into()),
                sample_line: Some("Failed password from 192.0.2.44".into()),
            })
            .await
            .unwrap();
        let second = engine
            .record_offense(OffenseInput {
                ip_address: "192.0.2.44".into(),
                source_type: "sniff".into(),
                reason: "Failed ssh login".into(),
                severity: AlertSeverity::High,
                container_id: None,
                source_path: Some("/var/log/auth.log".into()),
                sample_line: Some("Failed password from 192.0.2.44".into()),
            })
            .await;

        assert!(!first);
        #[cfg(target_os = "linux")]
        if !running_as_root() {
            let error = second.unwrap_err().to_string();
            assert!(
                error.contains("Operation not permitted")
                    || error.contains("Permission denied")
                    || error.contains("you must be root")
            );
            return;
        }

        let second = second.unwrap();
        assert!(second);
        assert!(active_block_for_ip(&pool, "192.0.2.44").unwrap().is_some());
    }

    #[actix_rt::test]
    async fn test_unban_expired_releases_ban_and_emits_release_alert() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 0,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
            },
        );

        let blocked = engine
            .record_offense(OffenseInput {
                ip_address: "192.0.2.55".into(),
                source_type: "sniff".into(),
                reason: "Repeated ssh login failure".into(),
                severity: AlertSeverity::Critical,
                container_id: None,
                source_path: Some("/var/log/auth.log".into()),
                sample_line: Some("Failed password from 192.0.2.55".into()),
            })
            .await;

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            let error = blocked.unwrap_err().to_string();
            assert!(
                error.contains("Operation not permitted")
                    || error.contains("Permission denied")
                    || error.contains("you must be root")
            );
            return;
        }

        let blocked = blocked.unwrap();
        assert!(blocked);

        let released = engine.unban_expired().await.unwrap();
        assert_eq!(released, 1);
        assert!(active_block_for_ip(&pool, "192.0.2.55").unwrap().is_none());

        let offenses = find_recent_offenses(
            &pool,
            "192.0.2.55",
            "sniff",
            Utc::now() - Duration::minutes(5),
        )
        .unwrap();
        assert_eq!(offenses.len(), 1);
        assert_eq!(offenses[0].status, OffenseStatus::Released);

        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].alert_type.to_string(), "SystemEvent");
        assert_eq!(alerts[0].message, "Released IP ban for 192.0.2.55");
        assert_eq!(
            alerts[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.source.as_deref()),
            Some("ip_ban")
        );
        assert_eq!(
            alerts[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.reason.as_deref()),
            Some("Released expired ban for 192.0.2.55")
        );
    }
}
