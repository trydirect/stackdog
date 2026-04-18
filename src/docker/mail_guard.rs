use std::collections::{HashMap, HashSet};
use std::env;

use tokio::time::{sleep, Duration};

use crate::alerting::alert::{AlertSeverity, AlertType};
use crate::database::models::Alert;
use crate::database::models::AlertMetadata;
use crate::database::repositories::alerts::create_alert;
use crate::database::DbPool;
use crate::docker::client::{ContainerInfo, ContainerStats};
use crate::docker::containers::ContainerManager;

const DEFAULT_TARGET_PATTERNS: &[&str] = &[
    "wordpress",
    "php",
    "php-fpm",
    "apache",
    "httpd",
    "drupal",
    "joomla",
    "woocommerce",
];
const DEFAULT_ALLOWLIST_PATTERNS: &[&str] =
    &["postfix", "exim", "mailhog", "mailpit", "smtp", "sendmail"];

#[derive(Debug, Clone)]
pub struct MailAbuseGuardConfig {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub min_tx_packets_per_interval: u64,
    pub min_tx_bytes_per_interval: u64,
    pub max_avg_bytes_per_packet: u64,
    pub consecutive_suspicious_intervals: u32,
    pub target_patterns: Vec<String>,
    pub allowlist_patterns: Vec<String>,
}

impl MailAbuseGuardConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: parse_bool_env("STACKDOG_MAIL_GUARD_ENABLED", true),
            poll_interval_secs: parse_u64_env("STACKDOG_MAIL_GUARD_INTERVAL_SECS", 10),
            min_tx_packets_per_interval: parse_u64_env("STACKDOG_MAIL_GUARD_MIN_TX_PACKETS", 250),
            min_tx_bytes_per_interval: parse_u64_env("STACKDOG_MAIL_GUARD_MIN_TX_BYTES", 64 * 1024),
            max_avg_bytes_per_packet: parse_u64_env(
                "STACKDOG_MAIL_GUARD_MAX_AVG_BYTES_PER_PACKET",
                800,
            ),
            consecutive_suspicious_intervals: parse_u32_env(
                "STACKDOG_MAIL_GUARD_CONSECUTIVE_INTERVALS",
                3,
            ),
            target_patterns: parse_list_env("STACKDOG_MAIL_GUARD_TARGETS").unwrap_or_else(|| {
                DEFAULT_TARGET_PATTERNS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            }),
            allowlist_patterns: parse_list_env("STACKDOG_MAIL_GUARD_ALLOWLIST").unwrap_or_else(
                || {
                    DEFAULT_ALLOWLIST_PATTERNS
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                },
            ),
        }
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_u32_env(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_list_env(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(|part| part.trim().to_ascii_lowercase())
            .filter(|part| !part.is_empty())
            .collect()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficSnapshot {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
}

impl From<&ContainerStats> for TrafficSnapshot {
    fn from(stats: &ContainerStats) -> Self {
        Self {
            tx_bytes: stats.network_tx,
            rx_bytes: stats.network_rx,
            tx_packets: stats.network_tx_packets,
            rx_packets: stats.network_rx_packets,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficDelta {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
}

#[derive(Debug, Default)]
struct ContainerTrafficState {
    previous: Option<TrafficSnapshot>,
    suspicious_intervals: u32,
    quarantined: bool,
}

#[derive(Debug, Clone)]
struct GuardDecision {
    should_quarantine: bool,
    reason: Option<String>,
}

impl GuardDecision {
    fn no_action() -> Self {
        Self {
            should_quarantine: false,
            reason: None,
        }
    }
}

#[derive(Debug, Default)]
struct MailAbuseDetector {
    states: HashMap<String, ContainerTrafficState>,
}

impl MailAbuseDetector {
    fn evaluate_container(
        &mut self,
        info: &ContainerInfo,
        stats: &ContainerStats,
        config: &MailAbuseGuardConfig,
    ) -> GuardDecision {
        if is_allowlisted(info, config) {
            self.states.remove(&info.id);
            return GuardDecision::no_action();
        }

        let state = self.states.entry(info.id.clone()).or_default();
        let current = TrafficSnapshot::from(stats);

        let Some(previous) = state.previous.replace(current) else {
            return GuardDecision::no_action();
        };

        let Some(delta) = compute_delta(previous, current) else {
            state.suspicious_intervals = 0;
            return GuardDecision::no_action();
        };

        if state.quarantined {
            return GuardDecision::no_action();
        }

        if !is_targeted_container(info, config) || !is_suspicious_egress(delta, config) {
            state.suspicious_intervals = 0;
            return GuardDecision::no_action();
        }

        state.suspicious_intervals += 1;
        let avg_bytes_per_packet = delta.tx_bytes.checked_div(delta.tx_packets).unwrap_or(0);
        let reason = format!(
            "possible outbound mail abuse detected for {} (image: {}) — {} tx packets / {} bytes over {}s, avg {} bytes/packet, strike {}/{}",
            info.name,
            info.image,
            delta.tx_packets,
            delta.tx_bytes,
            config.poll_interval_secs,
            avg_bytes_per_packet,
            state.suspicious_intervals,
            config.consecutive_suspicious_intervals
        );

        GuardDecision {
            should_quarantine: state.suspicious_intervals
                >= config.consecutive_suspicious_intervals,
            reason: Some(reason),
        }
    }

    fn mark_quarantined(&mut self, container_id: &str) {
        if let Some(state) = self.states.get_mut(container_id) {
            state.quarantined = true;
        }
    }

    fn prune(&mut self, active_container_ids: &HashSet<String>) {
        self.states
            .retain(|container_id, _| active_container_ids.contains(container_id));
    }
}

fn compute_delta(previous: TrafficSnapshot, current: TrafficSnapshot) -> Option<TrafficDelta> {
    Some(TrafficDelta {
        tx_bytes: current.tx_bytes.checked_sub(previous.tx_bytes)?,
        rx_bytes: current.rx_bytes.checked_sub(previous.rx_bytes)?,
        tx_packets: current.tx_packets.checked_sub(previous.tx_packets)?,
        rx_packets: current.rx_packets.checked_sub(previous.rx_packets)?,
    })
}

fn is_targeted_container(info: &ContainerInfo, config: &MailAbuseGuardConfig) -> bool {
    let identity = format!(
        "{} {} {}",
        info.id.to_ascii_lowercase(),
        info.name.to_ascii_lowercase(),
        info.image.to_ascii_lowercase()
    );
    config
        .target_patterns
        .iter()
        .any(|pattern| identity.contains(pattern))
}

fn is_allowlisted(info: &ContainerInfo, config: &MailAbuseGuardConfig) -> bool {
    let identity = format!(
        "{} {} {}",
        info.id.to_ascii_lowercase(),
        info.name.to_ascii_lowercase(),
        info.image.to_ascii_lowercase()
    );
    config
        .allowlist_patterns
        .iter()
        .any(|pattern| identity.contains(pattern))
}

fn is_suspicious_egress(delta: TrafficDelta, config: &MailAbuseGuardConfig) -> bool {
    if delta.tx_packets < config.min_tx_packets_per_interval
        || delta.tx_bytes < config.min_tx_bytes_per_interval
    {
        return false;
    }

    let avg_bytes_per_packet = delta.tx_bytes / delta.tx_packets.max(1);
    avg_bytes_per_packet <= config.max_avg_bytes_per_packet
}

pub struct MailAbuseGuard;

impl MailAbuseGuard {
    pub async fn run(pool: DbPool, config: MailAbuseGuardConfig) {
        log::info!(
            "Starting mail abuse guard (interval={}s, min_tx_packets={}, min_tx_bytes={}, max_avg_bytes_per_packet={}, strikes={})",
            config.poll_interval_secs,
            config.min_tx_packets_per_interval,
            config.min_tx_bytes_per_interval,
            config.max_avg_bytes_per_packet,
            config.consecutive_suspicious_intervals
        );

        let mut detector = MailAbuseDetector::default();

        loop {
            if let Err(err) = Self::poll_once(&pool, &config, &mut detector).await {
                log::warn!("Mail abuse guard poll failed: {}", err);
            }

            sleep(Duration::from_secs(config.poll_interval_secs)).await;
        }
    }

    async fn poll_once(
        pool: &DbPool,
        config: &MailAbuseGuardConfig,
        detector: &mut MailAbuseDetector,
    ) -> anyhow::Result<()> {
        let manager = ContainerManager::new(pool.clone()).await?;
        let containers = manager.list_containers().await?;
        let mut active_container_ids = HashSet::new();

        for container in containers {
            if container.status != "Running" {
                continue;
            }

            active_container_ids.insert(container.id.clone());
            let stats = manager.get_container_stats(&container.id).await?;
            let decision = detector.evaluate_container(&container, &stats, config);

            if decision.should_quarantine {
                let reason = decision.reason.unwrap_or_else(|| {
                    format!(
                        "possible outbound mail abuse detected for {}",
                        container.name
                    )
                });

                manager.quarantine_container(&container.id, &reason).await?;
                detector.mark_quarantined(&container.id);
                create_alert(
                    pool,
                    Alert::new(
                        AlertType::ThreatDetected,
                        AlertSeverity::Critical,
                        format!(
                            "Mail abuse guard quarantined container {} ({})",
                            container.name, container.id
                        ),
                    )
                    .with_metadata(
                        AlertMetadata::default()
                            .with_container_id(&container.id)
                            .with_source("mail-abuse-guard")
                            .with_reason(reason.clone()),
                    ),
                )
                .await?;
                log::warn!("{}", reason);
            }
        }

        detector.prune(&active_container_ids);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MailAbuseGuardConfig {
        MailAbuseGuardConfig {
            enabled: true,
            poll_interval_secs: 10,
            min_tx_packets_per_interval: 100,
            min_tx_bytes_per_interval: 10_000,
            max_avg_bytes_per_packet: 300,
            consecutive_suspicious_intervals: 2,
            target_patterns: vec!["wordpress".into()],
            allowlist_patterns: vec!["mailhog".into()],
        }
    }

    fn container(name: &str, image: &str) -> ContainerInfo {
        ContainerInfo {
            id: "abc123".into(),
            name: name.into(),
            image: image.into(),
            status: "Running".into(),
            created: String::new(),
            network_settings: HashMap::new(),
        }
    }

    fn stats(tx_bytes: u64, rx_bytes: u64, tx_packets: u64, rx_packets: u64) -> ContainerStats {
        ContainerStats {
            cpu_percent: 0.0,
            memory_usage: 0,
            memory_limit: 0,
            network_rx: rx_bytes,
            network_tx: tx_bytes,
            network_rx_packets: rx_packets,
            network_tx_packets: tx_packets,
        }
    }

    #[test]
    fn test_detector_requires_consecutive_intervals() {
        let mut detector = MailAbuseDetector::default();
        let info = container("wordpress", "wordpress:latest");
        let config = config();

        let first = detector.evaluate_container(&info, &stats(10_000, 5_000, 100, 50), &config);
        assert!(!first.should_quarantine);

        let second = detector.evaluate_container(&info, &stats(40_000, 8_000, 260, 80), &config);
        assert!(!second.should_quarantine);

        let third = detector.evaluate_container(&info, &stats(80_000, 11_000, 420, 100), &config);
        assert!(third.should_quarantine);
    }

    #[test]
    fn test_detector_ignores_allowlisted_container() {
        let mut detector = MailAbuseDetector::default();
        let info = container("mailhog", "mailhog/mailhog");
        let config = config();

        detector.evaluate_container(&info, &stats(10_000, 5_000, 100, 50), &config);
        let decision = detector.evaluate_container(&info, &stats(50_000, 8_000, 260, 80), &config);

        assert!(!decision.should_quarantine);
    }

    #[test]
    fn test_detector_resets_strikes_after_normal_interval() {
        let mut detector = MailAbuseDetector::default();
        let info = container("wordpress", "wordpress:latest");
        let config = config();

        detector.evaluate_container(&info, &stats(10_000, 5_000, 100, 50), &config);
        detector.evaluate_container(&info, &stats(40_000, 8_000, 260, 80), &config);
        let normal = detector.evaluate_container(&info, &stats(42_000, 9_000, 265, 82), &config);
        assert!(!normal.should_quarantine);

        let suspicious =
            detector.evaluate_container(&info, &stats(82_000, 12_000, 430, 100), &config);
        assert!(!suspicious.should_quarantine);
    }
}
