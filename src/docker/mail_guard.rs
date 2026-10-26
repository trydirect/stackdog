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
    /// Quarantine only when outbound SMTP traffic is actually observed.
    ///
    /// The traffic heuristic alone reads ordinary HTTP/JSON chatter between
    /// microservices as mail abuse — small packets, high count is what a busy
    /// service looks like. With this on, a match without SMTP egress is an
    /// alert, not a network disconnect.
    pub require_smtp: bool,
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
            require_smtp: parse_bool_env("STACKDOG_MAIL_GUARD_REQUIRE_SMTP", true),
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
    /// A downgrade alert is on the record already: the heuristic keeps
    /// matching while the traffic pattern lasts, and a warning every poll is
    /// noise. Cleared when the pattern goes away.
    smtp_downgrade_alerted: bool,
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
            state.smtp_downgrade_alerted = false;
            return GuardDecision::no_action();
        };

        if state.quarantined {
            return GuardDecision::no_action();
        }

        if !is_targeted_container(info, config) || !is_suspicious_egress(delta, config) {
            state.suspicious_intervals = 0;
            state.smtp_downgrade_alerted = false;
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

    /// Record that a downgrade alert went out. Returns `false` when one is
    /// already on the record for this strike run.
    fn mark_downgrade_alerted(&mut self, container_id: &str) -> bool {
        if let Some(state) = self.states.get_mut(container_id) {
            if state.smtp_downgrade_alerted {
                return false;
            }
            state.smtp_downgrade_alerted = true;
            return true;
        }
        false
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

/// Ports an outbound mail stream would leave through.
const SMTP_PORTS: [u16; 3] = [25, 465, 587];

/// Does one nf_conntrack record describe SMTP egress from one of `ips`?
///
/// Records carry the original tuple first and the reply tuple second:
///
/// ```text
/// ipv4 2 tcp 6 431999 ESTABLISHED src=172.18.0.5 dst=93.184.216.34 \
///     sport=52344 dport=25 src=93.184.216.34 dst=172.18.0.5 sport=25 ...
/// ```
///
/// Only the first `src=` says who opened the connection, and only the `dport=`
/// before the second `src=` says where it is going — the reply direction shows
/// `sport=25` for every incoming connection too.
fn line_is_smtp_egress(line: &str, ips: &[std::net::Ipv4Addr]) -> bool {
    let mut parts = line.split("src=");
    if parts.next().is_none() {
        return false;
    }
    let Some(original) = parts.next() else {
        return false;
    };

    let mut fields = original.split_whitespace();
    let Some(src) = fields.next() else {
        return false;
    };
    let Ok(src) = src.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if !ips.contains(&src) {
        return false;
    }

    original
        .split_whitespace()
        .find_map(|word| word.strip_prefix("dport="))
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| SMTP_PORTS.contains(&port))
}

/// Whether any of `ips` has an SMTP connection in the host conntrack table.
///
/// `None` when the table cannot be read — the caller treats "cannot verify"
/// like "not verified" and skips the irreversible part.
fn smtp_egress_observed(ips: &[std::net::Ipv4Addr]) -> Option<bool> {
    if ips.is_empty() {
        return None;
    }
    let table = std::fs::read_to_string("/proc/net/nf_conntrack").ok()?;
    Some(table.lines().any(|line| line_is_smtp_egress(line, ips)))
}

fn container_ips(info: &ContainerInfo) -> Vec<std::net::Ipv4Addr> {
    info.network_settings
        .values()
        .filter_map(|ip| ip.parse().ok())
        .collect()
}

/// What the guard may do with a heuristic match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardAction {
    Quarantine,
    AlertOnly { note: &'static str },
    None,
}

/// Traffic heuristics say "suspicious"; SMTP evidence decides the response.
///
/// Quarantine disconnects the container from its networks and nothing in this
/// codebase reconnects it, so it must not rest on a guess about packet sizes.
fn resolve_action(
    should_quarantine: bool,
    require_smtp: bool,
    smtp_confirmed: Option<bool>,
) -> GuardAction {
    if !should_quarantine {
        return GuardAction::None;
    }
    if !require_smtp {
        return GuardAction::Quarantine;
    }
    match smtp_confirmed {
        Some(true) => GuardAction::Quarantine,
        Some(false) => GuardAction::AlertOnly {
            note: "no SMTP egress observed",
        },
        None => GuardAction::AlertOnly {
            note: "conntrack table unavailable, SMTP egress unverifiable",
        },
    }
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

                let smtp_confirmed = if config.require_smtp {
                    smtp_egress_observed(&container_ips(&container))
                } else {
                    None
                };
                match resolve_action(true, config.require_smtp, smtp_confirmed) {
                    GuardAction::None => {}
                    GuardAction::AlertOnly { note } => {
                        if detector.mark_downgrade_alerted(&container.id) {
                            let message = format!(
                                "Mail abuse guard flagged container {} ({}): {} — {note}; quarantine skipped",
                                container.name, container.id, reason
                            );
                            create_alert(
                                pool,
                                Alert::new(
                                    AlertType::ThreatDetected,
                                    AlertSeverity::High,
                                    message.clone(),
                                )
                                .with_metadata(
                                    AlertMetadata::default()
                                        .with_container_id(&container.id)
                                        .with_source("mail-abuse-guard")
                                        .with_reason(reason.clone()),
                                ),
                            )
                            .await?;
                            log::warn!("{}", message);
                        }
                    }
                    GuardAction::Quarantine => {
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
            require_smtp: true,
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
            labels: HashMap::new(),
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

    #[test]
    fn test_conntrack_line_is_smtp_egress_from_the_container() {
        let ips: Vec<std::net::Ipv4Addr> = vec!["172.18.0.5".parse().unwrap()];

        // Original direction dport=25 from our container: mail leaving.
        let line = "ipv4 2 tcp 6 431999 ESTABLISHED src=172.18.0.5 dst=93.184.216.34 \
                    sport=52344 dport=25 src=93.184.216.34 dst=172.18.0.5 sport=25 dport=52344 \
                    [ASSURED] mark=0 use=1";
        assert!(line_is_smtp_egress(line, &ips));

        for port in [465, 587] {
            let line = format!(
                "ipv4 2 tcp 6 431999 ESTABLISHED src=172.18.0.5 dst=93.184.216.34 \
                 sport=52344 dport={} src=93.184.216.34 dst=172.18.0.5 sport={} dport=52344",
                port, port
            );
            assert!(line_is_smtp_egress(&line, &ips), "port {port} is SMTP");
        }

        // Ordinary HTTP chatter is not mail.
        let http = "ipv4 2 tcp 6 431999 ESTABLISHED src=172.18.0.5 dst=93.184.216.34 \
                    sport=52344 dport=443 src=93.184.216.34 dst=172.18.0.5 sport=443 dport=52344";
        assert!(!line_is_smtp_egress(http, &ips));
    }

    #[test]
    fn test_conntrack_reply_direction_is_not_egress() {
        let ips: Vec<std::net::Ipv4Addr> = vec!["172.18.0.5".parse().unwrap()];

        // Somebody connects TO our container on port 25: the reply tuple
        // carries sport=25, but the connection is incoming, not mail abuse.
        let incoming = "ipv4 2 tcp 6 431999 ESTABLISHED src=93.184.216.34 dst=172.18.0.5 \
                        sport=40000 dport=8080 src=172.18.0.5 dst=93.184.216.34 sport=25 dport=40000";
        assert!(!line_is_smtp_egress(incoming, &ips));

        // Another container's SMTP traffic must not count as ours.
        let peer = "ipv4 2 tcp 6 431999 ESTABLISHED src=172.18.0.9 dst=93.184.216.34 \
                    sport=52344 dport=25 src=93.184.216.34 dst=172.18.0.9 sport=25 dport=52344";
        assert!(!line_is_smtp_egress(peer, &ips));
    }

    #[test]
    fn test_resolve_action_needs_smtp_before_quarantine() {
        // Heuristic match alone: alert, never disconnect.
        assert_eq!(
            resolve_action(true, true, Some(false)),
            GuardAction::AlertOnly {
                note: "no SMTP egress observed"
            }
        );
        // Unverifiable is not verified: an irreversible action needs evidence.
        assert!(matches!(
            resolve_action(true, true, None),
            GuardAction::AlertOnly { .. }
        ));
        // Confirmed SMTP egress: quarantine.
        assert_eq!(
            resolve_action(true, true, Some(true)),
            GuardAction::Quarantine
        );
        // Operator turned the requirement off: old behaviour.
        assert_eq!(resolve_action(true, false, None), GuardAction::Quarantine);
        // No heuristic match: nothing to do.
        assert_eq!(resolve_action(false, true, Some(true)), GuardAction::None);
    }

    #[test]
    fn test_downgrade_alert_fires_once_per_strike_run() {
        let mut detector = MailAbuseDetector::default();
        let info = container("wordpress", "wordpress:latest");
        let config = config();

        detector.evaluate_container(&info, &stats(10_000, 5_000, 100, 50), &config);
        detector.evaluate_container(&info, &stats(40_000, 8_000, 260, 80), &config);

        assert!(detector.mark_downgrade_alerted(&info.id));
        assert!(!detector.mark_downgrade_alerted(&info.id));

        // Once the pattern goes away, the next run may alert again.
        detector.evaluate_container(&info, &stats(42_000, 9_000, 265, 82), &config);
        assert!(detector.mark_downgrade_alerted(&info.id));
    }
}
