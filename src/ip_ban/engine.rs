use crate::alerting::notifications::{dispatch_stored_alert, env_flag_enabled, NotificationConfig};
use crate::alerting::{AlertSeverity, AlertType};
use crate::database::models::{Alert, AlertMetadata};
use crate::database::repositories::offenses::{
    active_block_for_ip, expired_blocks, list_offenses, mark_blocked, mark_released,
    record_offense_occurrence, IpOffenseRecord, NewIpOffense, OffenseMetadata, OffenseStatus,
};
use crate::database::{create_alert, DbPool};
use crate::ip_ban::config::IpBanConfig;
use crate::ip_ban::gate::{self, BanRefusal, LocalIpContext};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
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

/// What happened to a manual ban request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanOutcome {
    Banned { blocked_until: DateTime<Utc> },
    AlreadyBanned,
    Refused(BanRefusal),
}

/// What a firewall/database reconciliation pass changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Rules in the firewall with no active block in the database. Removed.
    pub orphan_rules_removed: Vec<String>,
    /// Active blocks in the database with no rule in the firewall. Re-applied.
    pub missing_rules_restored: Vec<String>,
}

pub struct IpBanEngine {
    pool: DbPool,
    config: IpBanConfig,
    /// Timestamps of recent blocks, for the per-minute ceiling.
    recent_blocks: std::sync::Mutex<std::collections::VecDeque<DateTime<Utc>>>,
    /// Addresses of this host and its containers, never bannable.
    local_context: LocalIpContext,
}

impl IpBanEngine {
    pub fn new(pool: DbPool, config: IpBanConfig) -> Self {
        Self {
            pool,
            config,
            recent_blocks: std::sync::Mutex::new(std::collections::VecDeque::new()),
            local_context: LocalIpContext::discover_local(),
        }
    }

    /// Replace the local-IP context. Tests use [`LocalIpContext::empty`] for
    /// hermeticity; production callers usually keep discovery.
    pub fn with_local_context(mut self, context: LocalIpContext) -> Self {
        self.local_context = context;
        self
    }

    /// Add Docker network subnets to the local-IP context, best-effort.
    ///
    /// Async and Docker-dependent, so it is a separate step from construction.
    pub async fn refresh_local_context(&mut self) {
        self.local_context.docker_subnets = LocalIpContext::discover_docker_subnets().await;
    }

    /// Whether another address may be blocked right now.
    ///
    /// A burst of blocks is far more likely to be a misread log than a crowd of
    /// attackers arriving in the same second, and the cost of the two mistakes
    /// is not symmetric: a missed ban is an alert nobody acted on, a wrong ban
    /// is a locked-out customer. The ceiling holds the damage to a handful.
    fn ban_budget_available(&self, now: DateTime<Utc>) -> bool {
        if self.config.max_bans_per_minute == 0 {
            return true;
        }

        let mut recent = match self.recent_blocks.lock() {
            Ok(recent) => recent,
            Err(poisoned) => poisoned.into_inner(),
        };
        while recent
            .front()
            .is_some_and(|stamp| now - *stamp > Duration::seconds(60))
        {
            recent.pop_front();
        }

        if recent.len() as u32 >= self.config.max_bans_per_minute {
            return false;
        }

        recent.push_back(now);
        true
    }

    pub fn config(&self) -> &IpBanConfig {
        &self.config
    }

    pub async fn record_offense(&self, offense: OffenseInput) -> Result<bool> {
        // Checked before the offense is even recorded: banning a load balancer
        // or health checker takes the service down, so protected addresses must
        // not accumulate offenses that a later config change could act on.
        if let Some(refusal) =
            gate::refuse_reason(&offense.ip_address, &self.config, &self.local_context)
        {
            log::info!(
                "Skipping offense for {} ({}): {}",
                offense.ip_address,
                offense.reason,
                refusal.reason()
            );
            return Ok(false);
        }

        if active_block_for_ip(&self.pool, &offense.ip_address)?.is_some() {
            return Ok(false);
        }

        let now = Utc::now();
        let offense_count = record_offense_occurrence(
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
            now - Duration::seconds(self.config.find_time_secs as i64),
        )?;

        if offense_count >= self.config.max_retries {
            self.block_ip(&offense, offense_count, now).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Release a ban ahead of its expiry.
    ///
    /// Returns `false` when the address has no active block, so callers can
    /// answer 404 rather than pretending something was undone.
    pub async fn unban_ip(&self, ip_address: &str) -> Result<bool> {
        let Some(offense) = active_block_for_ip(&self.pool, ip_address)? else {
            return Ok(false);
        };
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
                    .with_reason(format!("Manually released ban for {}", offense.ip_address)),
            ),
        )
        .await?;
        self.notify_action_alert(&alert, "STACKDOG_NOTIFY_IP_BAN_ACTIONS", "ip ban release")
            .await;

        Ok(true)
    }

    /// Release every block for `ip` and remove its firewall rules — row or no
    /// row.
    ///
    /// The CLI path: unlike [`Self::unban_ip`] it does not require a database
    /// record. A crash between the firewall write and the database write strands
    /// a DROP rule nothing else will ever remove, and the rules in the kernel
    /// are what is actually blocking traffic. Returns the number of records
    /// released.
    pub async fn unban_ip_best_effort(&self, ip_address: &str) -> Result<usize> {
        let mut released = 0;

        let blocked = list_offenses(&self.pool, Some(OffenseStatus::Blocked), usize::MAX)?;
        for record in &blocked {
            if record.ip_address != ip_address {
                continue;
            }
            mark_released(&self.pool, &record.id)?;
            released += 1;
        }

        #[cfg(target_os = "linux")]
        if let Err(err) = self.with_firewall_backend(|backend| backend.unblock_ip(ip_address)) {
            log::warn!(
                "Failed to remove firewall rules for {}: {}",
                ip_address,
                err
            );
        }

        Ok(released)
    }

    /// Blocks currently recorded in the database.
    pub fn active_bans(&self) -> Result<Vec<IpOffenseRecord>> {
        list_offenses(&self.pool, Some(OffenseStatus::Blocked), usize::MAX)
    }

    /// Addresses the Stackdog firewall rules are actually dropping.
    ///
    /// Empty off-Linux: there is no firewall backend there to ask.
    pub fn firewall_banned_ips(&self) -> Result<Vec<String>> {
        #[cfg(target_os = "linux")]
        {
            self.with_firewall_backend(|backend| backend.list_banned_ips())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Vec::new())
        }
    }

    /// Release every ban whose window has passed.
    ///
    /// Returns the number of addresses released, not the number of rows: one
    /// address accumulates an offense row per detection, and `mark_blocked`
    /// flips all of them, so a single ban expiring leaves several expired rows
    /// behind. Releasing per row meant one firewall call and one notification
    /// each — an address banned after five offenses produced five identical
    /// "Released IP ban" alerts within a second.
    pub async fn unban_expired(&self) -> Result<usize> {
        let now = Utc::now();
        let expired = expired_blocks(&self.pool, now)?;
        let mut released = 0;
        let mut handled: HashSet<String> = HashSet::new();

        for offense in &expired {
            mark_released(&self.pool, &offense.id)?;

            if !handled.insert(offense.ip_address.clone()) {
                continue;
            }

            #[cfg(target_os = "linux")]
            self.with_firewall_backend(|backend| backend.unblock_ip(&offense.ip_address))?;

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

    /// Release every ban and remove every Stackdog firewall rule.
    ///
    /// The panic button: when a wrong ban has taken the service down, restoring
    /// connectivity matters more than preserving the block list. Rules the
    /// database knows nothing about — a crash between the firewall write and
    /// the database write, a lost database — go too. What is in the kernel is
    /// what is actually blocking traffic.
    pub async fn unban_all(&self) -> Result<usize> {
        let blocked = list_offenses(&self.pool, Some(OffenseStatus::Blocked), usize::MAX)?;
        let mut released: HashSet<String> = HashSet::new();

        for record in &blocked {
            mark_released(&self.pool, &record.id)?;
            released.insert(record.ip_address.clone());
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(rule_ips) = self.with_firewall_backend(|backend| backend.list_banned_ips()) {
                released.extend(rule_ips);
            }

            for ip in &released {
                if let Err(err) = self.with_firewall_backend(|backend| backend.unblock_ip(ip)) {
                    log::warn!("Failed to remove firewall rule for {}: {}", ip, err);
                }
            }
        }

        Ok(released.len())
    }

    /// Make the firewall and the database agree again.
    ///
    /// Two failure modes leave them apart: a crash between the firewall rule
    /// and the database write strands a DROP rule nothing will ever remove,
    /// and a database row without a rule claims a ban that is not in effect.
    /// Untagged rules cannot be told apart from an operator's own and are left
    /// alone; `stackdog unban <ip>` removes those by address.
    pub async fn reconcile_firewall(&self) -> Result<ReconcileReport> {
        // Mutated only where a firewall backend exists (Linux).
        #[allow(unused_mut)]
        let mut report = ReconcileReport::default();

        #[cfg(target_os = "linux")]
        {
            let rule_ips: HashSet<String> = self
                .with_firewall_backend(|backend| backend.list_banned_ips())?
                .into_iter()
                .collect();
            let active: HashSet<String> =
                list_offenses(&self.pool, Some(OffenseStatus::Blocked), usize::MAX)?
                    .into_iter()
                    .map(|record| record.ip_address)
                    .collect();

            for ip in &rule_ips {
                if active.contains(ip) {
                    continue;
                }
                match self.with_firewall_backend(|backend| backend.unblock_ip(ip)) {
                    Ok(()) => report.orphan_rules_removed.push(ip.clone()),
                    Err(err) => log::warn!("Failed to remove orphan rule for {}: {}", ip, err),
                }
            }

            for ip in &active {
                if rule_ips.contains(ip) {
                    continue;
                }
                match self.with_firewall_backend(|backend| backend.block_ip(ip)) {
                    Ok(()) => report.missing_rules_restored.push(ip.clone()),
                    Err(err) => log::warn!("Failed to restore rule for {}: {}", ip, err),
                }
            }
        }

        Ok(report)
    }

    /// Longest sample line kept in an alert message, so one enormous log line
    /// cannot blow past a notification channel's size limit.
    const SAMPLE_LIMIT: usize = 300;

    /// Explain a ban in the alert itself: which file or container the evidence
    /// came from, what triggered it, and the line that did.
    ///
    /// Without this the alert says only "Blocked IP X after repeated sniff
    /// offenses", which is not enough to tell a real attacker from a parsing
    /// mistake — and the offending address may appear nowhere in the logs an
    /// operator would think to grep.
    fn describe_ban(
        offense: &OffenseInput,
        offense_count: u32,
        blocked_until: DateTime<Utc>,
    ) -> String {
        let mut message = format!(
            "Blocked IP {} after {} {} offenses (until {})",
            offense.ip_address,
            offense_count,
            offense.source_type,
            blocked_until.to_rfc3339(),
        );

        if let Some(source_path) = &offense.source_path {
            message.push_str(&format!(" — Source: {source_path}"));
        } else if let Some(container_id) = &offense.container_id {
            let short: String = container_id.chars().take(12).collect();
            message.push_str(&format!(" — Source: container {short}"));
        }

        message.push_str(&format!(" | Reason: {}", offense.reason));

        if let Some(sample_line) = &offense.sample_line {
            let sample = sample_line.trim();
            let sample: String = if sample.chars().count() > Self::SAMPLE_LIMIT {
                sample
                    .chars()
                    .take(Self::SAMPLE_LIMIT)
                    .chain("…".chars())
                    .collect()
            } else {
                sample.to_string()
            };
            message.push_str(&format!(" | Sample: {sample}"));
        }

        message
    }

    async fn block_ip(
        &self,
        offense: &OffenseInput,
        offense_count: u32,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        if !self.ban_budget_available(now) {
            log::warn!(
                "Ban ceiling of {}/min reached, not blocking {} ({}). This usually means log \
                 parsing implicated the wrong addresses; raise STACKDOG_IP_BAN_MAX_PER_MINUTE \
                 only once you have checked the findings.",
                self.config.max_bans_per_minute,
                offense.ip_address,
                offense.reason
            );
            return Ok(());
        }

        self.apply_block(offense, offense_count, now, self.config.ban_time_secs)
            .await
    }

    /// Ban an address immediately, whatever the offense threshold says.
    ///
    /// One confirmed attack is enough for a human or the AI assistant. Not
    /// enough to skip the gate, though: the same infrastructure addresses are
    /// off-limits here, and a CIDR range is refused just as hard.
    pub async fn ban_now(
        &self,
        ip: &str,
        reason: &str,
        source_type: &str,
        duration_secs: Option<u64>,
    ) -> Result<BanOutcome> {
        if let Some(refusal) = gate::refuse_reason(ip, &self.config, &self.local_context) {
            return Ok(BanOutcome::Refused(refusal));
        }

        if active_block_for_ip(&self.pool, ip)?.is_some() {
            return Ok(BanOutcome::AlreadyBanned);
        }

        let now = Utc::now();
        let duration = duration_secs.unwrap_or(self.config.ban_time_secs);

        // The row first: mark_blocked only flips existing rows, and a ban with
        // no row would never expire and never be released.
        record_offense_occurrence(
            &self.pool,
            &NewIpOffense {
                id: Uuid::new_v4().to_string(),
                ip_address: ip.to_string(),
                source_type: source_type.to_string(),
                container_id: None,
                first_seen: now,
                reason: reason.to_string(),
                metadata: None,
            },
            now - Duration::seconds(self.config.find_time_secs as i64),
        )?;

        let offense = OffenseInput {
            ip_address: ip.to_string(),
            source_type: source_type.to_string(),
            reason: reason.to_string(),
            severity: AlertSeverity::High,
            container_id: None,
            source_path: None,
            sample_line: None,
        };
        self.apply_block(&offense, 1, now, duration).await?;
        Ok(BanOutcome::Banned {
            blocked_until: now + Duration::seconds(duration as i64),
        })
    }

    async fn apply_block(
        &self,
        offense: &OffenseInput,
        offense_count: u32,
        now: chrono::DateTime<Utc>,
        duration_secs: u64,
    ) -> Result<()> {
        // Defence in depth: both callers gate already. Anything that reaches a
        // firewall backend must have passed through refuse_reason first.
        if let Some(refusal) =
            gate::refuse_reason(&offense.ip_address, &self.config, &self.local_context)
        {
            log::warn!(
                "Refusing to block {} ({}): {}",
                offense.ip_address,
                offense.reason,
                refusal.reason()
            );
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        self.with_firewall_backend(|backend| backend.block_ip(&offense.ip_address))?;

        let blocked_until = now + Duration::seconds(duration_secs as i64);
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
                Self::describe_ban(offense, offense_count, blocked_until),
            )
            .with_metadata({
                let mut metadata = AlertMetadata::default()
                    .with_source("ip_ban")
                    .with_reason(offense.reason.clone());
                if let Some(container_id) = &offense.container_id {
                    metadata = metadata.with_container_id(container_id.clone());
                }
                metadata
                    .extra
                    .insert("ip_address".into(), offense.ip_address.clone());
                metadata
                    .extra
                    .insert("offense_count".into(), offense_count.to_string());
                metadata
                    .extra
                    .insert("blocked_until".into(), blocked_until.to_rfc3339());
                if let Some(source_path) = &offense.source_path {
                    metadata
                        .extra
                        .insert("source_path".into(), source_path.clone());
                }
                if let Some(sample_line) = &offense.sample_line {
                    metadata
                        .extra
                        .insert("sample_line".into(), sample_line.clone());
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
    fn with_firewall_backend<T, F>(&self, action: F) -> Result<T>
    where
        F: FnOnce(&dyn crate::firewall::FirewallBackend) -> Result<T>,
    {
        if let Ok(mut backend) = crate::firewall::NfTablesBackend::new() {
            backend.initialize()?;
            return action(&backend);
        }

        let mut backend = crate::firewall::IptablesBackend::new()?;
        backend.initialize()?;
        action(&backend)
    }

    /// Pull IPv4 addresses out of a log line.
    ///
    /// Context matters: "Chrome/122.0.0.0" in a User-Agent tokenizes to a
    /// perfectly valid dotted quad, and banning it blocks a real network on
    /// behalf of a browser version number. A candidate is therefore rejected
    /// when it continues an identifier — anything directly preceded by a slash,
    /// letter, digit, hyphen or underscore.
    pub fn extract_ip_candidates(line: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        let mut token_start: Option<usize> = None;

        for (index, ch) in line.char_indices() {
            if ch.is_ascii_digit() || ch == '.' {
                token_start.get_or_insert(index);
            } else if let Some(start) = token_start.take() {
                Self::push_ip_candidate(&mut candidates, line, start, index);
            }
        }
        if let Some(start) = token_start {
            Self::push_ip_candidate(&mut candidates, line, start, line.len());
        }

        candidates
    }

    fn push_ip_candidate(candidates: &mut Vec<String>, line: &str, start: usize, end: usize) {
        // Sentence punctuation rides along: "from IP 1.2.3.4." tokenizes with a
        // trailing dot, which is not a valid address.
        let token = line[start..end].trim_matches('.');
        if !is_ipv4(token) {
            return;
        }

        if let Some(previous) = line[..start].chars().next_back() {
            if previous == '/'
                || previous == '-'
                || previous == '_'
                || previous.is_ascii_alphanumeric()
            {
                return;
            }
        }

        candidates.push(token.to_string());
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
    use crate::ip_ban::config::parse_cidr_list;
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
                allowlist_ranges: vec![],
                max_bans_per_minute: 0,
                protect_local_ips: true,
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
    async fn test_extract_ip_candidates_skips_version_strings() {
        let access_log = "203.0.113.9 - - [10/Sep/2026:07:17:00] \"GET / HTTP/1.1\" 200 \
             \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\"";

        let candidates = IpBanEngine::extract_ip_candidates(access_log);

        assert!(candidates.contains(&"203.0.113.9".to_string()));
        assert!(
            !candidates.contains(&"122.0.0.0".to_string()),
            "a Chrome version must not be read as a client address: {candidates:?}"
        );
    }

    #[actix_rt::test]
    async fn test_extract_ip_candidates_ignores_sentence_punctuation() {
        assert_eq!(
            IpBanEngine::extract_ip_candidates("Probing detected from IP 132.243.165.112."),
            vec!["132.243.165.112".to_string()]
        );
    }

    #[actix_rt::test]
    async fn test_extract_ip_candidates_keeps_delimited_addresses() {
        for line in [
            "Failed password for root from 198.51.100.7 port 22",
            "client=198.51.100.7,",
            "[198.51.100.7]",
            "X-Forwarded-For: 198.51.100.7",
            "198.51.100.7 - - [10/Sep/2026]",
        ] {
            let candidates = IpBanEngine::extract_ip_candidates(line);
            assert!(
                candidates.contains(&"198.51.100.7".to_string()),
                "missed the address in {line:?}"
            );
        }
    }

    #[actix_rt::test]
    async fn test_describe_ban_names_the_evidence() {
        let offense = OffenseInput {
            ip_address: "198.51.100.7".into(),
            source_type: "sniff".into(),
            reason: "Failed ssh login".into(),
            severity: AlertSeverity::High,
            container_id: None,
            source_path: Some("/var/log/auth.log".into()),
            sample_line: Some("Failed password for root from 198.51.100.7 port 22".into()),
        };
        let until = "2026-09-10T08:00:00Z".parse::<DateTime<Utc>>().unwrap();

        let message = IpBanEngine::describe_ban(&offense, 5, until);

        assert!(message.contains("198.51.100.7"));
        assert!(message.contains("after 5 sniff offenses"));
        assert!(message.contains("/var/log/auth.log"));
        assert!(message.contains("Failed ssh login"));
        assert!(message.contains("Failed password for root"));
    }

    #[actix_rt::test]
    async fn test_describe_ban_truncates_a_huge_sample() {
        let offense = OffenseInput {
            ip_address: "198.51.100.7".into(),
            source_type: "sniff".into(),
            reason: "Flood".into(),
            severity: AlertSeverity::High,
            container_id: Some("0f3b46ca0c16aaaaaaaa".into()),
            source_path: None,
            sample_line: Some("x".repeat(5_000)),
        };
        let until = "2026-09-10T08:00:00Z".parse::<DateTime<Utc>>().unwrap();

        let message = IpBanEngine::describe_ban(&offense, 5, until);

        assert!(message.contains("container 0f3b46ca0c16"));
        assert!(message.chars().count() < 600, "message stayed unbounded");
        assert!(message.ends_with('…'));
    }

    #[actix_rt::test]
    async fn test_ban_budget_stops_a_burst() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool,
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 1800,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
                allowlist_ranges: vec![],
                max_bans_per_minute: 3,
                protect_local_ips: true,
            },
        );
        let now = Utc::now();

        assert!(engine.ban_budget_available(now));
        assert!(engine.ban_budget_available(now));
        assert!(engine.ban_budget_available(now));
        assert!(
            !engine.ban_budget_available(now),
            "a burst past the ceiling must be refused"
        );

        // The window slides: a minute later the budget is back.
        assert!(engine.ban_budget_available(now + Duration::seconds(61)));
    }

    #[actix_rt::test]
    async fn test_ban_budget_can_be_disabled() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool,
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 1800,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
                allowlist_ranges: vec![],
                max_bans_per_minute: 0,
                protect_local_ips: true,
            },
        );
        let now = Utc::now();

        for _ in 0..50 {
            assert!(engine.ban_budget_available(now));
        }
    }

    #[actix_rt::test]
    async fn test_allowlisted_ip_is_never_recorded_or_banned() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 1,
                find_time_secs: 300,
                ban_time_secs: 1800,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
                allowlist_ranges: parse_cidr_list("167.233.9.19,10.0.0.0/8"),
                max_bans_per_minute: 0,
                protect_local_ips: true,
            },
        );

        for ip in ["167.233.9.19", "10.1.2.3"] {
            let blocked = engine
                .record_offense(OffenseInput {
                    ip_address: ip.into(),
                    source_type: "sniff".into(),
                    reason: "Repeated ssh login failure".into(),
                    severity: AlertSeverity::Critical,
                    container_id: None,
                    source_path: Some("/var/log/auth.log".into()),
                    sample_line: Some(format!("Failed password from {ip}")),
                })
                .await
                .unwrap();

            assert!(!blocked, "{ip} must not be banned");
            assert!(active_block_for_ip(&pool, ip).unwrap().is_none());

            // No offense row either: a later config change must not be able to
            // act on history collected while the address was protected.
            let offenses =
                find_recent_offenses(&pool, ip, "sniff", Utc::now() - Duration::minutes(5))
                    .unwrap();
            assert!(offenses.is_empty(), "{ip} must not accumulate offenses");
        }
    }

    #[actix_rt::test]
    async fn test_unban_expired_alerts_once_per_address() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool.clone(),
            IpBanConfig {
                enabled: true,
                max_retries: 3,
                find_time_secs: 300,
                ban_time_secs: 0,
                unban_check_interval_secs: 60,
                trusted_proxy_ranges: vec![],
                allowlist_ranges: vec![],
                max_bans_per_minute: 0,
                protect_local_ips: true,
            },
        );

        // Detections accumulate on a single row via offense_count.
        let mut blocked = Ok(false);
        for _ in 0..3 {
            blocked = engine
                .record_offense(OffenseInput {
                    ip_address: "192.0.2.77".into(),
                    source_type: "sniff".into(),
                    reason: "Repeated ssh login failure".into(),
                    severity: AlertSeverity::Critical,
                    container_id: None,
                    source_path: Some("/var/log/auth.log".into()),
                    sample_line: Some("Failed password from 192.0.2.77".into()),
                })
                .await;
        }

        #[cfg(target_os = "linux")]
        if !running_as_root() {
            assert!(blocked.is_err());
            return;
        }

        assert!(blocked.unwrap());

        let offenses = find_recent_offenses(
            &pool,
            "192.0.2.77",
            "sniff",
            Utc::now() - Duration::minutes(5),
        )
        .unwrap();
        assert_eq!(offenses.len(), 1, "expected one row per (ip, source_type)");
        assert_eq!(offenses[0].offense_count, 3);

        // One address, one release, one alert.
        let released = engine.unban_expired().await.unwrap();
        assert_eq!(released, 1);

        let offenses = find_recent_offenses(
            &pool,
            "192.0.2.77",
            "sniff",
            Utc::now() - Duration::minutes(5),
        )
        .unwrap();
        assert!(offenses
            .iter()
            .all(|offense| offense.status == OffenseStatus::Released));

        let alerts = list_alerts(&pool, AlertFilter::default()).await.unwrap();
        let releases = alerts
            .iter()
            .filter(|alert| alert.message.contains("Released IP ban for 192.0.2.77"))
            .count();
        assert_eq!(releases, 1);
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
                allowlist_ranges: vec![],
                max_bans_per_minute: 0,
                protect_local_ips: true,
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

    fn test_config() -> IpBanConfig {
        IpBanConfig {
            enabled: true,
            max_retries: 5,
            find_time_secs: 300,
            ban_time_secs: 60,
            unban_check_interval_secs: 60,
            trusted_proxy_ranges: vec![],
            allowlist_ranges: vec![],
            max_bans_per_minute: 0,
            protect_local_ips: true,
        }
    }

    #[actix_rt::test]
    async fn test_ban_now_refuses_unbannable_addresses() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(pool.clone(), test_config())
            .with_local_context(LocalIpContext::empty());

        for ip in ["172.16.0.0/12", "10.0.0.5", "127.0.0.1", "not-an-ip"] {
            let outcome = engine.ban_now(ip, "test", "cli", None).await.unwrap();
            assert!(
                matches!(outcome, BanOutcome::Refused(_)),
                "{ip} must be refused, got {:?}",
                outcome
            );
        }

        assert!(
            engine.active_bans().unwrap().is_empty(),
            "refused addresses must leave no trace"
        );
    }

    #[actix_rt::test]
    async fn test_ban_now_refuses_local_infrastructure() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let context = LocalIpContext {
            interface_ips: vec!["203.0.113.5".parse().unwrap()],
            docker_subnets: parse_cidr_list("198.51.100.0/24"),
        };
        let engine = IpBanEngine::new(pool.clone(), test_config()).with_local_context(context);

        for ip in ["203.0.113.5", "198.51.100.77"] {
            let outcome = engine.ban_now(ip, "test", "cli", None).await.unwrap();
            assert_eq!(
                outcome,
                BanOutcome::Refused(BanRefusal::LocalInfrastructure),
                "{ip} belongs to this host or its containers"
            );
        }
    }

    #[actix_rt::test]
    async fn test_record_offense_skips_unbannable_addresses() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(
            pool.clone(),
            IpBanConfig {
                max_retries: 1,
                ..test_config()
            },
        )
        .with_local_context(LocalIpContext::empty());

        for ip in ["172.16.0.0/12", "10.0.0.5", "192.168.4.7"] {
            let recorded = engine
                .record_offense(OffenseInput {
                    ip_address: ip.into(),
                    source_type: "sniff".into(),
                    reason: "test".into(),
                    severity: AlertSeverity::High,
                    container_id: None,
                    source_path: None,
                    sample_line: None,
                })
                .await
                .unwrap();
            assert!(!recorded, "{ip} must not reach the ban threshold");
        }

        assert!(engine.active_bans().unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn test_unban_ip_best_effort_releases_rows_without_a_firewall() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(pool.clone(), test_config())
            .with_local_context(LocalIpContext::empty());

        // Two source types block the same address — both rows must go.
        for source in ["sniff", "cli"] {
            record_offense_occurrence(
                &pool,
                &NewIpOffense {
                    id: Uuid::new_v4().to_string(),
                    ip_address: "192.0.2.66".into(),
                    source_type: source.into(),
                    container_id: None,
                    first_seen: Utc::now(),
                    reason: "test".into(),
                    metadata: None,
                },
                Utc::now() - Duration::minutes(5),
            )
            .unwrap();
            mark_blocked(
                &pool,
                "192.0.2.66",
                source,
                Utc::now() + Duration::minutes(30),
            )
            .unwrap();
        }

        let released = engine.unban_ip_best_effort("192.0.2.66").await.unwrap();
        assert_eq!(released, 2);
        assert!(engine.active_bans().unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn test_unban_all_releases_every_block() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let engine = IpBanEngine::new(pool.clone(), test_config())
            .with_local_context(LocalIpContext::empty());

        for ip in ["192.0.2.70", "192.0.2.71"] {
            record_offense_occurrence(
                &pool,
                &NewIpOffense {
                    id: Uuid::new_v4().to_string(),
                    ip_address: ip.into(),
                    source_type: "cli".into(),
                    container_id: None,
                    first_seen: Utc::now(),
                    reason: "test".into(),
                    metadata: None,
                },
                Utc::now() - Duration::minutes(5),
            )
            .unwrap();
            mark_blocked(&pool, ip, "cli", Utc::now() + Duration::minutes(30)).unwrap();
        }

        let released = engine.unban_all().await.unwrap();
        assert_eq!(released, 2);
        assert!(engine.active_bans().unwrap().is_empty());
    }
}
