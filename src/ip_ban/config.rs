use std::env;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct IpBanConfig {
    pub enabled: bool,
    pub max_retries: u32,
    pub find_time_secs: u64,
    pub ban_time_secs: u64,
    pub unban_check_interval_secs: u64,
    /// CIDR ranges of reverse proxies; when the source IP falls in one of
    /// these ranges the engine will look for the real client IP in
    /// X-Forwarded-For / X-Real-IP headers before banning.
    pub trusted_proxy_ranges: Vec<(Ipv4Addr, u8)>,
    /// CIDR ranges that must never be banned, whatever the logs say.
    ///
    /// Meant for infrastructure whose loss takes the service down with it:
    /// load balancers, health checkers, VPN gateways, the office egress.
    pub allowlist_ranges: Vec<(Ipv4Addr, u8)>,
    /// Ceiling on how many addresses may be blocked within a minute.
    ///
    /// A safety valve, not a policy: banning a dozen addresses in one second
    /// means the log was misread, not that a dozen attackers arrived together.
    /// Zero disables the ceiling.
    pub max_bans_per_minute: u32,
}

impl IpBanConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: parse_bool_env("STACKDOG_IP_BAN_ENABLED", true),
            max_retries: parse_u32_env("STACKDOG_IP_BAN_MAX_RETRIES", 5),
            find_time_secs: parse_u64_env("STACKDOG_IP_BAN_FIND_TIME_SECS", 300),
            ban_time_secs: parse_u64_env("STACKDOG_IP_BAN_BAN_TIME_SECS", 1800),
            unban_check_interval_secs: parse_u64_env(
                "STACKDOG_IP_BAN_UNBAN_CHECK_INTERVAL_SECS",
                60,
            ),
            trusted_proxy_ranges: parse_cidr_list(
                &env::var("STACKDOG_TRUSTED_PROXY_RANGES")
                    .unwrap_or_else(|_| "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16".into()),
            ),
            allowlist_ranges: parse_cidr_list(
                &env::var("STACKDOG_IP_BAN_ALLOWLIST").unwrap_or_default(),
            ),
            max_bans_per_minute: parse_u32_env("STACKDOG_IP_BAN_MAX_PER_MINUTE", 10),
        }
    }

    /// Returns true if `ip` is protected from banning.
    ///
    /// A bare address is accepted as well as CIDR notation: "167.233.9.19" is
    /// read as "167.233.9.19/32", since that is how operators write it.
    pub fn is_allowlisted(&self, ip: &Ipv4Addr) -> bool {
        self.allowlist_ranges
            .iter()
            .any(|(network, prefix_len)| in_cidr(ip, network, *prefix_len))
    }

    /// Returns true if `ip` falls within any configured trusted proxy range.
    pub fn is_trusted_proxy(&self, ip: &Ipv4Addr) -> bool {
        self.trusted_proxy_ranges
            .iter()
            .any(|(network, prefix_len)| in_cidr(ip, network, *prefix_len))
    }
}

fn in_cidr(ip: &Ipv4Addr, network: &Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = !0u32 << (32 - prefix_len);
    let ip_bits = u32::from_be_bytes(ip.octets());
    let net_bits = u32::from_be_bytes(network.octets());
    (ip_bits & mask) == (net_bits & mask)
}

pub(crate) fn parse_cidr_list(raw: &str) -> Vec<(Ipv4Addr, u8)> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|cidr| match cidr.split_once('/') {
            Some((addr_str, prefix_str)) => {
                let addr: Ipv4Addr = addr_str.parse().ok()?;
                let prefix: u8 = prefix_str.parse().ok()?;
                (prefix <= 32).then_some((addr, prefix))
            }
            // A bare address means a single host.
            None => cidr.parse::<Ipv4Addr>().ok().map(|addr| (addr, 32)),
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_list_accepts_bare_addresses() {
        let ranges = parse_cidr_list("167.233.9.19, 10.0.0.0/8 ,bogus,1.2.3.4/33");
        assert_eq!(
            ranges,
            vec![
                ("167.233.9.19".parse().unwrap(), 32),
                ("10.0.0.0".parse().unwrap(), 8)
            ]
        );
    }

    #[test]
    fn test_is_allowlisted_matches_host_and_range() {
        let config = IpBanConfig {
            enabled: true,
            max_retries: 5,
            find_time_secs: 300,
            ban_time_secs: 1800,
            unban_check_interval_secs: 60,
            trusted_proxy_ranges: vec![],
            allowlist_ranges: parse_cidr_list("167.233.9.19,192.168.0.0/16"),
            max_bans_per_minute: 10,
        };

        assert!(config.is_allowlisted(&"167.233.9.19".parse().unwrap()));
        assert!(config.is_allowlisted(&"192.168.4.7".parse().unwrap()));
        assert!(!config.is_allowlisted(&"167.233.9.20".parse().unwrap()));
        assert!(!config.is_allowlisted(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_allowlist_is_empty_by_default() {
        assert!(parse_cidr_list("").is_empty());
    }
}
