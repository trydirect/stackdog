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
        }
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

fn parse_cidr_list(raw: &str) -> Vec<(Ipv4Addr, u8)> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|cidr| {
            let (addr_str, prefix_str) = cidr.split_once('/')?;
            let addr: Ipv4Addr = addr_str.parse().ok()?;
            let prefix: u8 = prefix_str.parse().ok()?;
            Some((addr, prefix))
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
