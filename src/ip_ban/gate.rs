//! Ban gate — which addresses may never be blocked.
//!
//! A DROP rule is host-wide: it matches in INPUT and FORWARD, for every
//! container and every service. That is the right hammer for a remote attacker
//! and the wrong one for anything on our own side of the wire. Banning the
//! host's address, a container peer, or a whole subnet (which iptables accepts
//! happily as `-s 172.16.0.0/12`) severs the application from itself, and the
//! damage outlives the ban: the rules sit in the kernel until something
//! removes them.
//!
//! Every ban entry point — log sniffing, the CLI, the AI tool — passes through
//! [`refuse_reason`] first. When in doubt the answer is "do not ban": an
//! unbanned address is one alert away from an operator, a wrongly banned one
//! takes the service down.

use std::net::Ipv4Addr;

use crate::ip_ban::config::{in_cidr, IpBanConfig};

/// Addresses belonging to this machine or its containers.
///
/// The two sources cover each other's blind spots: interface addresses catch
/// the host's own public IP (microservices talking over published ports or a
/// load balancer log the peer as that address), docker subnets catch container
/// addresses outside the RFC1918 ranges the plain private-check already covers.
#[derive(Debug, Clone, Default)]
pub struct LocalIpContext {
    pub interface_ips: Vec<Ipv4Addr>,
    pub docker_subnets: Vec<(Ipv4Addr, u8)>,
}

impl LocalIpContext {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Host interface addresses, best-effort.
    ///
    /// Discovery failure is not an error: the private-range and allowlist
    /// checks still stand, and refusing to ban at all would trade a rare blind
    /// spot for no security function whatsoever.
    pub fn discover_local() -> Self {
        Self {
            interface_ips: discover_interface_ips(),
            docker_subnets: Vec::new(),
        }
    }

    /// Docker network subnets, best-effort. Async: needs the Docker API.
    pub async fn discover_docker_subnets() -> Vec<(Ipv4Addr, u8)> {
        let Ok(docker) = bollard::Docker::connect_with_local_defaults() else {
            return Vec::new();
        };
        let Ok(networks) = docker
            .list_networks(None::<bollard::network::ListNetworksOptions<String>>)
            .await
        else {
            return Vec::new();
        };

        let mut subnets = Vec::new();
        for network in networks {
            for config in network
                .ipam
                .into_iter()
                .flat_map(|ipam| ipam.config.into_iter().flatten())
            {
                let Some(subnet) = config.subnet else {
                    continue;
                };
                if let Some(parsed) = parse_cidr(&subnet) {
                    subnets.push(parsed);
                }
            }
        }
        subnets
    }

    /// Whether `ip` belongs to this machine or its containers.
    pub fn protects(&self, ip: &Ipv4Addr) -> bool {
        self.interface_ips.contains(ip)
            || self
                .docker_subnets
                .iter()
                .any(|(network, prefix)| in_cidr(ip, network, *prefix))
    }
}

/// Why a ban request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanRefusal {
    /// Not one plain IPv4 address: garbage, IPv6, or a CIDR range. iptables
    /// accepts `-s 172.16.0.0/12` without complaint and drops a whole network.
    NotASingleIpv4,
    /// Private, loopback, link-local, multicast — always our own side of the
    /// wire, never a remote client.
    PrivateOrNonRoutable,
    /// Named in `STACKDOG_IP_BAN_ALLOWLIST`: load balancers, health checkers,
    /// the office egress.
    Allowlisted,
    /// An address of this host or a running container.
    LocalInfrastructure,
    /// The reason names no concrete attack. Ordinary internet background noise
    /// — scanners, retries, crawlers — deserves an alert, not a firewall rule.
    WeakEvidence,
    /// The per-minute ceiling caught the request before the firewall did.
    BudgetExhausted,
}

impl BanRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotASingleIpv4 => {
                "not a single IPv4 address (CIDR ranges and garbage are never banned)"
            }
            Self::PrivateOrNonRoutable => {
                "private or non-routable address — always part of the local network"
            }
            Self::Allowlisted => "address is in STACKDOG_IP_BAN_ALLOWLIST",
            Self::LocalInfrastructure => {
                "address belongs to this host or a container (local interface or docker network)"
            }
            Self::WeakEvidence => {
                "reason names no confirmed attack — report it as an alert, not a ban"
            }
            Self::BudgetExhausted => {
                "ban ceiling reached for this minute — too many blocks at once to trust"
            }
        }
    }
}

/// Phrases that name a concrete attack — the only grounds a ban may rest on
/// when a human is not standing right there.
///
/// Deliberately excluded: "repeated connection attempts", "port scan",
/// "scanning", "frequent access", "rejected connection", "possible attack".
/// Every machine on the internet is scanned all day, and a banned scanner is
/// indistinguishable from a banned crawler, health checker or customer's NAT
/// — the mistake costs more than the ban saves.
pub const STRONG_ATTACK_PHRASES: &[&str] = &[
    "brute-force",
    "brute force",
    "failed ssh login",
    "failed login attempts",
    "authentication failures",
    "invalid user",
    "path traversal",
    "credential scanning",
    "credential stuffing",
    "sensitive file access",
    "sql injection",
    "ssrf",
    "metadata access",
    "webshell",
    "exploit attempt",
    "coordinated attack",
];

/// Whether `reason` names one of [`STRONG_ATTACK_PHRASES`].
pub fn names_confirmed_attack(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    STRONG_ATTACK_PHRASES
        .iter()
        .any(|needle| reason.contains(needle))
}

/// Why `raw` must not be banned, if it must not.
///
/// One gate for every ban entry point. The checks are ordered cheapest-first
/// and each failure names itself in [`BanRefusal::reason`] so the log line an
/// operator reads says exactly what was wrong with the request.
pub fn refuse_reason(
    raw: &str,
    config: &IpBanConfig,
    context: &LocalIpContext,
) -> Option<BanRefusal> {
    // Anything that is not one plain dotted quad — garbage, IPv6, or a CIDR
    // range like "172.16.0.0/12" — is refused here. iptables would accept a
    // range as `-s` and drop a whole network.
    let Ok(ip) = raw.trim().parse::<Ipv4Addr>() else {
        return Some(BanRefusal::NotASingleIpv4);
    };

    if is_local_wire_address(&ip) {
        return Some(BanRefusal::PrivateOrNonRoutable);
    }
    if config.is_allowlisted(&ip) {
        return Some(BanRefusal::Allowlisted);
    }
    if config.protect_local_ips && context.protects(&ip) {
        return Some(BanRefusal::LocalInfrastructure);
    }
    None
}

/// Addresses that are never a remote client: they live on our side of the wire,
/// and a DROP rule for one cuts the service off from itself.
fn is_local_wire_address(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
}

/// Interface addresses of the host, best-effort via `ip -j addr` (Linux).
///
/// Returns empty when the command is missing or unparseable — see
/// [`LocalIpContext::discover_local`] for why that is safe.
fn discover_interface_ips() -> Vec<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    parse_interface_ips(&String::from_utf8_lossy(&output.stdout))
}

/// Pull every `local` address out of `ip -j addr` output.
fn parse_interface_ips(json: &str) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    // The output is a JSON array of interface objects; addresses appear as
    // "local": "192.0.2.1". Scanning for the key keeps this working across
    // iproute2 versions without pulling in a JSON dependency for one call.
    let mut rest = json;
    while let Some(position) = rest.find("\"local\"") {
        let after = &rest[position + 7..];
        let Some(value_start) = after.find('"') else {
            break;
        };
        let after = &after[value_start + 1..];
        let Some(value_end) = after.find('"') else {
            break;
        };
        if let Ok(ip) = after[..value_end].parse::<Ipv4Addr>() {
            ips.push(ip);
        }
        rest = &after[value_end + 1..];
    }

    ips
}

fn parse_cidr(raw: &str) -> Option<(Ipv4Addr, u8)> {
    match raw.trim().split_once('/') {
        Some((addr, prefix)) => Some((addr.parse().ok()?, prefix.parse().ok()?)),
        None => Some((raw.trim().parse().ok()?, 32)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_ban::config::parse_cidr_list;

    fn config(allowlist: &str) -> IpBanConfig {
        IpBanConfig {
            enabled: true,
            max_retries: 5,
            find_time_secs: 300,
            ban_time_secs: 1800,
            unban_check_interval_secs: 60,
            trusted_proxy_ranges: vec![],
            allowlist_ranges: parse_cidr_list(allowlist),
            max_bans_per_minute: 10,
            protect_local_ips: true,
        }
    }

    fn context() -> LocalIpContext {
        LocalIpContext {
            interface_ips: vec!["203.0.113.5".parse().unwrap()],
            docker_subnets: parse_cidr_list("172.18.0.0/16"),
        }
    }

    #[test]
    fn test_public_address_is_bannable() {
        assert_eq!(refuse_reason("8.8.8.8", &config(""), &context()), None);
    }

    #[test]
    fn test_cidr_range_is_refused() {
        assert_eq!(
            refuse_reason("172.16.0.0/12", &config(""), &context()),
            Some(BanRefusal::NotASingleIpv4)
        );
        assert_eq!(
            refuse_reason("10.0.0.0/8", &config(""), &context()),
            Some(BanRefusal::NotASingleIpv4)
        );
    }

    #[test]
    fn test_garbage_and_ipv6_are_refused() {
        assert_eq!(
            refuse_reason("bogus", &config(""), &context()),
            Some(BanRefusal::NotASingleIpv4)
        );
        assert_eq!(
            refuse_reason("fe80::1", &config(""), &context()),
            Some(BanRefusal::NotASingleIpv4)
        );
    }

    #[test]
    fn test_private_and_loopback_are_refused() {
        for ip in [
            "10.0.0.5",
            "172.18.0.7",
            "192.168.1.1",
            "127.0.0.1",
            "0.1.2.3",
        ] {
            assert_eq!(
                refuse_reason(ip, &config(""), &LocalIpContext::empty()),
                Some(BanRefusal::PrivateOrNonRoutable),
                "{ip} must never be banned"
            );
        }
    }

    #[test]
    fn test_allowlisted_address_is_refused() {
        assert_eq!(
            refuse_reason("167.233.9.19", &config("167.233.9.19"), &context()),
            Some(BanRefusal::Allowlisted)
        );
    }

    #[test]
    fn test_host_interface_address_is_refused() {
        assert_eq!(
            refuse_reason("203.0.113.5", &config(""), &context()),
            Some(BanRefusal::LocalInfrastructure)
        );
    }

    #[test]
    fn test_docker_subnet_address_is_refused() {
        // 172.18/16 is already private; a public-IPAM subnet is the real test.
        let context = LocalIpContext {
            interface_ips: vec![],
            docker_subnets: parse_cidr_list("198.51.100.0/24"),
        };
        assert_eq!(
            refuse_reason("198.51.100.77", &config(""), &context),
            Some(BanRefusal::LocalInfrastructure)
        );
        assert_eq!(refuse_reason("8.8.8.8", &config(""), &context), None);
    }

    #[test]
    fn test_local_protection_can_be_disabled() {
        let mut cfg = config("");
        cfg.protect_local_ips = false;
        assert_eq!(
            refuse_reason("203.0.113.5", &cfg, &context()),
            None,
            "disabling protection restores the old behaviour"
        );
    }

    #[test]
    fn test_parse_interface_ips_extracts_locals() {
        let json = r#"[
            {"ifname":"eth0","addr_info":[{"local":"203.0.113.5","prefixlen":24},{"local":"2001:db8::1"}]},
            {"ifname":"docker0","addr_info":[{"local":"172.17.0.1","prefixlen":16}]}
        ]"#;
        let ips = parse_interface_ips(json);
        assert!(ips.contains(&"203.0.113.5".parse().unwrap()));
        assert!(ips.contains(&"172.17.0.1".parse().unwrap()));
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_parse_interface_ips_tolerates_junk() {
        assert!(parse_interface_ips("not json at all").is_empty());
        assert!(parse_interface_ips("").is_empty());
    }

    #[test]
    fn test_only_confirmed_attacks_pass_the_phrase_gate() {
        for reason in [
            "SQL injection attempt in /search",
            "path traversal probe for .env",
            "brute-force against /login",
            "webshell upload detected",
        ] {
            assert!(
                names_confirmed_attack(reason),
                "{reason} names a concrete attack"
            );
        }

        for reason in [
            "repeated connection attempts",
            "port scan",
            "scanning",
            "frequent access",
            "rejected connection",
            "possible attack",
            "high traffic volume",
        ] {
            assert!(
                !names_confirmed_attack(reason),
                "{reason} is background noise, not ban grounds"
            );
        }
    }
}
