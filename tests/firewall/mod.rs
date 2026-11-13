//! Firewall module tests

#[cfg(target_os = "linux")]
mod nftables_test;

#[cfg(target_os = "linux")]
mod iptables_test;

#[cfg(target_os = "linux")]
mod quarantine_test;

mod response_test;
