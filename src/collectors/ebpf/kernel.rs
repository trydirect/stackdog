//! Kernel compatibility checking
//!
//! Provides kernel version detection and compatibility checks for eBPF

use anyhow::{Context, Result};
use std::fmt;

/// Kernel version information
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    /// Parse kernel version from string (e.g., "5.15.0" or "4.19.0-16-amd64")
    pub fn parse(version: &str) -> Result<Self> {
        // Extract the first three numeric components
        let parts: Vec<&str> = version.split('.').take(3).collect();

        if parts.len() < 2 {
            anyhow::bail!("Invalid kernel version format: {}", version);
        }

        let major = parts[0]
            .parse::<u32>()
            .with_context(|| format!("Invalid major version: {}", parts[0]))?;

        let minor = parts[1]
            .split('-') // Handle versions like "15.0-16-amd64"
            .next()
            .unwrap_or("0")
            .parse::<u32>()
            .with_context(|| format!("Invalid minor version: {}", parts[1]))?;

        let patch = if parts.len() > 2 {
            parts[2]
                .split('-')
                .next()
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap_or(0)
        } else {
            0
        };

        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// Check if this version meets the minimum requirement
    pub fn meets_minimum(&self, minimum: &KernelVersion) -> bool {
        self >= minimum
    }

    /// Check if kernel supports eBPF (4.19+)
    pub fn supports_ebpf(&self) -> bool {
        self.meets_minimum(&KernelVersion {
            major: 4,
            minor: 19,
            patch: 0,
        })
    }

    /// Check if kernel supports BTF
    pub fn supports_btf(&self) -> bool {
        // BTF support improved significantly in 5.4+
        self.meets_minimum(&KernelVersion {
            major: 5,
            minor: 4,
            patch: 0,
        })
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Kernel information
#[derive(Debug)]
pub struct KernelInfo {
    pub version: KernelVersion,
    pub os: String,
    pub arch: String,
}

impl KernelInfo {
    /// Get current kernel information
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let version_str = get_kernel_version()?;
            let version = KernelVersion::parse(&version_str)
                .with_context(|| format!("Failed to parse kernel version: {}", version_str))?;

            Ok(Self {
                version,
                os: "linux".to_string(),
                arch: std::env::consts::ARCH.to_string(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Kernel info only available on Linux");
        }
    }

    /// Check if current kernel supports eBPF
    pub fn supports_ebpf(&self) -> bool {
        self.version.supports_ebpf()
    }

    /// Check if current kernel supports BTF
    pub fn supports_btf(&self) -> bool {
        self.version.supports_btf()
    }
}

impl Default for KernelInfo {
    fn default() -> Self {
        Self::new().expect("Failed to get kernel info")
    }
}

/// Check kernel version and return result
pub fn check_kernel_version() -> Result<KernelVersion> {
    let info = KernelInfo::new()?;
    Ok(info.version)
}

/// Get raw kernel version string
#[cfg(target_os = "linux")]
fn get_kernel_version() -> Result<String> {
    use std::fs;

    let version = fs::read_to_string("/proc/sys/kernel/osrelease")
        .with_context(|| "Failed to read /proc/sys/kernel/osrelease")?;

    Ok(version.trim().to_string())
}

/// Check if running on Linux
pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parse_simple() {
        let version = KernelVersion::parse("5.15.0").unwrap();
        assert_eq!(version.major, 5);
        assert_eq!(version.minor, 15);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_kernel_version_parse_with_suffix() {
        let version = KernelVersion::parse("4.19.0-16-amd64").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 19);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_kernel_version_parse_two_components() {
        let version = KernelVersion::parse("5.10").unwrap();
        assert_eq!(version.major, 5);
        assert_eq!(version.minor, 10);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_kernel_version_parse_invalid() {
        let result = KernelVersion::parse("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_kernel_version_comparison() {
        let v1 = KernelVersion::parse("5.10.0").unwrap();
        let v2 = KernelVersion::parse("5.15.0").unwrap();

        assert!(v2 > v1);
        assert!(v1 < v2);
    }

    #[test]
    fn test_kernel_version_equality() {
        let v1 = KernelVersion::parse("5.10.0").unwrap();
        let v2 = KernelVersion::parse("5.10.0").unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_kernel_version_display() {
        let version = KernelVersion::parse("5.15.0").unwrap();
        assert_eq!(format!("{}", version), "5.15.0");
    }

    #[test]
    fn test_kernel_version_supports_ebpf() {
        let v4_18 = KernelVersion::parse("4.18.0").unwrap();
        let v4_19 = KernelVersion::parse("4.19.0").unwrap();
        let v5_10 = KernelVersion::parse("5.10.0").unwrap();

        assert!(!v4_18.supports_ebpf());
        assert!(v4_19.supports_ebpf());
        assert!(v5_10.supports_ebpf());
    }

    #[test]
    fn test_kernel_version_supports_btf() {
        let v5_3 = KernelVersion::parse("5.3.0").unwrap();
        let v5_4 = KernelVersion::parse("5.4.0").unwrap();
        let v5_10 = KernelVersion::parse("5.10.0").unwrap();

        assert!(!v5_3.supports_btf());
        assert!(v5_4.supports_btf());
        assert!(v5_10.supports_btf());
    }
}
