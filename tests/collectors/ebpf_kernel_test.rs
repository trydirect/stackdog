//! eBPF kernel compatibility tests

use stackdog::collectors::ebpf::kernel::{check_kernel_version, KernelInfo, KernelVersion};

#[test]
fn test_kernel_version_parse() {
    let version = KernelVersion::parse("5.15.0");
    assert!(version.is_ok());
    let v = version.unwrap();
    assert_eq!(v.major, 5);
    assert_eq!(v.minor, 15);
    assert_eq!(v.patch, 0);
}

#[test]
fn test_kernel_version_parse_with_suffix() {
    let version = KernelVersion::parse("4.19.0-16-amd64");
    assert!(version.is_ok());
    let v = version.unwrap();
    assert_eq!(v.major, 4);
    assert_eq!(v.minor, 19);
    assert_eq!(v.patch, 0);
}

#[test]
fn test_kernel_version_parse_invalid() {
    let version = KernelVersion::parse("invalid");
    assert!(version.is_err());
}

#[test]
fn test_kernel_version_comparison() {
    let v1 = KernelVersion::parse("5.10.0").unwrap();
    let v2 = KernelVersion::parse("5.15.0").unwrap();
    let v3 = KernelVersion::parse("4.19.0").unwrap();

    assert!(v2 > v1);
    assert!(v1 > v3);
    assert!(v2 > v3);
}

#[test]
fn test_kernel_version_meets_minimum() {
    let current = KernelVersion::parse("5.10.0").unwrap();
    let min_4_19 = KernelVersion::parse("4.19.0").unwrap();
    let min_5_15 = KernelVersion::parse("5.15.0").unwrap();

    assert!(current.meets_minimum(&min_4_19));
    assert!(!current.meets_minimum(&min_5_15));
}

#[test]
fn test_kernel_info_creation() {
    let info = KernelInfo::new();

    #[cfg(target_os = "linux")]
    assert!(info.is_ok());

    #[cfg(not(target_os = "linux"))]
    assert!(info.is_err());
}

#[test]
fn test_kernel_version_check_function() {
    let result = check_kernel_version();

    #[cfg(target_os = "linux")]
    {
        // On Linux, should return some version info
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux, should indicate unsupported
        assert!(result.is_err());
    }
}

#[test]
fn test_kernel_version_display() {
    let version = KernelVersion::parse("5.15.0").unwrap();
    let display = format!("{}", version);
    assert!(display.contains("5.15.0"));
}

#[test]
fn test_kernel_version_equality() {
    let v1 = KernelVersion::parse("5.10.0").unwrap();
    let v2 = KernelVersion::parse("5.10.0").unwrap();
    let v3 = KernelVersion::parse("5.10.1").unwrap();

    assert_eq!(v1, v2);
    assert_ne!(v1, v3);
}
