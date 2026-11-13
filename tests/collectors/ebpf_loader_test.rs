//! eBPF loader tests
//!
//! Tests for the eBPF program loader

#[cfg(target_os = "linux")]
mod linux_tests {
    use stackdog::collectors::ebpf::loader::{EbpfLoader, LoadError};

    #[test]
    fn test_ebpf_loader_creation() {
        let loader = EbpfLoader::new();
        assert!(loader.is_ok(), "EbpfLoader::new() should succeed");
    }

    #[test]
    fn test_ebpf_loader_default() {
        let _loader = EbpfLoader::default();
    }

    #[test]
    fn test_ebpf_loader_has_programs() {
        let loader = EbpfLoader::new().expect("Failed to create loader");
        // Initially no programs loaded
        assert_eq!(loader.loaded_program_count(), 0);
    }

    #[test]
    #[ignore = "requires root and eBPF support"]
    fn test_ebpf_program_load_success() {
        let mut loader = EbpfLoader::new().expect("Failed to create loader");

        // Try to load a program (this requires the eBPF ELF file)
        let result = loader.load_program_from_bytes(&[]);

        // Should fail with empty bytes, but not panic
        assert!(result.is_err());
    }

    #[test]
    fn test_ebpf_loader_error_display() {
        let error = LoadError::ProgramNotFound("test_program".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("test_program"));

        let error = LoadError::KernelVersionTooLow {
            required: "4".to_string(),
            current: "3".to_string(),
        };
        let msg = format!("{}", error);
        assert!(msg.contains("4.19"));
    }
}

/// Cross-platform tests
mod cross_platform_tests {
    use stackdog::collectors::ebpf::loader::EbpfLoader;

    #[test]
    fn test_ebpf_loader_creation_cross_platform() {
        // This test should work on all platforms
        let result = EbpfLoader::new();

        #[cfg(target_os = "linux")]
        assert!(result.is_ok());

        #[cfg(not(target_os = "linux"))]
        assert!(result.is_err()); // Should error on non-Linux
    }

    #[test]
    fn test_ebpf_is_linux_check() {
        use stackdog::collectors::ebpf::loader::is_linux;

        #[cfg(target_os = "linux")]
        assert!(is_linux());

        #[cfg(not(target_os = "linux"))]
        assert!(!is_linux());
    }
}
