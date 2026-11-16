//! eBPF program loader
//!
//! Loads and manages eBPF programs using aya-rs
//!
//! Note: This module is only available on Linux with the ebpf feature enabled

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use anyhow::Context;
use anyhow::Result;
use std::collections::HashMap;

/// eBPF loader errors
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Failed to load program: {0}")]
    LoadFailed(String),

    #[error("Failed to attach program: {0}")]
    AttachFailed(String),

    #[error("Kernel version too low: required {required}, current {current}. eBPF requires kernel 4.19+")]
    KernelVersionTooLow { required: String, current: String },

    #[error("Not running on Linux")]
    NotLinux,

    #[error("Permission denied: eBPF programs require root or CAP_BPF")]
    PermissionDenied,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// eBPF program loader
///
/// Responsible for loading eBPF programs from ELF files
/// and attaching them to kernel tracepoints
#[derive(Default)]
pub struct EbpfLoader {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    bpf: Option<aya::Bpf>,

    loaded_programs: HashMap<String, ProgramInfo>,
    kernel_version: Option<crate::collectors::ebpf::kernel::KernelVersion>,
}

#[derive(Debug, Clone)]
struct ProgramInfo {
    _name: String,
    attached: bool,
}

impl EbpfLoader {
    /// Create a new eBPF loader
    pub fn new() -> Result<Self, LoadError> {
        // Check if running on Linux
        if !cfg!(target_os = "linux") {
            return Err(LoadError::NotLinux);
        }

        // Check kernel version
        #[cfg(target_os = "linux")]
        let kernel_version = {
            match crate::collectors::ebpf::kernel::check_kernel_version() {
                Ok(version) => {
                    if !version.supports_ebpf() {
                        return Err(LoadError::KernelVersionTooLow {
                            required: "4.19".to_string(),
                            current: version.to_string(),
                        });
                    }
                    Some(version)
                }
                Err(e) => {
                    // Log warning but continue
                    log::warn!("Could not check kernel version: {}", e);
                    None
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let kernel_version: Option<crate::collectors::ebpf::kernel::KernelVersion> = None;

        Ok(Self {
            #[cfg(all(target_os = "linux", feature = "ebpf"))]
            bpf: None,
            loaded_programs: HashMap::new(),
            kernel_version,
        })
    }

    /// Load an eBPF program from bytes (ELF file contents)
    pub fn load_program_from_bytes(&mut self, _bytes: &[u8]) -> Result<(), LoadError> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            if _bytes.is_empty() {
                return Err(LoadError::LoadFailed("Empty program bytes".to_string()));
            }

            let bpf = aya::Bpf::load(_bytes).map_err(|e| LoadError::LoadFailed(e.to_string()))?;
            self.bpf = Some(bpf);

            log::info!("eBPF program loaded ({} bytes)", _bytes.len());
            Ok(())
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Err(LoadError::NotLinux)
        }
    }

    /// Load an eBPF program from ELF file
    pub fn load_program_from_file(&mut self, _path: &str) -> Result<(), LoadError> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            use std::fs;

            let bytes = fs::read(_path)
                .with_context(|| format!("Failed to read eBPF program: {}", _path))
                .map_err(|e| LoadError::Other(e.into()))?;

            self.load_program_from_bytes(&bytes)
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Err(LoadError::NotLinux)
        }
    }

    /// Attach a loaded program to its tracepoint
    pub fn attach_program(&mut self, _program_name: &str) -> Result<(), LoadError> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let (category, tp_name) = program_to_tracepoint(_program_name).ok_or_else(|| {
                LoadError::ProgramNotFound(format!("No tracepoint mapping for '{}'", _program_name))
            })?;

            let bpf = self.bpf.as_mut().ok_or_else(|| {
                LoadError::LoadFailed(
                    "No eBPF program loaded; call load_program_from_bytes first".to_string(),
                )
            })?;

            let prog: &mut aya::programs::TracePoint = bpf
                .program_mut(_program_name)
                .ok_or_else(|| LoadError::ProgramNotFound(_program_name.to_string()))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| LoadError::AttachFailed(e.to_string()))?;

            prog.load()
                .map_err(|e| LoadError::AttachFailed(format!("load '{}': {}", _program_name, e)))?;

            prog.attach(category, tp_name).map_err(|e| {
                LoadError::AttachFailed(format!("attach '{}/{}': {}", category, tp_name, e))
            })?;

            self.loaded_programs.insert(
                _program_name.to_string(),
                ProgramInfo {
                    _name: _program_name.to_string(),
                    attached: true,
                },
            );

            log::info!(
                "eBPF program '{}' attached to {}/{}",
                _program_name,
                category,
                tp_name
            );
            Ok(())
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Err(LoadError::NotLinux)
        }
    }

    /// Attach all known syscall tracepoint programs
    pub fn attach_all_programs(&mut self) -> Result<(), LoadError> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            for name in &[
                "trace_execve",
                "trace_connect",
                "trace_openat",
                "trace_ptrace",
            ] {
                if let Err(e) = self.attach_program(name) {
                    log::warn!("Failed to attach '{}': {}", name, e);
                }
            }
            Ok(())
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Err(LoadError::NotLinux)
        }
    }

    /// Extract the EVENTS ring buffer map from the loaded eBPF program.
    /// Must be called after load_program_from_bytes and before the Bpf object is dropped.
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn take_ring_buf(&mut self) -> Result<aya::maps::RingBuf<aya::maps::MapData>, LoadError> {
        let bpf = self
            .bpf
            .as_mut()
            .ok_or_else(|| LoadError::LoadFailed("No eBPF program loaded".to_string()))?;

        let map = bpf.take_map("EVENTS").ok_or_else(|| {
            LoadError::LoadFailed("EVENTS ring buffer map not found in eBPF program".to_string())
        })?;

        aya::maps::RingBuf::try_from(map)
            .map_err(|e| LoadError::LoadFailed(format!("Failed to create ring buffer: {}", e)))
    }

    /// Detach a program
    pub fn detach_program(&mut self, program_name: &str) -> Result<(), LoadError> {
        if let Some(info) = self.loaded_programs.get_mut(program_name) {
            info.attached = false;
            Ok(())
        } else {
            Err(LoadError::ProgramNotFound(program_name.to_string()))
        }
    }

    /// Unload a program
    pub fn unload_program(&mut self, program_name: &str) -> Result<(), LoadError> {
        self.loaded_programs
            .remove(program_name)
            .ok_or_else(|| LoadError::ProgramNotFound(program_name.to_string()))?;
        Ok(())
    }

    /// Check if a program is loaded
    pub fn is_program_loaded(&self, program_name: &str) -> bool {
        self.loaded_programs.contains_key(program_name)
    }

    /// Check if a program is attached
    pub fn is_program_attached(&self, program_name: &str) -> bool {
        self.loaded_programs
            .get(program_name)
            .map(|info| info.attached)
            .unwrap_or(false)
    }

    /// Get the number of loaded programs
    pub fn loaded_program_count(&self) -> usize {
        self.loaded_programs.len()
    }

    /// Get the kernel version
    pub fn kernel_version(&self) -> Option<&crate::collectors::ebpf::kernel::KernelVersion> {
        self.kernel_version.as_ref()
    }

    /// Check if eBPF is supported on this system
    pub fn is_ebpf_supported(&self) -> bool {
        self.kernel_version
            .as_ref()
            .map(|v| v.supports_ebpf())
            .unwrap_or(false)
    }
}

/// Map program name to its tracepoint (category, name) for aya attachment.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn program_to_tracepoint(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "trace_execve" => Some(("syscalls", "sys_enter_execve")),
        "trace_connect" => Some(("syscalls", "sys_enter_connect")),
        "trace_openat" => Some(("syscalls", "sys_enter_openat")),
        "trace_ptrace" => Some(("syscalls", "sys_enter_ptrace")),
        _ => None,
    }
}

/// Check if running on Linux
pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

// Stub implementation for non-Linux or when ebpf feature is disabled
#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
impl EbpfLoader {
    /// Create a stub loader that always fails
    pub fn new_stub() -> Result<Self, LoadError> {
        Err(LoadError::NotLinux)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_loader_creation() {
        let loader = EbpfLoader::new();

        #[cfg(target_os = "linux")]
        assert!(loader.is_ok());

        #[cfg(not(target_os = "linux"))]
        assert!(loader.is_err());
    }

    #[test]
    fn test_is_linux() {
        #[cfg(target_os = "linux")]
        assert!(is_linux());

        #[cfg(not(target_os = "linux"))]
        assert!(!is_linux());
    }

    #[test]
    fn test_load_error_display() {
        let error = LoadError::ProgramNotFound("test".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("test"));

        let error = LoadError::NotLinux;
        let msg = format!("{}", error);
        assert!(msg.contains("Linux"));
    }
}
