//! eBPF programs module
//!
//! Contains eBPF program definitions
//!
//! Note: Actual eBPF programs will be implemented in TASK-004

/// Program types supported by Stackdog
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    /// Syscall tracepoint program
    SyscallTracepoint,
    /// Network monitoring program
    NetworkMonitor,
    /// Container monitoring program
    ContainerMonitor,
}

/// eBPF program metadata
#[derive(Debug, Clone)]
pub struct ProgramMetadata {
    pub name: &'static str,
    pub program_type: ProgramType,
    pub description: &'static str,
    pub required_kernel: (u32, u32), // (major, minor)
}

/// Built-in eBPF programs
pub mod builtin {
    use super::*;

    /// Execve syscall tracepoint program
    pub const EXECVE_PROGRAM: ProgramMetadata = ProgramMetadata {
        name: "trace_execve",
        program_type: ProgramType::SyscallTracepoint,
        description: "Monitors execve syscalls for process execution tracking",
        required_kernel: (4, 19),
    };

    /// Connect syscall tracepoint program
    pub const CONNECT_PROGRAM: ProgramMetadata = ProgramMetadata {
        name: "trace_connect",
        program_type: ProgramType::SyscallTracepoint,
        description: "Monitors connect syscalls for network connection tracking",
        required_kernel: (4, 19),
    };

    /// Openat syscall tracepoint program
    pub const OPENAT_PROGRAM: ProgramMetadata = ProgramMetadata {
        name: "trace_openat",
        program_type: ProgramType::SyscallTracepoint,
        description: "Monitors openat syscalls for file access tracking",
        required_kernel: (4, 19),
    };

    /// Ptrace syscall tracepoint program
    pub const PTRACE_PROGRAM: ProgramMetadata = ProgramMetadata {
        name: "trace_ptrace",
        program_type: ProgramType::SyscallTracepoint,
        description: "Monitors ptrace syscalls for debugging detection",
        required_kernel: (4, 19),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_type_variants() {
        let _syscall = ProgramType::SyscallTracepoint;
        let _network = ProgramType::NetworkMonitor;
        let _container = ProgramType::ContainerMonitor;
    }

    #[test]
    fn test_builtin_programs() {
        assert_eq!(builtin::EXECVE_PROGRAM.name, "trace_execve");
        assert_eq!(builtin::CONNECT_PROGRAM.name, "trace_connect");
        assert_eq!(builtin::OPENAT_PROGRAM.name, "trace_openat");
        assert_eq!(builtin::PTRACE_PROGRAM.name, "trace_ptrace");
    }

    #[test]
    fn test_program_metadata() {
        let program = builtin::EXECVE_PROGRAM;
        assert_eq!(program.required_kernel, (4, 19));
    }
}
