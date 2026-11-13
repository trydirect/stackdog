//! Event enrichment
//!
//! Enriches syscall events with additional context (container ID, process info, etc.)

use crate::events::syscall::{SyscallDetails, SyscallEvent};
use anyhow::Result;

/// Event enricher
pub struct EventEnricher {
    _process_cache: std::collections::HashMap<u32, ProcessInfo>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    _pid: u32,
    _ppid: u32,
    _comm: Option<String>,
}

impl EventEnricher {
    /// Create a new event enricher
    pub fn new() -> Result<Self> {
        Ok(Self {
            _process_cache: std::collections::HashMap::new(),
        })
    }

    /// Enrich an event with additional information
    pub fn enrich(&mut self, event: &mut SyscallEvent) -> Result<()> {
        // Add timestamp normalization (already done in event creation)
        // Add process information
        self.enrich_process_info(event);

        Ok(())
    }

    /// Enrich event with process information
    fn enrich_process_info(&mut self, event: &mut SyscallEvent) {
        // Try to get process comm if not already set
        if event.comm.is_none() {
            event.comm = self.get_process_comm(event.pid);
        }

        if let Some(SyscallDetails::Exec {
            filename,
            args,
            argc: _,
        }) = event.details.as_mut()
        {
            if filename.is_none() {
                *filename = self.get_process_exe(event.pid).or_else(|| {
                    self.get_process_cmdline(event.pid)
                        .and_then(|cmdline| cmdline.first().cloned())
                });
            }

            if args.is_empty() {
                if let Some(cmdline) = self.get_process_cmdline(event.pid) {
                    *args = cmdline;
                }
            }
        }
    }

    /// Get parent PID for a process
    pub fn get_parent_pid(&self, _pid: u32) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            // Read from /proc/[pid]/stat
            let stat_path = format!("/proc/{}/stat", _pid);
            if let Ok(content) = std::fs::read_to_string(&stat_path) {
                // Parse ppid from stat file (field 4)
                let parts: Vec<&str> = content.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(ppid) = parts[3].parse::<u32>() {
                        return Some(ppid);
                    }
                }
            }
        }

        None
    }

    /// Get process command name
    pub fn get_process_comm(&self, _pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            // Read from /proc/[pid]/comm
            let comm_path = format!("/proc/{}/comm", _pid);
            if let Ok(content) = std::fs::read_to_string(&comm_path) {
                return Some(content.trim().to_string());
            }

            // Alternative: read from /proc/[pid]/cmdline
            let cmdline_path = format!("/proc/{}/cmdline", _pid);
            if let Ok(content) = std::fs::read_to_string(&cmdline_path) {
                if let Some(first_null) = content.find('\0') {
                    let path = &content[..first_null];
                    // Get basename
                    if let Some(last_slash) = path.rfind('/') {
                        return Some(path[last_slash + 1..].to_string());
                    }
                    return Some(path.to_string());
                }
            }
        }

        None
    }

    /// Get process executable path
    pub fn get_process_exe(&self, _pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            // Read symlink /proc/[pid]/exe
            let exe_path = format!("/proc/{}/exe", _pid);
            if let Ok(path) = std::fs::read_link(&exe_path) {
                return path.to_str().map(|s| s.to_string());
            }
        }

        None
    }

    /// Get full process command line arguments.
    pub fn get_process_cmdline(&self, _pid: u32) -> Option<Vec<String>> {
        #[cfg(target_os = "linux")]
        {
            let cmdline_path = format!("/proc/{}/cmdline", _pid);
            if let Ok(content) = std::fs::read(&cmdline_path) {
                let args = content
                    .split(|byte| *byte == 0)
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| String::from_utf8_lossy(segment).to_string())
                    .collect::<Vec<_>>();
                if !args.is_empty() {
                    return Some(args);
                }
            }
        }

        None
    }

    /// Get process working directory
    pub fn get_process_cwd(&self, _pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            // Read symlink /proc/[pid]/cwd
            let cwd_path = format!("/proc/{}/cwd", _pid);
            if let Ok(path) = std::fs::read_link(&cwd_path) {
                return path.to_str().map(|s| s.to_string());
            }
        }

        None
    }
}

impl Default for EventEnricher {
    fn default() -> Self {
        Self::new().expect("Failed to create EventEnricher")
    }
}

/// Normalize timestamp to UTC
pub fn normalize_timestamp(ts: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    ts
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    #[test]
    fn test_enricher_creation() {
        let enricher = EventEnricher::new();
        assert!(enricher.is_ok());
    }

    #[test]
    fn test_normalize_timestamp() {
        let now = Utc::now();
        let normalized = normalize_timestamp(now);
        assert_eq!(now, normalized);
    }

    #[test]
    fn test_get_process_cmdline_current_process() {
        let enricher = EventEnricher::new().unwrap();
        let _cmdline = enricher.get_process_cmdline(std::process::id());

        #[cfg(target_os = "linux")]
        assert!(_cmdline.is_some());
    }
}
