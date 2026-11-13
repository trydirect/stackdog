//! Container detection
//!
//! Detects container ID from cgroup and other sources

use anyhow::Result;

/// Container detector
pub struct ContainerDetector {
    // Cache for container IDs
    cache: std::collections::HashMap<u32, String>,
}

impl ContainerDetector {
    /// Create a new container detector
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                cache: std::collections::HashMap::new(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("Container detection only available on Linux");
        }
    }

    /// Detect container ID for a process
    pub fn detect_container(&mut self, pid: u32) -> Option<String> {
        // Check cache first
        if let Some(cached) = self.cache.get(&pid) {
            return Some(cached.clone());
        }

        // Try to detect from cgroup
        let container_id = self.detect_from_cgroup(pid);

        // Cache result
        if let Some(id) = &container_id {
            self.cache.insert(pid, id.clone());
        }

        container_id
    }

    /// Detect container ID from cgroup file
    fn detect_from_cgroup(&self, _pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            // Read /proc/[pid]/cgroup
            let cgroup_path = format!("/proc/{}/cgroup", _pid);
            if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
                for line in content.lines() {
                    if let Some(id) = Self::parse_container_from_cgroup(line) {
                        return Some(id);
                    }
                }
            }
        }

        None
    }

    /// Parse container ID from cgroup line
    pub fn parse_container_from_cgroup(cgroup_line: &str) -> Option<String> {
        // Format: hierarchy:controllers:path
        // Docker: 12:memory:/docker/abc123def456...
        // Kubernetes: 11:cpu:/kubepods/pod123/def456...

        let parts: Vec<&str> = cgroup_line.split(':').collect();
        if parts.len() < 3 {
            return None;
        }

        let path = parts[2];

        // Try Docker format
        if let Some(id) = Self::extract_docker_id(path) {
            return Some(id);
        }

        // Try Kubernetes format
        if let Some(id) = Self::extract_kubernetes_id(path) {
            return Some(id);
        }

        // Try containerd format
        if let Some(id) = Self::extract_containerd_id(path) {
            return Some(id);
        }

        None
    }

    /// Extract Docker container ID
    fn extract_docker_id(path: &str) -> Option<String> {
        // Look for /docker/[container_id]
        if let Some(pos) = path.find("/docker/") {
            let start = pos + 8;
            let id = &path[start..];
            let id = id.split('/').next()?;

            if Self::is_valid_container_id(id) {
                return Some(id.to_string());
            }
        }

        None
    }

    /// Extract Kubernetes container ID
    fn extract_kubernetes_id(path: &str) -> Option<String> {
        // Look for /kubepods/.../container_id
        if path.contains("/kubepods/") {
            // Get last component
            let id = path.split('/').next_back()?;

            if Self::is_valid_container_id(id) {
                return Some(id.to_string());
            }
        }

        None
    }

    /// Extract containerd container ID
    fn extract_containerd_id(path: &str) -> Option<String> {
        // Look for /containerd/[container_id]
        if let Some(pos) = path.find("/containerd/") {
            let start = pos + 12;
            let id = &path[start..];
            let id = id.split('/').next()?;

            if Self::is_valid_container_id(id) {
                return Some(id.to_string());
            }
        }

        None
    }

    /// Validate container ID format
    pub fn validate_container_id(&self, id: &str) -> bool {
        Self::is_valid_container_id(id)
    }

    /// Check if string is a valid container ID
    fn is_valid_container_id(id: &str) -> bool {
        // Container IDs are typically 64 hex characters (full) or 12 hex characters (short)
        if id.is_empty() {
            return false;
        }

        // Check length
        if id.len() != 12 && id.len() != 64 {
            return false;
        }

        // Check all characters are hex
        id.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Get current process container ID
    pub fn current_container(&mut self) -> Option<String> {
        let pid = std::process::id();
        self.detect_container(pid)
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for ContainerDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create ContainerDetector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = ContainerDetector::new();

        #[cfg(target_os = "linux")]
        assert!(detector.is_ok());

        #[cfg(not(target_os = "linux"))]
        assert!(detector.is_err());
    }

    #[test]
    fn test_parse_docker_cgroup() {
        let cgroup =
            "12:memory:/docker/abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        let result = ContainerDetector::parse_container_from_cgroup(cgroup);
        assert_eq!(
            result,
            Some("abc123def456abc123def456abc123def456abc123def456abc123def456abcd".to_string())
        );
    }

    #[test]
    fn test_parse_kubernetes_cgroup() {
        let cgroup = "11:cpu:/kubepods/pod123/def456abc123def456abc123def456abc123def456abc123def456abc123def4";
        let result = ContainerDetector::parse_container_from_cgroup(cgroup);
        assert_eq!(
            result,
            Some("def456abc123def456abc123def456abc123def456abc123def456abc123def4".to_string())
        );
    }

    #[test]
    fn test_parse_non_container_cgroup() {
        let cgroup = "10:cpuacct:/";
        let result = ContainerDetector::parse_container_from_cgroup(cgroup);
        assert_eq!(result, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_valid_container_id() {
        let detector = ContainerDetector::new().unwrap();

        // Full ID (64 chars)
        assert!(detector.validate_container_id(
            "abc123def456789012345678901234567890123456789012345678901234abcd"
        ));

        // Short ID (12 chars)
        assert!(detector.validate_container_id("abc123def456"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_invalid_container_id() {
        let detector = ContainerDetector::new().unwrap();

        // Empty
        assert!(!detector.validate_container_id(""));

        // Too short
        assert!(!detector.validate_container_id("abc123"));

        // Invalid chars
        assert!(!detector.validate_container_id("abc123def45!"));

        // Too long
        assert!(!detector.validate_container_id(
            "abc123def4567890123456789012345678901234567890123456789012345678901234567890"
        ));
    }
}
