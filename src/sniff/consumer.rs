//! Log consumer: compress, deduplicate, and purge original logs
//!
//! When `--consume` is enabled, logs are archived to zstd-compressed files,
//! deduplicated, and then originals are purged to free disk space.

use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::sniff::discovery::LogSourceType;
use crate::sniff::reader::LogEntry;

/// Result of a consume operation
#[derive(Debug, Clone, Default)]
pub struct ConsumeResult {
    pub entries_archived: usize,
    pub duplicates_skipped: usize,
    pub bytes_freed: u64,
    pub compressed_size: u64,
}

/// Consumes log entries: deduplicates, compresses to zstd, and purges originals
pub struct LogConsumer {
    output_dir: PathBuf,
    seen_hashes: HashSet<u64>,
    max_seen_hashes: usize,
}

impl LogConsumer {
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&output_dir).with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;

        Ok(Self {
            output_dir,
            seen_hashes: HashSet::new(),
            max_seen_hashes: 100_000,
        })
    }

    /// Hash a log line for deduplication
    fn hash_line(line: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        line.hash(&mut hasher);
        hasher.finish()
    }

    /// Deduplicate entries, returning only unique ones
    pub fn deduplicate<'a>(&mut self, entries: &'a [LogEntry]) -> Vec<&'a LogEntry> {
        // Evict oldest hashes if at capacity
        if self.seen_hashes.len() > self.max_seen_hashes {
            self.seen_hashes.clear();
        }

        let seen = &mut self.seen_hashes;
        entries
            .iter()
            .filter(|entry| {
                let hash = Self::hash_line(&entry.line);
                seen.insert(hash)
            })
            .collect()
    }

    /// Write entries to a zstd-compressed file
    pub fn write_compressed(
        &self,
        entries: &[&LogEntry],
        source_name: &str,
    ) -> Result<(PathBuf, u64)> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let safe_name = source_name.replace(['/', '\\', ':', ' '], "_");
        let filename = format!("{}_{}.log.zst", safe_name, timestamp);
        let path = self.output_dir.join(&filename);

        let file = File::create(&path)
            .with_context(|| format!("Failed to create archive file: {}", path.display()))?;

        let encoder = zstd::Encoder::new(file, 3).context("Failed to create zstd encoder")?;
        let mut writer = BufWriter::new(encoder);

        for entry in entries {
            writeln!(writer, "{}\t{}", entry.timestamp.to_rfc3339(), entry.line)?;
        }

        let encoder = writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!("Buffer flush error: {}", e))?;
        encoder.finish().context("Failed to finish zstd encoding")?;

        let compressed_size = fs::metadata(&path)?.len();
        Ok((path, compressed_size))
    }

    /// Purge a file-based log source by truncating it
    pub fn purge_file(path: &Path) -> Result<u64> {
        if !path.exists() {
            return Ok(0);
        }

        let original_size = fs::metadata(path)?.len();

        // Truncate the file (preserves the fd for syslog daemons)
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("Failed to truncate log file: {}", path.display()))?;

        Ok(original_size)
    }

    /// Purge Docker container logs by truncating the JSON log file
    pub async fn purge_docker_logs(container_id: &str) -> Result<u64> {
        // Docker stores logs at /var/lib/docker/containers/<id>/<id>-json.log
        let log_path = format!(
            "/var/lib/docker/containers/{}/{}-json.log",
            container_id, container_id
        );
        let path = Path::new(&log_path);

        if path.exists() {
            Self::purge_file(path)
        } else {
            log::info!(
                "Docker log file not found for container {}, skipping purge",
                container_id
            );
            Ok(0)
        }
    }

    /// Full consume pipeline: deduplicate → compress → purge
    pub async fn consume(
        &mut self,
        entries: &[LogEntry],
        source_name: &str,
        source_type: &LogSourceType,
        source_path: &str,
    ) -> Result<ConsumeResult> {
        if entries.is_empty() {
            return Ok(ConsumeResult::default());
        }

        let total = entries.len();
        let unique_entries = self.deduplicate(entries);
        let duplicates_skipped = total - unique_entries.len();

        let (_, compressed_size) = self.write_compressed(&unique_entries, source_name)?;

        let bytes_freed = match source_type {
            LogSourceType::DockerContainer => Self::purge_docker_logs(source_path).await?,
            LogSourceType::SystemLog | LogSourceType::CustomFile => {
                let path = Path::new(source_path);
                Self::purge_file(path)?
            }
        };

        Ok(ConsumeResult {
            entries_archived: unique_entries.len(),
            duplicates_skipped,
            bytes_freed,
            compressed_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::io::Read;

    fn make_entry(line: &str) -> LogEntry {
        LogEntry {
            source_id: "test".into(),
            timestamp: Utc::now(),
            line: line.to_string(),
            metadata: HashMap::new(),
        }
    }

    fn make_entries(lines: &[&str]) -> Vec<LogEntry> {
        lines.iter().map(|l| make_entry(l)).collect()
    }

    #[test]
    fn test_hash_line_deterministic() {
        let h1 = LogConsumer::hash_line("hello world");
        let h2 = LogConsumer::hash_line("hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_line_different_for_different_inputs() {
        let h1 = LogConsumer::hash_line("hello");
        let h2 = LogConsumer::hash_line("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_deduplicate_removes_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let entries = make_entries(&["line A", "line B", "line A", "line C", "line B"]);
        let unique = consumer.deduplicate(&entries);
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_deduplicate_all_unique() {
        let dir = tempfile::tempdir().unwrap();
        let mut consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let entries = make_entries(&["line 1", "line 2", "line 3"]);
        let unique = consumer.deduplicate(&entries);
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_deduplicate_all_same() {
        let dir = tempfile::tempdir().unwrap();
        let mut consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let entries = make_entries(&["same", "same", "same"]);
        let unique = consumer.deduplicate(&entries);
        assert_eq!(unique.len(), 1);
    }

    #[test]
    fn test_write_compressed_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let entries = make_entries(&["line 1", "line 2"]);
        let refs: Vec<&LogEntry> = entries.iter().collect();
        let (path, size) = consumer.write_compressed(&refs, "test-source").unwrap();

        assert!(path.exists());
        assert!(size > 0);
        assert!(path.to_string_lossy().ends_with(".log.zst"));
    }

    #[test]
    fn test_write_compressed_is_valid_zstd() {
        let dir = tempfile::tempdir().unwrap();
        let consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let entries = make_entries(&["test line 1", "test line 2"]);
        let refs: Vec<&LogEntry> = entries.iter().collect();
        let (path, _) = consumer.write_compressed(&refs, "zstd-test").unwrap();

        // Decompress and verify
        let file = File::open(&path).unwrap();
        let mut decoder = zstd::Decoder::new(file).unwrap();
        let mut content = String::new();
        decoder.read_to_string(&mut content).unwrap();

        assert!(content.contains("test line 1"));
        assert!(content.contains("test line 2"));
    }

    #[test]
    fn test_purge_file_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("to_purge.log");
        {
            let mut f = File::create(&path).unwrap();
            write!(f, "lots of log data here that takes up space").unwrap();
        }

        let original_size = fs::metadata(&path).unwrap().len();
        assert!(original_size > 0);

        let freed = LogConsumer::purge_file(&path).unwrap();
        assert_eq!(freed, original_size);

        let new_size = fs::metadata(&path).unwrap().len();
        assert_eq!(new_size, 0);
    }

    #[test]
    fn test_purge_file_nonexistent() {
        let freed = LogConsumer::purge_file(Path::new("/nonexistent/file.log")).unwrap();
        assert_eq!(freed, 0);
    }

    #[tokio::test]
    async fn test_consume_full_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("app.log");
        {
            let mut f = File::create(&log_path).unwrap();
            writeln!(f, "line 1").unwrap();
            writeln!(f, "line 2").unwrap();
            writeln!(f, "line 1").unwrap(); // duplicate
        }

        let output_dir = dir.path().join("output");
        let mut consumer = LogConsumer::new(output_dir.clone()).unwrap();

        let entries = make_entries(&["line 1", "line 2", "line 1"]);
        let log_path_str = log_path.to_string_lossy().to_string();

        let result = consumer
            .consume(&entries, "app", &LogSourceType::CustomFile, &log_path_str)
            .await
            .unwrap();

        assert_eq!(result.entries_archived, 2); // deduplicated
        assert_eq!(result.duplicates_skipped, 1);
        assert!(result.compressed_size > 0);
        assert!(result.bytes_freed > 0);

        // Original file should be truncated
        let size = fs::metadata(&log_path).unwrap().len();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_consume_empty_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut consumer = LogConsumer::new(dir.path().to_path_buf()).unwrap();

        let result = consumer
            .consume(&[], "empty", &LogSourceType::SystemLog, "/var/log/test")
            .await
            .unwrap();

        assert_eq!(result.entries_archived, 0);
        assert_eq!(result.duplicates_skipped, 0);
    }

    #[test]
    fn test_consumer_creates_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c");
        assert!(!nested.exists());

        let consumer = LogConsumer::new(nested.clone());
        assert!(consumer.is_ok());
        assert!(nested.exists());
    }

    #[test]
    fn test_consume_result_default() {
        let result = ConsumeResult::default();
        assert_eq!(result.entries_archived, 0);
        assert_eq!(result.bytes_freed, 0);
    }
}
