use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::database::connection::DbPool;
use crate::sniff::analyzer::AnomalySeverity;

use super::{DetectorFamily, DetectorFinding};

const DETECTOR_ID: &str = "integrity.file-baseline";

#[derive(Debug, Clone, Default)]
pub struct FileIntegrityMonitor;

#[derive(Debug, Clone)]
struct FileSnapshot {
    path: String,
    file_type: String,
    sha256: String,
    size_bytes: u64,
    readonly: bool,
    modified_at: i64,
}

impl FileIntegrityMonitor {
    pub fn detect(&self, pool: &DbPool, paths: &[String]) -> Result<Vec<DetectorFinding>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let scopes = normalize_scopes(paths)?;
        let previous = load_snapshots(pool, &scopes)?;
        let current = collect_snapshots(&scopes)?;
        let findings = diff_snapshots(&scopes, &previous, &current);

        persist_snapshots(pool, &current, &previous)?;

        Ok(findings)
    }
}

fn normalize_scopes(paths: &[String]) -> Result<Vec<PathBuf>> {
    let current_dir = std::env::current_dir().context("Failed to read current directory")?;
    let mut scopes = Vec::new();

    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        }

        let candidate = PathBuf::from(trimmed);
        let normalized = if candidate.exists() {
            candidate.canonicalize().with_context(|| {
                format!(
                    "Failed to canonicalize integrity path {}",
                    candidate.display()
                )
            })?
        } else if candidate.is_absolute() {
            candidate
        } else {
            current_dir.join(candidate)
        };

        if !scopes.iter().any(|existing| existing == &normalized) {
            scopes.push(normalized);
        }
    }

    Ok(scopes)
}

fn load_snapshots(pool: &DbPool, scopes: &[PathBuf]) -> Result<HashMap<String, FileSnapshot>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT path, file_type, sha256, size_bytes, readonly, modified_at
         FROM file_integrity_baselines",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(FileSnapshot {
            path: row.get(0)?,
            file_type: row.get(1)?,
            sha256: row.get(2)?,
            size_bytes: row.get::<_, i64>(3)? as u64,
            readonly: row.get::<_, i64>(4)? != 0,
            modified_at: row.get(5)?,
        })
    })?;

    let mut snapshots = HashMap::new();
    for row in rows {
        let snapshot = row?;
        if scopes
            .iter()
            .any(|scope| path_is_within_scope(&snapshot.path, scope))
        {
            snapshots.insert(snapshot.path.clone(), snapshot);
        }
    }

    Ok(snapshots)
}

fn collect_snapshots(scopes: &[PathBuf]) -> Result<HashMap<String, FileSnapshot>> {
    let mut snapshots = HashMap::new();

    for scope in scopes {
        collect_path(scope, &mut snapshots)?;
    }

    Ok(snapshots)
}

fn collect_path(path: &Path, snapshots: &mut HashMap<String, FileSnapshot>) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to inspect integrity path {}", path.display()));
        }
    };

    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("Failed to read integrity directory {}", path.display()))?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            collect_path(&entry.path(), snapshots)?;
        }

        return Ok(());
    }

    if metadata.is_file() {
        let snapshot = snapshot_file(path, &metadata)?;
        snapshots.insert(snapshot.path.clone(), snapshot);
    }

    Ok(())
}

fn snapshot_file(path: &Path, metadata: &fs::Metadata) -> Result<FileSnapshot> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open monitored file {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to hash monitored file {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let normalized_path = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();

    Ok(FileSnapshot {
        path: normalized_path,
        file_type: "file".into(),
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: metadata.len(),
        readonly: metadata.permissions().readonly(),
        modified_at,
    })
}

fn diff_snapshots(
    scopes: &[PathBuf],
    previous: &HashMap<String, FileSnapshot>,
    current: &HashMap<String, FileSnapshot>,
) -> Vec<DetectorFinding> {
    let mut findings = Vec::new();

    for (path, snapshot) in current {
        match previous.get(path) {
            Some(before) => {
                if let Some(finding) = compare_snapshot(before, snapshot) {
                    findings.push(finding);
                }
            }
            None if scope_has_baseline(path, scopes, previous) => findings.push(DetectorFinding {
                detector_id: DETECTOR_ID.into(),
                family: DetectorFamily::Integrity,
                description: format!("New file observed in monitored integrity path: {}", path),
                severity: AnomalySeverity::Medium,
                confidence: 79,
                sample_line: path.clone(),
            }),
            None => {}
        }
    }

    for path in previous.keys() {
        if !current.contains_key(path) {
            findings.push(DetectorFinding {
                detector_id: DETECTOR_ID.into(),
                family: DetectorFamily::Integrity,
                description: format!("Previously monitored file is missing: {}", path),
                severity: AnomalySeverity::High,
                confidence: 88,
                sample_line: path.clone(),
            });
        }
    }

    findings.sort_by(|left, right| left.sample_line.cmp(&right.sample_line));
    findings
}

fn compare_snapshot(previous: &FileSnapshot, current: &FileSnapshot) -> Option<DetectorFinding> {
    let mut drift = Vec::new();

    if previous.file_type != current.file_type {
        drift.push("type");
    }
    if previous.sha256 != current.sha256 {
        drift.push("content");
    }
    if previous.size_bytes != current.size_bytes {
        drift.push("size");
    }
    if previous.readonly != current.readonly {
        drift.push("permissions");
    }
    if previous.modified_at == 0 && current.modified_at != 0 {
        drift.push("modified_time");
    }

    if drift.is_empty() {
        return None;
    }

    Some(DetectorFinding {
        detector_id: DETECTOR_ID.into(),
        family: DetectorFamily::Integrity,
        description: format!(
            "File integrity drift detected for {} ({})",
            current.path,
            drift.join(", ")
        ),
        severity: if drift.contains(&"content") || drift.contains(&"permissions") {
            AnomalySeverity::High
        } else {
            AnomalySeverity::Medium
        },
        confidence: 93,
        sample_line: current.path.clone(),
    })
}

fn scope_has_baseline(
    path: &str,
    scopes: &[PathBuf],
    previous: &HashMap<String, FileSnapshot>,
) -> bool {
    scopes.iter().any(|scope| {
        path_is_within_scope(path, scope)
            && previous
                .keys()
                .any(|existing| path_is_within_scope(existing, scope))
    })
}

fn path_is_within_scope(path: &str, scope: &Path) -> bool {
    let scope_str = scope.to_string_lossy();
    let scope_str = scope_str.trim_end_matches('/');
    path == scope_str || path.starts_with(&format!("{}/", scope_str))
}

fn persist_snapshots(
    pool: &DbPool,
    current: &HashMap<String, FileSnapshot>,
    previous: &HashMap<String, FileSnapshot>,
) -> Result<()> {
    let conn = pool.get()?;

    for snapshot in current.values() {
        conn.execute(
            "INSERT INTO file_integrity_baselines (
                path, file_type, sha256, size_bytes, readonly, modified_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(path) DO UPDATE SET
                file_type = excluded.file_type,
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                readonly = excluded.readonly,
                modified_at = excluded.modified_at,
                updated_at = excluded.updated_at",
            params![
                &snapshot.path,
                &snapshot.file_type,
                &snapshot.sha256,
                snapshot.size_bytes as i64,
                if snapshot.readonly { 1_i64 } else { 0_i64 },
                snapshot.modified_at,
                Utc::now().to_rfc3339(),
            ],
        )?;
    }

    for path in previous.keys() {
        if !current.contains_key(path) {
            conn.execute(
                "DELETE FROM file_integrity_baselines WHERE path = ?1",
                params![path],
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};

    #[test]
    fn test_file_integrity_monitor_detects_content_drift() {
        let dir = tempfile::tempdir().unwrap();
        let monitored = dir.path().join("app.env");
        fs::write(&monitored, "API_KEY=first").unwrap();

        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let monitor = FileIntegrityMonitor;
        let paths = vec![monitored.to_string_lossy().into_owned()];

        let initial = monitor.detect(&pool, &paths).unwrap();
        assert!(initial.is_empty());

        fs::write(&monitored, "API_KEY=second").unwrap();

        let findings = monitor.detect(&pool, &paths).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_id, DETECTOR_ID);
        assert!(findings[0].description.contains("File integrity drift"));
    }

    #[test]
    fn test_file_integrity_monitor_detects_new_file_in_monitored_directory() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing.conf");
        fs::write(&existing, "setting=true").unwrap();

        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let monitor = FileIntegrityMonitor;
        let paths = vec![dir.path().to_string_lossy().into_owned()];

        let initial = monitor.detect(&pool, &paths).unwrap();
        assert!(initial.is_empty());

        let added = dir.path().join("added.conf");
        fs::write(&added, "setting=false").unwrap();

        let findings = monitor.detect(&pool, &paths).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("New file observed"));
        assert_eq!(
            findings[0].sample_line,
            added.canonicalize().unwrap().to_string_lossy().into_owned()
        );
    }
}
