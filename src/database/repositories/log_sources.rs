//! Log sources repository using rusqlite
//!
//! Persists discovered log sources and AI summaries, following
//! the same pattern as the alerts repository.

use crate::database::connection::DbPool;
use crate::sniff::discovery::LogSource;
use anyhow::Result;
use chrono::Utc;
use rusqlite::params;

/// Create or update a log source (upsert by path_or_id)
pub fn upsert_log_source(pool: &DbPool, source: &LogSource) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO log_sources (id, source_type, path_or_id, name, discovered_at, last_read_position)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(path_or_id) DO UPDATE SET
            name = excluded.name,
            source_type = excluded.source_type",
        params![
            source.id,
            source.source_type.to_string(),
            source.path_or_id,
            source.name,
            source.discovered_at.to_rfc3339(),
            source.last_read_position as i64,
        ],
    )?;
    Ok(())
}

/// List all registered log sources
pub fn list_log_sources(pool: &DbPool) -> Result<Vec<LogSource>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, source_type, path_or_id, name, discovered_at, last_read_position
         FROM log_sources ORDER BY discovered_at DESC",
    )?;

    let sources = stmt
        .query_map([], |row| {
            let source_type_str: String = row.get(1)?;
            let discovered_str: String = row.get(4)?;
            let pos: i64 = row.get(5)?;
            Ok(LogSource {
                id: row.get(0)?,
                source_type: source_type_str.parse().unwrap(),
                path_or_id: row.get(2)?,
                name: row.get(3)?,
                discovered_at: chrono::DateTime::parse_from_rfc3339(&discovered_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_read_position: pos as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(sources)
}

/// Get a log source by its path or container ID
pub fn get_log_source_by_path(pool: &DbPool, path_or_id: &str) -> Result<Option<LogSource>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, source_type, path_or_id, name, discovered_at, last_read_position
         FROM log_sources WHERE path_or_id = ?",
    )?;

    let result = stmt.query_row(params![path_or_id], |row| {
        let source_type_str: String = row.get(1)?;
        let discovered_str: String = row.get(4)?;
        let pos: i64 = row.get(5)?;
        Ok(LogSource {
            id: row.get(0)?,
            source_type: source_type_str.parse().unwrap(),
            path_or_id: row.get(2)?,
            name: row.get(3)?,
            discovered_at: chrono::DateTime::parse_from_rfc3339(&discovered_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_read_position: pos as u64,
        })
    });

    match result {
        Ok(source) => Ok(Some(source)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Database error: {}", e)),
    }
}

/// Update the read position for a log source
pub fn update_read_position(pool: &DbPool, path_or_id: &str, position: u64) -> Result<()> {
    let conn = pool.get()?;
    let updated = conn.execute(
        "UPDATE log_sources SET last_read_position = ?1 WHERE path_or_id = ?2",
        params![position as i64, path_or_id],
    )?;
    if updated == 0 {
        return Err(anyhow::anyhow!(
            "No log source registered for path_or_id '{}'",
            path_or_id
        ));
    }
    Ok(())
}

/// Delete a log source
pub fn delete_log_source(pool: &DbPool, path_or_id: &str) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "DELETE FROM log_sources WHERE path_or_id = ?",
        params![path_or_id],
    )?;
    Ok(())
}

/// Parameters for creating a log summary
pub struct CreateLogSummaryParams<'a> {
    pub source_id: &'a str,
    pub summary_text: &'a str,
    pub period_start: &'a str,
    pub period_end: &'a str,
    pub total_entries: i64,
    pub error_count: i64,
    pub warning_count: i64,
}

/// Store a log summary
pub fn create_log_summary(pool: &DbPool, params: CreateLogSummaryParams<'_>) -> Result<String> {
    let conn = pool.get()?;
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO log_summaries (id, source_id, summary_text, period_start, period_end,
         total_entries, error_count, warning_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            id,
            params.source_id,
            params.summary_text,
            params.period_start,
            params.period_end,
            params.total_entries,
            params.error_count,
            params.warning_count,
            now
        ],
    )?;

    Ok(id)
}

/// List summaries for a source
pub fn list_summaries_for_source(pool: &DbPool, source_id: &str) -> Result<Vec<LogSummaryRow>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT id, source_id, summary_text, period_start, period_end,
                total_entries, error_count, warning_count, created_at
         FROM log_summaries WHERE source_id = ? ORDER BY created_at DESC",
    )?;

    let rows = stmt
        .query_map(params![source_id], |row| {
            Ok(LogSummaryRow {
                id: row.get(0)?,
                source_id: row.get(1)?,
                summary_text: row.get(2)?,
                period_start: row.get(3)?,
                period_end: row.get(4)?,
                total_entries: row.get(5)?,
                error_count: row.get(6)?,
                warning_count: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(rows)
}

/// Database row for a log summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogSummaryRow {
    pub id: String,
    pub source_id: String,
    pub summary_text: String,
    pub period_start: String,
    pub period_end: String,
    pub total_entries: i64,
    pub error_count: i64,
    pub warning_count: i64,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};
    use crate::sniff::discovery::LogSourceType;

    fn setup_test_db() -> DbPool {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        pool
    }

    #[test]
    fn test_upsert_and_list_log_sources() {
        let pool = setup_test_db();
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/test.log".into(),
            "test.log".into(),
        );

        upsert_log_source(&pool, &source).unwrap();
        let sources = list_log_sources(&pool).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path_or_id, "/var/log/test.log");
        assert_eq!(sources[0].name, "test.log");
    }

    #[test]
    fn test_upsert_deduplicates_by_path() {
        let pool = setup_test_db();
        let source1 = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog-v1".into(),
        );
        let source2 = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog-v2".into(),
        );

        upsert_log_source(&pool, &source1).unwrap();
        upsert_log_source(&pool, &source2).unwrap();

        let sources = list_log_sources(&pool).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "syslog-v2");
    }

    #[test]
    fn test_get_log_source_by_path() {
        let pool = setup_test_db();
        let source = LogSource::new(
            LogSourceType::DockerContainer,
            "container-abc123".into(),
            "docker:myapp".into(),
        );
        upsert_log_source(&pool, &source).unwrap();

        let found = get_log_source_by_path(&pool, "container-abc123").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "docker:myapp");

        let not_found = get_log_source_by_path(&pool, "nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_update_read_position() {
        let pool = setup_test_db();
        let source = LogSource::new(
            LogSourceType::CustomFile,
            "/tmp/app.log".into(),
            "app.log".into(),
        );
        upsert_log_source(&pool, &source).unwrap();

        update_read_position(&pool, "/tmp/app.log", 4096).unwrap();

        let updated = get_log_source_by_path(&pool, "/tmp/app.log")
            .unwrap()
            .unwrap();
        assert_eq!(updated.last_read_position, 4096);
    }

    #[test]
    fn test_delete_log_source() {
        let pool = setup_test_db();
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/test.log".into(),
            "test.log".into(),
        );
        upsert_log_source(&pool, &source).unwrap();
        assert_eq!(list_log_sources(&pool).unwrap().len(), 1);

        delete_log_source(&pool, "/var/log/test.log").unwrap();
        assert_eq!(list_log_sources(&pool).unwrap().len(), 0);
    }

    #[test]
    fn test_create_and_list_summaries() {
        let pool = setup_test_db();
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog".into(),
        );
        upsert_log_source(&pool, &source).unwrap();

        let summary_id = create_log_summary(
            &pool,
            CreateLogSummaryParams {
                source_id: &source.id,
                summary_text: "System running normally. 3 warnings about disk space.",
                period_start: "2026-03-30T12:00:00Z",
                period_end: "2026-03-30T13:00:00Z",
                total_entries: 500,
                error_count: 0,
                warning_count: 3,
            },
        )
        .unwrap();

        assert!(!summary_id.is_empty());

        let summaries = list_summaries_for_source(&pool, &source.id).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_entries, 500);
        assert_eq!(summaries[0].warning_count, 3);
        assert!(summaries[0].summary_text.contains("disk space"));
    }
}
