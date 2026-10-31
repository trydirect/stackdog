//! Database connection pool using rusqlite and r2d2

use anyhow::Result;
use r2d2::{ManageConnection, Pool};
use rusqlite::{Connection, Result as RusqliteResult};

/// Rusqlite connection manager
#[derive(Debug)]
pub struct SqliteConnectionManager {
    database_url: String,
}

impl SqliteConnectionManager {
    pub fn new(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_string(),
        }
    }
}

impl ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> RusqliteResult<Self::Connection> {
        Connection::open(&self.database_url)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> RusqliteResult<()> {
        conn.execute_batch("")
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

pub type DbPool = Pool<SqliteConnectionManager>;

/// Create database connection pool
pub fn create_pool(database_url: &str) -> Result<DbPool> {
    let manager = SqliteConnectionManager::new(database_url);
    let pool = Pool::builder().max_size(10).build(manager)?;

    Ok(pool)
}

/// Initialize database (create tables if not exist)
pub fn init_database(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;

    // Create alerts table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            timestamp TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Create threats table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            source TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Create containers_cache table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS containers_cache (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            image TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            security_state TEXT DEFAULT 'Unknown',
            threats_count INTEGER DEFAULT 0,
            last_updated TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Create indexes for performance
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_container_id
         ON alerts(json_extract(metadata, '$.container_id'))
         WHERE json_valid(metadata)",
        [],
    );

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)",
        [],
    );

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_containers_status ON containers_cache(status)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_containers_name ON containers_cache(name)",
        [],
    );

    // Create log_sources table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_sources (
            id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            path_or_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            last_read_position INTEGER DEFAULT 0
        )",
        [],
    )?;

    // Create log_summaries table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_summaries (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            summary_text TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            total_entries INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            warning_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )",
        [],
    )?;

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_log_sources_type ON log_sources(source_type)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_log_summaries_source ON log_summaries(source_id)",
        [],
    );

    // Create baselines table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS baselines (
            scope TEXT PRIMARY KEY,
            sample_count INTEGER NOT NULL,
            mean TEXT NOT NULL,
            stddev TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    )?;

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_baselines_updated_at ON baselines(updated_at)",
        [],
    );

    conn.execute(
        "CREATE TABLE IF NOT EXISTS file_integrity_baselines (
            path TEXT PRIMARY KEY,
            file_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            readonly INTEGER NOT NULL,
            modified_at INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    )?;

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_file_integrity_updated_at ON file_integrity_baselines(updated_at)",
        [],
    );

    conn.execute(
        "CREATE TABLE IF NOT EXISTS php_shell_scans (
            path TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            logical_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            modified_at INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            score INTEGER NOT NULL,
            rules TEXT NOT NULL,
            in_upload_dir INTEGER NOT NULL,
            scanned_at TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_offenses (
            id TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            source_type TEXT NOT NULL,
            container_id TEXT,
            offense_count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            blocked_until TEXT,
            status TEXT NOT NULL DEFAULT 'Active',
            reason TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ip_offenses_ip ON ip_offenses(ip_address)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ip_offenses_status ON ip_offenses(status)",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ip_offenses_last_seen ON ip_offenses(last_seen)",
        [],
    );

    collapse_duplicate_offenses(&conn)?;

    Ok(())
}

/// Index whose presence marks the one-row-per-(ip, source_type) layout.
const OFFENSE_UNIQUE_INDEX: &str = "idx_ip_offenses_ip_source";

/// Collapse the historical one-row-per-detection layout into one row per
/// (ip_address, source_type), then enforce it with a unique index.
///
/// Older builds inserted a row per detection and left `offense_count` at 1, so
/// a noisy scanner grew the table without bound and a single ban left several
/// rows behind — which is why expiring one ban emitted several notifications.
///
/// Guarded by the index's existence: re-running the collapse after it has
/// already happened would recount each surviving row as a group of one and
/// reset every counter to 1.
fn collapse_duplicate_offenses(conn: &rusqlite::Connection) -> Result<()> {
    let already_migrated: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
        [OFFENSE_UNIQUE_INDEX],
        |row| row.get(0),
    )?;
    if already_migrated > 0 {
        return Ok(());
    }

    // Fold each group's history into the row that will survive it.
    conn.execute(
        "UPDATE ip_offenses SET
            offense_count = (
                SELECT COUNT(*) FROM ip_offenses AS peer
                WHERE peer.ip_address = ip_offenses.ip_address
                  AND peer.source_type = ip_offenses.source_type
            ),
            first_seen = (
                SELECT MIN(peer.first_seen) FROM ip_offenses AS peer
                WHERE peer.ip_address = ip_offenses.ip_address
                  AND peer.source_type = ip_offenses.source_type
            )",
        [],
    )?;

    // Keep one row per group: a live block first, then the most recent.
    conn.execute(
        "DELETE FROM ip_offenses WHERE id IN (
            SELECT id FROM (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY ip_address, source_type
                    ORDER BY
                        CASE status WHEN 'Blocked' THEN 0 WHEN 'Active' THEN 1 ELSE 2 END,
                        last_seen DESC
                ) AS position
                FROM ip_offenses
            ) WHERE position > 1
        )",
        [],
    )?;

    conn.execute(
        &format!(
            "CREATE UNIQUE INDEX {OFFENSE_UNIQUE_INDEX} ON ip_offenses(ip_address, source_type)"
        ),
        [],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recreate the pre-migration layout: several rows per (ip, source_type),
    /// each with offense_count stuck at 1.
    fn seed_legacy_offenses(conn: &rusqlite::Connection) {
        let rows = [
            (
                "o1",
                "192.0.2.10",
                "sniff",
                "2026-01-01T00:00:00Z",
                "Released",
            ),
            (
                "o2",
                "192.0.2.10",
                "sniff",
                "2026-01-01T00:05:00Z",
                "Blocked",
            ),
            (
                "o3",
                "192.0.2.10",
                "sniff",
                "2026-01-01T00:03:00Z",
                "Active",
            ),
            (
                "o4",
                "192.0.2.10",
                "ai-tool",
                "2026-01-01T00:04:00Z",
                "Active",
            ),
            (
                "o5",
                "198.51.100.7",
                "sniff",
                "2026-01-01T00:06:00Z",
                "Active",
            ),
        ];
        for (id, ip, source, seen, status) in rows {
            conn.execute(
                "INSERT INTO ip_offenses (
                    id, ip_address, source_type, offense_count,
                    first_seen, last_seen, status, reason
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?4, ?5, 'legacy')",
                rusqlite::params![id, ip, source, seen, status],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_collapse_duplicate_offenses_folds_history_into_one_row() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        {
            let conn = pool.get().unwrap();
            // Drop the index init_database just created to simulate an old DB.
            conn.execute(&format!("DROP INDEX IF EXISTS {OFFENSE_UNIQUE_INDEX}"), [])
                .unwrap();
            seed_legacy_offenses(&conn);
            collapse_duplicate_offenses(&conn).unwrap();

            let (id, count, first_seen): (String, i64, String) = conn
                .query_row(
                    "SELECT id, offense_count, first_seen FROM ip_offenses
                     WHERE ip_address = '192.0.2.10' AND source_type = 'sniff'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();

            // The live block survives, carrying the group's tally and its
            // earliest sighting.
            assert_eq!(id, "o2");
            assert_eq!(count, 3);
            assert_eq!(first_seen, "2026-01-01T00:00:00Z");

            // Other pairs are untouched.
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM ip_offenses", [], |row| row.get(0))
                .unwrap();
            assert_eq!(total, 3);

            // Running it again must not recount the survivors as groups of one.
            collapse_duplicate_offenses(&conn).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT offense_count FROM ip_offenses WHERE id = 'o2'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 3, "the migration must be idempotent");
        }
    }

    #[test]
    fn test_create_pool() {
        let pool = create_pool(":memory:");
        assert!(pool.is_ok());
    }

    #[test]
    fn test_init_database() {
        let pool = create_pool(":memory:").unwrap();
        let result = init_database(&pool);
        assert!(result.is_ok());
    }
}
