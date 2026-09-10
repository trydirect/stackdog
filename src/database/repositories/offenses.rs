//! Persistent IP ban offense tracking.

use crate::database::connection::DbPool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffenseStatus {
    Active,
    Blocked,
    Released,
}

impl std::fmt::Display for OffenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Blocked => write!(f, "Blocked"),
            Self::Released => write!(f, "Released"),
        }
    }
}

impl std::str::FromStr for OffenseStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Active" => Ok(Self::Active),
            "Blocked" => Ok(Self::Blocked),
            "Released" => Ok(Self::Released),
            _ => Err(format!("unknown offense status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OffenseMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpOffenseRecord {
    pub id: String,
    pub ip_address: String,
    pub source_type: String,
    pub container_id: Option<String>,
    pub offense_count: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub blocked_until: Option<String>,
    pub status: OffenseStatus,
    pub reason: String,
    pub metadata: Option<OffenseMetadata>,
}

#[derive(Debug, Clone)]
pub struct NewIpOffense {
    pub id: String,
    pub ip_address: String,
    pub source_type: String,
    pub container_id: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub reason: String,
    pub metadata: Option<OffenseMetadata>,
}

fn serialize_metadata(metadata: Option<&OffenseMetadata>) -> Result<Option<String>> {
    match metadata {
        Some(metadata) => Ok(Some(serde_json::to_string(metadata)?)),
        None => Ok(None),
    }
}

fn parse_metadata(value: Option<String>) -> Option<OffenseMetadata> {
    value.and_then(|raw| serde_json::from_str(&raw).ok())
}

fn parse_status(value: String) -> Result<OffenseStatus, rusqlite::Error> {
    value.parse().map_err(|err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    })
}

fn map_row(row: &rusqlite::Row) -> Result<IpOffenseRecord, rusqlite::Error> {
    Ok(IpOffenseRecord {
        id: row.get(0)?,
        ip_address: row.get(1)?,
        source_type: row.get(2)?,
        container_id: row.get(3)?,
        offense_count: row.get::<_, i64>(4)?.max(0) as u32,
        first_seen: row.get(5)?,
        last_seen: row.get(6)?,
        blocked_until: row.get(7)?,
        status: parse_status(row.get(8)?)?,
        reason: row.get(9)?,
        metadata: parse_metadata(row.get(10)?),
    })
}

/// Record one detection for `(ip_address, source_type)`.
///
/// One row per pair, with `offense_count` carrying the tally. The counter
/// restarts when the previous activity fell outside `window_start`, or when the
/// address had already served a ban — otherwise an address banned once would
/// stay one detection away from being banned again forever.
///
/// Returns the offense count after recording.
pub fn record_offense_occurrence(
    pool: &DbPool,
    offense: &NewIpOffense,
    window_start: DateTime<Utc>,
) -> Result<u32> {
    let conn = pool.get()?;
    let window_start = window_start.to_rfc3339();
    let seen_at = offense.first_seen.to_rfc3339();

    conn.execute(
        "INSERT INTO ip_offenses (
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, NULL, 'Active', ?6, ?7)
         ON CONFLICT(ip_address, source_type) DO UPDATE SET
            offense_count = CASE
                WHEN ip_offenses.status = 'Released' OR ip_offenses.last_seen < ?8 THEN 1
                ELSE ip_offenses.offense_count + 1
            END,
            first_seen = CASE
                WHEN ip_offenses.status = 'Released' OR ip_offenses.last_seen < ?8 THEN excluded.first_seen
                ELSE ip_offenses.first_seen
            END,
            status = CASE WHEN ip_offenses.status = 'Released' THEN 'Active' ELSE ip_offenses.status END,
            blocked_until = CASE WHEN ip_offenses.status = 'Released' THEN NULL ELSE ip_offenses.blocked_until END,
            last_seen = excluded.last_seen,
            container_id = excluded.container_id,
            reason = excluded.reason,
            metadata = excluded.metadata",
        params![
            offense.id,
            offense.ip_address,
            offense.source_type,
            offense.container_id,
            seen_at,
            offense.reason,
            serialize_metadata(offense.metadata.as_ref())?,
            window_start,
        ],
    )?;

    let count: i64 = conn.query_row(
        "SELECT offense_count FROM ip_offenses WHERE ip_address = ?1 AND source_type = ?2",
        params![offense.ip_address, offense.source_type],
        |row| row.get(0),
    )?;

    Ok(count.max(0) as u32)
}

pub fn find_recent_offenses(
    pool: &DbPool,
    ip_address: &str,
    source_type: &str,
    since: DateTime<Utc>,
) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE ip_address = ?1
           AND source_type = ?2
           AND last_seen >= ?3
         ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map(
        params![ip_address, source_type, since.to_rfc3339()],
        map_row,
    )?;
    let mut offenses = Vec::new();
    for row in rows {
        offenses.push(row?);
    }
    Ok(offenses)
}

/// Recent offense rows for an address across every source type.
///
/// `find_recent_offenses` narrows to one source; this is for callers that want
/// the whole picture for an address, such as the AI's `check_ip_status`.
pub fn recent_offenses_for_ip(
    pool: &DbPool,
    ip_address: &str,
    since: DateTime<Utc>,
) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE ip_address = ?1 AND last_seen >= ?2
         ORDER BY last_seen DESC",
    )?;

    let rows = stmt.query_map(params![ip_address, since.to_rfc3339()], map_row)?;
    let mut offenses = Vec::new();
    for row in rows {
        offenses.push(row?);
    }
    Ok(offenses)
}

pub fn active_block_for_ip(pool: &DbPool, ip_address: &str) -> Result<Option<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE ip_address = ?1 AND status = 'Blocked'
         ORDER BY last_seen DESC
         LIMIT 1",
    )?;

    match stmt.query_row(params![ip_address], map_row) {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn mark_blocked(
    pool: &DbPool,
    ip_address: &str,
    source_type: &str,
    blocked_until: DateTime<Utc>,
) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE ip_offenses
         SET status = 'Blocked', blocked_until = ?1
         WHERE ip_address = ?2 AND source_type = ?3 AND status = 'Active'",
        params![blocked_until.to_rfc3339(), ip_address, source_type],
    )?;
    Ok(())
}

pub fn expired_blocks(pool: &DbPool, now: DateTime<Utc>) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses
         WHERE status = 'Blocked'
           AND blocked_until IS NOT NULL
           AND blocked_until <= ?1
         ORDER BY blocked_until ASC",
    )?;

    let rows = stmt.query_map(params![now.to_rfc3339()], map_row)?;
    let mut offenses = Vec::new();
    for row in rows {
        offenses.push(row?);
    }
    Ok(offenses)
}

/// List offenses, newest first, optionally narrowed to one status.
pub fn list_offenses(
    pool: &DbPool,
    status: Option<OffenseStatus>,
    limit: usize,
) -> Result<Vec<IpOffenseRecord>> {
    let conn = pool.get()?;
    let base = "SELECT
            id, ip_address, source_type, container_id, offense_count,
            first_seen, last_seen, blocked_until, status, reason, metadata
         FROM ip_offenses";

    let mut offenses = Vec::new();
    match status {
        Some(status) => {
            let mut stmt = conn.prepare(&format!(
                "{base} WHERE status = ?1 ORDER BY last_seen DESC LIMIT ?2"
            ))?;
            let rows = stmt.query_map(params![status.to_string(), limit as i64], map_row)?;
            for row in rows {
                offenses.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare(&format!("{base} ORDER BY last_seen DESC LIMIT ?1"))?;
            let rows = stmt.query_map(params![limit as i64], map_row)?;
            for row in rows {
                offenses.push(row?);
            }
        }
    }

    Ok(offenses)
}

pub fn mark_released(pool: &DbPool, offense_id: &str) -> Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE ip_offenses SET status = 'Released' WHERE id = ?1",
        params![offense_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};
    use chrono::Duration;

    #[test]
    fn test_insert_and_find_offense() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        record_offense_occurrence(
            &pool,
            &NewIpOffense {
                id: "o1".into(),
                ip_address: "192.0.2.10".into(),
                source_type: "sniff".into(),
                container_id: None,
                first_seen: Utc::now(),
                reason: "Repeated ssh failures".into(),
                metadata: Some(OffenseMetadata {
                    source_path: Some("/var/log/auth.log".into()),
                    sample_line: None,
                }),
            },
            Utc::now() - Duration::minutes(5),
        )
        .unwrap();

        let offenses = find_recent_offenses(
            &pool,
            "192.0.2.10",
            "sniff",
            Utc::now() - Duration::minutes(1),
        )
        .unwrap();
        assert_eq!(offenses.len(), 1);
        assert_eq!(offenses[0].status, OffenseStatus::Active);
    }

    fn detection(ip: &str, reason: &str) -> NewIpOffense {
        NewIpOffense {
            id: uuid::Uuid::new_v4().to_string(),
            ip_address: ip.into(),
            source_type: "sniff".into(),
            container_id: None,
            first_seen: Utc::now(),
            reason: reason.into(),
            metadata: None,
        }
    }

    #[test]
    fn test_record_offense_occurrence_increments_single_row() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let window_start = Utc::now() - Duration::minutes(5);

        for expected in 1..=4 {
            let count =
                record_offense_occurrence(&pool, &detection("192.0.2.30", "ssh"), window_start)
                    .unwrap();
            assert_eq!(count, expected);
        }

        let offenses = find_recent_offenses(&pool, "192.0.2.30", "sniff", window_start).unwrap();
        assert_eq!(offenses.len(), 1, "the table must not grow per detection");
        assert_eq!(offenses[0].offense_count, 4);
    }

    #[test]
    fn test_record_offense_occurrence_restarts_outside_the_window() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        record_offense_occurrence(
            &pool,
            &detection("192.0.2.31", "ssh"),
            Utc::now() - Duration::minutes(5),
        )
        .unwrap();

        // A window that starts in the future makes the stored activity stale.
        let count = record_offense_occurrence(
            &pool,
            &detection("192.0.2.31", "ssh"),
            Utc::now() + Duration::minutes(5),
        )
        .unwrap();
        assert_eq!(count, 1, "the counter restarts once activity ages out");
    }

    #[test]
    fn test_record_offense_occurrence_reactivates_a_released_row() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let now = Utc::now();
        let window_start = now - Duration::minutes(5);

        record_offense_occurrence(&pool, &detection("192.0.2.32", "ssh"), window_start).unwrap();
        mark_blocked(&pool, "192.0.2.32", "sniff", now + Duration::minutes(5)).unwrap();
        let blocked = active_block_for_ip(&pool, "192.0.2.32").unwrap().unwrap();
        mark_released(&pool, &blocked.id).unwrap();

        // A served ban starts the count over, rather than leaving the address
        // one detection away from being banned again.
        let count = record_offense_occurrence(&pool, &detection("192.0.2.32", "ssh"), window_start)
            .unwrap();
        assert_eq!(count, 1);

        let offenses = find_recent_offenses(&pool, "192.0.2.32", "sniff", window_start).unwrap();
        assert_eq!(offenses[0].status, OffenseStatus::Active);
        assert!(offenses[0].blocked_until.is_none());
    }

    #[test]
    fn test_offenses_are_unique_per_ip_and_source() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let window_start = Utc::now() - Duration::minutes(5);

        record_offense_occurrence(&pool, &detection("192.0.2.33", "ssh"), window_start).unwrap();
        let mut other_source = detection("192.0.2.33", "ai");
        other_source.source_type = "ai-tool".into();
        record_offense_occurrence(&pool, &other_source, window_start).unwrap();

        let conn = pool.get().unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ip_offenses WHERE ip_address = ?1",
                params!["192.0.2.33"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "different sources keep their own tally");
    }

    #[test]
    fn test_mark_blocked_and_released() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let now = Utc::now();

        record_offense_occurrence(
            &pool,
            &NewIpOffense {
                id: "o2".into(),
                ip_address: "192.0.2.20".into(),
                source_type: "sniff".into(),
                container_id: None,
                first_seen: now,
                reason: "test".into(),
                metadata: None,
            },
            now - Duration::minutes(5),
        )
        .unwrap();

        mark_blocked(&pool, "192.0.2.20", "sniff", now + Duration::minutes(5)).unwrap();
        assert!(active_block_for_ip(&pool, "192.0.2.20").unwrap().is_some());

        let expired = expired_blocks(&pool, now + Duration::minutes(10)).unwrap();
        assert_eq!(expired.len(), 1);
        mark_released(&pool, &expired[0].id).unwrap();
        assert!(active_block_for_ip(&pool, "192.0.2.20").unwrap().is_none());
    }
}
