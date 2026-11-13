//! Baselines database operations

use crate::baselines::learning::{FeatureBaseline, FeatureSummary};
use crate::database::connection::DbPool;
use anyhow::Result;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Baselines database manager
pub struct BaselinesDb {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredBaseline {
    pub scope: String,
    pub baseline: FeatureBaseline,
}

impl BaselinesDb {
    pub fn new(pool: DbPool) -> Result<Self> {
        Ok(Self { pool })
    }

    pub fn save_baseline(&self, scope: &str, baseline: &FeatureBaseline) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO baselines (scope, sample_count, mean, stddev, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(scope) DO UPDATE SET
                 sample_count = excluded.sample_count,
                 mean = excluded.mean,
                 stddev = excluded.stddev,
                 updated_at = excluded.updated_at",
            params![
                scope,
                baseline.sample_count as i64,
                serde_json::to_string(&baseline.mean)?,
                serde_json::to_string(&baseline.stddev)?,
                baseline.last_updated.to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn load_baseline(&self, scope: &str) -> Result<Option<FeatureBaseline>> {
        let conn = self.pool.get()?;
        let row = conn
            .query_row(
                "SELECT sample_count, mean, stddev, updated_at FROM baselines WHERE scope = ?1",
                params![scope],
                |row| {
                    Ok(FeatureBaseline {
                        sample_count: row.get::<_, i64>(0)? as u64,
                        mean: serde_json::from_str::<FeatureSummary>(&row.get::<_, String>(1)?)
                            .map_err(to_sql_error)?,
                        stddev: serde_json::from_str::<FeatureSummary>(&row.get::<_, String>(2)?)
                            .map_err(to_sql_error)?,
                        last_updated: chrono::DateTime::parse_from_rfc3339(
                            &row.get::<_, String>(3)?,
                        )
                        .map_err(to_sql_error)?
                        .with_timezone(&chrono::Utc),
                    })
                },
            )
            .optional()?;

        Ok(row)
    }

    pub fn list_baselines(&self) -> Result<Vec<StoredBaseline>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT scope, sample_count, mean, stddev, updated_at
             FROM baselines
             ORDER BY updated_at DESC, scope ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(StoredBaseline {
                scope: row.get(0)?,
                baseline: FeatureBaseline {
                    sample_count: row.get::<_, i64>(1)? as u64,
                    mean: serde_json::from_str::<FeatureSummary>(&row.get::<_, String>(2)?)
                        .map_err(to_sql_error)?,
                    stddev: serde_json::from_str::<FeatureSummary>(&row.get::<_, String>(3)?)
                        .map_err(to_sql_error)?,
                    last_updated: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .map_err(to_sql_error)?
                        .with_timezone(&chrono::Utc),
                },
            })
        })?;

        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn delete_baseline(&self, scope: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute("DELETE FROM baselines WHERE scope = ?1", params![scope])?;
        Ok(())
    }
}

fn to_sql_error(err: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};

    fn sample_baseline() -> FeatureBaseline {
        FeatureBaseline {
            sample_count: 3,
            mean: FeatureSummary {
                syscall_rate: 8.5,
                network_rate: 1.2,
                unique_processes: 2.0,
                privileged_calls: 0.5,
            },
            stddev: FeatureSummary {
                syscall_rate: 1.0,
                network_rate: 0.2,
                unique_processes: 0.5,
                privileged_calls: 0.3,
            },
            last_updated: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_baseline_persistence_round_trip() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let db = BaselinesDb::new(pool).unwrap();

        db.save_baseline("global", &sample_baseline()).unwrap();
        let loaded = db.load_baseline("global").unwrap().unwrap();

        assert_eq!(loaded.sample_count, 3);
        assert_eq!(loaded.mean.syscall_rate, 8.5);
    }

    #[test]
    fn test_list_and_delete_baselines() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let db = BaselinesDb::new(pool).unwrap();

        db.save_baseline("global", &sample_baseline()).unwrap();
        db.save_baseline("container:abc", &sample_baseline())
            .unwrap();

        assert_eq!(db.list_baselines().unwrap().len(), 2);
        db.delete_baseline("global").unwrap();
        assert!(db.load_baseline("global").unwrap().is_none());
    }
}
