CREATE TABLE IF NOT EXISTS ip_offenses (
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
);

CREATE INDEX IF NOT EXISTS idx_ip_offenses_ip ON ip_offenses(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_offenses_status ON ip_offenses(status);
CREATE INDEX IF NOT EXISTS idx_ip_offenses_last_seen ON ip_offenses(last_seen);
