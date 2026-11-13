-- Containers cache table (for quick access to Docker container info)
CREATE TABLE IF NOT EXISTS containers_cache (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    security_state TEXT DEFAULT 'Unknown',
    threats_count INTEGER DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_containers_status ON containers_cache(status);
CREATE INDEX IF NOT EXISTS idx_containers_name ON containers_cache(name);
