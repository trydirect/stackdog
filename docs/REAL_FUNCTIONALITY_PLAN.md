# Real Functionality Implementation Plan

**Goal:** Add real Docker integration and database persistence  
**Timeline:** 3-5 days  
**Target Release:** v0.3.0 "Alpha"  

---

## Day 1: Database Integration

### Morning: SQLite Schema & Migrations

**Tasks:**
1. Create database schema
2. Write SQL migrations
3. Test migration execution

**Files:**
```
migrations/
├── 00000000000000_create_alerts/
│   ├── up.sql
│   └── down.sql
├── 00000000000001_create_threats/
│   ├── up.sql
│   └── down.sql
└── 00000000000002_create_containers_cache/
    ├── up.sql
    └── down.sql
```

**Schema:**
```sql
-- Alerts table
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    timestamp DATETIME NOT NULL,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Threats table
CREATE TABLE threats (
    id TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    source TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Containers cache table
CREATE TABLE containers_cache (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Tests:**
- Migration runs successfully
- Tables created correctly
- Can insert/query data

---

### Afternoon: Database Repository Layer

**Tasks:**
1. Create repository traits
2. Implement AlertRepository
3. Implement ThreatRepository
4. Implement ContainerRepository

**Files:**
```
src/database/
├── mod.rs
├── connection.rs          # DB connection pool
├── repositories/
│   ├── mod.rs
│   ├── alerts.rs
│   ├── threats.rs
│   └── containers.rs
└── models/
    ├── mod.rs
    ├── alert.rs
    ├── threat.rs
    └── container.rs
```

**Implementation:**
```rust
// src/database/repositories/alerts.rs
pub trait AlertRepository: Send + Sync {
    async fn list(&self, filter: AlertFilter) -> Result<Vec<Alert>>;
    async fn get(&self, id: &str) -> Result<Option<Alert>>;
    async fn create(&self, alert: Alert) -> Result<Alert>;
    async fn update_status(&self, id: &str, status: AlertStatus) -> Result<()>;
    async fn get_stats(&self) -> Result<AlertStats>;
}
```

**Tests:**
- Can create alert
- Can list alerts with filter
- Can update status
- Stats calculation correct

---

## Day 2: Docker Integration

### Morning: Docker Client Setup

**Tasks:**
1. Add bollard dependency
2. Create Docker client wrapper
3. Test Docker connection
4. List containers

**Files:**
```
src/docker/
├── mod.rs
├── client.rs              # Docker client wrapper
├── containers.rs          # Container operations
└── types.rs               # Docker type conversions
```

**Implementation:**
```rust
// src/docker/client.rs
pub struct DockerClient {
    client: bollard::Docker,
}

impl DockerClient {
    pub fn new() -> Result<Self>;
    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>>;
    pub async fn get_container(&self, id: &str) -> Result<ContainerInfo>;
    pub async fn quarantine_container(&self, id: &str) -> Result<()>;
    pub async fn release_container(&self, id: &str) -> Result<()>;
}
```

**Tests:**
- Docker client connects
- Can list containers
- Can get container details

---

### Afternoon: Container Management

**Tasks:**
1. Implement container listing
2. Implement quarantine (disconnect network)
3. Implement release (reconnect network)
4. Cache container data in DB

**Implementation:**
```rust
// Quarantine implementation
pub async fn quarantine_container(&self, id: &str) -> Result<()> {
    // Disconnect from all networks
    let networks = self.client.list_networks().await?;
    for network in networks {
        self.client.disconnect_network(
            &network.name,
            NetworkDisconnectOptions {
                container_id: Some(id.to_string()),
                ..Default::default()
            }
        ).await?;
    }
    Ok(())
}
```

**Tests:**
- List real containers from Docker
- Quarantine actually disconnects network
- Release reconnects network

---

## Day 3: Connect API to Real Data

### Morning: Update API Endpoints

**Tasks:**
1. Inject repositories into API handlers
2. Replace mock data with DB queries
3. Test all endpoints

**Changes:**
```rust
// Before (mock)
pub async fn get_alerts() -> impl Responder {
    let alerts = vec![/* mock data */];
    HttpResponse::Ok().json(alerts)
}

// After (real)
pub async fn get_alerts(
    repo: web::Data<dyn AlertRepository>,
    query: web::Query<AlertQuery>
) -> impl Responder {
    let filter = AlertFilter::from(query);
    let alerts = repo.list(filter).await?;
    HttpResponse::Ok().json(alerts)
}
```

**Endpoints to Update:**
- [ ] `GET /api/alerts` - Query database
- [ ] `GET /api/alerts/stats` - Calculate from DB
- [ ] `POST /api/alerts/:id/acknowledge` - Update DB
- [ ] `POST /api/alerts/:id/resolve` - Update DB
- [ ] `GET /api/containers` - Query Docker + cache
- [ ] `POST /api/containers/:id/quarantine` - Call Docker API
- [ ] `POST /api/containers/:id/release` - Call Docker API
- [ ] `GET /api/threats` - Query database
- [ ] `GET /api/threats/statistics` - Calculate from DB

---

### Afternoon: Testing & Bug Fixes

**Tasks:**
1. Test each endpoint with real data
2. Fix any bugs
3. Add error handling
4. Performance testing

**Test Script:**
```bash
# Test alerts endpoint
curl http://localhost:5000/api/alerts

# Test containers endpoint
curl http://localhost:5000/api/containers

# Test quarantine
curl -X POST http://localhost:5000/api/containers/test123/quarantine
```

---

## Day 4: Real-Time Events

### Morning: Event Generation

**Tasks:**
1. Create event generator service
2. Generate alerts from Docker events
3. Store events in database

**Implementation:**
```rust
// Listen to Docker events
pub async fn listen_docker_events(
    client: DockerClient,
    alert_repo: Arc<dyn AlertRepository>
) {
    let mut events = client.events().await;
    while let Some(event) = events.next().await {
        match event {
            DockerEvent::ContainerStart { id, name } => {
                alert_repo.create(Alert::new(
                    AlertType::SystemEvent,
                    AlertSeverity::Info,
                    format!("Container {} started", name)
                )).await?;
            }
            DockerEvent::ContainerDie { id, name } => {
                // Check if container was quarantined
            }
            _ => {}
        }
    }
}
```

---

### Afternoon: WebSocket Real-Time Updates

**Tasks:**
1. Implement proper WebSocket with actix-web-actors
2. Broadcast events to connected clients
3. Test real-time updates

---

## Day 5: Polish & Release Prep

### Morning: Security Features

**Tasks:**
1. Add basic threat detection rules
2. Generate alerts from suspicious activity
3. Test detection accuracy

**Example Rules:**
```rust
// Rule: Container running as root
if container.user == "root" {
    generate_alert(AlertSeverity::Medium, "Container running as root");
}

// Rule: Container with privileged mode
if container.privileged {
    generate_alert(AlertSeverity::High, "Container in privileged mode");
}
```

---

### Afternoon: Release Preparation

**Tasks:**
1. Update CHANGELOG.md
2. Update README.md with real features
3. Write release notes
4. Create git tag v0.3.0-alpha
5. Test release build

---

## Success Criteria

### Must Have (for v0.3.0-alpha)

- [ ] Alerts stored in SQLite
- [ ] Can list real Docker containers
- [ ] Can actually quarantine container
- [ ] Can actually release container
- [ ] Alert acknowledge/resolve persists
- [ ] All API endpoints use real data

### Nice to Have

- [ ] Real-time WebSocket updates
- [ ] Docker event listening
- [ ] Basic threat detection rules
- [ ] Container risk scoring

### Future (v0.4.0+)

- [ ] eBPF syscall monitoring
- [ ] ML anomaly detection
- [ ] Advanced threat detection
- [ ] Network traffic analysis

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Docker API changes | Medium | Use stable bollard version |
| SQLite concurrency | Low | Use connection pool |
| WebSocket complexity | Medium | Use polling as fallback |
| Performance issues | Medium | Add caching layer |

---

## Testing Checklist

### Database
- [ ] Migrations run successfully
- [ ] Can insert alerts
- [ ] Can query alerts with filters
- [ ] Can update alert status
- [ ] Stats calculation correct

### Docker
- [ ] Can list containers
- [ ] Can get container details
- [ ] Quarantine disconnects network
- [ ] Release reconnects network
- [ ] Works with running containers

### API
- [ ] All endpoints return real data
- [ ] Error handling works
- [ ] CORS works
- [ ] Performance acceptable

### Frontend
- [ ] Dashboard shows real containers
- [ ] Can acknowledge alerts
- [ ] Can resolve alerts
- [ ] Quarantine button works
- [ ] Release button works

---

*Plan created: 2026-03-15*
