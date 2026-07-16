# Stackdog Security - Development Plan

**Last Updated:** 2026-04-07  
**Current Version:** 0.2.2  
**Status:** Phase 2 In Progress

## Project Vision

**Stackdog Security** is a Rust-based security platform for Docker containers and Linux servers that provides real-time threat detection, AI-powered anomaly detection, and automated response through firewall management.

### Core Capabilities

1. **Real-time Monitoring** — System events, network traffic, and container activity via eBPF
2. **AI/ML Detection** — Anomaly detection using Candle (HuggingFace Rust ML framework)
3. **Automated Response** — Fast iptables/nftables management and container quarantine
4. **Security Dashboard** — Web UI for threat visualization and management

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Stackdog Security Core                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐   │
│  │  Collectors  │    │   ML Engine  │    │    Response Engine       │   │
│  │              │    │              │    │                          │   │
│  │  • eBPF      │───▶│  • Candle    │───▶│  • nftables/iptables     │   │
│  │  • Auditd    │    │  • Anomaly   │    │  • Docker policies       │   │
│  │  • Docker    │    │    Detection │    │  • Auto-quarantine       │   │
│  │  • Network   │    │  • Scoring   │    │  • Alerting              │   │
│  └──────────────┘    └──────────────┘    └──────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Core Language** | Rust 2021 | Performance, safety, concurrency |
| **ML Framework** | Candle (HuggingFace) | Native Rust, fast inference, no Python |
| **eBPF** | aya-rs | Pure Rust eBPF framework |
| **Firewall** | nftables (netlink) | Modern, faster than iptables |
| **Web Framework** | Actix-web | High performance, existing codebase |
| **Database** | SQLite + rusqlite + r2d2 | Embedded, low overhead |
| **Frontend** | React + TypeScript | Existing codebase, rich ecosystem |

---

## Development Phases

### Phase 1: Foundation & eBPF Collectors (Weeks 1-4)

**Goal:** Establish core monitoring infrastructure with eBPF-based syscall collection

#### Milestones

- [ ] **1.1** Project scaffolding with new security-focused structure
- [ ] **1.2** eBPF build pipeline (aya-rs integration)
- [ ] **1.3** Syscall monitoring (execve, connect, open, ptrace)
- [ ] **1.4** Event streaming infrastructure
- [ ] **1.5** Basic rule engine (signature-based detection)

#### Deliverables

```
src/
├── collectors/
│   ├── ebpf/
│   │   ├── mod.rs
│   │   ├── syscalls.rs      # Syscall event collection
│   │   └── programs/        # eBPF programs
│   ├── docker_events.rs     # Docker daemon events
│   └── mod.rs
├── events/
│   ├── mod.rs
│   ├── syscall.rs           # Syscall event types
│   └── security.rs          # Security event types
└── rules/
    ├── mod.rs
    ├── engine.rs            # Rule evaluation engine
    └── signatures.rs        # Known threat signatures
```

#### Tests (TDD)

```rust
// tests/collectors/ebpf_syscalls_test.rs
#[test]
fn test_syscall_event_capture()
#[test]
fn test_execve_detection()
#[test]
fn test_network_connect_detection()

// tests/rules/rule_engine_test.rs
#[test]
fn test_rule_matching()
#[test]
fn test_signature_detection()
```

---

### Phase 2: Firewall & Response Engine (Weeks 5-6)

**Goal:** Implement automated threat response through firewall management

#### Milestones

- [ ] **2.1** nftables integration (netlink-packet-route)
- [ ] **2.2** iptables fallback support
- [ ] **2.3** Docker network policy enforcement
- [ ] **2.4** Container quarantine mechanism
- [ ] **2.5** Response action pipeline

#### Deliverables

```
src/
├── firewall/
│   ├── mod.rs
│   ├── nftables.rs          # nftables management
│   ├── iptables.rs          # iptables fallback
│   ├── docker_policies.rs   # Docker network policies
│   └── quarantine.rs        # Container isolation
└── response/
    ├── mod.rs
    ├── actions.rs           # Response actions
    └── pipeline.rs          # Action pipeline
```

#### Tests (TDD)

```rust
// tests/firewall/nftables_test.rs
#[test]
fn test_add_block_rule()
#[test]
fn test_remove_rule()
#[test]
fn test_batch_update()

// tests/firewall/quarantine_test.rs
#[test]
fn test_container_quarantine()
#[test]
fn test_network_isolation()
```

---

### Phase 3: ML Anomaly Detection with Candle (Weeks 7-10)

**Goal:** Implement AI-powered anomaly detection using Candle ML framework

#### Milestones

- [ ] **3.1** Candle integration and model loading
- [ ] **3.2** Feature extraction pipeline
- [ ] **3.3** Isolation Forest implementation
- [ ] **3.4** Baseline learning system
- [ ] **3.5** Real-time threat scoring
- [ ] **3.6** Model persistence and updates

#### Deliverables

```
src/
├── ml/
│   ├── mod.rs
│   ├── candle_backend.rs    # Candle ML backend
│   ├── features.rs          # Feature extraction
│   ├── anomaly.rs           # Anomaly detection
│   ├── scorer.rs            # Threat scoring
│   └── models/              # Pre-trained models
│       ├── isolation_forest.rs
│       └── autoencoder.rs
├── baselines/
│   ├── mod.rs
│   └── learning.rs          # Baseline learning
└── database/
    ├── events.rs            # Security event storage
    └── baselines.rs         # ML baseline storage
```

#### Feature Vector Example

```rust
pub struct SecurityFeatures {
    // Temporal features
    pub syscall_rate: f64,           // syscalls per second
    pub network_rate: f64,           // connections per second
    
    // Process features
    pub unique_processes: u32,       // unique process count
    pub privileged_calls: u32,       // privileged syscall count
    
    // Network features
    pub unique_destinations: u32,    // unique IP destinations
    pub egress_bytes: u64,           // outbound data volume
    
    // Container features
    pub namespace_changes: u32,      // namespace switch count
    pub mount_operations: u32,       // mount/unmount count
}
```

#### Tests (TDD)

```rust
// tests/ml/feature_extraction_test.rs
#[test]
fn test_feature_normalization()
#[test]
fn test_feature_vector_creation()

// tests/ml/anomaly_detection_test.rs
#[test]
fn test_isolation_forest_training()
#[test]
fn test_anomaly_scoring()
#[test]
fn test_threshold_detection()

// tests/ml/scorer_test.rs
#[test]
fn test_threat_score_calculation()
#[test]
fn test_score_aggregation()
```

---

### Phase 4: Event Correlation & Alerting (Weeks 11-12)

**Goal:** Implement event correlation engine and alerting system

#### Milestones

- [ ] **4.1** Event correlation engine
- [ ] **4.2** Alert rules engine
- [ ] **4.3** Notification system (Slack, email, webhook)
- [ ] **4.4** Alert deduplication
- [ ] **4.5** Security dashboard API

#### Deliverables

```
src/
├── correlator/
│   ├── mod.rs
│   └── engine.rs            # Event correlation
├── alerting/
│   ├── mod.rs
│   ├── rules.rs             # Alert rule definitions
│   ├── notifications.rs     # Notification channels
│   └── dedup.rs             # Alert deduplication
└── api/
    └── alerts.rs            # Alert management endpoints
```

#### Tests (TDD)

```rust
// tests/correlator/engine_test.rs
#[test]
fn test_event_correlation()
#[test]
fn test_pattern_detection()

// tests/alerting/rules_test.rs
#[test]
fn test_alert_rule_evaluation()
#[test]
fn test_alert_deduplication()
```

---

### Phase 5: Web Dashboard & API (Weeks 13-16)

**Goal:** Complete web interface for security monitoring and management

#### Milestones

- [ ] **5.1** Security dashboard (React/TypeScript)
- [ ] **5.2** Real-time threat visualization (WebSocket)
- [ ] **5.3** Container security status
- [ ] **5.4** Alert management UI
- [ ] **5.5** Policy configuration UI
- [ ] **5.6** Security reports

#### Deliverables

```
web/
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx
│   │   ├── ThreatMap.tsx
│   │   ├── ContainerList.tsx
│   │   └── AlertPanel.tsx
│   └── services/
│       ├── security.ts      # Security API client
│       └── websocket.ts     # Real-time updates
└── public/
```

#### Tests (TDD)

```typescript
// web/tests/components/Dashboard.test.tsx
test('displays threat score correctly')
test('updates in real-time via WebSocket')

// web/tests/services/security.test.ts
test('fetches security events')
test('quarantines container via API')
```

---

### Phase 6: Hardening & Production Readiness (Weeks 17-18)

**Goal:** Production hardening, performance optimization, security audit

#### Milestones

- [ ] **6.1** Performance benchmarking
- [ ] **6.2** Memory safety audit
- [ ] **6.3** Integration tests
- [ ] **6.4** Documentation
- [ ] **6.5** Release candidate

#### Tests

```rust
// tests/integration/full_stack_test.rs
#[test]
fn test_end_to_end_threat_detection()
#[test]
fn test_auto_quarantine_workflow()
#[test]
fn test_ml_anomaly_detection_pipeline()

// tests/performance/benchmark_test.rs
#[test]
fn test_event_throughput()
#[test]
fn test_ml_inference_latency()
```

---

## Testing Strategy (TDD)

### Test Pyramid

```
           /\
          /  \       E2E Tests (10%)
         /----\      Integration tests
        /      \     Component tests
       /--------\    Unit tests (60%)
      /          \   
     --------------
```

### Test Categories

| Category | Tools | Coverage Target |
|----------|-------|-----------------|
| **Unit Tests** | `cargo test` | 80%+ |
| **Integration Tests** | `cargo test --test integration` | Critical paths |
| **E2E Tests** | Custom test harness | Key workflows |
| **Performance Tests** | `criterion` | Benchmarks |
| **Security Tests** | `cargo audit`, `cargo deny` | All dependencies |

### TDD Workflow

```
1. Write failing test
2. Run test (verify failure)
3. Implement minimal code to pass
4. Run test (verify pass)
5. Refactor (maintain passing tests)
6. Repeat
```

### Test Commands

```bash
# Run all tests
cargo test --all

# Run with coverage (requires cargo-tarpaulin)
cargo tarpaulin --all

# Run specific test module
cargo test --test ml::anomaly_detection

# Run tests in watch mode (requires cargo-watch)
cargo watch -x test

# Performance benchmarks
cargo bench
```

---

## Code Quality Standards

### Clean Code Principles (Robert C. Martin)

1. **DRY (Don't Repeat Yourself)**
   - Extract common logic into reusable functions
   - Use traits for shared behavior

2. **Single Responsibility Principle**
   - Each module/function has one purpose
   - Keep functions small (<50 lines)

3. **Open/Closed Principle**
   - Open for extension, closed for modification
   - Use traits for extensibility

4. **Dependency Inversion**
   - Depend on abstractions, not concretions
   - Use dependency injection

5. **Functional Programming**
   - Prefer immutable data
   - Use `From`/`Into` traits for conversions
   - Builder pattern for complex objects
   - Avoid mutable state where possible

### Code Review Checklist

- [ ] Functions are small and focused
- [ ] Error handling is comprehensive (`Result` types)
- [ ] No code duplication
- [ ] Tests cover edge cases
- [ ] Documentation for public APIs
- [ ] Follows Rust idioms and conventions

---

## Dependencies

### Core Dependencies (Cargo.toml)

```toml
[dependencies]
# Web framework
actix-web = "4"
actix-rt = "2"
actix-cors = "0.6"

# Database
rusqlite = { version = "0.32", features = ["bundled"] }
r2d2 = "0.8"

# eBPF
aya = "0.12"

# ML
candle-core = "0.3"
candle-nn = "0.3"

# Firewall
netlink-packet-route = "0.17"
netlink-sys = "0.8"

# Docker
bollard = "0.16"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Logging & tracing
tracing = "0.1"
tracing-subscriber = "0.3"
log = "0.4"

# Async
tokio = { version = "1", features = ["full"] }
futures = "0.3"

# Utilities
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
thiserror = "1"
anyhow = "1"
```

### Development Dependencies

```toml
[dev-dependencies]
# Testing
tokio-test = "0.4"
mockall = "0.11"
criterion = "0.5"

# Code quality
cargo-audit = "0.18"
cargo-deny = "0.14"
```

---

## Security Considerations

### Security by Design

1. **Memory Safety**
   - Rust's ownership system prevents buffer overflows
   - No manual memory management

2. **Least Privilege**
   - Run with minimal required capabilities
   - Drop privileges after initialization

3. **Secure Defaults**
   - Deny-by-default firewall policies
   - Encrypted communications (TLS)

4. **Audit Logging**
   - All security events logged
   - Tamper-evident logs

5. **Dependency Security**
   - Regular `cargo audit` scans
   - Minimal dependency surface

---

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Event Throughput** | 100K events/sec | `criterion` benchmark |
| **ML Inference Latency** | <10ms per event | `criterion` benchmark |
| **Firewall Update** | <1ms per rule | Integration test |
| **Memory Usage** | <256MB baseline | `heaptrack` profiling |
| **CPU Overhead** | <5% on monitored host | `perf` profiling |

---

## Milestones & Releases

| Version | Target Date | Features | Status |
|---------|-------------|----------|--------|
| **v0.1.0** | 2022-03-01 | Initial container management | ✅ Released |
| **v0.2.0** | 2026-03-13 | Security platform foundation | ✅ Complete |
| **v0.3.0** | Week 10 | ML anomaly detection | 🚧 In Progress |
| **v0.4.0** | Week 12 | Alerting system | ⏳ Pending |
| **v0.5.0** | Week 16 | Web dashboard | ⏳ Pending |
| **v1.0.0** | Week 18 | Production release | ⏳ Pending |

### Phase 1: Foundation (Complete ✅)

- [x] Project structure (TASK-001)
- [x] Event types (TASK-002)
- [x] eBPF infrastructure (TASK-003)
- [x] Event enrichment (TASK-004)
- [x] Rule engine (TASK-005)
- [x] Signature detection (TASK-006)
- [x] Alert system (TASK-007)
- [x] Firewall integration (TASK-008)

### Phase 2: Detection & Response (In Progress 🚧)

- [ ] Web dashboard (TASK-009)
- [ ] ML anomaly detection (TASK-010)
- [ ] Automated response workflows (TASK-011)

### Phase 3: Production Ready (Pending ⏳)

- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation complete
- [ ] v1.0.0 release

---

## Getting Started

### Development Setup

```bash
# Clone repository
git clone https://github.com/trydirect/stackdog
cd stackdog

# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
apt-get install libsqlite3-dev libssl-dev clang llvm

# Setup eBPF build tools
cargo install cargo-bpf

# Build project
cargo build

# Run tests
cargo test --all

# Run with debug logging
RUST_LOG=debug cargo run
```

### eBPF Development

```bash
# Install eBPF tools
cargo install cargo-bpf

# Build eBPF programs
cd ebpf && cargo build --release

# Load eBPF programs
sudo cargo bpf build
```

---

## Resources

### Documentation

- [Rust Book](https://doc.rust-lang.org/book/)
- [Candle Documentation](https://docs.rs/candle-core)
- [aya-rs Documentation](https://aya-rs.dev/)
- [Clean Code by Robert C. Martin](https://www.amazon.com/Clean-Code-Handbook-Software-Craftsmanship/dp/0132350882)

### References

- [eBPF Documentation](https://ebpf.io/)
- [nftables Wiki](https://wiki.nftables.org/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

### Pull Request Requirements

- [ ] All tests pass (`cargo test --all`)
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --all`)
- [ ] Changelog updated
- [ ] Documentation updated (if needed)
- [ ] TDD approach followed (tests before implementation)

---

## License

[MIT](LICENSE)

---

## Contact

- **Project Lead:** Vasili Pascal
- **Twitter:** [@VasiliiPascal](https://twitter.com/VasiliiPascal)
- **Gitter:** [stackdog/community](https://gitter.im/stackdog/community)
