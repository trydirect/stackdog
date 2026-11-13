# Stackdog Security - Project Memory

## Project Identity

**Name:** Stackdog Security  
**Version:** 0.1.0 (Security-focused rewrite)  
**Type:** Container and Linux Server Security Platform  
**License:** MIT  

## Core Mission

> Provide real-time security monitoring, AI-powered threat detection, and automated response for Docker containers and Linux servers using Rust and eBPF technologies.

## Key Decisions

### Architecture Decisions

| ID | Decision | Rationale | Date |
|----|----------|-----------|------|
| **ARCH-001** | Use eBPF for syscall monitoring | Minimal overhead (<5% CPU), kernel-level visibility, safe (sandboxed) | 2026-03-13 |
| **ARCH-002** | Use Candle for ML instead of Python | Native Rust, no Python dependencies, fast inference, maintained by HuggingFace | 2026-03-13 |
| **ARCH-003** | Use nftables over iptables | Modern, faster, better batch support, iptables as fallback | 2026-03-13 |
| **ARCH-004** | TDD development methodology | Better code quality, maintainability, regression prevention | 2026-03-13 |
| **ARCH-005** | Functional programming principles | Immutability, fewer bugs, easier reasoning about code | 2026-03-13 |

### Technology Choices

| Component | Technology | Alternatives Considered |
|-----------|-----------|------------------------|
| **eBPF Framework** | aya-rs | libbpf (C), bcc (Python) |
| **ML Framework** | Candle (HuggingFace) | PyTorch (Python), ONNX Runtime, linfa |
| **Web Framework** | Actix-web 4.x | Axum, Rocket |
| **Database** | SQLite + rusqlite + r2d2 | PostgreSQL, Redis |
| **Firewall** | nftables (netlink) | iptables, firewalld |

## Project Structure

```
stackdog/
├── src/
│   ├── collectors/          # Event collection (eBPF, Docker, etc.)
│   ├── events/              # Event types and structures
│   ├── ml/                  # ML engine (Candle-based)
│   ├── firewall/            # Firewall management (nftables/iptables)
│   ├── response/            # Automated response actions
│   ├── correlator/          # Event correlation
│   ├── alerting/            # Alert system
│   ├── api/                 # REST API + WebSocket
│   ├── config/              # Configuration
│   ├── models/              # Data models
│   ├── database/            # Database operations
│   └── utils/               # Utilities
├── ebpf/                    # eBPF programs (separate crate)
├── web/                     # React/TypeScript frontend
├── tests/                   # Integration tests
├── benches/                 # Performance benchmarks
└── models/                  # Pre-trained ML models
```

## Development Principles

### Clean Code (Robert C. Martin)

1. **DRY** - Don't Repeat Yourself
2. **SRP** - Single Responsibility Principle
3. **OCP** - Open/Closed Principle
4. **DIP** - Dependency Inversion Principle
5. **Functional First** - Immutability, From/Into traits, builder pattern

### TDD Workflow

```
Red → Green → Refactor
```

1. Write failing test
2. Run test (verify failure)
3. Implement minimal code to pass
4. Run test (verify pass)
5. Refactor (maintain passing tests)

### Code Review Checklist

- [ ] Tests written first (TDD)
- [ ] All tests pass
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings
- [ ] DRY principle followed
- [ ] Functions < 50 lines
- [ ] Error handling comprehensive
- [ ] Documentation for public APIs

## Key APIs and Interfaces

### Event Types

```rust
// Core security event
pub enum SecurityEvent {
    Syscall(SyscallEvent),
    Network(NetworkEvent),
    Container(ContainerEvent),
    Alert(AlertEvent),
}

// Syscall event from eBPF
pub struct SyscallEvent {
    pub pid: u32,
    pub uid: u32,
    pub syscall_type: SyscallType,
    pub timestamp: DateTime<Utc>,
    pub container_id: Option<String>,
}
```

### ML Interface

```rust
// Feature vector for ML
pub struct SecurityFeatures {
    pub syscall_rate: f64,
    pub network_rate: f64,
    pub unique_processes: u32,
    pub privileged_calls: u32,
    // ...
}

// Threat score output
pub enum ThreatScore {
    Normal,
    Low,
    Medium,
    High,
    Critical,
}
```

### Firewall Interface

```rust
pub trait FirewallBackend {
    fn add_rule(&self, rule: &Rule) -> Result<()>;
    fn remove_rule(&self, rule: &Rule) -> Result<()>;
    fn batch_update(&self, rules: &[Rule]) -> Result<()>;
    fn block_container(&self, container_id: &str) -> Result<()>;
    fn quarantine_container(&self, container_id: &str) -> Result<()>;
}
```

## Configuration

### Environment Variables

```bash
APP_HOST=0.0.0.0
APP_PORT=5000
DATABASE_URL=stackdog.db
RUST_LOG=info
RUST_BACKTRACE=full

# Security-specific
EBPF_ENABLED=true
FIREWALL_BACKEND=nftables  # or iptables
ML_ENABLED=true
ML_MODEL_PATH=models/
ALERT_THRESHOLD=0.75
```

### Cargo Features

```toml
[features]
default = ["nftables", "ml"]
nftables = ["netlink-packet-route"]
iptables = ["iptables"]
ml = ["candle-core", "candle-nn"]
ebpf = ["aya"]
```

## Testing Strategy

### Test Categories

| Category | Location | Command | Coverage Target |
|----------|----------|---------|-----------------|
| Unit | `src/**/*.rs` | `cargo test` | 80%+ |
| Integration | `tests/integration/` | `cargo test --test integration` | Critical paths |
| E2E | `tests/e2e/` | `cargo test --test e2e` | Key workflows |
| Benchmark | `benches/` | `cargo bench` | Performance targets |

### Performance Targets

| Metric | Target |
|--------|--------|
| Event throughput | 100K events/sec |
| ML inference latency | <10ms |
| Firewall update | <1ms per rule |
| Memory usage | <256MB baseline |
| CPU overhead | <5% |

## Dependencies

### Core

- `actix-web` - Web framework
- `aya` - eBPF framework
- `candle-core`, `candle-nn` - ML framework
- `bollard` - Docker API
- `rusqlite` - SQLite driver
- `r2d2` - Connection pool
- `netlink-packet-route` - nftables
- `tokio` - Async runtime

### Development

- `mockall` - Mocking for tests
- `criterion` - Benchmarking
- `cargo-audit` - Security audit
- `cargo-deny` - Dependency linting

## Milestones

| Version | Target | Features |
|---------|--------|----------|
| v0.1.0 | Week 4 | eBPF collectors, basic rules |
| v0.2.0 | Week 6 | Firewall integration |
| v0.3.0 | Week 10 | ML anomaly detection |
| v0.4.0 | Week 12 | Alerting system |
| v0.5.0 | Week 16 | Web dashboard |
| v1.0.0 | Week 18 | Production release |

## Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| eBPF kernel compatibility | High | Medium | Fallback to auditd |
| ML model accuracy | High | Medium | Start with rule-based, iterate |
| Performance overhead | High | Low | Benchmark early, optimize |
| False positives | Medium | High | Tunable thresholds, learning period |

## Open Questions

1. **Model Training:** How to collect training data for ML models?
   - Decision: Start with synthetic data, then real-world collection

2. **Multi-node Support:** Single node first, cluster later?
   - Decision: Single node for v1.0, cluster in v2.0

3. **Kubernetes Support:** Include in scope?
   - Decision: Out of scope for v1.0, backlog for v2.0

## Resources

### Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) - Full development plan
- [TODO.md](TODO.md) - Task tracking
- [BUGS.md](BUGS.md) - Bug tracking
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

### External

- [Rust Book](https://doc.rust-lang.org/book/)
- [Candle Docs](https://docs.rs/candle-core)
- [aya-rs Docs](https://aya-rs.dev/)
- [eBPF Documentation](https://ebpf.io/)

## Contact

- **Project Lead:** Vasili Pascal
- **Email:** info@try.direct
- **Twitter:** [@VasiliiPascal](https://twitter.com/VasiliiPascal)
- **Gitter:** [stackdog/community](https://gitter.im/stackdog/community)

---

*Last updated: 2026-03-13*
