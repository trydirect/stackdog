# Stackdog Security - Project Context

## Project Overview

**Stackdog Security** is a Rust-based security platform for Docker containers and Linux servers. It provides real-time threat detection, AI-powered anomaly detection using Candle (HuggingFace's Rust ML framework), and automated response through firewall management (nftables/iptables).

### Core Capabilities

1. **Real-time Monitoring** — System events via eBPF (aya-rs), network traffic, and container activity
2. **AI/ML Detection** — Anomaly detection using Candle (native Rust, no Python)
3. **Automated Response** — Fast nftables/iptables management and container quarantine
4. **Security Dashboard** — Web UI for threat visualization and management

### Key Technologies

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Core Language** | Rust 2021 | Performance, safety, concurrency |
| **ML Framework** | Candle (HuggingFace) | Native Rust, fast inference, no Python dependencies |
| **eBPF** | aya-rs | Pure Rust eBPF framework, minimal overhead |
| **Firewall** | nftables (netlink) | Modern, faster than iptables |
| **Web Framework** | Actix-web 4.x | High performance |
| **Database** | SQLite + rusqlite + r2d2 | Embedded, low overhead |

---

## Architecture

```
stackdog/
├── src/
│   ├── collectors/          # Event collection (eBPF, Docker, network)
│   ├── events/              # Event types (SyscallEvent, SecurityEvent)
│   ├── ml/                  # ML engine (Candle-based anomaly detection)
│   ├── firewall/            # Firewall management (nftables/iptables)
│   ├── response/            # Automated response actions
│   ├── correlator/          # Event correlation engine
│   ├── alerting/            # Alert system and notifications
│   ├── api/                 # REST API + WebSocket
│   ├── config/              # Configuration
│   ├── models/              # Data models
│   ├── database/            # Database operations
│   └── utils/               # Utilities
├── ebpf/                    # eBPF programs (separate crate)
├── web/                     # React/TypeScript frontend
├── tests/                   # Integration and E2E tests
├── benches/                 # Performance benchmarks
└── models/                  # Pre-trained ML models
```

---

## Development Status

**Current Phase:** Phase 1 - Foundation & eBPF Collectors (Weeks 1-4)

**Active Tasks:** See [TODO.md](TODO.md)

**Development Plan:** See [DEVELOPMENT.md](DEVELOPMENT.md)

---

## Building and Running

### Prerequisites

- Rust 1.75+ (edition 2021)
- SQLite3 + libsqlite3-dev
- Clang + LLVM (for eBPF)
- Kernel 4.19+ (for eBPF with BTF support)
- Docker & Docker Compose (optional)

### Quick Start

```bash
# Clone and setup
git clone https://github.com/trydirect/stackdog
cd stackdog

# Environment setup
cp .env.sample .env

# Install dependencies (Ubuntu/Debian)
apt-get install libsqlite3-dev libssl-dev clang llvm

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
```

---

## Development Commands

```bash
# Build
cargo build --release

# Run all tests
cargo test --all

# Run specific test module
cargo test --test ml::anomaly_detection

# Linting
cargo clippy --all

# Formatting
cargo fmt --all -- --check  # Check
cargo fmt --all             # Fix

# Performance benchmarks
cargo bench

# Security audit
cargo audit

# Watch mode (with cargo-watch)
cargo watch -x test
```

---

## Testing Strategy (TDD)

### TDD Workflow

```
1. Write failing test
2. Run test (verify failure)
3. Implement minimal code to pass
4. Run test (verify pass)
5. Refactor (maintain passing tests)
```

### Test Categories

| Category | Location | Command | Coverage Target |
|----------|----------|---------|-----------------|
| **Unit Tests** | `src/**/*.rs` | `cargo test` | 80%+ |
| **Integration Tests** | `tests/integration/` | `cargo test --test integration` | Critical paths |
| **E2E Tests** | `tests/e2e/` | `cargo test --test e2e` | Key workflows |
| **Benchmarks** | `benches/` | `cargo bench` | Performance targets |

### Test Naming Convention

```rust
#[test]
fn test_<component>_<scenario>_<expected_result>()
```

Example:
```rust
#[test]
fn test_syscall_event_capture_execve()
#[test]
fn test_isolation_forest_training_valid_data()
#[test]
fn test_container_quarantine_success()
```

---

## Code Quality Standards

### Clean Code Principles (Robert C. Martin)

1. **DRY** - Don't Repeat Yourself
2. **SRP** - Single Responsibility Principle
3. **OCP** - Open/Closed Principle
4. **DIP** - Dependency Inversion Principle
5. **Functional First** - Immutability, `From`/`Into` traits, builder pattern

### Code Review Checklist

- [ ] Tests written first (TDD)
- [ ] All tests pass
- [ ] Code formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --all`)
- [ ] DRY principle followed
- [ ] Functions < 50 lines
- [ ] Error handling comprehensive (`Result` types)
- [ ] Documentation for public APIs

---

## Configuration

### Environment Variables (`.env`)

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

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Event throughput | 100K events/sec |
| ML inference latency | <10ms |
| Firewall update | <1ms per rule |
| Memory usage | <256MB baseline |
| CPU overhead | <5% on monitored host |

---

## Key Files

| File | Description |
|------|-------------|
| [DEVELOPMENT.md](DEVELOPMENT.md) | Comprehensive development plan with phases |
| [TODO.md](TODO.md) | Task tracking with TDD approach |
| [BUGS.md](BUGS.md) | Bug tracking and reporting |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [ROADMAP.md](ROADMAP.md) | Original roadmap (being updated) |
| `.qwen/PROJECT_MEMORY.md` | Project memory and decisions |

---

## Current Sprint (Phase 1)

**Goal:** Establish core monitoring infrastructure with eBPF-based syscall collection

### Active Tasks

| ID | Task | Status |
|----|------|--------|
| **TASK-001** | Create new project structure for security modules | Pending |
| **TASK-002** | Define security event types | Pending |
| **TASK-003** | Setup aya-rs eBPF integration | Pending |
| **TASK-004** | Implement syscall event capture | Pending |
| **TASK-005** | Create rule engine infrastructure | Pending |

See [TODO.md](TODO.md) for detailed task descriptions.

---

## Contributing

1. Pick a task from [TODO.md](TODO.md) or create a new issue
2. Write failing test first (TDD)
3. Implement minimal code to pass
4. Refactor while keeping tests green
5. Submit PR with updated changelog

### PR Requirements

- [ ] All tests pass (`cargo test --all`)
- [ ] Code formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --all`)
- [ ] Changelog updated
- [ ] TDD approach followed

---

## License

[MIT](LICENSE)

---

## Contact

- **Project Lead:** Vasili Pascal
- **Email:** info@try.direct
- **Twitter:** [@VasiliiPascal](https://twitter.com/VasiliiPascal)
- **Gitter:** [stackdog/community](https://gitter.im/stackdog/community)

---

*Last updated: 2026-03-13*
