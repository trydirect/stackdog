# Stackdog Security — Copilot Instructions

## What This Project Is

Stackdog is a Rust-based security platform for Docker containers and Linux servers. It collects events via eBPF syscall monitoring, runs them through a rule/signature engine and optional ML anomaly detection, manages firewall responses (nftables/iptables + container quarantine), and exposes a REST + WebSocket API consumed by a React/TypeScript dashboard.

## Workspace Structure

This is a Cargo workspace with two crates:
- `.` — Main crate (`stackdog`): HTTP server, all security logic
- `ebpf/` — Separate crate (`stackdog-ebpf`): eBPF programs compiled for the kernel (uses `aya-ebpf`)

## Build, Test, and Lint Commands

```bash
# Build
cargo build
cargo build --release

# Tests
cargo test --lib                        # Unit tests only (in-source)
cargo test --all                        # All tests including integration
cargo test --lib -- events::            # Run tests for a specific module
cargo test --lib -- rules::scorer       # Run a single test by name prefix

# Code quality
cargo fmt --all
cargo clippy --all
cargo audit                             # Dependency vulnerability scan

# Benchmarks
cargo bench

# Frontend (in web/)
npm test
npm run lint
npm run build
```

## Environment Setup

Requires a `.env` file (copy `.env.sample`). Key variables:
```
APP_HOST=0.0.0.0
APP_PORT=5000
DATABASE_URL=stackdog.db
RUST_BACKTRACE=full
```

System dependencies (Linux): `libsqlite3-dev libssl-dev clang llvm pkg-config`

## Architecture

```
Collectors (Linux only)     Rule Engine          Response
  eBPF syscall events   →   Signatures       →   nftables/iptables
  Docker daemon events  →   Threat scoring   →   Container quarantine
  Network events        →   ML anomaly det.  →   Alerting

                         REST + WebSocket API
                         React/TypeScript UI
```

**Key src/ modules:**

| Module | Purpose |
|---|---|
| `events/` | Core event types: `SyscallEvent`, `SecurityEvent`, `NetworkEvent`, `ContainerEvent` |
| `rules/` | Rule engine, signature database, threat scorer |
| `alerting/` | `AlertManager`, notification channels (Slack/email/webhook) |
| `collectors/` | eBPF loader, Docker daemon events, network collector (Linux only) |
| `firewall/` | nftables management, iptables fallback, `QuarantineManager` (Linux only) |
| `ml/` | Candle-based anomaly detection (optional `ml` feature) |
| `correlator/` | Event correlation engine |
| `baselines/` | Baseline learning for anomaly detection |
| `database/` | SQLite connection pool (`r2d2` + raw `rusqlite`), repositories |
| `api/` | actix-web REST endpoints + WebSocket |
| `response/` | Automated response action pipeline |

## Key Conventions

### Platform-Gating
Linux-only modules (`collectors`, `firewall`) and deps (aya, netlink) are gated:
```rust
#[cfg(target_os = "linux")]
pub mod firewall;
```
The `ebpf` and `ml` features are opt-in and must be enabled explicitly:
```bash
cargo build --features ebpf
cargo build --features ml
```

### Error Handling
- Use `anyhow::{Result, Context}` for application/binary code
- Use `thiserror` for library error types
- Never use `.unwrap()` in production code; use `?` with `.context("...")`

### Database
The project uses raw `rusqlite` with `r2d2` connection pooling. `DbPool` is `r2d2::Pool<SqliteConnectionManager>`. Tables are created with `CREATE TABLE IF NOT EXISTS` in `database::connection::init_database`. Repositories are in `src/database/repositories/` and receive a `&DbPool`.

### API Routes
Each API sub-module exports a `configure_routes(cfg: &mut web::ServiceConfig)` function. All routes are composed in `api::configure_all_routes`, which is the single call site in `main.rs`.

### Test Location
- **Unit tests**: `#[cfg(test)] mod tests { ... }` inside source files
- **Integration tests**: `tests/` directory at workspace root

### eBPF Programs
The `ebpf/` crate is compiled separately for the Linux kernel. User-space loading is handled by `src/collectors/ebpf/` using the `aya` library. Kernel-side programs use `aya-ebpf`.

### Async Runtime
The main binary uses `#[actix_rt::main]`. Library code uses `tokio`. Avoid mixing runtimes.
