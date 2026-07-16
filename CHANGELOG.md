# Changelog

All notable changes to Stackdog Security will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-04-07

### Fixed

- **CLI startup robustness** — `.env` loading is now non-fatal.
  - `stackdog --help` and other commands no longer panic when `.env` is missing or contains malformed lines.
  - Stackdog now logs a warning and continues with existing environment variables.

- **Installer release resolution** — `install.sh` now handles missing `/releases/latest` responses gracefully.
  - Falls back to the most recent release entry when no stable "latest" release is available.
  - Improves error messaging and updates install examples to use the `main` branch script URL.

### Added

- **Expanded detector framework** with additional log-driven detection coverage.
  - Reverse shell, sensitive file access, cloud metadata / SSRF, exfiltration chain, and secret leakage detectors.
  - file integrity monitoring with SQLite-backed baselines via `STACKDOG_FIM_PATHS`.
  - configuration assessment via `STACKDOG_SCA_PATHS`.
  - package inventory heuristics via `STACKDOG_PACKAGE_INVENTORY_PATHS`.
  - Docker posture audits for privileged mode, host namespaces, dangerous capabilities, Docker socket mounts, and writable sensitive mounts.

- **Improved syslog ingestion**
  - RFC3164 and RFC5424 parsing in file-based log ingestion for cleaner timestamps and normalized message bodies.

#### Log Sniffing & Analysis (`stackdog sniff`)
- **CLI Subcommands** — Multi-mode binary with `stackdog serve` and `stackdog sniff`
  - `--once` flag for single-pass mode
  - `--consume` flag to archive logs (zstd) and purge originals
  - `--sources` to add custom log paths
  - `--ai-provider` to select AI backend (openai/candle)
  - `--interval` for polling frequency
  - `--output` for archive destination

- **Log Source Discovery** — Automatic and manual log source management
  - System logs (`/var/log/syslog`, `messages`, `auth.log`, etc.)
  - Docker container logs via bollard API
  - Custom file paths (CLI, env var, or REST API)
  - Incremental read position tracking (byte offset persisted in DB)

- **Log Readers** — Trait-based reader abstraction
  - `FileLogReader` with byte-offset tracking and log rotation detection
  - `DockerLogReader` using bollard streaming API
  - `JournaldReader` (Linux-gated) for systemd journal

- **AI-Powered Analysis** — Dual-backend log summarization
  - `OpenAiAnalyzer` — works with any OpenAI-compatible API (OpenAI, Ollama, vLLM)
  - `PatternAnalyzer` — local fallback with error/warning counting and spike detection
  - Structured `LogSummary` with anomaly detection (`LogAnomaly`, severity levels)

- **Log Consumer** — Archive and purge pipeline
  - FNV hash-based deduplication
  - zstd compression (level 3) for archived logs
  - File truncation and Docker log purge
  - `ConsumeResult` tracking (entries archived, duplicates skipped, bytes freed)

- **Reporter** — Bridges log analysis to existing alert system
  - Converts `LogAnomaly` → `Alert` using `AlertManager` infrastructure
  - Routes notifications via `route_by_severity()` to configured channels
  - Persists `LogSummary` records to database

- **REST API Endpoints**
  - `GET /api/logs/sources` — list discovered log sources
  - `POST /api/logs/sources` — manually add a custom source
  - `GET /api/logs/sources/{path}` — get source details
  - `DELETE /api/logs/sources/{path}` — remove a source
  - `GET /api/logs/summaries` — list AI-generated summaries (filterable by source)

- **Database Tables** — `log_sources` and `log_summaries` with indexes

#### Dependencies
- `clap = "4"` (derive) — CLI argument parsing
- `async-trait = "0.1"` — async trait support
- `reqwest = "0.12"` (json) — HTTP client for AI APIs
- `zstd = "0.13"` — log compression
- `futures-util = "0.3"` — Docker log streaming

### Changed

- Refactored `main.rs` to dispatch `serve`/`sniff` subcommands via clap
- Added `events`, `rules`, `alerting`, `models` modules to binary crate
- Updated `.env.sample` with `STACKDOG_LOG_SOURCES`, `STACKDOG_AI_*` config vars
- Version metadata updated to `0.2.2` across Cargo, the web package manifest, and current release documentation.

### Testing

- **80+ new tests** covering all sniff modules (TDD)
  - Config: 12, Discovery: 14, Readers: 10, Analyzer: 16, Consumer: 13, Reporter: 5, Orchestrator: 3, API: 7

### Planned

- Web dashboard (React/TypeScript)
- ML anomaly detection with Candle
- Kubernetes support
- Grafana integration
- Package builds (deb, rpm)

---

## [0.2.0] - 2026-03-13

### 🎉 Major Release - Security Platform Rewrite

Complete repositioning from container management to security-focused platform.

### Added

#### Core Security Modules
- **Event System** - Comprehensive security event types with validation
  - SyscallEvent with builder pattern
  - SecurityEvent enum (Syscall, Network, Container, Alert)
  - Event validation (IP, port, message validation)
  - Event streaming (batch, filter, iterator)

- **Rule Engine** - Flexible rule evaluation system
  - Rule trait with priority support
  - Built-in rules (allowlist, blocklist, process execution, network, file access)
  - Rule chaining and aggregation
  - Detailed evaluation results

- **Signature Detection** - Threat signature database
  - 10+ built-in threat signatures
  - Categories: CryptoMiner, ContainerEscape, NetworkScanner, PrivilegeEscalation
  - Pattern matching engine
  - Multi-event pattern detection

- **Threat Scoring** - ML-ready scoring system
  - Configurable scoring (base, multiplier, time-decay)
  - Severity levels (Info, Low, Medium, High, Critical)
  - Cumulative scoring
  - Threshold-based alerting

- **Alert System** - Comprehensive alerting
  - Alert lifecycle management (New → Acknowledged → Resolved)
  - Alert deduplication with time windows
  - 4 notification channels (Console, Slack, Email, Webhook)
  - Alert statistics and tracking

- **Firewall Integration** - Automated response
  - nftables backend (Linux)
  - iptables fallback
  - Container quarantine
  - Automated response actions
  - Response audit trail

#### Infrastructure
- **eBPF Support** - Syscall monitoring infrastructure (Linux)
  - eBPF loader with aya-rs
  - Kernel compatibility checking
  - Event ring buffer
  - Syscall monitor

- **Event Enrichment** - Context enhancement
  - Process information from /proc
  - Container ID detection (Docker, Kubernetes, containerd)
  - Timestamp normalization
  - Process tree enrichment

#### Documentation
- Complete development plan (18 weeks)
- Testing guide
- Usage examples
- API documentation
- Contributing guidelines

### Changed

- **Project Focus** - From container management to security platform
- **Architecture** - Modular, security-first design
- **Dependencies** - Removed legacy web framework dependencies
- **Codebase** - Complete rewrite following Clean Code principles

### Removed

- Legacy REST API controllers
- Old authentication middleware
- React/TypeScript frontend (moved to future phase)
- Old database models and migrations
- Unused utility modules

### Technical Details

#### Dependencies Added
- `aya = "0.12"` - eBPF framework
- `candle-core = "0.3"` - ML framework
- `netlink-packet-route = "0.17"` - nftables
- `bollard = "0.16"` - Docker API
- `uuid = "1"` - UUID generation

#### Dependencies Removed
- Old actix-web 3.x (will be added back in Phase 4)
- Legacy authentication libraries

### Testing

- **49+ unit tests** passing
- Tests for all security modules
- TDD approach adopted
- Integration test framework

### Documentation

- `README.md` - Complete rewrite
- `CONTRIBUTING.md` - Updated guidelines
- `DEVELOPMENT.md` - 18-week plan
- `TESTING.md` - Testing guide
- `STATUS.md` - Implementation status
- `examples/usage_examples.rs` - Working examples

---

## [0.1.0] - 2022-03-01

### Initial Release

**Note:** This was the original container management tool. Version 0.2.0 represents a complete repositioning to a security-focused platform.

### Added

- Basic container management UI
- Docker integration
- SQLite database
- JWT authentication
- React frontend scaffolding

---

## Versioning

Stackdog Security uses [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible changes
- **MINOR** version for backwards-compatible features
- **PATCH** version for backwards-compatible bug fixes

### Version Format

```
MAJOR.MINOR.PATCH

Examples:
0.2.0 - Initial security platform release
0.2.1 - Bug fixes
0.3.0 - New features
1.0.0 - Production release
```

---

## Release Schedule

| Version | Target Date | Focus |
|---------|-------------|-------|
| **0.2.x** | Q1 2026 | Security foundation |
| **0.3.x** | Q2 2026 | ML & automation |
| **0.4.x** | Q3 2026 | Web dashboard |
| **1.0.0** | Q4 2026 | Production release |

---

## Migration Guide

### From 0.1.0 to 0.2.0

Version 0.2.0 is a complete rewrite. There is no direct migration path.

**For existing users:**
- Old container management features are deprecated
- New security features are the focus
- Web dashboard will be added in Phase 4 (0.4.x)

**For new users:**
- Start with 0.2.0
- Follow [README.md](README.md) for setup
- See [examples/usage_examples.rs](examples/usage_examples.rs) for usage

---

## Breaking Changes

### Version 0.2.0

- Complete API change
- New module structure
- Different configuration format
- Legacy features removed

---

## Contributors

This release was made possible by contributions from:

- **Vasili Pascal** - Project lead
- **Community contributors** - See GitHub for full list

---

## Links

- **GitHub:** https://github.com/trydirect/stackdog
- **Documentation:** See docs/ directory
- **Issues:** https://github.com/trydirect/stackdog/issues
- **Discussions:** https://github.com/trydirect/stackdog/discussions
