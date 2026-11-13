# Stackdog Testing Guide

## Overview

This guide explains how to test the Stackdog Security modules.

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Start development environment
docker-compose up -d

# View logs
docker-compose logs -f stackdog

# Run tests inside container
docker-compose exec stackdog cargo test --lib
```

### Option 2: Local Development

```bash
# Setup environment
cp .env.sample .env

# Create database directory
mkdir -p db

# Set database URL
export DATABASE_URL=./db/stackdog.db

# Run tests (schema is initialized automatically via init_database)
cargo test --lib
```

## Testable Modules (No Database Required)

The following modules can be tested without database connection:

### 1. Event Modules
```bash
cargo test --lib -- events::syscall::tests
cargo test --lib -- events::security::tests
```

### 2. Rules Modules
```bash
cargo test --lib -- rules::engine::tests
cargo test --lib -- rules::signatures::tests
cargo test --lib -- rules::builtin::tests
cargo test --lib -- rules::result::tests
cargo test --lib -- rules::signature_matcher::tests
cargo test --lib -- rules::threat_scorer::tests
cargo test --lib -- rules::stats::tests
```

### 3. Alerting Modules
```bash
cargo test --lib -- alerting::alert::tests
cargo test --lib -- alerting::manager::tests
cargo test --lib -- alerting::dedup::tests
cargo test --lib -- alerting::notifications::tests
```

### 4. Firewall Modules (Linux only)
```bash
# These require root and Linux
sudo cargo test --lib -- firewall::nftables::tests
sudo cargo test --lib -- firewall::iptables::tests
sudo cargo test --lib -- firewall::quarantine::tests
```

### 5. Collector Modules
```bash
# eBPF tests require Linux with eBPF support
sudo cargo test --lib -- collectors::ebpf::tests
```

## Running Test Script

```bash
# Make executable
chmod +x scripts/test.sh

# Run test script
./scripts/test.sh
```

## Test Coverage by Module

| Module | Tests | Database Required | Root Required | Platform |
|--------|-------|-------------------|---------------|----------|
| events/* | 64+ | No | No | All |
| rules/* | 100+ | No | No | All |
| alerting/* | 52+ | No | No | All |
| firewall/* | 44+ | No | Yes (some) | Linux |
| collectors/ebpf/* | 35+ | No | Yes | Linux |

## Integration Tests

Integration tests require:
- SQLite database
- Migrations run
- (Optional) Docker daemon for container tests

```bash
# Run integration tests
cargo test --test integration
```

## Known Issues

### Compilation Errors

Some existing code (auth middleware) has compatibility issues with actix-web 4.x. These modules are being updated.

**Workaround:** Test only the new security modules:
```bash
cargo test --lib -- events:: rules:: alerting::
```

### Database Connection

If you see database connection errors:
```bash
# Create SQLite database
mkdir -p db
touch db/stackdog.db

# Set environment variable
export DATABASE_URL=./db/stackdog.db

```

### eBPF Tests

eBPF tests require:
- Linux kernel 4.19+
- Root privileges
- BTF support (recommended)

```bash
# Check kernel version
uname -r

# Check eBPF support
bpftool version
```

## Docker Compose Profiles

```bash
# Default (SQLite)
docker-compose up

# With PostgreSQL (optional)
docker-compose --profile postgres up

# With Adminer (database UI)
docker-compose --profile adminer up
```

## Environment Variables

```bash
# Required
APP_HOST=0.0.0.0
APP_PORT=5000
DATABASE_URL=./db/stackdog.db

# Optional
RUST_LOG=debug
RUST_BACKTRACE=full
```

## Troubleshooting

### "database table not found"
Tables are created automatically by `init_database` on startup. Ensure `DATABASE_URL` points to a writable path.

### "permission denied"
```bash
# For eBPF/firewall tests
sudo cargo test --lib
```

### "command not found: nft"
```bash
# Install nftables
sudo apt-get install nftables  # Debian/Ubuntu
sudo yum install nftables      # RHEL/CentOS
```

### "command not found: iptables"
```bash
# Install iptables
sudo apt-get install iptables  # Debian/Ubuntu
sudo yum install iptables      # RHEL/CentOS
```

## Next Steps

1. Run unit tests for security modules
2. Setup Docker environment for integration tests
3. Run eBPF tests on Linux VM (if developing on macOS)

## Additional Resources

- [DEVELOPMENT.md](DEVELOPMENT.md) - Full development guide
- [QUICKSTART.md](docs/QUICKSTART.md) - Quick start guide
- [TODO.md](TODO.md) - Task tracking
