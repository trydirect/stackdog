# Quick Start Guide - Stackdog Security Development

## Getting Started

### 1. Prerequisites

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install system dependencies (Ubuntu/Debian)
apt-get install libsqlite3-dev libssl-dev clang llvm pkg-config

# Install system dependencies (macOS)
brew install sqlite openssl llvm
```

### 2. Clone and Setup

```bash
cd /Users/vasilipascal/work/stackdog

# Copy environment file
cp .env.sample .env

# Generate secret key
head -c16 /dev/urandom > src/secret.key
```

### 3. Build and Test

```bash
# Build the project
cargo build

# Run all tests
cargo test --all

# Run specific test module
cargo test --test events::syscall_event_test

# Check code formatting
cargo fmt --all -- --check

# Run clippy linter
cargo clippy --all
```

### 4. Run the Application

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Run in release mode
cargo run --release
```

---

## Development Workflow

### TDD Workflow

1. **Write a failing test** in `tests/` directory
2. **Run the test** to verify it fails:
   ```bash
   cargo test --test <test_file>
   ```
3. **Implement minimal code** to make the test pass
4. **Run test again** to verify it passes
5. **Refactor** while keeping tests green
6. **Repeat**

### Example: Creating a New Event Type

```rust
// 1. Write test first (tests/events/my_event_test.rs)
#[test]
fn test_my_event_creation() {
    let event = MyEvent::new("test");
    assert_eq!(event.name, "test");
}

// 2. Run test (should fail)
cargo test --test events::my_event_test

// 3. Implement in src/events/my_event.rs
pub struct MyEvent {
    pub name: String,
}

impl MyEvent {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }
}

// 4. Run test again (should pass)
cargo test --test events::my_event_test

// 5. Refactor and add documentation
```

---

## Module Structure

### Adding a New Module

1. **Create directory** under `src/`:
   ```bash
   mkdir src/my_module
   ```

2. **Create mod.rs**:
   ```rust
   //! My module documentation
   
   pub mod my_submodule;
   
   pub struct MyModuleMarker;
   ```

3. **Add to main.rs**:
   ```rust
   mod my_module;
   ```

4. **Create tests**:
   ```bash
   mkdir tests/my_module
   ```

---

## Running Specific Tests

```bash
# All tests
cargo test --all

# Specific test file
cargo test --test events::syscall_event_test

# Specific test function
cargo test test_syscall_event_creation

# Tests with pattern
cargo test test_syscall

# Integration tests
cargo test --test integration

# With output
cargo test -- --nocapture

# With coverage (requires cargo-tarpaulin)
cargo tarpaulin --all --out Html
```

---

## Code Quality Commands

```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run linter
cargo clippy --all

# Run linter with all features
cargo clippy --all-features

# Security audit
cargo audit

# Check dependencies
cargo deny check
```

---

## Debugging

### Enable Debug Logging

```bash
RUST_LOG=debug cargo run
RUST_LOG=stackdog=debug cargo run
RUST_LOG=trace cargo run
```

### Print Debug Information

```rust
// In your code
dbg!(&variable);
println!("Debug: {:?}", variable);
```

### Using gdb/lldb

```bash
# Build with debug symbols
cargo build

# Run with debugger
lldb target/debug/stackdog
```

---

## eBPF Development

### Build eBPF Programs

```bash
cd ebpf
cargo build --release
```

### Load eBPF Programs

```bash
# Requires root
sudo cargo bpf build
```

### Debug eBPF

```bash
# List loaded eBPF programs
bpftool prog list

# View eBPF maps
bpftool map list
```

---

## ML Development with Candle

### Load Model

```rust
use candle_core::{Tensor, DType, Device};

let tensor = Tensor::new(&[1.0f32, 2.0, 3.0], &Device::Cpu)?;
```

### Run Inference

```rust
use candle_nn::{Module, Linear};

let output = model.forward(&input)?;
```

---

## Common Issues

### Issue: Compilation errors with aya

**Solution:** Ensure you have LLVM installed:
```bash
# Ubuntu/Debian
apt-get install llvm clang

# macOS
brew install llvm
```

### Issue: eBPF programs won't load

**Solution:** Check kernel version (requires 4.19+):
```bash
uname -r
```

### Issue: Tests failing

**Solution:** Clean and rebuild:
```bash
cargo clean
cargo build
cargo test
```

---

## Resources

- **Development Plan:** [DEVELOPMENT.md](DEVELOPMENT.md)
- **Task List:** [TODO.md](TODO.md)
- **Project Memory:** [.qwen/PROJECT_MEMORY.md](.qwen/PROJECT_MEMORY.md)
- **Task Specification:** [docs/tasks/TASK-001.md](docs/tasks/TASK-001.md)
- **Rust Book:** https://doc.rust-lang.org/book/
- **Candle Docs:** https://docs.rs/candle-core
- **aya-rs Docs:** https://aya-rs.dev/

---

## Getting Help

- **GitHub Issues:** https://github.com/trydirect/stackdog/issues
- **Gitter:** https://gitter.im/stackdog/community
- **Email:** info@try.direct

---

*Last updated: 2026-03-13*
