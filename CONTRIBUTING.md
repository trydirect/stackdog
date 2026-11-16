# Contributing to Stackdog Security

Thank you for considering contributing to Stackdog Security! We welcome contributions from the community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE-OF-CONDUCT.md). By participating, you are expected to uphold this code.

---

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository
git clone https://github.com/YOUR_USERNAME/stackdog
cd stackdog

# Add upstream remote
git remote add upstream https://github.com/trydirect/stackdog
```

### 2. Setup Development Environment

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install system dependencies (Ubuntu/Debian)
apt-get install libsqlite3-dev libssl-dev clang llvm pkg-config

# Copy environment file
cp .env.sample .env
```

### 3. Build and Test

```bash
# Build the project
cargo build

# Run tests
cargo test --lib

# Run examples
cargo run --example usage_examples
```

---

## Development Workflow

### 1. Create a Branch

```bash
# Sync with upstream
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow the [TDD approach](#test-driven-development)
- Keep commits small and focused
- Write clear commit messages

### 3. Run Tests

```bash
# Run all tests
cargo test --lib

# Run specific module tests
cargo test --lib -- events::
cargo test --lib -- rules::

# Run with coverage (requires cargo-tarpaulin)
cargo tarpaulin --all --out Html
```

### 4. Check Code Quality

```bash
# Format code
cargo fmt --all

# Run clippy
cargo clippy --all

# Check for security issues
cargo audit
```

### 5. Commit Changes

```bash
git add .
git commit -m "feat: add your feature description"
```

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

---

## Pull Request Guidelines

### PR Title Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: fix bug in module
docs: update documentation
test: add tests for feature
refactor: refactor code
chore: update dependencies
```

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added
- [ ] Tests pass
- [ ] Code formatted

## Checklist
- [ ] Code follows project guidelines
- [ ] Self-review completed
- [ ] Comments added where needed
- [ ] Documentation updated
```

### Review Process

1. **Automated Checks** - CI/CD must pass
2. **Code Review** - At least 1 maintainer approval
3. **Testing** - All tests must pass
4. **Documentation** - Update docs if needed

---

## Coding Standards

### Rust Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Avoid `unwrap()` in production code
- Use descriptive variable names

### Example Code Structure

```rust
//! Module documentation
//!
//! Detailed description

use anyhow::Result;

/// Struct documentation
pub struct MyStruct {
    /// Field documentation
    field: String,
}

impl MyStruct {
    /// Create new instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            field: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_function() {
        // Test implementation
    }
}
```

### Error Handling

```rust
// Use anyhow for application code
use anyhow::{Result, Context};

pub fn my_function() -> Result<()> {
    some_operation()
        .context("Failed to perform operation")?;
    Ok(())
}

// Use thiserror for library errors
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MyError {
    #[error("Operation failed: {0}")]
    OperationFailed(String),
}
```

---

## Testing

### Test-Driven Development (TDD)

We follow TDD methodology:

1. **Write failing test**
2. **Run test** (verify failure)
3. **Implement minimal code** to pass
4. **Run test** (verify pass)
5. **Refactor** (keep tests green)

### Test Categories

| Type | Location | Command |
|------|----------|---------|
| Unit tests | In source files | `cargo test --lib` |
| Integration tests | `tests/` | `cargo test --test integration` |
| Examples | `examples/` | `cargo run --example` |
| Benchmarks | `benches/` | `cargo bench` |

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature_works() {
        // Arrange
        let input = create_test_input();
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value());
    }
}
```

---

## Documentation

### Code Documentation

- Document all public APIs with `///` comments
- Include examples for complex functions
- Keep comments up-to-date

### Example Documentation

```rust
/// Calculate threat score for event
///
/// # Arguments
///
/// * `event` - Security event to score
///
/// # Returns
///
/// * `ThreatScore` - Score between 0-100
///
/// # Example
///
/// ```
/// let scorer = ThreatScorer::new();
/// let score = scorer.calculate_score(&event);
/// ```
pub fn calculate_score(&self, event: &SecurityEvent) -> ThreatScore {
    // Implementation
}
```

### Documentation Files

Update relevant documentation:

- `README.md` - Main project overview
- `DEVELOPMENT.md` - Development guide
- `TESTING.md` - Testing guide
- `CHANGELOG.md` - Version changes

---

## Areas We Need Help

### High Priority

- 🚨 eBPF program implementation
- 🚨 ML anomaly detection
- 🚨 Web dashboard (React/TypeScript)

### Medium Priority

- 📝 Documentation improvements
- 🧪 More test coverage
- 🔧 Performance optimization

### Nice to Have

- 📊 Grafana dashboards
- 📦 Package builds (deb, rpm)
- 🌐 Translations

---

## Questions?

- **General questions:** [Gitter](https://gitter.im/stackdog/community)
- **Bug reports:** [GitHub Issues](https://github.com/trydirect/stackdog/issues)
- **Feature requests:** [GitHub Discussions](https://github.com/trydirect/stackdog/discussions)

---

## Thank You!

Every contribution, no matter how small, helps make Stackdog Security better.

🐕 **Happy Coding!**
