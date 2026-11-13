# Bugs - Stackdog Security

## Known Issues

### Critical

None currently tracked.

### High Priority

None currently tracked.

### Medium Priority

None currently tracked.

### Low Priority

None currently tracked.

---

## Bug Report Template

When reporting a bug, please use the following template:

```markdown
### Description
[Clear and concise description of the bug]

### Steps to Reproduce
1. [First step]
2. [Second step]
3. [and so on...]

### Expected Behavior
[What should happen]

### Actual Behavior
[What actually happens]

### Environment
- OS: [e.g., Ubuntu 22.04]
- Kernel: [e.g., 5.15.0]
- Rust version: [e.g., 1.75.0]
- Stackdog version: [e.g., 0.1.0]

### Logs
```
[Paste relevant logs here]
```

### Additional Context
[Any additional information]
```

---

## Resolved Bugs

### [0.1.0] - 2022-03-01

None currently resolved.

---

## Investigation Needed

### eBPF Compatibility

- **Issue:** eBPF requires kernel 4.19+ with BTF support
- **Impact:** May not work on older systems
- **Status:** Known limitation, documenting supported systems
- **Workaround:** Use fallback collectors (auditd) on older kernels

### ML Model Size

- **Issue:** Candle models may be large for embedded scenarios
- **Impact:** Memory usage on resource-constrained systems
- **Status:** Investigating model quantization
- **Workaround:** Use simpler rule-based detection initially

---

## Performance Issues

None currently tracked.

---

## Security Vulnerabilities

### Dependency Vulnerabilities

Track with `cargo audit`:

```bash
cargo audit
```

No known vulnerabilities in current dependencies.

---

## Reporting Security Issues

**IMPORTANT:** Do not report security vulnerabilities via public GitHub issues.

Please report security vulnerabilities to:
- **Email:** info@try.direct
- **GPG Key:** [Request via email]

### Security Report Template

```markdown
### Vulnerability Type
[e.g., Buffer overflow, SQL injection, etc.]

### Affected Component
[Module/function name]

### Impact
[What can an attacker do?]

### Steps to Reproduce
[Detailed reproduction steps]

### Suggested Fix
[If you have one]
```

---

## Bug Triage Process

1. **Report submitted** → Acknowledge within 48 hours
2. **Triage** → Assign severity and priority (within 1 week)
3. **Investigation** → Root cause analysis
4. **Fix development** → Implement and test fix
5. **Review** → Code review and security review
6. **Release** → Include in next patch release
7. **Disclosure** → Public disclosure after fix is available

---

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| **Critical** | System compromise, data loss | 24 hours |
| **High** | Significant functionality broken | 1 week |
| **Medium** | Minor functionality affected | 2 weeks |
| **Low** | Cosmetic, documentation | Next release |

---

## Testing for Regressions

When fixing bugs, ensure:

- [ ] Test case added for the bug
- [ ] All existing tests pass
- [ ] No performance regression
- [ ] Documentation updated (if needed)
- [ ] Changelog updated

---

## Contact

For bug-related questions:
- **GitHub Issues:** https://github.com/trydirect/stackdog/issues
- **Gitter:** https://gitter.im/stackdog/community
