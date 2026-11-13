# Day 2: Docker Integration

**Date:** 2026-03-16  
**Goal:** Connect to Docker API and list real containers  

---

## Morning: Docker Client Setup

### Tasks
- [x] Add bollard dependency
- [ ] Create Docker client wrapper
- [ ] Test Docker connection
- [ ] List containers

### Files to Create
```
src/docker/
├── mod.rs
├── client.rs              # Docker client wrapper
├── containers.rs          # Container operations
└── types.rs               # Type conversions
```

---

## Afternoon: Container Management

### Tasks
- [ ] Implement container listing
- [ ] Implement quarantine (disconnect network)
- [ ] Implement release (reconnect network)
- [ ] Cache container data in DB

---

## Success Criteria

- [ ] Can list real Docker containers
- [ ] Can get container details
- [ ] Quarantine actually disconnects network
- [ ] Release reconnects network
- [ ] All tests passing

---

*Plan created: 2026-03-16*
