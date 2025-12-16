# Precedence Diagramming Method (PDM) - MUTEX Project

## Overview

This document outlines the Precedence Diagramming Method (PDM) for the MUTEX kernel-level proxy module project. PDM is a critical path method used to schedule project activities by representing dependencies between tasks using nodes (activities) and arrows (dependencies).

---

## PDM Fundamentals

### Dependency Types Used:
- **Finish-to-Start (FS):** Successor activity cannot start until predecessor finishes (most common)
- **Start-to-Start (SS):** Successor can start when predecessor starts (parallel work)
- **Finish-to-Finish (FF):** Successor cannot finish until predecessor finishes

### Key Metrics:
- **ES (Early Start):** Earliest time an activity can begin
- **EF (Early Finish):** Earliest time an activity can complete (ES + Duration)
- **LS (Late Start):** Latest time an activity can start without delaying project
- **LF (Late Finish):** Latest time an activity can finish without delaying project
- **Float/Slack:** LF - EF (or LS - ES); amount of time an activity can be delayed

---

## Dependency Table

| Branch ID | Branch Name | Immediate Predecessors | Dependency Type | Duration (weeks) | Float |
|-----------|-------------|----------------------|-----------------|------------------|-------|
| B1 | basic-module-structure | - | - | 1 | 0 |
| B2 | syscall-and-fd-operations | B1 | FS | 2.5 | 0 |
| B3 | userspace-interface | B2 | FS | 2 | 4 |
| B4 | netfilter-hooks | B2 | FS | 2 | 0 |
| B5 | proxy-configuration | B2 | FS | 1.5 | 2 |
| B6 | connection-tracking | B4, B5 | FS | 2 | 0 |
| B7 | packet-rewriting | B4, B6 | FS | 2.5 | 0 |
| B8 | socks-protocol | B6, B7 | FS | 2 | 0 |
| B9 | http-proxy-support | B6, B7 | FS | 2 | 0 |
| B10 | transparent-proxying | B7, B8 | FS | 3 | 0 |
| B11 | process-filtering | B4, B5 | FS | 1.5 | 3 |
| B12 | protocol-detection | B4, B7 | FS | 2 | 1 |
| B13 | performance-optimization | B7, B8, B10 | FS | 3 | 0 |
| B14 | security-hardening | B7, B8, B10 | FS | 2.5 | 0 |
| B15 | ipv6-support | B7, B6 | FS | 2 | 1 |
| B16 | advanced-routing | B5, B6 | FS | 2 | 2 |
| B17 | dns-handling | B10, B7 | FS | 2.5 | 0 |
| B18 | statistics-monitoring | B6 | FS | 1.5 | 4 |
| B19 | error-recovery | B13, B14, B17 | FS | 2 | 0 |
| B20 | configuration-file | B3, B5 | FS | 1.5 | 5 |
| B21 | logging-framework | B1 | FS | 1 | 6 |
| B22 | testing-framework | B19 | FS | 3 | 0 |
| B23 | documentation | B22 | SS | 4 | 0 |
| B24 | packaging | B22 | FS | 2 | 0 |
| B25 | integration-fixes | B22, B23, B24 | FS | 2 | 0 |

---

## Network Diagram Description

### Phase 1: Foundation (Weeks 1-3.5)
```
[B1: Module Structure]
         |
         v
[B2: mprox_create() syscall → returns fd]
         |    (anon inode + file_operations)
         +------------+-------------+
         |            |             |
         v            v             v
   [B3: FD-based] [B4: Netfilter] [B5: Proxy Config]
   [API library]                  [per-fd via write()]
                     |
                     +------+------+
                            v
                   [B6: Connection Tracking]
```

### Phase 2: Core Networking (Weeks 4-8)
```
          [B4] [B6]
              \ /
               v
        [B7: Packet Rewriting]
               |
         +-----+-----+
         |           |
         v           v
   [B8: SOCKS]  [B9: HTTP Proxy]
         |
         v
   [B10: Transparent Proxy]
```

### Phase 3: Advanced Features (Weeks 9-14)
```
[B10] [B8] [B7]
   |    |    |
   +----+----+
        |
   +----+----+
   |         |
   v         v
[B13: Perf] [B14: Security]
   |         |
   +----+----+
        |
        v
  [B17: DNS] [B15: IPv6] [B16: Routing] [B11: Filtering] [B12: Detection]
        |
        v
  [B19: Error Recovery]
```

### Phase 4: Quality & Release (Weeks 15-22)
```
      [B19]
        |
        v
  [B22: Testing]
        |
   +----+----+
   |    |    |
   v    v    v
[B23] [B24] [B18: Stats]
 Doc  Pkg
   |    |
   +----+
     |
     v
[B25: Integration Fixes]
```

---

## Critical Path Analysis

### Critical Path:
**B1 → B2 → B4 → B6 → B7 → B8 → B10 → B13 → B14 → B17 → B19 → B22 → B25**

**Total Duration: 31.5 weeks** (~8 months)

### Critical Path Activities:
1. **B1** - basic-module-structure (1 week)
2. **B2** - syscall-and-fd-operations (2.5 weeks) - `mprox_create()` syscall returns fd with file_operations
3. **B4** - netfilter-hooks (2 weeks)
4. **B6** - connection-tracking (2 weeks)
5. **B7** - packet-rewriting (2.5 weeks)
6. **B8** - socks-protocol (2 weeks)
7. **B10** - transparent-proxying (3 weeks)
8. **B13** - performance-optimization (3 weeks)
9. **B14** - security-hardening (2.5 weeks)
10. **B17** - dns-handling (2.5 weeks)
11. **B19** - error-recovery (2 weeks)
12. **B22** - testing-framework (3 weeks)
13. **B25** - integration-fixes (2 weeks)

### Non-Critical Activities with Float:
- **B3** - userspace-interface (4 weeks float)
- **B5** - proxy-configuration (2 weeks float)
- **B11** - process-filtering (3 weeks float)
- **B12** - protocol-detection (1 week float)
- **B15** - ipv6-support (1 week float)
- **B16** - advanced-routing (2 weeks float)
- **B18** - statistics-monitoring (4 weeks float)
- **B20** - configuration-file (5 weeks float)
- **B21** - logging-framework (6 weeks float)

---

## Detailed Dependency Analysis

### Level 0 (Start):
- **B1** - No dependencies, must start first

### Level 1 (Depends on B1):
- **B2** - Requires basic module structure to implement syscall and fd operations
- **B21** - Can start early but has large float

### Level 2 (Depends on B2):
- **B3** - Userspace interface (wrapper for syscall, fd-based API)
- **B4** - Netfilter hooks (CRITICAL)
- **B5** - Proxy configuration (per-fd via write() operations)

### Level 3 (Depends on B4 and/or B5):
- **B6** - Requires both B4 and B5 (CRITICAL)
- **B11** - Process filtering (requires B4, B5)

### Level 4 (Depends on B6):
- **B7** - Packet rewriting (requires B4, B6) (CRITICAL)
- **B18** - Statistics monitoring (requires B6)

### Level 5 (Depends on B7):
- **B8** - SOCKS protocol (requires B6, B7) (CRITICAL)
- **B9** - HTTP proxy (requires B6, B7)
- **B12** - Protocol detection (requires B4, B7)
- **B15** - IPv6 support (requires B6, B7)
- **B16** - Advanced routing (requires B5, B6)

### Level 6 (Depends on B8):
- **B10** - Transparent proxying (requires B7, B8) (CRITICAL)

### Level 7 (Depends on B10):
- **B13** - Performance optimization (requires B7, B8, B10) (CRITICAL)
- **B14** - Security hardening (requires B7, B8, B10) (CRITICAL)
- **B17** - DNS handling (requires B7, B10) (CRITICAL)

### Level 8 (Depends on B13, B14, B17):
- **B19** - Error recovery (CRITICAL)

### Level 9 (Depends on B19):
- **B22** - Testing framework (CRITICAL)

### Level 10 (Depends on B22):
- **B23** - Documentation (Start-to-Start with B22)
- **B24** - Packaging (CRITICAL)

### Level 11 (Final):
- **B25** - Integration fixes (requires B22, B23, B24) (CRITICAL)

### Independent Branches (can be done in parallel):
- **B20** - Configuration file (depends on B3, B5 but has 5 weeks float)
- **B21** - Logging framework (depends only on B1 but has 6 weeks float)

---

## Parallel Execution Opportunities

### Week 1:
- **B1** (Full team focus)

### Weeks 2-4 (mid):
- **B2** (Critical path - priority team: syscall implementation + anon inode + file_operations)

### Weeks 4-5:
- **B4** (Critical - Team A)
- **B3** (Team B)
- **B5** (Team C)
- **B21** (Can start, Team D)

### Weeks 6-7:
- **B6** (Critical - Team A)
- **B11** (Team B)

### Weeks 8-10:
- **B7** (Critical - Team A)
- **B18** (Team B)

### Weeks 11-12:
- **B8** (Critical - Team A)
- **B9** (Team B)
- **B12** (Team C)
- **B15** (Team D)

### Weeks 13-15:
- **B10** (Critical - Team A)
- **B16** (Team B)
- **B20** (Team C)

### Weeks 16-18:
- **B13** (Critical - Team A)
- **B14** (Team A, overlapping end)

### Weeks 19-21:
- **B17** (Critical - Team A)
- **B14** (Team A, parallel completion)

### Weeks 22-23:
- **B19** (Critical - Full team)

### Weeks 24-26:
- **B22** (Critical - Testing team)
- **B23** (Documentation team - starts with B22)

### Weeks 27-28:
- **B22** (continues)
- **B23** (continues)
- **B24** (Packaging team)

### Weeks 29-30:
- **B23** (finishes)
- **B24** (finishes)

### Weeks 31:
- **B25** (Full team - final integration)

---

## Resource Allocation Recommendations

### Critical Path Resources:
- Assign most experienced developers to critical path tasks
- Ensure critical tasks have backup resources
- Monitor critical path tasks daily
- Minimize context switching for critical path team members

### Non-Critical Resources:
- Junior developers can work on tasks with float
- These tasks can absorb resource fluctuations
- Good training opportunities on non-critical tasks
- Can be delayed if critical path needs support

### Recommended Team Structure:
```
Team A (Critical Path Team - 3 senior developers):
- Focus on B1, B2, B4, B6, B7, B8, B10, B13, B14, B17, B19

Team B (Parallel Features - 2 mid-level developers):
- Focus on B3, B5, B11, B18, B16

Team C (Advanced Features - 2 developers):
- Focus on B9, B12, B15, B20

Team D (Support - 1-2 developers):
- Focus on B21, documentation support, testing support

Testing Team (2-3 QA engineers):
- Begin integration testing from Week 10
- Full focus on B22, B25

Documentation Team (1-2 technical writers):
- Continuous documentation (B23)
- Start from Week 24
```

---

## Risk Management

### High-Risk Critical Path Items:
1. **B7 (Packet Rewriting):** Complex kernel networking, high risk of bugs
   - Mitigation: Extensive unit testing, code reviews, senior developer assignment

2. **B10 (Transparent Proxying):** Requires deep kernel knowledge
   - Mitigation: Research phase, prototype testing, expert consultation

3. **B13 (Performance Optimization):** May require architecture changes
   - Mitigation: Early performance baseline, continuous profiling

4. **B22 (Testing Framework):** Delayed testing means late bug discovery
   - Mitigation: Parallel testing throughout development

### Schedule Risks:
- **Critical path has 0 float** - any delay impacts final delivery
- **Dependencies create bottlenecks** - B6 blocks multiple branches
- **Testing phase is late** - consider continuous integration testing

### Mitigation Strategies:
1. **Fast-track critical reviews:** Prioritize code reviews for critical path
2. **Parallel prototyping:** Start research for complex tasks early
3. **Continuous integration:** Test incrementally, don't wait for B22
4. **Buffer time:** Add 10-15% contingency to critical estimates
5. **Weekly checkpoints:** Track progress on critical path weekly

---

## Optimization Strategies

### Fast-Tracking (Parallel Execution):
- **B8 and B9** can be done simultaneously (both need B6, B7)
- **B13 and B14** can overlap significantly
- **B23 can start earlier** (Start-to-Start with B22)

### Crashing (Add Resources):
Priority tasks to crash if schedule is tight:
1. **B7** - Add developer to reduce from 2.5 to 2 weeks
2. **B10** - Critical 3-week task, add resources to reduce to 2 weeks
3. **B13** - Performance optimization, can parallelize some work

### Schedule Compression:
If 31 weeks is too long, compress to ~24 weeks by:
1. Crash B7 (save 0.5 weeks)
2. Crash B10 (save 1 week)
3. Crash B13 (save 1 week)
4. Parallel B14 with B13 (save 1 week)
5. Crash B22 (save 1 week)
6. Reduce B25 scope (save 0.5 weeks)
7. Overlap B23 more aggressively (save 1 week)

**Compressed Critical Path: ~25 weeks**

---

## Milestones and Gates

### Milestone 1: Foundation Complete (Week 3.5)
- **Gates:** B1, B2 complete
- **Deliverable:** Module loads, `mprox_create()` syscall implemented and returns valid fd
- **Go/No-Go:** Can userspace call syscall, receive fd, perform read/write/ioctl/poll operations on fd?

### Milestone 2: Core Networking (Week 10)
- **Gates:** B4, B6, B7 complete
- **Deliverable:** Packets can be intercepted and modified
- **Go/No-Go:** Can we rewrite and forward packets?

### Milestone 3: Proxy Protocols (Week 15)
- **Gates:** B8, B9, B10 complete
- **Deliverable:** Basic proxy functionality working
- **Go/No-Go:** Can we proxy HTTP/HTTPS traffic?

### Milestone 4: Production Ready (Week 23)
- **Gates:** B13, B14, B17, B19 complete
- **Deliverable:** Secure, performant, robust system
- **Go/No-Go:** Is system ready for testing?

### Milestone 5: Release Candidate (Week 28)
- **Gates:** B22, B23, B24 complete
- **Deliverable:** Tested, documented, packaged
- **Go/No-Go:** Ready for release?

### Milestone 6: Version 1.0 (Week 31)
- **Gates:** B25 complete
- **Deliverable:** Production release
- **Success Criteria:** All tests pass, documentation complete, packages available

---

## Gantt Chart Overview

```
Week:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
───────────────────────────────────────────────────────────────────────────────────────────────────
B1:  [█]
B2:     [███]
B21:       [█]─────────────────────────── (can be delayed)
B3:        [███]──────
B4:        [███]
B5:        [██]────
B6:           [███]
B11:             [██]──────
B18:             [██]─────────────
B7:              [████]
B12:                [███]──
B9:                 [███]
B15:                [███]──
B16:                [███]────
B8:                 [███]
B20:                   [██]────────────
B10:                    [█████]
B13:                         [█████]
B14:                         [████]
B17:                              [████]
B19:                                  [███]
B22:                                     [█████]
B23:                                     [███████]
B24:                                         [███]
B25:                                            [███]

Legend:
█ = Critical Path (no float)
─ = Non-critical (has float, can be delayed)
```

---

## Summary Statistics

- **Total Project Duration:** 31.5 weeks (~8 months)
- **Critical Path Length:** 31.5 weeks
- **Number of Critical Activities:** 13
- **Number of Non-Critical Activities:** 12
- **Maximum Float:** 6 weeks (B21 - logging-framework)
- **Average Activity Duration:** 2.1 weeks
- **Longest Activity:** B10 (transparent-proxying) - 3 weeks
- **Shortest Activity:** B1 (basic-module-structure) - 1 week
- **Key Technical Challenge:** B2 (syscall-and-fd-operations) - 2.5 weeks

### API Design (B2 Critical Component):
```c
// Syscall (similar to eventfd, timerfd)
int mprox_create(unsigned int flags);

// File operations on returned fd
ssize_t read(int fd, void *buf, size_t count);   // Read status/stats
ssize_t write(int fd, const void *buf, size_t count); // Write config
int ioctl(int fd, unsigned long request, ...);    // Control operations
int poll(int fd, struct pollfd *fds, nfds_t nfds); // Event notification
int close(int fd);                                 // Cleanup
```

### Effort Distribution:
- **Foundation & Infrastructure:** 15% (B1, B2, B3, B21)
- **Core Networking:** 35% (B4, B5, B6, B7, B8, B9, B10)
- **Advanced Features:** 25% (B11-B17)
- **Reliability & Quality:** 15% (B18, B19, B22)
- **Documentation & Release:** 10% (B23, B24, B25)

---

## Conclusion

The PDM analysis reveals a **31.5-week critical path** with significant dependencies in the networking core (B4-B10). The file descriptor-based approach follows the "everything is a file" paradigm, making the system truly Unix-like and maintainable.

### Architecture Summary:
- **Single syscall:** `int mprox_create(unsigned int flags)` returns fd (like `eventfd()`, `timerfd()`, `signalfd()`)
- **All operations via fd:** read(), write(), ioctl(), poll(), close()
- **Per-fd state:** Each fd has independent proxy configuration
- **Standard semantics:** Supports dup(), fork() inheritance, SCM_RIGHTS passing

Key success factors include:

1. **Protect the critical path** - Any delay cascades to final delivery
2. **Leverage parallelism** - 12 tasks have float and can absorb delays
3. **Early testing** - Don't wait until Week 24 to start testing
4. **Resource allocation** - Assign best developers to critical path
5. **Risk management** - Focus on B2 (syscall+fd implementation), B7 (packet rewriting), B10 (transparent proxy), B13 (performance)
6. **File descriptor paradigm** - Ensures consistent, clean API through standard file operations
7. **Anonymous inode implementation** - Similar to eventfd, requires deep kernel knowledge

With proper resource allocation and risk management, the project can deliver a production-ready kernel module with a clean, Unix-like file descriptor interface in approximately **8 months**.

---

*Document Version: 1.0*  
*Last Updated: December 14, 2025*  
*Project: MUTEX - Multi-User Threaded Exchange Xfer*
