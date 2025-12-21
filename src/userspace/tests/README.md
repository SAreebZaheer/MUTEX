# MUTEX Userspace Integration Tests

This directory contains userspace integration tests for the MUTEX kernel module. These tests validate the module's functionality from userspace by exercising syscalls, network operations, and end-to-end scenarios.

## Overview

These tests complement the kernel-space unit tests (Branch 22 testing framework) by providing:
- **System-level integration testing** - Tests across user/kernel boundary
- **Syscall interface validation** - Verifies syscall behavior and API contracts
- **Network functionality testing** - Real socket operations and protocol handling
- **End-to-end workflows** - Complete proxy scenarios from userspace perspective

## Test Files

### test_syscall.c
**Purpose:** MUTEX syscall interface validation  
**What it tests:**
- `mprox_create()` syscall functionality
- File descriptor creation and management
- Capability checks (CAP_NET_ADMIN requirement)
- Flag handling (CLOEXEC, NONBLOCK, GLOBAL)

**Usage:**
```bash
sudo ./test_syscall 0x0    # Basic proxy fd creation
sudo ./test_syscall 0x1    # With CLOEXEC flag
sudo ./test_syscall 0x3    # With CLOEXEC | NONBLOCK
```

**Requirements:** Root privileges (CAP_NET_ADMIN)

---

### test_config.c
**Purpose:** Proxy configuration interface testing  
**What it tests:**
- Multiple proxy server configuration
- Selection strategies (round-robin, failover, random)
- Configuration read/write via write() and ioctl()
- Configuration validation
- Statistics tracking

**Usage:**
```bash
sudo ./test_config
```

**Test scenarios:**
- Configure 3 proxy servers (SOCKS5, HTTP, HTTPS)
- Test round-robin selection strategy
- Verify configuration persistence
- Validate stats collection

**Requirements:** Root privileges, MUTEX module loaded

---

### test_ipv6.c
**Purpose:** IPv6 functionality validation  
**What it tests:**
- IPv6 socket creation (AF_INET6, SOCK_STREAM)
- Binding to IPv6 addresses
- IPv6 address parsing (inet_pton/inet_ntop)
- IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
- Link-local address detection (fe80::/10)
- Multicast address handling
- IPv6 loopback (::1)
- Connection tracking with IPv6
- Transparent proxy with IPv6

**Usage:**
```bash
sudo ./test_ipv6
```

**Test coverage:**
- ✅ Socket creation
- ✅ Address binding
- ✅ Address parsing/conversion
- ✅ IPv4-mapped detection
- ✅ Link-local detection
- ✅ Multicast detection
- ✅ Loopback detection
- ✅ Connection establishment
- ✅ Proxy redirection

**Requirements:** IPv6 enabled system, root privileges

---

### test_dns.c
**Purpose:** DNS handling and caching validation  
**What it tests:**
- DNS query parsing and header validation
- DNS cache operations (insert, lookup, eviction)
- TTL-based expiration
- Cache statistics tracking
- Domain name label parsing
- DNS response construction
- Hash collision handling
- Cache size limits

**Usage:**
```bash
./test_dns
```

**Test scenarios:**
- DNS header parsing (queries, responses)
- Cache CRUD operations
- TTL expiration logic
- Domain name validation
- Hash function distribution
- Cache size enforcement
- Statistics accuracy

**Requirements:** None (pure userspace testing with mocked kernel structures)

---

### test_routing.c
**Purpose:** Advanced routing and load balancing validation  
**What it tests:**
- Routing table management
- Load balancing algorithms:
  - Round-robin
  - Least connections
  - Weighted distribution
  - Random selection
  - Hash-based routing
  - Least latency
- Server health checking
- Failover mechanisms
- Route priority handling
- Connection distribution
- Latency tracking

**Usage:**
```bash
./test_routing
```

**Test coverage:**
- ✅ Round-robin algorithm
- ✅ Least connections algorithm
- ✅ Weighted load balancing
- ✅ Random distribution
- ✅ Hash-based routing
- ✅ Latency-based selection
- ✅ Server failover
- ✅ Health checks
- ✅ Statistics tracking

**Requirements:** None (pure userspace testing with mocked structures)

---

### test_module.sh
**Purpose:** Module lifecycle and integration testing  
**What it tests:**
- Module loading/unloading
- Module parameter configuration
- Sysfs/procfs interface validation
- Basic smoke tests
- Error handling

**Usage:**
```bash
sudo ./test_module.sh
```

**Test steps:**
1. Load MUTEX module
2. Verify module parameters
3. Check procfs entries
4. Run basic functionality tests
5. Unload module cleanly

**Requirements:** Root privileges, module not already loaded

---

## Building the Tests

### Build All Tests
```bash
cd /home/areeb/MUTEX/src/userspace/tests
make all
```

### Build Individual Tests
```bash
gcc -o test_syscall test_syscall.c
gcc -o test_config test_config.c
gcc -o test_ipv6 test_ipv6.c
gcc -o test_dns test_dns.c -lm
gcc -o test_routing test_routing.c
```

### Compiler Flags
```bash
CFLAGS = -Wall -Wextra -O2 -std=gnu11
LDFLAGS = -lm  # For DNS and routing tests
```

## Running the Test Suite

### Prerequisites
1. **Kernel Module Loaded:**
   ```bash
   sudo insmod /home/areeb/MUTEX/src/module/build/mutex_proxy.ko
   ```

2. **Root Privileges:**
   Most tests require `sudo` due to syscall restrictions and network operations.

3. **System Configuration:**
   - IPv6 enabled: `sysctl net.ipv6.conf.all.disable_ipv6=0`
   - Sufficient file descriptors: `ulimit -n 4096`

### Run All Tests
```bash
sudo ./test_module.sh      # Module lifecycle
sudo ./test_syscall 0      # Syscall interface
sudo ./test_config         # Configuration API
sudo ./test_ipv6           # IPv6 functionality
./test_dns                 # DNS caching
./test_routing             # Routing algorithms
```

### Expected Results
Each test prints:
- ✅ `[PASS]` for successful tests
- ❌ `[FAIL]` for failed tests
- Summary statistics at the end

## Integration with CI/CD

These tests are designed to be integrated into automated testing pipelines:

### GitHub Actions Example
```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Build kernel module
        run: cd src/module && make

      - name: Load module
        run: sudo insmod src/module/build/mutex_proxy.ko

      - name: Build tests
        run: cd src/userspace/tests && make all

      - name: Run integration tests
        run: |
          cd src/userspace/tests
          sudo ./test_module.sh
          sudo ./test_syscall 0
          sudo ./test_config
          sudo ./test_ipv6
          ./test_dns
          ./test_routing

      - name: Unload module
        run: sudo rmmod mutex_proxy
```

## Relationship to Kernel Tests (Branch 22)

| Test Type | Location | Purpose | Scope |
|-----------|----------|---------|-------|
| **Unit Tests** | `src/module/mutex_testing.c` | Module-level testing | Individual functions, kernel-space |
| **Integration Tests** | `src/userspace/tests/` (this dir) | System-level testing | Syscalls, network, end-to-end |

### Testing Pyramid
```
                    /\
                   /  \     E2E Tests (test_module.sh)
                  /____\
                 /      \   Integration Tests (these files)
                /________\
               /          \  Unit Tests (Branch 22 framework)
              /____________\
```

### Test Coverage Strategy

1. **Kernel Unit Tests** (Branch 22) cover:
   - Individual module functions
   - Internal data structures
   - Edge cases and error paths
   - Performance benchmarks
   - Mock-based testing

2. **Userspace Integration Tests** (this directory) cover:
   - Syscall interfaces
   - User/kernel boundary crossing
   - Real network operations
   - Configuration persistence
   - Multi-component workflows

## Debugging Failed Tests

### Enable Debug Logging
```bash
# Kernel module debug logs
sudo dmesg -w &
sudo insmod mutex_proxy.ko debug=1

# Test program debug output
export MUTEX_DEBUG=1
sudo ./test_syscall 0
```

### Common Issues

**Problem:** `mprox_create: Function not implemented`  
**Solution:** Syscall not registered; check kernel module loaded and syscall table updated

**Problem:** `Permission denied`  
**Solution:** Tests require root privileges; run with `sudo`

**Problem:** `Module not found`  
**Solution:** Load MUTEX module: `sudo insmod src/module/build/mutex_proxy.ko`

**Problem:** IPv6 tests fail  
**Solution:** Enable IPv6: `sudo sysctl net.ipv6.conf.all.disable_ipv6=0`

## Test Results Interpretation

### test_syscall
- **Expected:** File descriptor >= 3, successful creation
- **Checks:** Capability enforcement, flag handling

### test_config
- **Expected:** All configuration operations succeed
- **Checks:** Multi-server config, strategy selection, persistence

### test_ipv6
- **Expected:** 9/9 tests pass (all IPv6 operations)
- **Checks:** Socket ops, address parsing, special addresses

### test_dns
- **Expected:** 15-20 tests pass (DNS operations)
- **Checks:** Parsing, caching, TTL, statistics

### test_routing
- **Expected:** 12-15 tests pass (routing algorithms)
- **Checks:** Load balancing, failover, latency tracking

## Adding New Tests

To add a new integration test:

1. **Create test file:** `test_<feature>.c`
2. **Include headers:**
   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include "../../linux/include/uapi/linux/mutex_proxy.h"
   ```
3. **Implement tests:**
   ```c
   #define TEST_PASS 0
   #define TEST_FAIL 1

   static int test_my_feature(void) {
       // Test implementation
       return TEST_PASS;
   }
   ```
4. **Add to Makefile:** (if you create one)
5. **Document in this README**

## Test Maintenance

- **Update tests** when kernel APIs change
- **Add tests** for new features
- **Keep synchronized** with kernel module versions
- **Document breaking changes** in commit messages

## Performance Benchmarks

Some tests include performance measurements:

| Test | Metric | Target | Notes |
|------|--------|--------|-------|
| test_dns | Cache lookup | < 1µs | Average lookup time |
| test_routing | Route selection | < 10µs | Algorithm overhead |
| test_config | Config update | < 100µs | Write + validation |

## Security Considerations

- All syscall tests require **CAP_NET_ADMIN**
- Tests create **real network sockets** (be cautious on production)
- DNS tests do **NOT** send external queries (local only)
- Routing tests use **mock structures** (no real traffic)

## Contributing

When adding or modifying tests:
1. Follow existing test structure and naming
2. Include test purpose documentation
3. Add usage examples
4. Update this README
5. Ensure tests clean up resources
6. Handle both success and failure cases

## License

SPDX-License-Identifier: GPL-2.0

Copyright (C) 2025 MUTEX Team  
Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

---

**Last Updated:** December 21, 2025  
**MUTEX Version:** Branch 22 (Testing Framework)  
**Test Coverage:** System-level integration tests complementing kernel unit tests
