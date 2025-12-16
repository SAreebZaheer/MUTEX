# MUTEX Project - Development Branch Plan

## Project Overview
Building a loadable kernel module (LKM) for Linux that provides a system call to create a kernel-level proxy service. This proxy will hook into the network stack and route all packets through a proxy server, eliminating the need for user-level proxying typically required by VPNs and proxy services.

---

## Branch Structure and Development Roadmap

### 1. `feature/basic-module-structure`
**Description:** Set up the foundational loadable kernel module infrastructure
- Create basic LKM skeleton with init and exit functions
- Implement proper module metadata (MODULE_LICENSE, MODULE_AUTHOR, MODULE_DESCRIPTION)
- Set up Makefile for building the kernel module
- Test module loading/unloading with `insmod`/`rmmod`
- Add proper kernel logging with `printk`
- Implement basic error handling
- Create initial documentation structure
- Design file descriptor-based architecture overview

**Dependencies:** None  
**Testing:** Module loads and unloads cleanly without kernel panics

---

### 2. `feature/syscall-and-fd-operations`
**Description:** Implement single system call that returns file descriptor for proxy control
- Add new system call in the linux kernel.
- Create `mprox_create()` syscall that returns a file descriptor
- Implement anonymous inode-based file operations (similar to eventfd, timerfd, signalfd)
- Define file operations structure (open, read, write, ioctl, poll, release)
- Design ioctl command structure for all proxy operations
- Add permission checks (CAP_NET_ADMIN) in syscall before fd creation
- Handle architecture-specific considerations (x86_64, ARM, etc.)
- Implement per-fd private data structure for proxy state
- Implement cleanup on fd close and module unload
- Handle fd inheritance across fork/exec properly

**Dependencies:** `feature/basic-module-structure`  
**Testing:** Syscall returns valid fd, file operations work, fd can be closed cleanly

---

### 3. `feature/userspace-interface`
**Description:** Create userspace library/tools to interact with the proxy via file descriptor
- Create C library wrapper for `mprox_create()` syscall
- Design high-level API around returned file descriptor
- Implement helper functions for common ioctl commands (set proxy, enable/disable, get status)
- Implement configuration through write() operations (structured format)
- Support status queries through read() operations (JSON/binary format)
- Support poll/select/epoll for event notifications
- Develop command-line utility for proxy management using the fd API
- Add proper error handling and errno mapping
- Create example programs demonstrating fd-based workflow
- Write comprehensive API documentation
- Support multiple concurrent file descriptors in same process

**Dependencies:** `feature/syscall-and-fd-operations`  
**Testing:** Programs can call syscall, get fd, perform operations, close fd successfully

---

### 4. `feature/netfilter-hooks`
**Description:** Implement Netfilter hooks for packet interception
- Register Netfilter hooks at appropriate points (NF_INET_PRE_ROUTING, NF_INET_POST_ROUTING, NF_INET_LOCAL_OUT)
- Implement hook handler functions
- Add packet inspection logic based on per-fd proxy configurations
- Implement filtering based on configured rules
- Handle different protocols (TCP, UDP, ICMP)
- Add hook priority management
- Link packets to owning process and its proxy fd(s)
- Implement hook registration/unregistration on proxy enable/disable via ioctl
- Support multiple active proxy fds with different configurations

**Dependencies:** `feature/syscall-and-fd-operations`  
**Testing:** Hooks successfully intercept packets without dropping legitimate traffic

---

### 5. `feature/proxy-configuration`
**Description:** Implement proxy server configuration and management
- Design data structures for proxy configuration (server address, port, protocol)
- Store configuration in per-fd private data structure
- Add proxy server validation
- Implement configuration update via write() operations with structured format (JSON/binary)
- Implement alternative ioctl-based configuration for atomic updates
- Add support for multiple proxy servers per fd
- Implement proxy selection logic (round-robin, failover, etc.)
- Expose configuration via read() operations
- Create /proc or /sys interface for global read-only status
- Implement read/write locking for thread-safety on per-fd data
- Support both text and binary configuration formats
- Allow fd to be passed between processes (SCM_RIGHTS) with configuration intact

**Dependencies:** `feature/syscall-and-fd-operations`  
**Testing:** Proxy configurations can be written to fd, retrieved from fd correctly

---

### 6. `feature/connection-tracking`
**Description:** Implement connection state tracking for proxied connections
- Design connection tracking data structures
- Implement connection table (hash table or similar)
- Track original destination addresses
- Map connections to proxy connections
- Implement connection lifecycle management
- Add garbage collection for stale connections
- Implement connection lookup optimization
- Handle connection timeouts

**Dependencies:** `feature/netfilter-hooks`, `feature/proxy-configuration`  
**Testing:** Connections are properly tracked and can be mapped bidirectionally

---

### 7. `feature/packet-rewriting`
**Description:** Implement packet modification for proxy routing
- Implement IP header modification (source/destination address changes)
- Handle TCP header modifications (ports, sequence numbers)
- Implement UDP header modifications
- Calculate and update checksums (IP, TCP, UDP)
- Handle fragmented packets
- Implement packet cloning for inspection
- Add packet validation before/after modification
- Handle MTU considerations

**Dependencies:** `feature/netfilter-hooks`, `feature/connection-tracking`  
**Testing:** Packets are correctly rewritten and checksums are valid

---

### 8. `feature/socks-protocol`
**Description:** Implement SOCKS protocol support (SOCKS4/SOCKS5)
- Implement SOCKS5 handshake in kernel space
- Handle SOCKS authentication methods
- Implement connection establishment via SOCKS
- Add support for SOCKS4 (optional)
- Handle SOCKS error responses
- Implement protocol state machine
- Add UDP association support (SOCKS5)
- Handle DNS resolution through proxy

**Dependencies:** `feature/packet-rewriting`, `feature/connection-tracking`  
**Testing:** Successful SOCKS handshake and data transfer through SOCKS proxy

---

### 9. `feature/http-proxy-support`
**Description:** Implement HTTP/HTTPS proxy support (CONNECT method)
- Implement HTTP CONNECT tunnel establishment
- Handle HTTP proxy authentication
- Parse HTTP headers in kernel space
- Implement CONNECT request generation
- Handle proxy responses and errors
- Support HTTPS tunneling
- Implement keep-alive connections
- Add proxy authentication caching

**Dependencies:** `feature/packet-rewriting`, `feature/connection-tracking`  
**Testing:** HTTP/HTTPS traffic successfully proxied using CONNECT method

---

### 10. `feature/transparent-proxying`
**Description:** Implement transparent proxy mode (no application changes needed)
- Implement transparent socket interception for processes with active proxy fd
- Handle DNS requests through proxy based on fd configuration
- Implement UDP proxying for DNS
- Add NAT-like translation for return traffic
- Handle local vs. remote address detection
- Implement bypass rules for local traffic (configurable via fd)
- Add support for proxy auto-configuration via fd settings
- Handle applications that bind to specific interfaces
- Support "global" mode where fd affects all system traffic vs "scoped" mode for specific processes
- Allow LD_PRELOAD-based library to auto-create fd for legacy apps

**Dependencies:** `feature/packet-rewriting`, `feature/connection-tracking`, `feature/socks-protocol`  
**Testing:** Applications work without modification when process holds active proxy fd

---

### 11. `feature/process-filtering`
**Description:** Implement per-process proxy rules via file descriptor ownership
- Track process information (PID, UID, GID) associated with each fd at creation time
- Implement process-based filtering rules configured via ioctl/write on fd
- Add cgroup integration for process groups
- Implement process whitelist/blacklist configurable via write() to fd
- Handle process hierarchy (parent/child relationships)
- Add executable path-based filtering
- Implement dynamic rule updates through fd file operations
- Handle short-lived processes efficiently
- Support fd inheritance across fork/exec (proxy applies to child processes)
- Allow fd to specify "current process only" vs "process tree" scope
- Support fd passing via Unix domain sockets with proper credential tracking

**Dependencies:** `feature/netfilter-hooks`, `feature/proxy-configuration`  
**Testing:** Specific processes with open fds are proxied while others use direct connection

---

### 12. `feature/protocol-detection`
**Description:** Implement intelligent protocol detection and routing
- Implement deep packet inspection for protocol detection
- Add heuristics for identifying protocols
- Support protocol-specific routing rules
- Handle encrypted traffic identification
- Implement fallback mechanisms
- Add SNI (Server Name Indication) parsing for HTTPS
- Handle multi-protocol connections
- Optimize detection for performance

**Dependencies:** `feature/netfilter-hooks`, `feature/packet-rewriting`  
**Testing:** Different protocols are correctly identified and routed

---

### 13. `feature/performance-optimization`
**Description:** Optimize module for high-throughput scenarios
- Implement per-CPU data structures
- Add RCU (Read-Copy-Update) for lock-free reads
- Optimize hash table lookups
- Implement connection pooling
- Add zero-copy packet handling where possible
- Optimize memory allocation (slab caches)
- Profile and optimize hot paths
- Implement lockless algorithms where applicable
- Add packet batching support

**Dependencies:** All core features  
**Testing:** Measure throughput and latency improvements with benchmarking tools

---

### 14. `feature/security-hardening`
**Description:** Implement security features and hardening
- Add input validation and sanitization
- Implement buffer overflow protections
- Add rate limiting to prevent DoS
- Implement capability checks (CAP_NET_ADMIN, CAP_NET_RAW)
- Add seccomp/SELinux policy support
- Implement audit logging for security events
- Add crypto verification for proxy certificates
- Handle race conditions and TOCTOU issues
- Implement memory wiping for sensitive data

**Dependencies:** All core features  
**Testing:** Security audit and penetration testing

---

### 15. `feature/ipv6-support`
**Description:** Add full IPv6 support
- Implement IPv6 header parsing
- Handle IPv6 extension headers
- Implement IPv6 checksum calculations
- Add IPv6 address translation
- Support dual-stack (IPv4/IPv6) scenarios
- Handle IPv6 fragmentation
- Implement ICMPv6 handling
- Add IPv6-specific proxy protocols

**Dependencies:** `feature/packet-rewriting`, `feature/connection-tracking`  
**Testing:** IPv6 traffic successfully proxied alongside IPv4

---

### 16. `feature/advanced-routing`
**Description:** Implement advanced routing and policy-based routing
- Add multiple routing tables support
- Implement policy-based routing rules
- Support source routing
- Add failover between multiple proxies
- Implement load balancing
- Add geographic routing (GeoIP-based)
- Support routing based on packet characteristics
- Implement routing cache

**Dependencies:** `feature/proxy-configuration`, `feature/connection-tracking`  
**Testing:** Traffic is correctly distributed according to routing policies

---

### 17. `feature/dns-handling`
**Description:** Implement intelligent DNS handling and proxying
- Implement DNS request interception for processes with active proxy fd
- Add per-fd DNS caching in kernel space
- Support DNS over proxy (SOCKS DNS) configurable via fd
- Implement DNS leak prevention based on fd settings
- Add custom DNS server configuration per fd
- Support DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) via fd config
- Implement DNS response validation
- Handle split-horizon DNS with per-fd DNS rules
- Allow DNS bypass for specific domains via fd write() operation
- Support DNS query logging readable via fd

**Dependencies:** `feature/transparent-proxying`, `feature/packet-rewriting`  
**Testing:** DNS queries from processes with proxy fd are correctly proxied and cached

---

### 18. `feature/statistics-monitoring`
**Description:** Add statistics collection and monitoring
- Implement per-connection statistics tracked by owning fd
- Add per-fd aggregate statistics (bandwidth, packet counts)
- Expose per-fd statistics via read() operations on the fd
- Create procfs/sysfs interface for global statistics
- Implement statistics export to userspace via ioctl
- Add real-time monitoring support via poll/select on fd (becomes readable when stats update)
- Implement statistics persistence across fd lifecycle
- Add alerts/notifications for anomalies (available via read() on fd)
- Create dashboard-compatible output format (JSON from read())
- Support statistics aggregation across multiple fds

**Dependencies:** `feature/connection-tracking`  
**Testing:** Statistics are accurate and accessible via fd read operations

---

### 19. `feature/error-recovery`
**Description:** Implement robust error handling and recovery
- Add connection recovery mechanisms
- Implement automatic proxy failover
- Handle network interruptions gracefully
- Add packet retransmission logic
- Implement state recovery after errors
- Add logging for debugging
- Handle kernel memory pressure
- Implement graceful degradation

**Dependencies:** All core features  
**Testing:** System remains stable under error conditions

---

### 20. `feature/configuration-file`
**Description:** Implement configuration file support
- Design configuration file format (JSON/YAML/INI)
- Implement userspace daemon that creates proxy fd via syscall
- Daemon writes configuration to fd from config file
- Add hot-reload capability: daemon re-writes to fd on config change
- Support configuration validation in userspace before write to fd
- Implement default configurations
- Add configuration migration tools
- Support environment-specific configs
- Implement configuration backup/restore via read() from fd
- Create file-watch mechanism to auto-reload config and update fd
- Support multiple daemon instances with different fds/configs

**Dependencies:** `feature/userspace-interface`, `feature/proxy-configuration`  
**Testing:** Configuration file changes are written to fd and take effect immediately

---

### 21. `feature/logging-framework`
**Description:** Implement comprehensive logging system
- Create structured logging framework
- Add log levels (DEBUG, INFO, WARN, ERROR)
- Implement rate-limited logging
- Add context-aware logging (per-connection)
- Support log filtering
- Implement log rotation in userspace
- Add syslog integration
- Create log analysis tools

**Dependencies:** `feature/basic-module-structure`  
**Testing:** Logs are helpful for debugging and don't impact performance

---

### 22. `feature/testing-framework`
**Description:** Build comprehensive testing infrastructure
- Create unit tests for core functions
- Implement integration tests
- Add stress testing tools
- Create network simulation tests
- Implement fuzzing for robustness
- Add performance benchmarks
- Create regression test suite
- Implement continuous integration

**Dependencies:** All features  
**Testing:** All tests pass consistently

---

### 23. `feature/documentation`
**Description:** Create comprehensive documentation
- Write architecture documentation
- Create API reference documentation
- Add user guides and tutorials
- Write troubleshooting guides
- Create diagrams for packet flow
- Add example configurations
- Write developer guide for contributions
- Create man pages for userspace tools

**Dependencies:** All features  
**Deliverable:** Complete documentation website/wiki

---

### 24. `feature/packaging`
**Description:** Create distribution packages
- Create Debian/Ubuntu packages (.deb)
- Create RPM packages for RHEL/Fedora
- Add DKMS support for kernel updates
- Create Arch Linux AUR package
- Add systemd service files
- Create installation scripts
- Implement post-install configuration wizard
- Add uninstallation cleanup scripts

**Dependencies:** All features  
**Deliverable:** Packages available for major distributions

---

### 25. `bugfix/integration-fixes`
**Description:** Integration testing and bug fixing branch
- Perform end-to-end testing
- Fix integration issues between features
- Resolve race conditions
- Fix memory leaks
- Resolve deadlocks
- Fix performance bottlenecks
- Handle edge cases
- Stabilize for production

**Dependencies:** All feature branches  
**Testing:** System is stable and production-ready

---

## Branch Workflow

### Recommended Development Order:
1. Basic infrastructure (branches 1-3: module structure, syscall+fd operations, userspace interface)
2. Core networking (branches 4-7: netfilter, config, tracking, rewriting)
3. Proxy protocols (branches 8-10: SOCKS, HTTP, transparent)
4. Advanced features (branches 11-17: filtering, routing, DNS, etc.)
5. Monitoring and reliability (branches 18-21)
6. Quality assurance (branches 22-23)
7. Distribution (branches 24-25)

### Merge Strategy:
- All feature branches merge into `develop`
- Regular integration testing in `develop`
- Stable releases merge from `develop` to `main`
- Hotfixes branch from `main` and merge to both `main` and `develop`

### Branch Naming Convention:
- Feature branches: `feature/<descriptive-name>`
- Bugfix branches: `bugfix/<issue-description>`
- Hotfix branches: `hotfix/<version-number>`
- Release branches: `release/<version-number>`

---

## Key Technical Considerations

### File Descriptor Design:
- Single syscall `mprox_create()` returns fd (like `eventfd()`, `timerfd()`)
- All operations through standard file operations (read, write, ioctl, poll, close)
- Per-fd private data stores proxy configuration and state
- Supports fd passing between processes via Unix domain sockets
- Proper reference counting for fd lifecycle management

### Security Concerns:
- Kernel modules run with elevated privileges
- Syscall checks CAP_NET_ADMIN before creating fd
- Input validation is critical to prevent kernel panics
- Memory safety is paramount (no buffer overflows)
- Proper locking to prevent race conditions on per-fd data
- Validate all data written to fd before processing

### Performance Considerations:
- Minimize per-packet processing overhead
- Use efficient data structures (hash tables, RCU)
- Avoid memory allocations in fast path
- Consider CPU affinity for multi-core systems

### Compatibility:
- Support multiple kernel versions (at least 5.x+)
- Handle architecture differences (x86_64, ARM, etc.)
- Test with different network configurations
- Ensure compatibility with existing iptables/nftables rules

### Maintainability:
- Follow Linux kernel coding style
- Use kernel APIs correctly
- Add comments and documentation
- Regular code reviews

---

## Testing Strategy

### Unit Tests:
- Test individual functions in isolation
- Mock kernel APIs where necessary
- Use kernel test framework (KUnit)

### Integration Tests:
- Test interaction between modules
- Verify packet flow end-to-end
- Test with real proxy servers

### Performance Tests:
- Measure throughput (Gbps)
- Measure latency (microseconds)
- Test with concurrent connections
- Profile CPU and memory usage

### Stress Tests:
- High connection rate
- Large packet sizes
- Memory pressure scenarios
- CPU saturation tests

---

## Project Milestones

1. **Alpha Release (Branches 1-10):** Basic proxy functionality working
2. **Beta Release (Branches 1-17):** Full feature set with IPv6 support
3. **RC1 (Branches 1-22):** Feature complete with testing
4. **Version 1.0 (All branches):** Production-ready release

---

## Resources and References

- Linux Kernel Documentation: https://www.kernel.org/doc/html/latest/
- Netfilter Documentation: https://www.netfilter.org/documentation/
- SOCKS Protocol: RFC 1928 (SOCKS5), RFC 1929 (Authentication)
- Linux Device Drivers, 3rd Edition
- Understanding the Linux Kernel, 3rd Edition
- Linux Kernel Development by Robert Love

---

*Last Updated: December 14, 2025*
*Project: MUTEX - Multi-User Threaded Exchange Xfer*
*Team: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir*
