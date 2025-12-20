# MUTEX Proxy Testing Guide

## Overview

This document describes the testing strategy for the mutex_proxy kernel syscall implementation (Branch 2).

## Test Categories

### 1. Syscall Creation Tests

#### Test 1.1: Basic Creation
```c
/* Test basic mprox_create syscall */
int fd = syscall(SYS_mprox_create, 0);
assert(fd >= 0);
close(fd);
```
**Expected**: Returns valid fd

#### Test 1.2: CLOEXEC Flag
```c
/* Test mprox_create with CLOEXEC flag */
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_CLOEXEC);
assert(fd >= 0);
int flags = fcntl(fd, F_GETFD);
assert(flags & FD_CLOEXEC);
close(fd);
```
**Expected**: fd has close-on-exec flag set

#### Test 1.3: NONBLOCK Flag
```c
/* Test mprox_create with NONBLOCK flag */
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_NONBLOCK);
assert(fd >= 0);
int flags = fcntl(fd, F_GETFL);
assert(flags & O_NONBLOCK);
close(fd);
```
**Expected**: fd has non-blocking flag set

#### Test 1.4: Multiple Flags
```c
/* Test mprox_create with multiple flags */
int fd = syscall(SYS_mprox_create,
                 MUTEX_PROXY_CLOEXEC | MUTEX_PROXY_NONBLOCK);
assert(fd >= 0);
close(fd);
```
**Expected**: Both flags applied correctly

#### Test 1.5: Invalid Flags
```c
/* Test mprox_create with invalid flags */
int fd = syscall(SYS_mprox_create, 0xFFFF);
assert(fd == -EINVAL);
```
**Expected**: Returns -EINVAL for invalid flags

#### Test 1.6: Capability Check
```c
/* Test mprox_create without CAP_NET_ADMIN */
cap_t caps = cap_get_proc();
cap_value_t cap_list[] = {CAP_NET_ADMIN};
cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR);
cap_set_proc(caps);

int fd = syscall(SYS_mprox_create, 0);
assert(fd == -EPERM);

cap_free(caps);
```
**Expected**: Returns -EPERM without CAP_NET_ADMIN

### 2. Configuration Tests

#### Test 2.1: Write Configuration
```c
/* Test configuration via write() after mprox_create */
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg = {
    .version = 1,
    .proxy_type = PROXY_TYPE_SOCKS5,
    .proxy_port = 1080,
    .proxy_addr = {127, 0, 0, 1}
};
ssize_t ret = write(fd, &cfg, sizeof(cfg));
assert(ret == sizeof(cfg));
close(fd);
```
**Expected**: Configuration written successfully

#### Test 2.2: Read Configuration via ioctl
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg_in = {
    .version = 1,
    .proxy_type = PROXY_TYPE_HTTP,
    .proxy_port = 8080,
    .proxy_addr = {192, 168, 1, 1}
};
write(fd, &cfg_in, sizeof(cfg_in));

struct mutex_proxy_config cfg_out;
int ret = ioctl(fd, MUTEX_PROXY_IOC_GET_CONFIG, &cfg_out);
assert(ret == 0);
assert(cfg_out.proxy_type == PROXY_TYPE_HTTP);
assert(cfg_out.proxy_port == 8080);
close(fd);
```
**Expected**: Configuration read back correctly

#### Test 2.3: Invalid Version
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg = {
    .version = 99,
    .proxy_type = PROXY_TYPE_SOCKS5,
    .proxy_port = 1080
};
ssize_t ret = write(fd, &cfg, sizeof(cfg));
assert(ret == -EINVAL);
close(fd);
```
**Expected**: Returns -EINVAL for invalid version

#### Test 2.4: Invalid Proxy Type
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg = {
    .version = 1,
    .proxy_type = 99,
    .proxy_port = 1080
};
ssize_t ret = write(fd, &cfg, sizeof(cfg));
assert(ret == -EINVAL);
close(fd);
```
**Expected**: Returns -EINVAL for invalid proxy type

#### Test 2.5: Invalid Port
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg = {
    .version = 1,
    .proxy_type = PROXY_TYPE_SOCKS5,
    .proxy_port = 0  /* Invalid */
};
ssize_t ret = write(fd, &cfg, sizeof(cfg));
assert(ret == -EINVAL);
close(fd);
```
**Expected**: Returns -EINVAL for port 0

#### Test 2.6: Zero Address
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_config cfg = {
    .version = 1,
    .proxy_type = PROXY_TYPE_SOCKS5,
    .proxy_port = 1080,
    .proxy_addr = {0}  /* All zeros */
};
ssize_t ret = write(fd, &cfg, sizeof(cfg));
assert(ret == -EINVAL);
close(fd);
```
**Expected**: Returns -EINVAL for zero address

### 3. Statistics Tests

#### Test 3.1: Read Statistics
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_stats stats;
ssize_t ret = read(fd, &stats, sizeof(stats));
assert(ret == sizeof(stats));
assert(stats.bytes_sent == 0);
assert(stats.connections_active == 0);
close(fd);
```
**Expected**: Returns initialized statistics

#### Test 3.2: Statistics via ioctl
```c
int fd = syscall(SYS_mprox_create, 0);
struct mutex_proxy_stats stats;
int ret = ioctl(fd, MUTEX_PROXY_IOC_GET_STATS, &stats);
assert(ret == 0);
close(fd);
```
**Expected**: Returns statistics successfully

### 4. Enable/Disable Tests

#### Test 4.1: Enable Proxy
```c
int fd = syscall(SYS_mprox_create, 0);
int ret = ioctl(fd, MUTEX_PROXY_IOC_ENABLE);
assert(ret == 0);
close(fd);
```
**Expected**: Proxy enabled successfully

#### Test 4.2: Disable Proxy
```c
int fd = syscall(SYS_mprox_create, 0);
ioctl(fd, MUTEX_PROXY_IOC_ENABLE);
int ret = ioctl(fd, MUTEX_PROXY_IOC_DISABLE);
assert(ret == 0);
close(fd);
```
**Expected**: Proxy disabled successfully

### 5. Poll Tests

#### Test 5.1: Poll Readiness
```c
int fd = syscall(SYS_mprox_create, 0);
struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN | POLLOUT
};
int ret = poll(&pfd, 1, 0);
assert(ret == 1);
assert(pfd.revents & POLLIN);
assert(pfd.revents & POLLOUT);
close(fd);
```
**Expected**: fd always ready for read/write

### 6. Inheritance Tests

#### Test 6.1: Fork Without CLOEXEC
```c
int fd = syscall(SYS_mprox_create, 0);
pid_t pid = fork();
if (pid == 0) {
    /* Child: fd should be valid */
    struct mutex_proxy_stats stats;
    ssize_t ret = read(fd, &stats, sizeof(stats));
    assert(ret == sizeof(stats));
    exit(0);
}
waitpid(pid, NULL, 0);
close(fd);
```
**Expected**: Child inherits fd

#### Test 6.2: Fork With CLOEXEC
```c
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_CLOEXEC);
pid_t pid = fork();
if (pid == 0) {
    /* Child: fd should still be valid (CLOEXEC only affects exec) */
    struct mutex_proxy_stats stats;
    ssize_t ret = read(fd, &stats, sizeof(stats));
    assert(ret == sizeof(stats));
    exit(0);
}
waitpid(pid, NULL, 0);
close(fd);
```
**Expected**: Child inherits CLOEXEC fd (closes on exec only)

#### Test 6.3: Exec With CLOEXEC
```c
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_CLOEXEC);
pid_t pid = fork();
if (pid == 0) {
    /* Try to use fd after exec - should fail */
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", fd);
    execl("./test_fd_access", "test_fd_access", fd_str, NULL);
    /* exec failed */
    exit(1);
}
int status;
waitpid(pid, &status, 0);
/* test_fd_access should report fd is invalid */
close(fd);
```
**Expected**: fd closed on exec

#### Test 6.4: Exec Without CLOEXEC
```c
int fd = syscall(SYS_mprox_create, 0);
pid_t pid = fork();
if (pid == 0) {
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "%d", fd);
    execl("./test_fd_access", "test_fd_access", fd_str, NULL);
    exit(1);
}
int status;
waitpid(pid, &status, 0);
/* test_fd_access should successfully use fd */
close(fd);
```
**Expected**: fd preserved across exec

### 7. SCM_RIGHTS Tests

#### Test 7.1: Pass fd via Unix Socket
```c
int sv[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

int fd = syscall(SYS_mprox_create, 0);

/* Send fd */
struct msghdr msg = {0};
struct cmsghdr *cmsg;
char buf[CMSG_SPACE(sizeof(int))];
msg.msg_control = buf;
msg.msg_controllen = sizeof(buf);
cmsg = CMSG_FIRSTHDR(&msg);
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type = SCM_RIGHTS;
cmsg->cmsg_len = CMSG_LEN(sizeof(int));
*(int *)CMSG_DATA(cmsg) = fd;
sendmsg(sv[0], &msg, 0);

/* Receive fd */
msg.msg_control = buf;
msg.msg_controllen = sizeof(buf);
recvmsg(sv[1], &msg, 0);
cmsg = CMSG_FIRSTHDR(&msg);
int received_fd = *(int *)CMSG_DATA(cmsg);

/* Test received fd */
struct mutex_proxy_stats stats;
ssize_t ret = read(received_fd, &stats, sizeof(stats));
assert(ret == sizeof(stats));

close(received_fd);
close(fd);
close(sv[0]);
close(sv[1]);
```
**Expected**: fd transferred successfully

### 8. Global Flag Tests

#### Test 8.1: Global Proxy Creation
```c
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_GLOBAL);
assert(fd >= 0);
/* Configure and enable */
/* Should affect ALL processes */
close(fd);
```
**Expected**: Global proxy created successfully

### 9. Stress Tests

#### Test 9.1: Multiple fds
```c
#define NUM_FDS 100
int fds[NUM_FDS];

for (int i = 0; i < NUM_FDS; i++) {
    fds[i] = syscall(SYS_mprox_create, 0);
    assert(fds[i] >= 0);
}

for (int i = 0; i < NUM_FDS; i++) {
    close(fds[i]);
}
```
**Expected**: All fds created and closed successfully

#### Test 9.2: Rapid Create/Close
```c
for (int i = 0; i < 1000; i++) {
    int fd = syscall(SYS_mprox_create, 0);
    assert(fd >= 0);
    close(fd);
}
```
**Expected**: No memory leaks, stable performance

### 10. Error Condition Tests

#### Test 10.1: NULL Buffer in read()
```c
int fd = syscall(SYS_mprox_create, 0);
ssize_t ret = read(fd, NULL, sizeof(struct mutex_proxy_stats));
assert(ret == -EFAULT || ret == -EINVAL);
close(fd);
```
**Expected**: Returns error for NULL buffer

#### Test 10.2: NULL Buffer in write()
```c
int fd = syscall(SYS_mprox_create, 0);
ssize_t ret = write(fd, NULL, sizeof(struct mutex_proxy_config));
assert(ret == -EFAULT || ret == -EINVAL);
close(fd);
```
**Expected**: Returns error for NULL buffer

#### Test 10.3: Invalid ioctl Command
```c
int fd = syscall(SYS_mprox_create, 0);
int ret = ioctl(fd, 0xDEADBEEF);
assert(ret == -EINVAL);
close(fd);
```
**Expected**: Returns -EINVAL for unknown ioctl

## Manual Testing Procedures

### 1. Module Loading
```bash
# Load module
sudo insmod /lib/modules/$(uname -r)/kernel/kernel/mutex_proxy.ko

# Verify module loaded
lsmod | grep mutex_proxy

# Check kernel log
dmesg | tail -n 20 | grep mutex_proxy
```

### 2. Debug Mode
```bash
# Load with debug enabled
sudo insmod mutex_proxy.ko debug=1

# Monitor debug output
sudo dmesg -w | grep mutex_proxy
```

### 3. Module Parameters
```bash
# Load with custom conn_table_size
sudo insmod mutex_proxy.ko conn_table_size=2048

# Verify parameter
cat /sys/module/mutex_proxy/parameters/conn_table_size
```

### 4. Syscall Verification
```bash
# Check syscall table
grep mprox /proc/kallsyms
```

### 5. fd Creation
```bash
# Compile test program
gcc -o test_mprox test_mprox.c

# Run test
sudo ./test_mprox
```

## Test Tools

### Required Tools
- GCC/Clang compiler
- libcap-dev (for capability tests)
- strace (for syscall tracing)
- gdb (for debugging)

### Compilation
```bash
# Compile test program for mprox_create syscall
gcc -o test_mprox test_mprox.c -lcap -lpthread
```

### Running Tests
```bash
# Run all tests
sudo ./test_mprox --all

# Run specific test category
sudo ./test_mprox --category=inheritance

# Run with verbose output
sudo ./test_mprox --verbose
```

## Expected Kernel Log Messages

### Module Load
```
mutex_proxy: initializing mutex_proxy kernel module
mutex_proxy: debug logging: disabled
mutex_proxy: default conn_table_size: 1024
mutex_proxy: mutex_proxy module loaded successfully
```

### fd Creation
```
mutex_proxy: allocated context for PID 1234 (UID 0, GID 0, conn_table_size=1024)
mutex_proxy: created fd 3 for PID 1234
mutex_proxy: Created fd 3 for process 1234 (test_mprox) with flags 0x0
```

### fd Release
```
mutex_proxy: releasing fd for PID 1234 (opened by PID 1234)
mutex_proxy: destroying context for PID 1234
```

## Performance Benchmarks

### Syscall Creation
- **Target**: < 10 µs per syscall
- **Measurement**: Use `perf` or custom timing

### Configuration Update
- **Target**: < 5 µs per write()
- **Measurement**: Time write() calls

### Statistics Read
- **Target**: < 2 µs per read()
- **Measurement**: Time read() calls

## Memory Leak Detection

### Using kmemleak
```bash
# Enable kmemleak
echo scan > /sys/kernel/debug/kmemleak

# Run tests
sudo ./test_mprox --all

# Check for leaks
cat /sys/kernel/debug/kmemleak
```

### Using KASAN
Build kernel with CONFIG_KASAN=y and run tests.

## Security Testing

### Capability Tests
- Verify CAP_NET_ADMIN requirement
- Test with dropped capabilities
- Test with different user contexts

### Race Condition Tests
- Multiple threads creating fds
- Concurrent read/write operations
- Fork while updating configuration

## Regression Testing

After any code changes, run full test suite:
```bash
sudo ./run_all_tests.sh
```

## CI/CD Integration

### Pre-commit Tests
- Syntax validation
- Static analysis (sparse, checkpatch)
- Unit test compilation

### Post-commit Tests
- Full test suite execution
- Performance benchmarks
- Memory leak detection

## Known Limitations

1. Connection tracking not yet implemented (hash table allocated but unused)
2. Proxy application logic not yet implemented (syscall provides interface only)
3. Network hook integration pending (Branch 3)

---

## ⚠️ CRITICAL: System Call Availability Limitation

### Current State (As of Branch 7)

**IMPORTANT:** The `mprox_create()` syscall (syscall #471) has been added to the Linux kernel source code in the `linux/` submodule, but:

- ✅ The syscall is defined in kernel source
- ✅ The syscall table entry exists
- ❌ **The kernel has NOT been compiled**
- ❌ **Your running kernel does NOT have this syscall**

### Impact on Testing

**What Works:**
- ✅ Kernel module compilation and loading
- ✅ Netfilter hooks (packet interception)
- ✅ Connection tracking functionality
- ✅ Packet rewriting operations
- ✅ Module parameters and debug logging

**What Doesn't Work:**
- ❌ Userspace syscall invocation
- ❌ File descriptor creation from userspace
- ❌ Userspace library and CLI tools
- ❌ Example programs requiring syscall

### Workaround: Module-Only Testing

Until you compile a custom kernel, test without syscall:

```bash
# Test module loading
cd src/module
make clean && make
sudo insmod build/mutex_proxy.ko

# Verify components initialized
sudo dmesg | tail -30
# Should see:
# - connection tracking initialized
# - packet rewriting initialized  
# - registered 3 netfilter hooks

# Enable debug logging
echo 1 | sudo tee /sys/module/mutex_proxy/parameters/debug
echo 1 | sudo tee /sys/module/mutex_packet_rewrite/parameters/debug

# Generate test traffic
ping -c 10 8.8.8.8

# Check packet processing
sudo dmesg | grep "mutex_pkt"

# View statistics on unload
sudo rmmod mutex_proxy
sudo dmesg | tail -30
```

### To Enable Syscall: Compile Custom Kernel

For full testing with userspace programs:

1. **Configure kernel:**
   ```bash
   cd linux
   make menuconfig  # or use existing .config
   ```

2. **Compile (takes hours):**
   ```bash
   make -j$(nproc)
   ```

3. **Install modules and kernel:**
   ```bash
   sudo make modules_install
   sudo make install
   sudo update-grub  # or bootctl update
   ```

4. **Reboot into new kernel:**
   ```bash
   sudo reboot
   uname -r  # Verify new kernel version
   ```

5. **Then test userspace:**
   ```bash
   cd src/userspace
   make
   LD_LIBRARY_PATH=lib ./cli/mprox create
   ```

**⚠️ WARNING:** Custom kernel compilation can take 1-4 hours and may render system unbootable if done incorrectly. Test in VM first!

---

## Branch 7: Packet Rewriting Tests

### Automated Test Script

Create `src/module/test_packet_rewrite.sh`:

```bash
#!/bin/bash
# Test packet rewriting module

set -e

MODULE="build/mutex_proxy.ko"

echo "=== Testing Packet Rewriting Module ==="

# Load module
sudo insmod "$MODULE"
echo "✓ Module loaded"

# Enable debug
echo 1 | sudo tee /sys/module/mutex_packet_rewrite/parameters/debug > /dev/null
echo "✓ Debug enabled"

# Generate ICMP traffic
echo "Generating ICMP traffic..."
ping -c 5 8.8.8.8 > /dev/null 2>&1 || true

# Generate TCP traffic
echo "Generating TCP traffic..."
curl -s http://example.com > /dev/null 2>&1 || true

# Generate UDP traffic
echo "Generating UDP traffic..."
nslookup google.com > /dev/null 2>&1 || true

# Check logs
if sudo dmesg | tail -50 | grep -q "mutex_pkt"; then
    echo "✓ Packet processing detected"
else
    echo "⚠ No packet logs (may be expected if no rewriting active)"
fi

# Unload and check statistics
sudo rmmod mutex_proxy
echo "✓ Module unloaded"

# Display statistics
echo ""
echo "=== Statistics ==="
sudo dmesg | tail -30 | grep -E "(rewrote|rewrites|Checksum)"

echo ""
echo "=== Test Complete ==="
```

Run with:
```bash
chmod +x src/module/test_packet_rewrite.sh
sudo src/module/test_packet_rewrite.sh
```

### Manual Testing Procedures

#### Test 1: Module Load/Unload
```bash
cd src/module
make clean && make
sudo insmod build/mutex_proxy.ko
lsmod | grep mutex_proxy  # Verify loaded
sudo rmmod mutex_proxy     # Verify unloads cleanly
sudo dmesg | tail -30      # Check for errors
```

#### Test 2: Debug Logging
```bash
sudo insmod build/mutex_proxy.ko
echo 1 | sudo tee /sys/module/mutex_packet_rewrite/parameters/debug
ping -c 3 8.8.8.8
sudo dmesg | grep "mutex_pkt"  # Should see validation logs
sudo rmmod mutex_proxy
```

#### Test 3: Statistics Tracking
```bash
sudo insmod build/mutex_proxy.ko
curl http://example.com > /dev/null 2>&1
sudo rmmod mutex_proxy
sudo dmesg | tail -20 | grep "rewrote"  # View stats
```

#### Test 4: Multiple Load/Unload Cycles
```bash
for i in {1..5}; do
    echo "Cycle $i"
    sudo insmod build/mutex_proxy.ko
    sleep 1
    ping -c 2 8.8.8.8 > /dev/null 2>&1 || true
    sudo rmmod mutex_proxy
    sleep 1
done
sudo dmesg | tail -50  # Check for memory leaks
```

### Performance Testing

#### Latency Impact
```bash
# Baseline (no module)
ping -c 100 8.8.8.8 | grep avg

# With module
sudo insmod build/mutex_proxy.ko
ping -c 100 8.8.8.8 | grep avg
sudo rmmod mutex_proxy

# Compare results
```

#### Throughput Testing
```bash
# Install iperf3
sudo apt-get install iperf3

# Test without module
iperf3 -c <server_ip> -t 30

# Test with module
sudo insmod build/mutex_proxy.ko
iperf3 -c <server_ip> -t 30
sudo rmmod mutex_proxy

# Compare throughput
```

### Integration Testing

Test interaction between components:

```bash
# Load with all features enabled
sudo insmod build/mutex_proxy.ko
echo 1 | sudo tee /sys/module/mutex_proxy/parameters/debug
echo 1 | sudo tee /sys/module/mutex_packet_rewrite/parameters/debug

# Generate diverse traffic
ping -c 5 8.8.8.8 &              # ICMP
curl http://example.com &         # TCP
nslookup google.com &             # UDP
wait

# Check all subsystems
sudo dmesg | grep -E "(mutex_pkt|connection|netfilter)"

# Unload
sudo rmmod mutex_proxy
```

### Packet Capture Verification

```bash
# Terminal 1: Start capture
sudo tcpdump -i any -n -w capture.pcap

# Terminal 2: Load module and generate traffic
sudo insmod build/mutex_proxy.ko
ping -c 10 8.8.8.8
sudo rmmod mutex_proxy

# Terminal 1: Stop capture (Ctrl+C)

# Analyze capture
wireshark capture.pcap
# or
tcpdump -r capture.pcap -n -vv | less
```

---

## Safety and Best Practices

### Before Testing

1. **Save all work** - Module can crash system
2. **Test in VM first** - VirtualBox, QEMU, or KVM
3. **Have recovery plan** - Know how to boot recovery mode
4. **Check dmesg** - Ensure no existing issues

### During Testing

1. **Monitor dmesg:** `sudo dmesg -w` in separate terminal
2. **Watch resources:** `htop` or `top`
3. **Limit duration:** Don't run untested code for hours
4. **Document issues:** Save dmesg output if crashes occur

### If Something Goes Wrong

1. **Try clean unload:** `sudo rmmod mutex_proxy`
2. **Force unload:** `sudo rmmod -f mutex_proxy`
3. **Reboot if stuck:** `sudo reboot`
4. **Boot recovery:** Hold Shift during boot (GRUB)
5. **Remove auto-load:** Check `/etc/modules` and `/etc/modules-load.d/`

---

## Troubleshooting

### Module Won't Load

**Error:** `insmod: ERROR: could not insert module`

**Solutions:**
```bash
# Check kernel version match
uname -r
modinfo build/mutex_proxy.ko | grep vermagic

# Rebuild for current kernel
make clean && make

# Check for symbol conflicts
sudo dmesg | tail -20
```

### No Debug Output

**Problem:** Debug enabled but no output

**Solutions:**
```bash
# Verify debug enabled
cat /sys/module/mutex_packet_rewrite/parameters/debug

# Enable all debug
echo 1 | sudo tee /sys/module/*/parameters/debug

# Check kernel log level
dmesg -n 8

# Use dmesg follow mode
sudo dmesg -w
```

### Module Won't Unload

**Error:** `rmmod: ERROR: Module mutex_proxy is in use`

**Solutions:**
```bash
# Check reference count
lsmod | grep mutex_proxy

# Wait for connections to close
sleep 5
sudo rmmod mutex_proxy

# Force unload (last resort)
sudo rmmod -f mutex_proxy
```

---

## See Also

- `docs/SYSCALL_API.md` - API documentation
- `docs/BRANCH_2_SUMMARY.md` - Implementation details
- `docs/BRANCH_7_SUMMARY.md` - Packet rewriting details
- `CONTRIBUTING.md` - Contributing guidelines
- `README.md` - Project overview

---

**Last Updated:** December 20, 2025  
**Version:** 0.6.0  
**Status:** Branch 7 Testing Verified
