# MUTEX Proxy Syscall API Documentation

## Overview

The `mprox_create()` syscall provides a file descriptor-based interface for kernel-level proxy control. It follows the Unix "everything is a file" philosophy, similar to `eventfd()`, `timerfd()`, and `signalfd()`.

## Syscall Number

- **x86_64**: 471
- **ARM64**: 471

## Syscall Definition

```c
int mprox_create(unsigned int flags);
```

**Note**: The syscall is named `mprox_create` (not `mutex_proxy_create`) for brevity.

### Parameters

- **flags**: Creation flags controlling fd behavior and proxy scope
  - `MUTEX_PROXY_CLOEXEC` (0x1): Close-on-exec (similar to `O_CLOEXEC`)
  - `MUTEX_PROXY_NONBLOCK` (0x2): Non-blocking I/O (similar to `O_NONBLOCK`)
  - `MUTEX_PROXY_GLOBAL` (0x4): Apply proxy system-wide

### Return Value

- **Success**: Non-negative file descriptor number
- **Failure**: Negative error code
  - `-EPERM`: Caller lacks `CAP_NET_ADMIN` capability
  - `-EINVAL`: Invalid flags provided
  - `-ENOMEM`: Failed to allocate kernel resources

### Required Capabilities

- `CAP_NET_ADMIN`: Required to create proxy control fds

## File Descriptor Operations

The returned file descriptor supports standard file operations:

**Note**: The file descriptor appears as `[mutex_proxy]` in `/proc/<pid>/fd/` for identification.

### `read()` - Read Statistics

```c
ssize_t read(int fd, void *buf, size_t count);
```

Reads `struct mutex_proxy_stats` containing:
- `bytes_sent`: Total bytes sent through proxy
- `bytes_received`: Total bytes received
- `packets_sent`: Total packets sent
- `packets_received`: Total packets received
- `connections_active`: Currently active connections
- `connections_total`: Total connections established

**Returns**: Number of bytes read, or negative error code

**Errors**:
- `-EINVAL`: Invalid buffer or count size
- `-EFAULT`: Invalid user buffer pointer

### `write()` - Update Configuration

```c
ssize_t write(int fd, const void *buf, size_t count);
```

Writes `struct mutex_proxy_config` containing:
- `version`: Config version (must be 1)
- `proxy_type`: Proxy type (1=SOCKS5, 2=HTTP, 3=HTTPS)
- `proxy_port`: Proxy port (1-65535)
- `proxy_addr`: Proxy address (16 bytes, IPv4 or IPv6)

**Returns**: Number of bytes written, or negative error code

**Errors**:
- `-EINVAL`: Invalid configuration parameters
- `-EFAULT`: Invalid user buffer pointer

### `ioctl()` - Control Operations

```c
int ioctl(int fd, unsigned long cmd, ...);
```

#### Commands

##### `MUTEX_PROXY_IOC_ENABLE`
Enable proxy for this fd (and inheriting processes).

```c
ioctl(fd, MUTEX_PROXY_IOC_ENABLE);
```

**Returns**: 0 on success, negative error code on failure

##### `MUTEX_PROXY_IOC_DISABLE`
Disable proxy for this fd.

```c
ioctl(fd, MUTEX_PROXY_IOC_DISABLE);
```

**Returns**: 0 on success, negative error code on failure

##### `MUTEX_PROXY_IOC_SET_CONFIG`
Set proxy configuration (alternative to `write()`).

```c
struct mutex_proxy_config cfg = {
    .version = 1,
    .proxy_type = PROXY_TYPE_SOCKS5,
    .proxy_port = 1080,
    .proxy_addr = { /* IP address bytes */ }
};
ioctl(fd, MUTEX_PROXY_IOC_SET_CONFIG, &cfg);
```

**Returns**: 0 on success, negative error code on failure

##### `MUTEX_PROXY_IOC_GET_CONFIG`
Get current proxy configuration.

```c
struct mutex_proxy_config cfg;
ioctl(fd, MUTEX_PROXY_IOC_GET_CONFIG, &cfg);
```

**Returns**: 0 on success, negative error code on failure

##### `MUTEX_PROXY_IOC_GET_STATS`
Get proxy statistics (alternative to `read()`).

```c
struct mutex_proxy_stats stats;
ioctl(fd, MUTEX_PROXY_IOC_GET_STATS, &stats);
```

**Returns**: 0 on success, negative error code on failure

### `poll()` - Event Notification

```c
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
```

The fd always returns:
- `POLLIN`: Ready for reading (statistics available)
- `POLLOUT`: Ready for writing (config updates accepted)
- `POLLHUP`: Connection events occurred

**Returns**: Number of ready fds, or negative error code

### `close()` - Release Resources

```c
int close(int fd);
```

Closes the file descriptor and releases resources.

**Behavior**:
- **CLOEXEC fd**: Proxy is disabled on close
- **Regular fd**: Proxy state maintained (for inherited fds)
- **Reference counting**: Context freed when all fds closed (RCU-safe)

## File Descriptor Inheritance

### `fork()` Semantics

- **CLOEXEC fd**: Not inherited by child processes
- **Regular fd**: Inherited by child, shares same proxy context
- **GLOBAL flag**: Applies to all processes regardless of fd inheritance

### `exec()` Semantics

- **CLOEXEC fd**: Automatically closed on `exec()`
- **Regular fd**: Preserved across `exec()`

### Unix Domain Socket (SCM_RIGHTS)

Fds can be passed between processes via `sendmsg()`/`recvmsg()` with `SCM_RIGHTS`:

```c
struct msghdr msg = {0};
struct cmsghdr *cmsg;
char buf[CMSG_SPACE(sizeof(int))];

msg.msg_control = buf;
msg.msg_controllen = sizeof(buf);

cmsg = CMSG_FIRSTHDR(&msg);
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type = SCM_RIGHTS;
cmsg->cmsg_len = CMSG_LEN(sizeof(int));
*(int *)CMSG_DATA(cmsg) = proxy_fd;

sendmsg(socket_fd, &msg, 0);
```

## Module Parameters

The kernel module accepts the following parameters at load time:

### `debug`
- **Type**: bool
- **Default**: false
- **Description**: Enable debug logging
- **Usage**: `insmod mutex_proxy.ko debug=1`

### `conn_table_size`
- **Type**: uint
- **Default**: 1024
- **Range**: 1-65536
- **Description**: Size of connection tracking hash table
- **Usage**: `insmod mutex_proxy.ko conn_table_size=2048`

## Usage Examples

### Basic Usage

```c
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/mutex_proxy.h>

#define SYS_mprox_create 471

int main() {
    int fd;
    struct mutex_proxy_config cfg;
    struct mutex_proxy_stats stats;

    /* Create proxy fd using mprox_create syscall */
    fd = syscall(SYS_mprox_create, 0);
    if (fd < 0) {
        perror("mprox_create");
        return 1;
    }

    /* Configure proxy */
    cfg.version = 1;
    cfg.proxy_type = PROXY_TYPE_SOCKS5;
    cfg.proxy_port = 1080;
    memcpy(cfg.proxy_addr, "\x7f\x00\x00\x01", 4); /* 127.0.0.1 */

    if (write(fd, &cfg, sizeof(cfg)) != sizeof(cfg)) {
        perror("write");
        close(fd);
        return 1;
    }

    /* Enable proxy */
    if (ioctl(fd, MUTEX_PROXY_IOC_ENABLE) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    /* Read statistics */
    if (read(fd, &stats, sizeof(stats)) != sizeof(stats)) {
        perror("read");
        close(fd);
        return 1;
    }

    printf("Active connections: %lu\n", stats.connections_active);

    close(fd);
    return 0;
}
```

### Close-on-Exec

```c
/* Create fd that closes on exec using mprox_create */
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_CLOEXEC);

/* Configure and enable proxy */
/* ... */

/* Fork child process */
pid_t pid = fork();
if (pid == 0) {
    /* Child process: fd is NOT inherited */
    execl("/bin/ls", "ls", NULL);
}
```

### Process Inheritance

```c
/* Create fd WITHOUT CLOEXEC using mprox_create */
int fd = syscall(SYS_mprox_create, 0);

/* Configure and enable proxy */
/* ... */

/* Fork child process */
pid_t pid = fork();
if (pid == 0) {
    /* Child process: fd is inherited, shares proxy state */
    printf("Child has access to fd %d\n", fd);
    /* All network connections in child will use proxy */
}
```

### System-Wide Proxy

```c
/* Create global proxy affecting all processes using mprox_create */
int fd = syscall(SYS_mprox_create, MUTEX_PROXY_GLOBAL);

/* Configure and enable proxy */
/* ... */

/* Proxy now applies to ALL processes system-wide */
/* Requires CAP_NET_ADMIN capability */
```

## Architecture Support

- **x86_64**: Fully supported
- **ARM64**: Fully supported (64-bit and 32-bit compat modes)

## Security Considerations

1. **CAP_NET_ADMIN Required**: Prevents unprivileged users from hijacking network traffic
2. **Reference Counting**: Safe cleanup even with active fds
3. **RCU Protection**: Memory-safe destruction across CPUs
4. **Ownership Tracking**: Each fd tracks creator PID, UID, GID
5. **CLOEXEC Support**: Prevents accidental fd leakage to child processes

## Error Handling

All operations validate inputs and return appropriate error codes:

- **NULL pointers**: `-EINVAL`
- **Invalid sizes**: `-EINVAL`
- **Invalid config**: `-EINVAL` (with detailed kernel log message)
- **Capability check failure**: `-EPERM`
- **Memory allocation failure**: `-ENOMEM`
- **Copy from/to user failure**: `-EFAULT`

## Debugging

Enable debug logging via module parameter:

```bash
# Load module with debugging enabled
sudo insmod /lib/modules/$(uname -r)/kernel/kernel/mutex_proxy.ko debug=1

# View debug messages
sudo dmesg | grep mutex_proxy
```

Debug messages include:
- Context allocation/destruction
- fd creation/release
- Configuration changes
- Enable/disable operations
- Inheritance events

## Performance Considerations

1. **Connection Table Size**: Default 1024 buckets, tunable via module parameter
2. **Spinlock Protection**: Fine-grained locking for config/stats
3. **RCU Destruction**: Non-blocking cleanup via `call_rcu()`
4. **Reference Counting**: Atomic operations for thread-safety
5. **Hash Table**: O(1) average-case connection lookup

## Related System Calls

- `eventfd()` - Event notification fd
- `timerfd_create()` - Timer fd
- `signalfd()` - Signal delivery fd
- `pidfd_open()` - Process fd
- `mprox_create()` - Proxy control fd (this syscall)

## See Also

- `include/uapi/linux/mutex_proxy.h` - UAPI header
- `kernel/mutex_proxy.c` - Kernel implementation
- `CONTRIBUTING.md` - Contributing guidelines
- `docs/BRANCH_2_SUMMARY.md` - Branch 2 implementation details
