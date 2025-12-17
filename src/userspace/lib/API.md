# MUTEX Userspace Library API Documentation

## Overview

The MUTEX userspace library (`libmutex`) provides a high-level C API for interacting with the MUTEX kernel-level proxy through file descriptors. The library follows the Unix philosophy: everything is a file.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Core Functions](#core-functions)
  - [Configuration Functions](#configuration-functions)
  - [Statistics Functions](#statistics-functions)
  - [Utility Functions](#utility-functions)
- [Data Structures](#data-structures)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [Best Practices](#best-practices)

---

## Installation

### Building from Source

```bash
cd src/userspace/lib
make
sudo make install
```

### Linking

```bash
# Compile your program
gcc -o myapp myapp.c -lmutex

# Or with pkg-config
gcc -o myapp myapp.c $(pkg-config --cflags --libs libmutex)
```

---

## Quick Start

```c
#include <libmutex.h>

int main(void) {
    int fd;

    /* 1. Create proxy file descriptor */
    fd = mprox_create(MUTEX_PROXY_CLOEXEC);
    if (fd < 0) {
        perror("mprox_create");
        return 1;
    }

    /* 2. Configure SOCKS5 proxy */
    if (mprox_set_socks5(fd, "127.0.0.1", 1080) < 0) {
        perror("mprox_set_socks5");
        close(fd);
        return 1;
    }

    /* 3. Enable proxy */
    if (mprox_enable(fd) < 0) {
        perror("mprox_enable");
        close(fd);
        return 1;
    }

    /* 4. Your network code here - traffic will be proxied */
    /* ... */

    /* 5. Disable and close when done */
    mprox_disable(fd);
    close(fd);

    return 0;
}
```

---

## API Reference

### Core Functions

#### `mprox_create()`

Create a new proxy file descriptor.

**Prototype:**
```c
int mprox_create(unsigned int flags);
```

**Parameters:**
- `flags`: Creation flags (bitwise OR):
  - `MUTEX_PROXY_CLOEXEC` - Set close-on-exec flag
  - `MUTEX_PROXY_NONBLOCK` - Set non-blocking mode
  - `MUTEX_PROXY_GLOBAL` - Global proxy (affects all processes)

**Returns:**
- File descriptor (≥ 0) on success
- -1 on error with `errno` set

**Errors:**
- `EINVAL` - Invalid flags
- `ENOMEM` - Out of memory
- `EPERM` - Permission denied (requires CAP_NET_ADMIN)

**Example:**
```c
/* Create fd with close-on-exec */
int fd = mprox_create(MUTEX_PROXY_CLOEXEC);

/* Create global, non-blocking proxy fd */
int fd = mprox_create(MUTEX_PROXY_GLOBAL | MUTEX_PROXY_NONBLOCK);
```

---

#### `mprox_enable()`

Enable the proxy for this file descriptor.

**Prototype:**
```c
int mprox_enable(int fd);
```

**Parameters:**
- `fd`: Proxy file descriptor from `mprox_create()`

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Errors:**
- `EBADF` - Invalid file descriptor
- `EINVAL` - Proxy not configured
- `EALREADY` - Proxy already enabled

**Example:**
```c
if (mprox_enable(fd) < 0) {
    perror("Failed to enable proxy");
}
```

---

#### `mprox_disable()`

Disable the proxy for this file descriptor.

**Prototype:**
```c
int mprox_disable(int fd);
```

**Parameters:**
- `fd`: Proxy file descriptor

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Example:**
```c
mprox_disable(fd);
close(fd);
```

---

### Configuration Functions

#### `mprox_set_config()`

Set proxy configuration (low-level function).

**Prototype:**
```c
int mprox_set_config(int fd, const struct mutex_proxy_config *config);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `config`: Pointer to configuration structure

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Note:** Most users should use `mprox_set_socks5()` or `mprox_set_http()` instead.

---

#### `mprox_get_config()`

Get current proxy configuration.

**Prototype:**
```c
int mprox_get_config(int fd, struct mutex_proxy_config *config);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `config`: Pointer to configuration structure (output)

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Example:**
```c
struct mutex_proxy_config config;
if (mprox_get_config(fd, &config) == 0) {
    printf("Proxy type: %u\n", config.proxy_type);
    printf("Proxy port: %u\n", config.proxy_port);
}
```

---

#### `mprox_set_socks5()`

Configure SOCKS5 proxy (convenience function).

**Prototype:**
```c
int mprox_set_socks5(int fd, const char *addr, uint16_t port);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `addr`: Proxy server address (IPv4 or IPv6 string)
- `port`: Proxy server port (1-65535)

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Example:**
```c
/* IPv4 */
mprox_set_socks5(fd, "127.0.0.1", 1080);

/* IPv6 */
mprox_set_socks5(fd, "::1", 1080);

/* Domain names not supported - use getaddrinfo() first */
```

---

#### `mprox_set_http()`

Configure HTTP/HTTPS proxy (convenience function).

**Prototype:**
```c
int mprox_set_http(int fd, const char *addr, uint16_t port, int use_https);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `addr`: Proxy server address (IPv4 or IPv6 string)
- `port`: Proxy server port
- `use_https`: 1 for HTTPS, 0 for HTTP

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Example:**
```c
/* HTTP proxy */
mprox_set_http(fd, "127.0.0.1", 8080, 0);

/* HTTPS proxy */
mprox_set_http(fd, "127.0.0.1", 8443, 1);
```

---

### Statistics Functions

#### `mprox_get_stats()`

Get proxy statistics.

**Prototype:**
```c
int mprox_get_stats(int fd, struct mutex_proxy_stats *stats);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `stats`: Pointer to statistics structure (output)

**Returns:**
- 0 on success
- -1 on error with `errno` set

**Example:**
```c
struct mutex_proxy_stats stats;
if (mprox_get_stats(fd, &stats) == 0) {
    printf("Bytes sent: %llu\n", stats.bytes_sent);
    printf("Bytes received: %llu\n", stats.bytes_received);
    printf("Active connections: %llu\n", stats.connections_active);
}
```

---

#### `mprox_reset_stats()` ⚠️

Reset statistics counters.

**Status:** Not yet implemented in kernel

**Prototype:**
```c
int mprox_reset_stats(int fd);
```

---

### Utility Functions

#### `mprox_wait_event()`

Wait for events on proxy file descriptor.

**Prototype:**
```c
int mprox_wait_event(int fd, int timeout_ms);
```

**Parameters:**
- `fd`: Proxy file descriptor
- `timeout_ms`: Timeout in milliseconds (-1 for infinite)

**Returns:**
- 1 if event occurred
- 0 on timeout
- -1 on error with `errno` set

**Example:**
```c
/* Wait up to 5 seconds for event */
int ret = mprox_wait_event(fd, 5000);
if (ret == 1) {
    /* Event occurred - read statistics */
    struct mutex_proxy_stats stats;
    mprox_get_stats(fd, &stats);
}
```

---

#### `mprox_is_enabled()`

Check if proxy is enabled.

**Prototype:**
```c
int mprox_is_enabled(int fd);
```

**Parameters:**
- `fd`: Proxy file descriptor

**Returns:**
- 1 if enabled
- 0 if disabled
- -1 on error with `errno` set

---

#### `mprox_get_version()`

Get library version.

**Prototype:**
```c
void mprox_get_version(int *major, int *minor, int *patch);
```

**Parameters:**
- `major`: Pointer to major version (output, can be NULL)
- `minor`: Pointer to minor version (output, can be NULL)
- `patch`: Pointer to patch version (output, can be NULL)

**Example:**
```c
int major, minor, patch;
mprox_get_version(&major, &minor, &patch);
printf("libmutex version %d.%d.%d\n", major, minor, patch);
```

---

#### `mprox_strerror()`

Convert error code to string.

**Prototype:**
```c
const char *mprox_strerror(int errnum);
```

**Parameters:**
- `errnum`: Error number (EMUTEX_* or standard errno)

**Returns:**
- Error description string

**Example:**
```c
if (mprox_enable(fd) < 0) {
    fprintf(stderr, "Error: %s\n", mprox_strerror(errno));
}
```

---

## Data Structures

### `struct mutex_proxy_config`

Proxy configuration structure.

```c
struct mutex_proxy_config {
    __u32 version;        /* API version, currently 1 */
    __u32 proxy_type;     /* PROXY_TYPE_SOCKS5, HTTP, HTTPS */
    __u32 proxy_port;     /* Proxy server port */
    __u32 flags;          /* Configuration flags */
    __u8  proxy_addr[16]; /* IPv4/IPv6 address (network byte order) */
    __u8  reserved[64];   /* Reserved for future use */
};
```

**Proxy Types:**
- `PROXY_TYPE_SOCKS5` (1) - SOCKS5 proxy
- `PROXY_TYPE_HTTP` (2) - HTTP proxy
- `PROXY_TYPE_HTTPS` (3) - HTTPS proxy

---

### `struct mutex_proxy_stats`

Proxy statistics structure.

```c
struct mutex_proxy_stats {
    __u64 bytes_sent;          /* Total bytes sent through proxy */
    __u64 bytes_received;      /* Total bytes received from proxy */
    __u64 packets_sent;        /* Total packets sent */
    __u64 packets_received;    /* Total packets received */
    __u64 connections_active;  /* Currently active connections */
    __u64 connections_total;   /* Total connections since creation */
};
```

---

## Error Handling

### Standard errno Values

The library uses standard POSIX errno values:

- `EINVAL` - Invalid argument
- `EBADF` - Bad file descriptor
- `ENOMEM` - Out of memory
- `EPERM` - Operation not permitted
- `ENOSYS` - Function not implemented
- `EALREADY` - Operation already in progress

### MUTEX-Specific Errors

- `EMUTEX_NOTSUPP` (-1000) - Operation not supported
- `EMUTEX_BADCONFIG` (-1001) - Invalid configuration
- `EMUTEX_NOPROXY` (-1002) - No proxy configured

### Error Handling Pattern

```c
if (mprox_set_socks5(fd, addr, port) < 0) {
    fprintf(stderr, "Failed to set proxy: %s\n", mprox_strerror(errno));

    /* Handle specific errors */
    switch (errno) {
    case EINVAL:
        fprintf(stderr, "Invalid address or port\n");
        break;
    case EBADF:
        fprintf(stderr, "Invalid file descriptor\n");
        break;
    default:
        fprintf(stderr, "Unknown error\n");
    }

    return -1;
}
```

---

## Examples

### Example 1: Basic SOCKS5 Proxy

```c
#include <libmutex.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd = mprox_create(MUTEX_PROXY_CLOEXEC);

    if (fd < 0) {
        perror("mprox_create");
        return 1;
    }

    if (mprox_set_socks5(fd, "127.0.0.1", 1080) < 0) {
        perror("mprox_set_socks5");
        close(fd);
        return 1;
    }

    if (mprox_enable(fd) < 0) {
        perror("mprox_enable");
        close(fd);
        return 1;
    }

    printf("Proxy enabled! Network traffic will be proxied.\n");

    /* Your application code here */
    sleep(10);

    mprox_disable(fd);
    close(fd);
    return 0;
}
```

---

### Example 2: Multiple Proxies

```c
#include <libmutex.h>

int main(void) {
    int fd1, fd2;

    /* Create two proxy fds */
    fd1 = mprox_create(MUTEX_PROXY_CLOEXEC);
    fd2 = mprox_create(MUTEX_PROXY_CLOEXEC);

    /* Configure differently */
    mprox_set_socks5(fd1, "127.0.0.1", 1080);
    mprox_set_http(fd2, "127.0.0.1", 8080, 0);

    /* Enable both */
    mprox_enable(fd1);
    mprox_enable(fd2);

    /* Each fd has independent configuration */

    /* Clean up */
    mprox_disable(fd1);
    mprox_disable(fd2);
    close(fd1);
    close(fd2);

    return 0;
}
```

---

### Example 3: Event Notification

```c
#include <libmutex.h>
#include <poll.h>

int main(void) {
    int fd = mprox_create(MUTEX_PROXY_CLOEXEC | MUTEX_PROXY_NONBLOCK);
    struct pollfd pfd;

    mprox_set_socks5(fd, "127.0.0.1", 1080);
    mprox_enable(fd);

    /* Wait for events using poll() */
    pfd.fd = fd;
    pfd.events = POLLIN;

    while (1) {
        if (poll(&pfd, 1, -1) > 0) {
            if (pfd.revents & POLLIN) {
                /* Event occurred - check statistics */
                struct mutex_proxy_stats stats;
                mprox_get_stats(fd, &stats);
                printf("Connections: %llu\n", stats.connections_total);
            }
        }
    }

    return 0;
}
```

---

## Best Practices

### 1. Always Check Return Values

```c
/* BAD */
int fd = mprox_create(0);
mprox_enable(fd);

/* GOOD */
int fd = mprox_create(0);
if (fd < 0) {
    perror("mprox_create");
    return -1;
}

if (mprox_enable(fd) < 0) {
    perror("mprox_enable");
    close(fd);
    return -1;
}
```

### 2. Use CLOEXEC Flag

Always use `MUTEX_PROXY_CLOEXEC` to prevent fd leakage to child processes:

```c
int fd = mprox_create(MUTEX_PROXY_CLOEXEC);
```

### 3. Disable Before Closing

Always disable the proxy before closing the fd:

```c
mprox_disable(fd);
close(fd);
```

### 4. Handle Signals Properly

In long-running applications, handle signals gracefully:

```c
static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int fd = mprox_create(MUTEX_PROXY_CLOEXEC);
    /* ... */

    while (running) {
        /* ... */
    }

    mprox_disable(fd);
    close(fd);
}
```

### 5. Thread Safety

Each thread should have its own proxy fd. The library is thread-safe for operations on different fds.

```c
/* Thread 1 */
int fd1 = mprox_create(MUTEX_PROXY_CLOEXEC);
mprox_set_socks5(fd1, "127.0.0.1", 1080);

/* Thread 2 */
int fd2 = mprox_create(MUTEX_PROXY_CLOEXEC);
mprox_set_http(fd2, "127.0.0.1", 8080, 0);
```

---

## See Also

- [Kernel UAPI Documentation](../../../linux/include/uapi/linux/mutex_proxy.h)
- [Example Programs](../examples/)
- [Command-Line Tool (mprox)](../cli/mprox.c)
- [MUTEX Project Documentation](../../../docs/)

---

**Copyright (C) 2025 MUTEX Team**  
**License: LGPL-2.1 OR BSD-3-Clause**
