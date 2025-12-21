# MUTEX Proxy Usage Guide

## Option 1: Using Example Programs (Recommended for Testing)

### Simple proxy example:
```bash
cd /home/areeb/MUTEX/src/userspace
sudo LD_LIBRARY_PATH=./lib ./examples/simple_proxy
```

This demonstrates the complete workflow: create → configure → enable → use

### Multi-FD example (demonstrates multiple proxy contexts):
```bash
sudo LD_LIBRARY_PATH=./lib ./examples/multi_fd
```

### Poll example (demonstrates event handling):
```bash
sudo LD_LIBRARY_PATH=./lib ./examples/poll_example
```

## Option 2: Using libmutex in Your Own Program

### Example Code:
```c
#include "libmutex.h"

int main() {
    // 1. Create proxy file descriptor
    int fd = mprox_create(0);

    // 2. Configure SOCKS5 proxy
    mprox_set_socks5(fd, "127.0.0.1", 1080);

    // 3. Enable the proxy
    mprox_enable(fd);

    // 4. Check status
    struct mutex_proxy_config config;
    mprox_get_config(fd, &config);

    // 5. Get statistics
    struct mutex_proxy_stats stats;
    mprox_get_stats(fd, &stats);

    // 6. Use normal socket operations - they'll be proxied
    // ... your socket code here ...

    // 7. Cleanup
    close(fd);
}
```

### Compile:
```bash
gcc -o myproxy myproxy.c -I./lib -L./lib -lmutex
sudo LD_LIBRARY_PATH=./lib ./myproxy
```

## Option 3: Using the CLI Tool (Limited - for inspection)

The CLI tool doesn't maintain file descriptors between invocations, but you can:

### Create a proxy fd (returns the fd number):
```bash
sudo LD_LIBRARY_PATH=./lib ./cli/mprox create
# Output: 3
```

### View help:
```bash
./cli/mprox help
```

**Note:** Configuration and enable commands won't work across invocations since the fd closes when the program exits.

## Option 4: Using the Daemon (Production Use)

### Start the daemon:
```bash
cd /home/areeb/MUTEX/src/userspace/daemon
sudo ./mutexd -c /path/to/config.json
```

### Control the daemon:
```bash
sudo ./mutexctl start
sudo ./mutexctl stop
sudo ./mutexctl status
sudo ./mutexctl reload
```

## Checking Statistics

### From a program:
```c
struct mutex_proxy_stats stats;
if (mprox_get_stats(fd, &stats) == 0) {
    printf("Bytes sent: %lu\n", stats.bytes_sent);
    printf("Bytes received: %lu\n", stats.bytes_received);
    printf("Active connections: %lu\n", stats.connections_active);
}
```

### Using the CLI (on an open fd):
```bash
sudo LD_LIBRARY_PATH=./lib ./cli/mprox stats <fd_number>
```

## Testing with a Real SOCKS5 Proxy

### 1. Install a SOCKS5 proxy server:
```bash
sudo apt-get install dante-server
# or
sudo apt-get install shadowsocks-libev
```

### 2. Start the proxy on localhost:1080

### 3. Run the example:
```bash
cd /home/areeb/MUTEX/src/userspace
sudo LD_LIBRARY_PATH=./lib ./examples/simple_proxy
```

### 4. The connection should now succeed through the proxy

## Complete Workflow Summary

```
1. CREATE:    Get a proxy file descriptor
   ↓
2. CONFIGURE: Set proxy type, address, and port
   ↓
3. ENABLE:    Activate proxying for this fd
   ↓
4. USE:       All socket operations go through proxy
   ↓
5. STATS:     Check performance metrics
   ↓
6. DISABLE:   Turn off proxying (optional)
   ↓
7. CLOSE:     Release the file descriptor
```

## API Reference

### libmutex Functions

- `int mprox_create(unsigned int flags)` - Create proxy file descriptor
- `int mprox_enable(int fd)` - Enable proxy on fd
- `int mprox_disable(int fd)` - Disable proxy on fd
- `int mprox_set_socks5(int fd, const char *addr, uint16_t port)` - Configure SOCKS5
- `int mprox_set_http(int fd, const char *addr, uint16_t port, int use_https)` - Configure HTTP/HTTPS
- `int mprox_get_config(int fd, struct mutex_proxy_config *config)` - Get configuration
- `int mprox_get_stats(int fd, struct mutex_proxy_stats *stats)` - Get statistics
- `int mprox_is_enabled(int fd)` - Check if proxy is enabled

### Proxy Types

- `PROXY_TYPE_SOCKS5` - SOCKS5 proxy
- `PROXY_TYPE_HTTP` - HTTP CONNECT proxy
- `PROXY_TYPE_HTTPS` - HTTPS proxy

### Creation Flags

- `MPROX_CLOEXEC` - Close on exec
- `MPROX_NONBLOCK` - Non-blocking mode

## Troubleshooting

### "Operation not permitted" error
- Make sure to run with `sudo`
- Verify the kernel module is loaded: `cat /sys/module/mutex_proxy/version`

### "Bad file descriptor" error
- The fd was closed between commands (expected with CLI tool)
- Use example programs or write code that keeps the fd open

### "Connection refused" error
- No proxy server is running at the configured address/port
- Start a SOCKS5/HTTP proxy server first

### Module not found
- Check if module is built-in: `cat /sys/module/mutex_proxy/version`
- If not built-in, load it: `sudo insmod /path/to/mutex_proxy.ko`

## Building the Project

### Build kernel module:
```bash
cd /home/areeb/MUTEX/src/module
make
```

### Build userspace tools:
```bash
cd /home/areeb/MUTEX/src/userspace
make
```

### Install library system-wide (optional):
```bash
cd /home/areeb/MUTEX/src/userspace/lib
sudo make install
```
