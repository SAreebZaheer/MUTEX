# MUTEX Userspace Examples

This directory contains example programs demonstrating the MUTEX proxy API.

## Examples

### 1. simple_proxy.c
Basic usage of the MUTEX proxy API:
- Create a proxy file descriptor
- Configure SOCKS5 proxy
- Enable the proxy
- Make HTTP connection through proxy
- View statistics

**Build:**
```bash
make simple_proxy
```

**Run:**
```bash
./simple_proxy
```

**Note:** Requires a SOCKS5 proxy running on 127.0.0.1:1080

---

### 2. multi_fd.c
Demonstrates using multiple proxy file descriptors:
- Create multiple independent proxy fds
- Configure each with different settings (SOCKS5, HTTP, HTTPS)
- Show that each fd is independent
- Demonstrate fd lifecycle management

**Build:**
```bash
make multi_fd
```

**Run:**
```bash
./multi_fd
```

---

### 3. poll_example.c
Event-driven programming with poll():
- Use non-blocking mode
- Wait for events using poll()
- Handle statistics updates
- Signal handling for clean shutdown

**Build:**
```bash
make poll_example
```

**Run:**
```bash
./poll_example
```

**Note:** Press Ctrl+C to exit

---

## Building All Examples

```bash
make
```

## Cleaning

```bash
make clean
```

## Requirements

- Linux kernel with MUTEX module loaded
- `libmutex` library installed
- C compiler (gcc or clang)
- SOCKS5 proxy server for testing (optional)

## Testing Without Proxy Server

Most examples will run without an actual proxy server, but network connections will fail. The examples demonstrate the API usage regardless.

To test with a real proxy, install and run a SOCKS5 server:

```bash
# Using dante (sockd)
sudo apt-get install dante-server

# Or using shadowsocks
pip install shadowsocks
sslocal -s SERVER_IP -p 8388 -l 1080 -k PASSWORD
```

## API Documentation

See `../lib/libmutex.h` for full API documentation.
