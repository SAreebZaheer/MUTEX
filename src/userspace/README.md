# MUTEX Userspace Components

This directory contains the userspace library, CLI tool, and examples for interacting with the MUTEX kernel-level proxy.

## Overview

The MUTEX userspace interface follows the Unix philosophy: **everything is a file**. The kernel module provides a single system call `mprox_create()` that returns a file descriptor. All proxy operations (configuration, statistics, control) are performed through standard file operations on this fd.

## Architecture

```
┌─────────────────────────────────────────┐
│         User Application                │
├─────────────────────────────────────────┤
│         libmutex.so                     │  ← High-level C API
│  (mprox_create, mprox_enable, etc.)    │
├─────────────────────────────────────────┤
│    System Call: mprox_create(flags)    │  ← Returns file descriptor
│      ↓                                  │
│  File Operations on FD:                 │
│    - ioctl() for control               │  ← Standard Unix operations
│    - read()  for status/stats          │
│    - write() for configuration         │
│    - poll()  for events                │
│    - close() for cleanup               │
├─────────────────────────────────────────┤
│         Kernel Module                   │
│   (anonymous inode + file_operations)   │
└─────────────────────────────────────────┘
```

## Components

### 1. Library (`lib/`)

**libmutex** - C library providing high-level API

- `libmutex.h` - Public API header
- `libmutex.c` - Implementation
- `API.md` - Comprehensive API documentation
- `Makefile` - Build system

**Key Features:**
- Wrapper for `mprox_create()` system call
- Helper functions for common operations
- SOCKS5/HTTP/HTTPS proxy configuration
- Statistics and event monitoring
- Error handling and errno mapping

### 2. CLI Tool (`cli/`)

**mprox** - Command-line utility for proxy management

```bash
# Create proxy fd
mprox create

# Configure SOCKS5 proxy
mprox config 3 -a 127.0.0.1 -p 1080 -t socks5

# Enable proxy
mprox enable 3

# Check status
mprox status 3

# View statistics
mprox stats 3

# Disable proxy
mprox disable 3
```

### 3. Examples (`examples/`)

**Example programs demonstrating the API:**

- `simple_proxy.c` - Basic usage walkthrough
- `multi_fd.c` - Multiple independent proxy fds
- `poll_example.c` - Event-driven programming with poll()

## Building

### Prerequisites

```bash
# Install build tools
sudo apt-get install build-essential  # Ubuntu/Debian
sudo dnf install gcc make             # Fedora/RHEL

# Ensure MUTEX kernel module is available
# (The userspace components can build without the kernel module,
#  but require it at runtime)
```

### Build Everything

```bash
cd src/userspace
make
```

This builds:
- `lib/libmutex.so` - Shared library
- `lib/libmutex.a` - Static library
- `cli/mprox` - CLI tool
- `examples/simple_proxy` - Example programs
- `examples/multi_fd`
- `examples/poll_example`

### Build Individual Components

```bash
# Library only
make lib

# CLI only (requires library)
make cli

# Examples only (requires library)
make examples
```

## Installation

### System-Wide Installation (requires root)

```bash
sudo make install
```

This installs:
- `/usr/local/lib/libmutex.so*` - Shared library
- `/usr/local/lib/libmutex.a` - Static library
- `/usr/local/include/libmutex.h` - Header file
- `/usr/local/lib/pkgconfig/libmutex.pc` - pkg-config file
- `/usr/local/bin/mprox` - CLI tool

### User-Local Installation

```bash
make PREFIX=~/.local install
```

Add to your shell profile:
```bash
export PATH="$HOME/.local/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH"
```

### Uninstall

```bash
sudo make uninstall
```

## Usage

### Using the Library

#### 1. Include the header

```c
#include <libmutex.h>
```

#### 2. Link with the library

```bash
# Using gcc
gcc -o myapp myapp.c -lmutex

# Using pkg-config (recommended)
gcc -o myapp myapp.c $(pkg-config --cflags --libs libmutex)
```

#### 3. Basic code example

```c
#include <libmutex.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd;

    /* Create proxy fd */
    fd = mprox_create(MUTEX_PROXY_CLOEXEC);
    if (fd < 0) {
        perror("mprox_create");
        return 1;
    }

    /* Configure SOCKS5 proxy */
    if (mprox_set_socks5(fd, "127.0.0.1", 1080) < 0) {
        perror("mprox_set_socks5");
        close(fd);
        return 1;
    }

    /* Enable proxy */
    if (mprox_enable(fd) < 0) {
        perror("mprox_enable");
        close(fd);
        return 1;
    }

    printf("Proxy enabled!\n");

    /* Your network code here - traffic will be proxied */
    /* ... */

    /* Clean up */
    mprox_disable(fd);
    close(fd);

    return 0;
}
```

### Using the CLI Tool

```bash
# Create a proxy fd (outputs the fd number)
FD=$(mprox create)
echo "Created fd: $FD"

# Configure SOCKS5 proxy
mprox config $FD -a 127.0.0.1 -p 1080 -t socks5

# Enable the proxy
mprox enable $FD

# Check status
mprox status $FD

# View real-time statistics
mprox stats $FD

# Disable when done
mprox disable $FD

# The fd is automatically cleaned up when the process exits
```

### Running Examples

```bash
# Run simple proxy example
cd examples
./simple_proxy

# Run multi-fd example
./multi_fd

# Run poll example (press Ctrl+C to exit)
./poll_example
```

## API Documentation

See [lib/API.md](lib/API.md) for comprehensive API documentation including:

- Function reference
- Data structures
- Error handling
- Code examples
- Best practices

## Development

### Project Structure

```
userspace/
├── Makefile           # Top-level build system
├── README.md          # This file
├── lib/               # Library
│   ├── libmutex.h     # Public API header
│   ├── libmutex.c     # Implementation
│   ├── API.md         # API documentation
│   └── Makefile       # Library build system
├── cli/               # CLI tool
│   ├── mprox.c        # CLI implementation
│   └── Makefile       # CLI build system
└── examples/          # Example programs
    ├── simple_proxy.c
    ├── multi_fd.c
    ├── poll_example.c
    ├── README.md
    └── Makefile
```

### Building for Development

```bash
# Build with debug symbols
make CFLAGS="-Wall -Wextra -g -O0"

# Build with address sanitizer (for debugging)
make CFLAGS="-Wall -Wextra -g -fsanitize=address" \
     LDFLAGS="-fsanitize=address"

# Static analysis with clang
clang --analyze lib/libmutex.c cli/mprox.c
```

### Testing

```bash
# Test library build
make lib
ldd lib/libmutex.so  # Check dependencies

# Test CLI build
make cli
./cli/mprox version
./cli/mprox help

# Test examples build
make examples
cd examples
./simple_proxy  # May fail if kernel module not loaded
```

### Debugging

```bash
# Debug with gdb
gdb ./cli/mprox
gdb ./examples/simple_proxy

# Check system calls
strace ./cli/mprox create
strace ./examples/simple_proxy

# Check library loading
LD_DEBUG=libs ./cli/mprox version

# Verbose make output
make V=1
```

## Requirements

### Build Requirements

- GCC 7.0+ or Clang 10.0+
- GNU Make 4.0+
- Linux kernel headers (for UAPI includes)

### Runtime Requirements

- Linux kernel 5.x+
- MUTEX kernel module loaded
- CAP_NET_ADMIN capability for creating proxy fds

### Optional

- pkg-config (for easier linking)
- SOCKS5/HTTP proxy server (for testing)

## Troubleshooting

### "Cannot find -lmutex"

The library is not installed or not in the library path.

```bash
# Install the library
sudo make -C lib install
sudo ldconfig

# Or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH
```

### "libmutex.h: No such file or directory"

Header not found. Either:

```bash
# Install system-wide
sudo make -C lib install

# Or specify include path
gcc -I/path/to/lib -o myapp myapp.c -lmutex
```

### "Operation not permitted" when calling mprox_create()

You need CAP_NET_ADMIN capability:

```bash
# Run as root
sudo ./myapp

# Or grant capability
sudo setcap cap_net_admin+ep ./myapp
```

### "Function not implemented"

The kernel module is not loaded:

```bash
# Load the MUTEX kernel module
sudo insmod /path/to/mutex_proxy.ko

# Verify it's loaded
lsmod | grep mutex
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines on contributing to the MUTEX project.

## License

- Library: LGPL-2.1 OR BSD-3-Clause
- CLI Tool: GPL-2.0
- Examples: GPL-2.0

## Authors

- Syed Areeb Zaheer
- Azeem
- Hamza Bin Aamir

## See Also

- [MUTEX Project Documentation](../../docs/)
- [Kernel Module](../module/)
- [Branch Plan](../../docs/BRANCH_PLAN.md)
- [API Documentation](lib/API.md)
