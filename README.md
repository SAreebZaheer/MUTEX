# MUTEX - Multi-User Threaded Exchange Xfer

A kernel-level proxy service module for Linux that provides transparent network proxying through kernel space.

Any mention of MUTEX is a direct reference to the development team's name unless specified explicitly.

## Project Overview

MUTEX is a loadable kernel module (LKM) that creates a kernel-level proxy service by hooking into the Linux network stack. This approach eliminates the need for user-level proxying typically required by VPNs and proxy services, providing better performance and transparency.

**Course:** CS 311 Operating Systems  
**Team Members:**
- Syed Areeb Zaheer
- Azeem
- Hamza Bin Aamir

## Current Status

✅ **Branch 1 Complete:** `feature/basic-module-structure`
- Basic kernel module infrastructure
- Module loading/unloading functionality
- Proper logging and error handling
- Build system and testing scripts

✅ **Branch 2 Complete:** `feature/syscall-registration`
- Custom system call registration mechanism
- Syscall table hooking using kprobes
- CAP_NET_ADMIN capability checking
- Architecture-specific syscall support (x86_64, i386, ARM64)
- Userspace test program for syscall validation
- Input validation and secure parameter passing

✅ **Branch 3 Complete:** `feature/userspace-interface`
- Userspace C library (libmutex) for proxy API
- Command-line tool (mprox) for proxy management
- File descriptor-based design (mprox_create syscall)
- Example programs demonstrating API usage
- Comprehensive API documentation
- Complete build system with install/uninstall support

✅ **Branch 5 Complete:** `feature/proxy-configuration`
- Multiple proxy servers per file descriptor (up to 8)
- Three selection strategies: round-robin, failover, random
- Comprehensive configuration validation
- Thread-safe proxy configuration via write() and ioctl()
- Per-server authentication support
- Priority-based failover mechanism
- IPv4/IPv6 address support

🚧 **In Progress:** Branch 4 - `feature/netfilter-hooks`

## Quick Start

### Prerequisites

```bash
# Install kernel headers
sudo apt-get install linux-headers-$(uname -r)  # Debian/Ubuntu
sudo dnf install kernel-devel kernel-headers     # Fedora/RHEL
sudo pacman -S linux-headers                     # Arch Linux
```

### Building and Testing

```bash
# Navigate to module directory
cd src/module

# Build the kernel module
make

# Run automated tests (requires root)
sudo ./test_module.sh

# Load the module
sudo insmod mutex_proxy.ko
lsmod | grep mutex_proxy
sudo dmesg | tail -10
sudo rmmod mutex_proxy

# Build userspace library and tools (Branch 3+)
cd ../userspace
make

# Test the CLI tool
LD_LIBRARY_PATH=./lib ./cli/mprox version
LD_LIBRARY_PATH=./lib ./cli/mprox help

# Install library and CLI system-wide (optional)
sudo make install

# Run example programs
cd examples
LD_LIBRARY_PATH=../lib ./simple_proxy
LD_LIBRARY_PATH=../lib ./multi_fd
```

## Project Structure

```
MUTEX/
├── docs/                   # Project documentation
│   ├── BRANCH_PLAN.md     # Development roadmap
│   ├── BRANCH_1_SUMMARY.md # Branch 1 completion summary
│   ├── BRANCH_2_SUMMARY.md # Branch 2 completion summary
│   ├── BRANCH_3_SUMMARY.md # Branch 3 completion summary
│   ├── BRANCH_5_SUMMARY.md # Branch 5 completion summary
│   ├── PDM-sequence.md    # Project scheduling
│   ├── COMMIT_CONVENTIONS.md
│   └── TESTING.md
├── src/                    # Source code
│   ├── module/            # Kernel module
│   │   ├── mutex_proxy.c  # Main module implementation
│   │   ├── mutex_proxy.h  # Module header
│   │   ├── syscall.c      # System call implementation
│   │   ├── file_ops.c     # File descriptor operations
│   │   ├── Makefile       # Build configuration
│   │   └── test_module.sh # Automated testing
│   ├── userspace/         # Userspace components
│   │   ├── lib/           # libmutex library
│   │   │   ├── libmutex.h # Public API header
│   │   │   ├── libmutex.c # Library implementation
│   │   │   ├── API.md     # API documentation
│   │   │   └── Makefile
│   │   ├── cli/           # mprox CLI tool
│   │   │   ├── mprox.c
│   │   │   └── Makefile
│   │   ├── examples/      # Example programs
│   │   │   ├── simple_proxy.c
│   │   │   ├── multi_fd.c
│   │   │   ├── poll_example.c
│   │   │   ├── README.md
│   │   │   └── Makefile
│   │   ├── Makefile       # Top-level build
│   │   └── README.md      # Userspace documentation
│   └── README.md          # Source documentation
├── linux/                 # Linux kernel UAPI headers
│   └── include/
│       └── uapi/
│           └── linux/
│               └── mutex_proxy.h  # Kernel-userspace interface
├── CONTRIBUTING.md         # Contribution guidelines
└── README.md              # This file
```

## Features

### Implemented (v0.4.0)
- ✅ Basic LKM structure with init/exit functions
- ✅ Module metadata and licensing
- ✅ Kernel logging infrastructure
- ✅ Build system with Makefile
- ✅ Automated testing framework
- ✅ **Custom system call registration (mprox_create)**
- ✅ **File descriptor-based proxy interface**
- ✅ **Anonymous inode implementation for proxy fds**
- ✅ **ioctl commands (enable/disable/config/stats)**
- ✅ **Per-fd proxy configuration and state**
- ✅ **Userspace C library (libmutex)**
- ✅ **Command-line tool (mprox)**
- ✅ **Example programs and comprehensive documentation**
- ✅ **pkg-config support for library**
- ✅ **Multiple proxy servers per fd (up to 8)**
- ✅ **Proxy selection strategies (round-robin, failover, random)**
- ✅ **Comprehensive configuration validation**
- ✅ **Thread-safe configuration operations**

### In Development
- 🚧 Netfilter hooks for packet interception

### Planned (See [BRANCH_PLAN.md](docs/BRANCH_PLAN.md))
- Connection tracking and management
- Packet rewriting for proxy routing
- SOCKS and HTTP proxy protocol support
- Transparent proxying
- Performance optimization
- Security hardening
- IPv6 support
- And much more...

## Development

### Branch Strategy

We follow a feature-branch workflow. See [BRANCH_PLAN.md](docs/BRANCH_PLAN.md) for the complete development roadmap.

Current branch: `feature/basic-module-structure`

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines, including:
- Code style requirements
- Commit message conventions
- Testing procedures
- Pull request process

### Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```bash
feat(scope): add new feature
fix(scope): fix a bug
docs(scope): documentation changes
test(scope): add or update tests
```

See [docs/COMMIT_CONVENTIONS.md](docs/COMMIT_CONVENTIONS.md) for details.

## Documentation

- **[Branch Plan](docs/BRANCH_PLAN.md):** Complete development roadmap with 25 feature branches
- **[PDM Sequence](docs/PDM-sequence.md):** Project scheduling and critical path analysis
- **[Contributing Guide](CONTRIBUTING.md):** How to contribute to the project
- **[Source Documentation](src/README.md):** Technical documentation for the codebase
- **[Userspace Library API](src/userspace/lib/API.md):** Complete libmutex API reference
- **[Userspace Guide](src/userspace/README.md):** Building and using userspace components

### Running Tests

```bash
cd src/module
sudo ./test_module.sh
```

All tests pass successfully with no kernel panics.

## Safety Warning

⚠️ **This is kernel-level code and can crash your system if buggy!**

- Always test in a virtual machine first
- Back up important data before testing
- Use version control to track changes
- Monitor kernel logs (`dmesg`) for errors

## License

GPL (GNU General Public License)

## Project Timeline

- **Total Duration:** ~31 weeks (7.5 months)
- **Milestone 1:** Foundation Complete ✅ (Week 5)
  - Branch 1: Module structure ✅
  - Branch 2: System call and fd operations ✅
  - Branch 3: Userspace interface ✅
  - Branch 5: Proxy configuration ✅
- **Milestone 2:** Core Networking (Week 10)
- **Milestone 3:** Proxy Protocols (Week 15)
- **Milestone 4:** Production Ready (Week 23)
- **Milestone 5:** Release Candidate (Week 28)
- **Milestone 6:** Version 1.0 (Week 31)

## Contact

For questions or issues, please open an issue on the project repository or contact the team members.

---

**Last Updated:** December 17, 2025  
**Version:** 0.4.0  
**Status:** In Development - Foundation Complete (Branches 1, 2, 3, 5)
