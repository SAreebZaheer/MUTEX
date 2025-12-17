# MUTEX - Multi-User Threaded Exchange Xfer

A kernel-level proxy service module for Linux that provides transparent network proxying through kernel space.

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

✅ **Branch 4 Complete:** `feature/netfilter-hooks`
- Netfilter hook integration at PRE_ROUTING, POST_ROUTING, LOCAL_OUT
- Multi-protocol packet filtering (TCP, UDP, ICMP)
- Runtime configurable hook priorities
- Global context list with RCU protection
- Per-context enable/disable via ioctl
- Comprehensive error handling with rate limiting
- Performance optimizations (likely/unlikely hints)
- Debugging infrastructure with module parameters
- Complete documentation and test suite

🚧 **In Progress:** Branch 3 - `feature/userspace-interface`

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

# Build the module
make

# Run automated tests (requires root)
sudo ./test_module.sh

# Test syscall functionality (Branch 2+)
gcc -o test_syscall test_syscall.c -Wall
sudo ./test_syscall enable 192.168.1.100 8080
sudo ./test_syscall disable 192.168.1.100 8080
sudo dmesg | grep KPROXY | tail -10

# Or manually load/unload
sudo insmod kproxy.ko
lsmod | grep kproxy
sudo dmesg | tail -10
sudo rmmod kproxy
```

## Project Structure

```
MUTEX/
├── docs/                   # Project documentation
│   ├── BRANCH_PLAN.md     # Development roadmap
│   ├── BRANCH_1_SUMMARY.md # Branch 1 completion summary
│   ├── BRANCH_2_SUMMARY.md # Branch 2 completion summary
│   ├── BRANCH_4_SUMMARY.md # Branch 4 completion summary
│   ├── NETFILTER_HOOKS.md # Netfilter integration documentation
│   ├── PDM-sequence.md    # Project scheduling
│   └── COMMIT_CONVENTIONS.md
├── src/                    # Source code
│   ├── module/            # Kernel module
│   │   ├── kproxy.c       # Main module implementation
│   │   ├── test_syscall.c # Userspace syscall test program
│   │   ├── Makefile       # Build configuration
│   │   └── test_module.sh # Automated testing
│   └── README.md          # Source documentation
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
- ✅ **Custom system call registration**
- ✅ **Syscall table hooking using kprobes**
- ✅ **CAP_NET_ADMIN capability checking**
- ✅ **Architecture-specific support (x86_64, i386, ARM64)**
- ✅ **Userspace test program**
- ✅ **Input validation and secure parameter passing**
- ✅ **Netfilter hooks (PRE_ROUTING, POST_ROUTING, LOCAL_OUT)**
- ✅ **Multi-protocol packet filtering (TCP/UDP/ICMP)**
- ✅ **Runtime configurable hook priorities**
- ✅ **Global context management with RCU**
- ✅ **Per-context packet interception control**
- ✅ **Debugging and performance optimization infrastructure**

### In Development
- 🚧 Userspace interface library
- 🚧 ioctl interface implementation

### Planned (See [BRANCH_PLAN.md](docs/BRANCH_PLAN.md))
- Connection tracking integration
- Packet rewriting and NAT
- SOCKS and HTTP proxy protocol support
- Transparent proxying
- Connection tracking and management
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
- **[Netfilter Hooks](docs/NETFILTER_HOOKS.md):** Netfilter integration architecture and usage
- **[Contributing Guide](CONTRIBUTING.md):** How to contribute to the project
- **[Source Documentation](src/README.md):** Technical documentation for the codebase

## Testing

The module has been tested on:
- Kernel version: 6.12.57+deb13-amd64
- Distribution: Debian-based systems

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
- **Milestone 1:** Foundation Complete ✅ (Week 3)
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
**Status:** In Development
