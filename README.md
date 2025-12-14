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
│   ├── PDM-sequence.md    # Project scheduling
│   └── COMMIT_CONVENTIONS.md
├── src/                    # Source code
│   ├── module/            # Kernel module
│   │   ├── kproxy.c       # Main module implementation
│   │   ├── Makefile       # Build configuration
│   │   └── test_module.sh # Automated testing
│   └── README.md          # Source documentation
├── CONTRIBUTING.md         # Contribution guidelines
└── README.md              # This file
```

## Features

### Implemented (v0.1.0)
- ✅ Basic LKM structure with init/exit functions
- ✅ Module metadata and licensing
- ✅ Kernel logging infrastructure
- ✅ Build system with Makefile
- ✅ Automated testing framework

### Planned (See [BRANCH_PLAN.md](docs/BRANCH_PLAN.md))
- System call registration
- Netfilter hooks for packet interception
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

**Last Updated:** December 14, 2025  
**Version:** 0.1.0  
**Status:** In Development
