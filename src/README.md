# MUTEX Source Code

This directory contains the source code for the MUTEX kernel module and associated userspace utilities.

## Directory Structure

```
src/
├── module/          # Kernel module source code
│   ├── kproxy.c     # Main module implementation
│   └── Makefile     # Build configuration
├── userspace/       # Userspace utilities (to be implemented)
└── tests/           # Test suite (to be implemented)
```

## Building the Module

### Prerequisites

Ensure you have the kernel headers installed for your current kernel:

```bash
# Fedora/RHEL
sudo dnf install kernel-devel kernel-headers

# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# Arch Linux
sudo pacman -S linux-headers
```

### Build Commands

```bash
# Navigate to the module directory
cd src/module

# Build the module
make

# Clean build artifacts
make clean
```

## Testing the Module

### Load the Module

```bash
# Load the module
sudo make load

# Or manually
sudo insmod kproxy.ko
```

### Verify the Module is Loaded

```bash
# Check loaded modules
lsmod | grep kproxy

# Check module information
modinfo kproxy.ko

# View kernel messages
dmesg | tail -20
```

### Unload the Module

```bash
# Unload the module
sudo make unload

# Or manually
sudo rmmod kproxy
```

## Module Information

- **Name:** KPROXY (Kernel Proxy)
- **Project:** MUTEX (Multi-User Threaded Exchange Xfer)
- **Version:** 0.1.0
- **License:** GPL
- **Authors:** Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

## Current Features

- Basic module structure with init/exit functions
- Proper kernel logging
- Module metadata
- Build system with Makefile

## Next Steps

See the [branch plan](../docs/BRANCH_PLAN.md) for upcoming features:
- System call registration
- Netfilter hooks
- Proxy configuration
- And more...

## Troubleshooting

### Module won't build

**Error:** `Cannot find kernel headers`
```bash
# Install kernel headers matching your kernel version
uname -r  # Check your kernel version
sudo apt-get install linux-headers-$(uname -r)
```

**Error:** `Permission denied`
```bash
# Use sudo for loading/unloading
sudo insmod kproxy.ko
```

### Module won't load

**Error:** `Invalid module format`
```bash
# Rebuild for your kernel version
make clean
make
```

Check `dmesg` for detailed error messages:
```bash
dmesg | tail -50
```

## Development

When making changes:

1. Make your changes to the source files
2. Clean previous builds: `make clean`
3. Rebuild: `make`
4. Reload the module: `sudo make reload`
5. Check logs: `dmesg | tail -20`

## Safety Notes

- **Always test in a virtual machine first**
- **Kernel modules can crash your system if buggy**
- **Back up important data before testing**
- **Use version control to track changes**

## License

This project is licensed under the GPL. See the LICENSE file for details.
