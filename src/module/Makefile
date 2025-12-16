# MUTEX_PROXY Kernel Module Makefile
# Part of the MUTEX Project
# Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

# Module name
obj-m += mutex_proxy.o

# Additional object files for the module
mutex_proxy-objs := mutex_proxy_lkm.o mutex_proxy_core.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Use system's default gcc
export CC := gcc-12

# Compiler flags
ccflags-y := -Wall -Wextra
ccflags-y += -DKBUILD_MODFILE='"mutex_proxy"'

# Disable flags not supported by current GCC version
KCPPFLAGS := $(filter-out -ftrivial-auto-var-init=zero,$(KCPPFLAGS))
CFLAGS_KERNEL := $(filter-out -ftrivial-auto-var-init=zero,$(CFLAGS_KERNEL))
CFLAGS_MODULE := $(filter-out -ftrivial-auto-var-init=zero,$(CFLAGS_MODULE))

# Default target - build the module
all:
	@echo "Building MUTEX_PROXY kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_CFLAGS_MODULE="$(filter-out -ftrivial-auto-var-init=zero,$(KBUILD_CFLAGS_MODULE))" modules
	@echo "Build complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f *.o *.ko *.mod.* .*.cmd Module.symvers modules.order
	@rm -rf .tmp_versions
	@echo "Clean complete!"

# Install the module (requires root)
install:
	@echo "Installing MUTEX_PROXY module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	@depmod -a
	@echo "Installation complete!"

# Load the module (requires root)
load:
	@echo "Loading MUTEX_PROXY module..."
	@sudo insmod mutex_proxy.ko
	@echo "Module loaded. Check 'dmesg' for output."

# Unload the module (requires root)
unload:
	@echo "Unloading MUTEX_PROXY module..."
	@sudo rmmod mutex_proxy
	@echo "Module unloaded."

# Reload the module (requires root)
reload: unload load

# Show module information
info:
	@modinfo mutex_proxy.ko

# Check if module is loaded
status:
	@lsmod | grep mutex_proxy || echo "Module not loaded"

# Display kernel messages
log:
	@dmesg | tail -20

# Help target
help:
	@echo "MUTEX_PROXY Kernel Module Build System (MUTEX Project)"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the kernel module"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Install module to system (requires root)"
	@echo "  make load     - Load the module (requires root)"
	@echo "  make unload   - Unload the module (requires root)"
	@echo "  make reload   - Unload and reload the module (requires root)"
	@echo "  make info     - Display module information"
	@echo "  make status   - Check if module is loaded"
	@echo "  make log      - Display recent kernel messages"
	@echo "  make help     - Display this help message"

.PHONY: all clean install load unload reload info status log help
