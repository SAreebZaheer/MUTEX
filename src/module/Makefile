# MUTEX Kernel Module Makefile
# Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

# Module name
obj-m += mutex.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Compiler flags
ccflags-y := -Wall -Wextra

# Default target - build the module
all:
	@echo "Building MUTEX kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
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
	@echo "Installing MUTEX module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	@depmod -a
	@echo "Installation complete!"

# Load the module (requires root)
load:
	@echo "Loading MUTEX module..."
	@sudo insmod mutex.ko
	@echo "Module loaded. Check 'dmesg' for output."

# Unload the module (requires root)
unload:
	@echo "Unloading MUTEX module..."
	@sudo rmmod mutex
	@echo "Module unloaded."

# Reload the module (requires root)
reload: unload load

# Show module information
info:
	@modinfo mutex.ko

# Check if module is loaded
status:
	@lsmod | grep mutex || echo "Module not loaded"

# Display kernel messages
log:
	@dmesg | tail -20

# Help target
help:
	@echo "MUTEX Kernel Module Build System"
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
