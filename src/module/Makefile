# MUTEX_PROXY Kernel Module Makefile
# Part of the MUTEX Project
# Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

ifneq ($(KERNELRELEASE),)
# Kbuild part - called from kernel build system
obj-m += mutex_proxy.o
mutex_proxy-objs := mutex_proxy_core.o mutex_conn_track.o mutex_packet_rewrite.o mutex_socks.o mutex_http_proxy.o mutex_transparent.o mutex_process_filter.o mutex_protocol_detect.o mutex_perf_opt.o mutex_security.o mutex_ipv6.o mutex_routing.o mutex_dns.o mutex_stats.o mutex_error.o mutex_logging.o mutex_testing.o
ccflags-y := -Wall -Wextra

else
# Normal Makefile part

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Build directory - cleaner build output
BUILD_DIR := $(CURDIR)/build
SRC_DIR := $(CURDIR)

# Compiler - defaults to gcc, can be overridden (e.g., make CC=gcc-12)
CC ?= gcc
export CC

# Default target - build the module
all:
	@echo "Building MUTEX_PROXY kernel module..."
	@mkdir -p $(BUILD_DIR)
	@# Create symlink to linux directory in build dir parent
	@mkdir -p $(BUILD_DIR)/../..
	@ln -sfn $(SRC_DIR)/../../linux $(BUILD_DIR)/../../linux 2>/dev/null || true
	@# Copy all source and header files to build directory
	@cp -f *.c $(BUILD_DIR)/ 2>/dev/null || true
	@cp -f *.h $(BUILD_DIR)/ 2>/dev/null || true
	@# Create Kbuild in build directory
	@echo 'obj-m += mutex_proxy.o' > $(BUILD_DIR)/Kbuild
		@echo 'mutex_proxy-objs := mutex_proxy_core.o mutex_conn_track.o mutex_packet_rewrite.o mutex_socks.o mutex_http_proxy.o mutex_transparent.o mutex_process_filter.o mutex_protocol_detect.o mutex_perf_opt.o mutex_security.o mutex_ipv6.o mutex_routing.o mutex_dns.o mutex_stats.o mutex_error.o mutex_logging.o mutex_testing.o' >> $(BUILD_DIR)/Kbuild
	@echo 'ccflags-y := -Wall -Wextra' >> $(BUILD_DIR)/Kbuild
	@# Build in the build directory
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) src=$(BUILD_DIR) modules
	@echo "Build complete! Module: $(BUILD_DIR)/mutex_proxy.ko"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@if [ -d $(BUILD_DIR) ]; then \
		$(MAKE) -C $(KDIR) M=$(BUILD_DIR) clean 2>/dev/null || true; \
	fi
	@rm -rf $(BUILD_DIR)
	@rm -f *.o *.ko *.mod.* .*.cmd Module.symvers modules.order
	@rm -rf .tmp_versions
	@echo "Clean complete!"

endif

# Install the module (requires root)
install:
	@echo "Installing MUTEX_PROXY module..."
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules_install
	@depmod -a
	@echo "Installation complete!"

# Load the module (requires root)
load:
	@echo "Loading MUTEX_PROXY module..."
	@if [ -f $(BUILD_DIR)/mutex_proxy.ko ]; then \
		sudo insmod $(BUILD_DIR)/mutex_proxy.ko; \
		echo "Module loaded. Check 'dmesg' for output."; \
	else \
		echo "Error: Module not built. Run 'make' first."; \
		exit 1; \
	fi

# Unload the module (requires root)
unload:
	@echo "Unloading MUTEX_PROXY module..."
	@sudo rmmod mutex_proxy 2>/dev/null || echo "Module not loaded"
	@echo "Module unloaded."

# Reload the module (requires root)
reload: unload load

# Show module information
info:
	@if [ -f $(BUILD_DIR)/mutex_proxy.ko ]; then \
		modinfo $(BUILD_DIR)/mutex_proxy.ko; \
	else \
		echo "Error: Module not built. Run 'make' first."; \
		exit 1; \
	fi

# Check if module is loaded
status:
	@lsmod | grep mutex_proxy || echo "Module not loaded"

# Display kernel messages
log:
	@dmesg | tail -20

# Run tests
test: test-build test-module test-netfilter

# Test: Build
test-build:
	@echo "========================================="
	@echo "TEST 1: Module Build Test"
	@echo "========================================="
	@$(MAKE) clean >/dev/null 2>&1
	@$(MAKE) all
	@if [ -f $(BUILD_DIR)/mutex_proxy.ko ]; then \
		echo "[PASS] Module built successfully"; \
	else \
		echo "[FAIL] Module build failed"; \
		exit 1; \
	fi
	@echo ""

# Test: Module loading/unloading
test-module:
	@echo "========================================="
	@echo "TEST 2: Module Load/Unload Test"
	@echo "========================================="
	@if [ ! -f $(BUILD_DIR)/mutex_proxy.ko ]; then \
		echo "[FAIL] Module not built"; \
		exit 1; \
	fi
	@echo "Loading module..."
	@sudo insmod $(BUILD_DIR)/mutex_proxy.ko 2>/dev/null || true
	@if lsmod | grep -q mutex_proxy; then \
		echo "[PASS] Module loaded successfully"; \
	else \
		echo "[FAIL] Module load failed"; \
		exit 1; \
	fi
	@sleep 1
	@echo "Checking module in lsmod..."
	@if lsmod | grep -q mutex_proxy; then \
		echo "[PASS] Module appears in lsmod"; \
	else \
		echo "[FAIL] Module not in lsmod"; \
		exit 1; \
	fi
	@echo "Unloading module..."
	@sudo rmmod mutex_proxy 2>/dev/null || true
	@sleep 1
	@if ! lsmod | grep -q mutex_proxy; then \
		echo "[PASS] Module unloaded successfully"; \
	else \
		echo "[FAIL] Module unload failed"; \
		exit 1; \
	fi
	@echo ""

# Test: Netfilter hooks
test-netfilter:
	@echo "========================================="
	@echo "TEST 3: Netfilter Hooks Test"
	@echo "========================================="
	@echo "Loading module with debug mode..."
	@sudo insmod $(BUILD_DIR)/mutex_proxy.ko debug=1 2>/dev/null || true
	@sleep 1
	@if dmesg | tail -50 | grep -q "MUTEX_PROXY:.*Registering netfilter hooks"; then \
		echo "[PASS] Netfilter hooks registered"; \
	else \
		echo "[FAIL] Netfilter hooks not registered"; \
		sudo rmmod mutex_proxy 2>/dev/null || true; \
		exit 1; \
	fi
	@echo "Checking hook registration..."
	@if dmesg | tail -50 | grep -q "PRE_ROUTING hook registered"; then \
		echo "[PASS] PRE_ROUTING hook registered"; \
	else \
		echo "[WARN] PRE_ROUTING hook registration not confirmed"; \
	fi
	@if dmesg | tail -50 | grep -q "POST_ROUTING hook registered"; then \
		echo "[PASS] POST_ROUTING hook registered"; \
	else \
		echo "[WARN] POST_ROUTING hook registration not confirmed"; \
	fi
	@if dmesg | tail -50 | grep -q "LOCAL_OUT hook registered"; then \
		echo "[PASS] LOCAL_OUT hook registered"; \
	else \
		echo "[WARN] LOCAL_OUT hook registration not confirmed"; \
	fi
	@echo "Testing module parameters..."
	@if [ -f /sys/module/mutex_proxy/parameters/debug ]; then \
		echo "[PASS] Debug parameter accessible"; \
	else \
		echo "[FAIL] Debug parameter not accessible"; \
	fi
	@if [ -f /sys/module/mutex_proxy/parameters/pre_routing_priority ]; then \
		echo "[PASS] pre_routing_priority parameter accessible"; \
	else \
		echo "[FAIL] pre_routing_priority parameter not accessible"; \
	fi
	@echo "Unloading module..."
	@sudo rmmod mutex_proxy 2>/dev/null || true
	@sleep 1
	@if dmesg | tail -50 | grep -q "MUTEX_PROXY:.*Unregistering netfilter hooks"; then \
		echo "[PASS] Netfilter hooks unregistered"; \
	else \
		echo "[WARN] Netfilter hooks unregistration not confirmed"; \
	fi
	@echo ""
	@echo "========================================="
	@echo "All tests completed!"
	@echo "========================================="

# Help target
help:
	@echo "MUTEX_PROXY Kernel Module Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the kernel module"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make test     - Run all tests (build, module, netfilter)"
	@echo "  make install  - Install module to system (requires root)"
	@echo "  make load     - Load the module (requires root)"
	@echo "  make unload   - Unload the module (requires root)"
	@echo "  make reload   - Unload and reload the module (requires root)"
	@echo "  make info     - Display module information"
	@echo "  make status   - Check if module is loaded"
	@echo "  make log      - Display recent kernel messages"
	@echo "  make help     - Display this help message"
	@echo ""
	@echo "Build output directory: $(BUILD_DIR)"
	@echo "Options:"
	@echo "  CC=<compiler> - Specify compiler (default: gcc)"
	@echo ""
	@echo "Examples:"
	@echo "  make                 # Use default gcc"
	@echo "  make CC=gcc-12       # Use gcc-12"
	@echo "  make CC=clang        # Use clang"

.PHONY: all clean install load unload reload info status log help test test-build test-module test-netfilter
