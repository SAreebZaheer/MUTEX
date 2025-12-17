# MUTEX Project - Root Makefile
# Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir

# Directories
MODULE_DIR := src/module
BUILD_DIR := $(MODULE_DIR)/build

# Default target
.PHONY: all
all: module

# Build the kernel module
.PHONY: module
module:
	@echo "Building MUTEX kernel module..."
	@$(MAKE) -C $(MODULE_DIR) all
	@echo "Build complete!"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning all build artifacts..."
	@$(MAKE) -C $(MODULE_DIR) clean
	@echo "Clean complete!"

# Run tests
.PHONY: test
test:
	@echo "Running MUTEX tests..."
	@$(MAKE) -C $(MODULE_DIR) test
	@echo "Tests complete!"

# Install module
.PHONY: install
install:
	@echo "Installing MUTEX module..."
	@$(MAKE) -C $(MODULE_DIR) install
	@echo "Installation complete!"

# Load module
.PHONY: load
load:
	@$(MAKE) -C $(MODULE_DIR) load

# Unload module
.PHONY: unload
unload:
	@$(MAKE) -C $(MODULE_DIR) unload

# Reload module
.PHONY: reload
reload:
	@$(MAKE) -C $(MODULE_DIR) reload

# Check module status
.PHONY: status
status:
	@$(MAKE) -C $(MODULE_DIR) status

# Display kernel messages
.PHONY: log
log:
	@$(MAKE) -C $(MODULE_DIR) log

# Help
.PHONY: help
help:
	@echo "MUTEX Project Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the kernel module"
	@echo "  make module   - Build the kernel module"
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make test     - Run all tests"
	@echo "  make install  - Install module to system (requires root)"
	@echo "  make load     - Load the module (requires root)"
	@echo "  make unload   - Unload the module (requires root)"
	@echo "  make reload   - Unload and reload the module (requires root)"
	@echo "  make status   - Check if module is loaded"
	@echo "  make log      - Display recent kernel messages"
	@echo "  make help     - Display this help message"
