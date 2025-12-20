# MUTEX Userspace Makefile

.PHONY: all lib cli daemon examples clean install uninstall help

all: lib cli daemon examples

# Build library first (required by cli and examples)
lib:
	@echo "Building libmutex..."
	$(MAKE) -C lib

# Build CLI tool
cli: lib
	@echo "Building mprox CLI..."
	$(MAKE) -C cli

# Build daemon (mutexd)
daemon:
	@echo "Building MUTEX daemon..."
	$(MAKE) -C daemon

# Build example programs
examples: lib
	@echo "Building examples..."
	$(MAKE) -C examples

# Clean all
clean:
	@echo "Cleaning all userspace components..."
	$(MAKE) -C lib clean
	$(MAKE) -C cli clean
	$(MAKE) -C daemon clean
	$(MAKE) -C examples clean
	@echo "All clean!"

# Install library, CLI tool, and daemon
install: lib cli daemon
	@echo "Installing libmutex..."
	$(MAKE) -C lib install
	@echo "Installing mprox CLI..."
	$(MAKE) -C cli install
	@echo "Installing MUTEX daemon..."
	$(MAKE) -C daemon install
	@echo "Installation complete!"
	@echo ""
	@echo "To use libmutex in your programs:"
	@echo "  gcc -o myapp myapp.c -lmutex"
	@echo ""
	@echo "To manage proxies from command line:"
	@echo "  mprox help"
	@echo ""
	@echo "To start the daemon:"
	@echo "  sudo mutexctl start"

# Uninstall library, CLI tool, and daemon
uninstall:
	@echo "Uninstalling..."
	$(MAKE) -C lib uninstall
	$(MAKE) -C cli uninstall
	$(MAKE) -C daemon uninstall
	@echo "Uninstallation complete!"

# Help
help:
	@echo "MUTEX Userspace Build System"
	@echo "============================"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build library, CLI, and examples (default)"
	@echo "  lib        - Build libmutex library only"
	@echo "  cli        - Build mprox CLI tool only"
	@echo "  examples   - Build example programs only"
	@echo "  clean      - Remove all build artifacts"
	@echo "  install    - Install library and CLI (requires root)"
	@echo "  uninstall  - Uninstall library and CLI (requires root)"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Installation directories:"
	@echo "  PREFIX     - Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build everything"
	@echo "  make clean        # Clean all"
	@echo "  sudo make install # Install system-wide"
	@echo "  make PREFIX=~/.local install  # Install to user directory"
