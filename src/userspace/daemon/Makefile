# Makefile for MUTEX userspace daemon and utilities
#
# Part of MUTEX (Multi-User Threaded Exchange Xfer)
# Kernel-level proxy module project

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS = -ljson-c

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc/mutex
SYSTEMDDIR = /etc/systemd/system
INITDIR = /etc/init.d
RUNDIR = /var/run
LOGDIR = /var/log

# Source files
DAEMON_SRC = src/mutexd.c src/daemon.c src/config.c
CTL_SRC = src/mutexctl.c

# Object files
DAEMON_OBJ = $(DAEMON_SRC:.c=.o)
CTL_OBJ = $(CTL_SRC:.c=.o)

# Targets
DAEMON = mutexd
CTL = mutexctl

.PHONY: all clean install uninstall install-systemd install-init

all: $(DAEMON) $(CTL)

$(DAEMON): $(DAEMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(CTL): $(CTL_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(DAEMON) $(CTL)
	rm -f $(DAEMON_OBJ) $(CTL_OBJ)
	rm -f src/*.o

install: all
	@echo "Installing MUTEX daemon and utilities..."
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -d $(DESTDIR)$(RUNDIR)
	install -d $(DESTDIR)$(LOGDIR)
	install -m 0755 $(DAEMON) $(DESTDIR)$(BINDIR)/
	install -m 0755 $(CTL) $(DESTDIR)$(BINDIR)/
	install -m 0644 config/mutex.conf.example $(DESTDIR)$(SYSCONFDIR)/
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/mutex.conf ]; then \
		cp config/mutex-minimal.conf $(DESTDIR)$(SYSCONFDIR)/mutex.conf; \
		echo "Installed default configuration to $(SYSCONFDIR)/mutex.conf"; \
	else \
		echo "Existing configuration preserved at $(SYSCONFDIR)/mutex.conf"; \
	fi
	@echo "Installation complete!"
	@echo ""
	@echo "To start the daemon:"
	@echo "  sudo mutexctl start"
	@echo ""
	@echo "To install systemd service:"
	@echo "  sudo make install-systemd"
	@echo ""
	@echo "To install init script:"
	@echo "  sudo make install-init"

install-systemd: install
	@echo "Installing systemd service..."
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 0644 systemd/mutexd.service $(DESTDIR)$(SYSTEMDDIR)/
	@echo "Systemd service installed!"
	@echo ""
	@echo "To enable and start:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable mutexd"
	@echo "  sudo systemctl start mutexd"

install-init: install
	@echo "Installing init script..."
	install -d $(DESTDIR)$(INITDIR)
	install -m 0755 init/mutexd $(DESTDIR)$(INITDIR)/
	@echo "Init script installed!"
	@echo ""
	@echo "To enable and start:"
	@echo "  sudo chkconfig mutexd on  # RHEL/CentOS"
	@echo "  sudo update-rc.d mutexd defaults  # Debian/Ubuntu"
	@echo "  sudo service mutexd start"

uninstall:
	@echo "Uninstalling MUTEX daemon and utilities..."
	rm -f $(DESTDIR)$(BINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(BINDIR)/$(CTL)
	rm -f $(DESTDIR)$(SYSTEMDDIR)/mutexd.service
	rm -f $(DESTDIR)$(INITDIR)/mutexd
	@echo "Uninstallation complete!"
	@echo ""
	@echo "Configuration files in $(SYSCONFDIR) were not removed."
	@echo "Remove them manually if desired."

# Development targets
.PHONY: check-deps help

check-deps:
	@echo "Checking dependencies..."
	@which $(CC) > /dev/null || (echo "Error: gcc not found" && exit 1)
	@pkg-config --exists json-c || (echo "Error: json-c library not found" && exit 1)
	@echo "All dependencies satisfied!"

help:
	@echo "MUTEX Userspace Daemon - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build daemon and control utility (default)"
	@echo "  clean            Remove built files"
	@echo "  install          Install binaries and configs"
	@echo "  install-systemd  Install systemd service file"
	@echo "  install-init     Install init script"
	@echo "  uninstall        Remove from system"
	@echo "  check-deps       Check for required dependencies"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX        Installation prefix (default: /usr/local)"
	@echo "  SYSCONFDIR    Configuration directory (default: /etc/mutex)"
	@echo ""
	@echo "Example:"
	@echo "  make"
	@echo "  sudo make install"
	@echo "  sudo make install-systemd"
	@echo "  sudo systemctl start mutexd"
