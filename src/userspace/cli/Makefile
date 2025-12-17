# Makefile for mprox - MUTEX CLI tool

CC		= gcc
CFLAGS		= -Wall -Wextra -O2 -I../lib -I../../linux/include/uapi
LDFLAGS		= -L../lib -lmutex

# Installation directories
PREFIX		?= /usr/local
BINDIR		= $(PREFIX)/bin

# Binary name
BINARY		= mprox

# Source files
SRCS		= mprox.c
OBJS		= $(SRCS:.c=.o)

.PHONY: all clean install uninstall

all: $(BINARY)

# Build binary
$(BINARY): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Install binary
install: $(BINARY)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BINARY) $(DESTDIR)$(BINDIR)/
	@echo "Installation complete!"
	@echo "Run '$(BINARY) help' for usage information"

# Uninstall binary
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	@echo "Uninstallation complete!"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(BINARY)
	@echo "Clean complete!"

# Test the CLI tool
test: $(BINARY)
	@echo "Running basic CLI tests..."
	./$(BINARY) version
	./$(BINARY) help
	@echo "Tests complete!"
