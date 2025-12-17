# Makefile for MUTEX examples

CC		= gcc
CFLAGS		= -Wall -Wextra -O2 -I../lib -I../../linux/include/uapi
LDFLAGS		= -L../lib -lmutex

# Example programs
EXAMPLES	= simple_proxy multi_fd poll_example

.PHONY: all clean

all: $(EXAMPLES)

# Build each example
simple_proxy: simple_proxy.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

multi_fd: multi_fd.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

poll_example: poll_example.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(EXAMPLES) *.o
	@echo "Clean complete!"

# Run all examples (for testing)
test: all
	@echo "Running examples..."
	@echo "\n=== simple_proxy ==="
	-./simple_proxy
	@echo "\n=== multi_fd ==="
	-./multi_fd
	@echo "\n=== poll_example (running for 5 seconds) ==="
	-timeout 5 ./poll_example || true
	@echo "\nExamples complete!"
