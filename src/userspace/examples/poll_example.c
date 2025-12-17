/* SPDX-License-Identifier: GPL-2.0 */
/*
 * poll_example.c - Poll/select/epoll example
 *
 * This example demonstrates:
 * 1. Using poll() to wait for events on proxy fd
 * 2. Event notification when statistics update
 * 3. Non-blocking mode with event-driven programming
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include "../lib/libmutex.h"

static volatile int running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	running = 0;
}

int main(void)
{
	int proxy_fd;
	struct mutex_proxy_stats stats;
	int event_count = 0;

	printf("MUTEX Poll/Event Example\n");
	printf("========================\n\n");

	/* Set up signal handler for clean exit */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Create proxy fd with non-blocking flag */
	printf("Creating proxy fd with non-blocking mode...\n");
	proxy_fd = mprox_create(MUTEX_PROXY_CLOEXEC | MUTEX_PROXY_NONBLOCK);
	if (proxy_fd < 0) {
		fprintf(stderr, "Failed to create proxy fd: %s\n",
			strerror(errno));
		return 1;
	}
	printf("  fd = %d\n\n", proxy_fd);

	/* Configure proxy */
	printf("Configuring SOCKS5 proxy...\n");
	if (mprox_set_socks5(proxy_fd, "127.0.0.1", 1080) < 0) {
		fprintf(stderr, "Failed to configure proxy: %s\n",
			strerror(errno));
		close(proxy_fd);
		return 1;
	}

	/* Enable proxy */
	printf("Enabling proxy...\n");
	if (mprox_enable(proxy_fd) < 0) {
		fprintf(stderr, "Failed to enable proxy: %s\n",
			strerror(errno));
		close(proxy_fd);
		return 1;
	}
	printf("Proxy enabled\n\n");

	/* Event loop using poll() */
	printf("Starting event loop (press Ctrl+C to exit)...\n");
	printf("Waiting for proxy events...\n\n");

	while (running) {
		struct pollfd pfd;
		int ret;

		pfd.fd = proxy_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		/* Wait for event with 5-second timeout */
		ret = poll(&pfd, 1, 5000);

		if (ret < 0) {
			if (errno == EINTR) {
				/* Interrupted by signal, continue */
				continue;
			}
			fprintf(stderr, "poll() failed: %s\n", strerror(errno));
			break;
		}

		if (ret == 0) {
			/* Timeout - no events */
			printf("  [timeout] No events in last 5 seconds\n");
			continue;
		}

		/* Event occurred */
		event_count++;

		if (pfd.revents & POLLIN) {
			printf("  [event %d] Proxy event detected!\n", event_count);

			/* Read statistics */
			if (mprox_get_stats(proxy_fd, &stats) == 0) {
				printf("    Bytes sent:     %llu\n",
				       (unsigned long long)stats.bytes_sent);
				printf("    Bytes received: %llu\n",
				       (unsigned long long)stats.bytes_received);
				printf("    Connections:    %llu active, %llu total\n",
				       (unsigned long long)stats.connections_active,
				       (unsigned long long)stats.connections_total);
			}
			printf("\n");
		}

		if (pfd.revents & (POLLERR | POLLHUP)) {
			fprintf(stderr, "Error or hangup on proxy fd\n");
			break;
		}
	}

	printf("\nShutting down...\n");

	/* Disable and close */
	mprox_disable(proxy_fd);
	close(proxy_fd);

	printf("Total events received: %d\n", event_count);
	printf("Done!\n");

	return 0;
}
