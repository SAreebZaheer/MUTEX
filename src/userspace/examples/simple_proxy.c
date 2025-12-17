/* SPDX-License-Identifier: GPL-2.0 */
/*
 * simple_proxy.c - Simple example of using MUTEX proxy
 *
 * This example demonstrates basic usage:
 * 1. Create a proxy file descriptor
 * 2. Configure it for SOCKS5
 * 3. Enable the proxy
 * 4. Make a network connection (which will be proxied)
 * 5. Clean up
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../lib/libmutex.h"

#define PROXY_ADDR	"127.0.0.1"
#define PROXY_PORT	1080

#define TARGET_ADDR	"93.184.216.34"	/* example.com */
#define TARGET_PORT	80

int main(void)
{
	int proxy_fd;
	int sock_fd;
	struct sockaddr_in target;
	const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
	char response[1024];
	ssize_t n;

	printf("MUTEX Simple Proxy Example\n");
	printf("==========================\n\n");

	/* Step 1: Create proxy file descriptor */
	printf("1. Creating proxy file descriptor...\n");
	proxy_fd = mprox_create(MUTEX_PROXY_CLOEXEC);
	if (proxy_fd < 0) {
		fprintf(stderr, "Failed to create proxy fd: %s\n",
			strerror(errno));
		return 1;
	}
	printf("   Created fd: %d\n\n", proxy_fd);

	/* Step 2: Configure SOCKS5 proxy */
	printf("2. Configuring SOCKS5 proxy...\n");
	printf("   Proxy: %s:%d\n", PROXY_ADDR, PROXY_PORT);
	if (mprox_set_socks5(proxy_fd, PROXY_ADDR, PROXY_PORT) < 0) {
		fprintf(stderr, "Failed to configure proxy: %s\n",
			strerror(errno));
		close(proxy_fd);
		return 1;
	}
	printf("   Configuration successful\n\n");

	/* Step 3: Enable the proxy */
	printf("3. Enabling proxy...\n");
	if (mprox_enable(proxy_fd) < 0) {
		fprintf(stderr, "Failed to enable proxy: %s\n",
			strerror(errno));
		close(proxy_fd);
		return 1;
	}
	printf("   Proxy enabled\n\n");

	/* Step 4: Make a network connection (will be proxied) */
	printf("4. Making HTTP connection to %s:%d...\n",
	       TARGET_ADDR, TARGET_PORT);
	printf("   (This connection will go through the proxy)\n\n");

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		fprintf(stderr, "Failed to create socket: %s\n",
			strerror(errno));
		close(proxy_fd);
		return 1;
	}

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_port = htons(TARGET_PORT);
	if (inet_pton(AF_INET, TARGET_ADDR, &target.sin_addr) <= 0) {
		fprintf(stderr, "Invalid address\n");
		close(sock_fd);
		close(proxy_fd);
		return 1;
	}

	if (connect(sock_fd, (struct sockaddr *)&target, sizeof(target)) < 0) {
		fprintf(stderr, "Connection failed: %s\n", strerror(errno));
		printf("   (This is expected if no SOCKS5 proxy is running)\n");
		close(sock_fd);
		close(proxy_fd);
		return 1;
	}

	printf("   Connected successfully!\n\n");

	/* Step 5: Send HTTP request */
	printf("5. Sending HTTP request...\n");
	if (write(sock_fd, request, strlen(request)) < 0) {
		fprintf(stderr, "Failed to send request: %s\n", strerror(errno));
		close(sock_fd);
		close(proxy_fd);
		return 1;
	}

	/* Step 6: Read response */
	printf("6. Reading response...\n\n");
	n = read(sock_fd, response, sizeof(response) - 1);
	if (n > 0) {
		response[n] = '\0';
		printf("--- Response (first %zd bytes) ---\n%s\n", n, response);
		printf("--- End of response ---\n\n");
	}

	/* Step 7: Check statistics */
	printf("7. Checking proxy statistics...\n");
	struct mutex_proxy_stats stats;
	if (mprox_get_stats(proxy_fd, &stats) == 0) {
		printf("   Bytes sent:     %llu\n",
		       (unsigned long long)stats.bytes_sent);
		printf("   Bytes received: %llu\n",
		       (unsigned long long)stats.bytes_received);
		printf("   Connections:    %llu\n",
		       (unsigned long long)stats.connections_total);
	}
	printf("\n");

	/* Step 8: Clean up */
	printf("8. Cleaning up...\n");
	close(sock_fd);

	if (mprox_disable(proxy_fd) < 0) {
		fprintf(stderr, "Failed to disable proxy: %s\n",
			strerror(errno));
	}

	close(proxy_fd);
	printf("   Done!\n\n");

	return 0;
}
