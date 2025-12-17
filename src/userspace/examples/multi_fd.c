/* SPDX-License-Identifier: GPL-2.0 */
/*
 * multi_fd.c - Multiple proxy file descriptors example
 *
 * This example demonstrates:
 * 1. Creating multiple proxy fds with different configurations
 * 2. Each fd has independent proxy settings
 * 3. Different processes can use different proxies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../lib/libmutex.h"

int main(void)
{
	int fd1, fd2, fd3;
	struct mutex_proxy_config config;

	printf("MUTEX Multiple File Descriptors Example\n");
	printf("========================================\n\n");

	/* Create three different proxy fds */
	printf("Creating three proxy file descriptors...\n");

	fd1 = mprox_create(MUTEX_PROXY_CLOEXEC);
	if (fd1 < 0) {
		fprintf(stderr, "Failed to create fd1: %s\n", strerror(errno));
		return 1;
	}
	printf("  fd1 = %d\n", fd1);

	fd2 = mprox_create(MUTEX_PROXY_CLOEXEC);
	if (fd2 < 0) {
		fprintf(stderr, "Failed to create fd2: %s\n", strerror(errno));
		close(fd1);
		return 1;
	}
	printf("  fd2 = %d\n", fd2);

	fd3 = mprox_create(MUTEX_PROXY_CLOEXEC | MUTEX_PROXY_NONBLOCK);
	if (fd3 < 0) {
		fprintf(stderr, "Failed to create fd3: %s\n", strerror(errno));
		close(fd1);
		close(fd2);
		return 1;
	}
	printf("  fd3 = %d\n\n", fd3);

	/* Configure each fd differently */
	printf("Configuring each fd with different proxy settings...\n");

	/* fd1: SOCKS5 proxy on localhost:1080 */
	printf("  fd1: SOCKS5 on 127.0.0.1:1080\n");
	if (mprox_set_socks5(fd1, "127.0.0.1", 1080) < 0) {
		fprintf(stderr, "Failed to configure fd1: %s\n", strerror(errno));
		goto cleanup;
	}

	/* fd2: HTTP proxy on localhost:8080 */
	printf("  fd2: HTTP on 127.0.0.1:8080\n");
	if (mprox_set_http(fd2, "127.0.0.1", 8080, 0) < 0) {
		fprintf(stderr, "Failed to configure fd2: %s\n", strerror(errno));
		goto cleanup;
	}

	/* fd3: HTTPS proxy on localhost:8443 */
	printf("  fd3: HTTPS on 127.0.0.1:8443\n");
	if (mprox_set_http(fd3, "127.0.0.1", 8443, 1) < 0) {
		fprintf(stderr, "Failed to configure fd3: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("\n");

	/* Verify configurations */
	printf("Verifying configurations...\n");

	/* Check fd1 */
	if (mprox_get_config(fd1, &config) == 0) {
		printf("  fd1: type=%u, port=%u\n",
		       config.proxy_type, config.proxy_port);
	}

	/* Check fd2 */
	if (mprox_get_config(fd2, &config) == 0) {
		printf("  fd2: type=%u, port=%u\n",
		       config.proxy_type, config.proxy_port);
	}

	/* Check fd3 */
	if (mprox_get_config(fd3, &config) == 0) {
		printf("  fd3: type=%u, port=%u\n",
		       config.proxy_type, config.proxy_port);
	}

	printf("\n");

	/* Enable only fd1 and fd2 */
	printf("Enabling fd1 and fd2 (leaving fd3 disabled)...\n");
	if (mprox_enable(fd1) < 0) {
		fprintf(stderr, "Failed to enable fd1: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("  fd1 enabled\n");

	if (mprox_enable(fd2) < 0) {
		fprintf(stderr, "Failed to enable fd2: %s\n", strerror(errno));
		goto cleanup;
	}
	printf("  fd2 enabled\n\n");

	/* Demonstrate that each fd is independent */
	printf("Demonstrating fd independence:\n");
	printf("  Each fd maintains its own configuration\n");
	printf("  Multiple fds can be active simultaneously\n");
	printf("  Closing one fd doesn't affect others\n\n");

	/* Close fd2 */
	printf("Closing fd2...\n");
	close(fd2);
	fd2 = -1;
	printf("  fd2 closed, but fd1 and fd3 remain open\n\n");

	/* Verify fd1 still works */
	printf("Verifying fd1 still works...\n");
	if (mprox_get_config(fd1, &config) == 0) {
		printf("  fd1 still configured: type=%u, port=%u\n",
		       config.proxy_type, config.proxy_port);
	}

	printf("\n");

cleanup:
	/* Clean up */
	printf("Cleaning up remaining file descriptors...\n");
	if (fd1 >= 0) {
		mprox_disable(fd1);
		close(fd1);
		printf("  fd1 closed\n");
	}
	if (fd2 >= 0) {
		mprox_disable(fd2);
		close(fd2);
		printf("  fd2 closed\n");
	}
	if (fd3 >= 0) {
		close(fd3);
		printf("  fd3 closed\n");
	}

	printf("\nDone!\n");
	return 0;
}
