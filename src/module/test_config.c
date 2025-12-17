// SPDX-License-Identifier: GPL-2.0
/*
 * test_config.c - Test program for proxy configuration features
 *
 * Copyright (C) 2025 MUTEX Team
 *
 * Demonstrates:
 * - Setting up multiple proxy servers
 * - Different selection strategies (round-robin, failover, random)
 * - Reading configuration back
 * - Using both write() and ioctl() interfaces
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "../../linux/include/uapi/linux/mutex_proxy.h"

#define __NR_mutex_proxy_create 471

int main(void)
{
	int fd;
	struct mutex_proxy_config config;
	struct mutex_proxy_stats stats;
	int ret;

	printf("=== MUTEX Proxy Configuration Test ===\n\n");

	/* Create proxy fd */
	printf("Creating proxy file descriptor...\n");
	fd = syscall(__NR_mutex_proxy_create, 0);
	if (fd < 0) {
		perror("mprox_create");
		return 1;
	}
	printf("Created fd %d\n\n", fd);

	/* Initialize configuration */
	memset(&config, 0, sizeof(config));
	config.version = 1;
	config.num_servers = 3;
	config.selection_strategy = PROXY_SELECT_ROUND_ROBIN;

	/* Configure first server (SOCKS5) */
	config.servers[0].proxy_type = PROXY_TYPE_SOCKS5;
	config.servers[0].proxy_port = 1080;
	config.servers[0].flags = PROXY_CONFIG_ACTIVE;
	config.servers[0].priority = 10;
	/* IP: 192.168.1.10 */
	config.servers[0].proxy_addr[0] = 192;
	config.servers[0].proxy_addr[1] = 168;
	config.servers[0].proxy_addr[2] = 1;
	config.servers[0].proxy_addr[3] = 10;

	/* Configure second server (HTTP) */
	config.servers[1].proxy_type = PROXY_TYPE_HTTP;
	config.servers[1].proxy_port = 8080;
	config.servers[1].flags = PROXY_CONFIG_ACTIVE;
	config.servers[1].priority = 20;
	/* IP: 192.168.1.20 */
	config.servers[1].proxy_addr[0] = 192;
	config.servers[1].proxy_addr[1] = 168;
	config.servers[1].proxy_addr[2] = 1;
	config.servers[1].proxy_addr[3] = 20;

	/* Configure third server (HTTPS) */
	config.servers[2].proxy_type = PROXY_TYPE_HTTPS;
	config.servers[2].proxy_port = 8443;
	config.servers[2].flags = PROXY_CONFIG_ACTIVE;
	config.servers[2].priority = 30;
	/* IP: 192.168.1.30 */
	config.servers[2].proxy_addr[0] = 192;
	config.servers[2].proxy_addr[1] = 168;
	config.servers[2].proxy_addr[2] = 1;
	config.servers[2].proxy_addr[3] = 30;

	/* Write configuration using write() */
	printf("Writing configuration with 3 servers (round-robin)...\n");
	ret = write(fd, &config, sizeof(config));
	if (ret < 0) {
		perror("write config");
		close(fd);
		return 1;
	}
	printf("Configuration written successfully\n\n");

	/* Read configuration back */
	printf("Reading configuration back...\n");
	ret = read(fd, &config, sizeof(config));
	if (ret < 0) {
		perror("read config");
		close(fd);
		return 1;
	}

	printf("Configuration:\n");
	printf("  Version: %u\n", config.version);
	printf("  Number of servers: %u\n", config.num_servers);
	printf("  Selection strategy: %u (1=round-robin, 2=failover, 3=random)\n",
	       config.selection_strategy);
	printf("  Current server: %u\n\n", config.current_server);

	for (unsigned int i = 0; i < config.num_servers; i++) {
		printf("  Server %u:\n", i);
		printf("    Type: %u (1=SOCKS5, 2=HTTP, 3=HTTPS)\n",
		       config.servers[i].proxy_type);
		printf("    Port: %u\n", config.servers[i].proxy_port);
		printf("    Address: %u.%u.%u.%u\n",
		       config.servers[i].proxy_addr[0],
		       config.servers[i].proxy_addr[1],
		       config.servers[i].proxy_addr[2],
		       config.servers[i].proxy_addr[3]);
		printf("    Priority: %u\n", config.servers[i].priority);
		printf("    Active: %s\n",
		       (config.servers[i].flags & PROXY_CONFIG_ACTIVE) ? "yes" : "no");
		printf("\n");
	}

	/* Test ioctl interface - enable proxy */
	printf("Enabling proxy using ioctl...\n");
	ret = ioctl(fd, MUTEX_PROXY_IOC_ENABLE);
	if (ret < 0) {
		perror("ioctl enable");
		close(fd);
		return 1;
	}
	printf("Proxy enabled\n\n");

	/* Read statistics */
	printf("Reading statistics...\n");
	ret = read(fd, &stats, sizeof(stats));
	if (ret < 0) {
		perror("read stats");
		close(fd);
		return 1;
	}

	printf("Statistics:\n");
	printf("  Bytes sent: %llu\n", (unsigned long long)stats.bytes_sent);
	printf("  Bytes received: %llu\n", (unsigned long long)stats.bytes_received);
	printf("  Packets sent: %llu\n", (unsigned long long)stats.packets_sent);
	printf("  Packets received: %llu\n", (unsigned long long)stats.packets_received);
	printf("  Active connections: %llu\n", (unsigned long long)stats.connections_active);
	printf("  Total connections: %llu\n\n", (unsigned long long)stats.connections_total);

	/* Test failover strategy */
	printf("Changing to failover strategy...\n");
	config.selection_strategy = PROXY_SELECT_FAILOVER;
	ret = ioctl(fd, MUTEX_PROXY_IOC_SET_CONFIG, &config);
	if (ret < 0) {
		perror("ioctl set_config");
		close(fd);
		return 1;
	}
	printf("Strategy changed to failover\n\n");

	/* Verify using ioctl GET_CONFIG */
	printf("Verifying configuration using ioctl...\n");
	memset(&config, 0, sizeof(config));
	ret = ioctl(fd, MUTEX_PROXY_IOC_GET_CONFIG, &config);
	if (ret < 0) {
		perror("ioctl get_config");
		close(fd);
		return 1;
	}
	printf("Selection strategy now: %u (should be 2 for failover)\n\n",
	       config.selection_strategy);

	/* Disable and close */
	printf("Disabling proxy...\n");
	ret = ioctl(fd, MUTEX_PROXY_IOC_DISABLE);
	if (ret < 0) {
		perror("ioctl disable");
		close(fd);
		return 1;
	}
	printf("Proxy disabled\n\n");

	printf("Closing file descriptor...\n");
	close(fd);
	printf("Test completed successfully!\n");

	return 0;
}
