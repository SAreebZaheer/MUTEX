/* SPDX-License-Identifier: LGPL-2.1 OR BSD-3-Clause */
/*
 * libmutex.c - MUTEX userspace library implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 */

#include "libmutex.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>

/* System call number for mprox_create (arch-specific) */
#ifndef __NR_mutex_proxy_create
#ifdef __x86_64__
#define __NR_mutex_proxy_create 471
#elif defined(__aarch64__)
#define __NR_mutex_proxy_create 471
#else
#error "Unsupported architecture - define __NR_mutex_proxy_create"
#endif
#endif

/*
 * Error message table
 */
static const char *mutex_error_messages[] = {
	[0] = "Success",
	[-EMUTEX_NOTSUPP] = "Operation not supported",
	[-EMUTEX_BADCONFIG] = "Invalid configuration",
	[-EMUTEX_NOPROXY] = "No proxy configured",
};

/**
 * mprox_create - Create a new proxy file descriptor
 */
int mprox_create(unsigned int flags)
{
	long ret;

	/* Validate flags */
	if (flags & ~MUTEX_PROXY_ALL_FLAGS) {
		errno = EINVAL;
		return -1;
	}

	/* Call the system call */
	ret = syscall(__NR_mutex_proxy_create, flags);
	if (ret < 0) {
		return -1;
	}

	return (int)ret;
}

/**
 * mprox_enable - Enable proxy for this file descriptor
 */
int mprox_enable(int fd)
{
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (ioctl(fd, MUTEX_PROXY_IOC_ENABLE) < 0) {
		return -1;
	}

	return 0;
}

/**
 * mprox_disable - Disable proxy for this file descriptor
 */
int mprox_disable(int fd)
{
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (ioctl(fd, MUTEX_PROXY_IOC_DISABLE) < 0) {
		return -1;
	}

	return 0;
}

/**
 * mprox_set_config - Configure proxy settings
 */
int mprox_set_config(int fd, const struct mutex_proxy_config *config)
{
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (!config) {
		errno = EINVAL;
		return -1;
	}

	/* Validate configuration */
	if (config->num_servers == 0 || config->num_servers > MUTEX_PROXY_MAX_SERVERS) {
		errno = EINVAL;
		return -1;
	}

	/* Validate at least one server */
	if (config->servers[0].proxy_type < 1 || config->servers[0].proxy_type > PROXY_TYPE_MAX) {
		errno = EINVAL;
		return -1;
	}

	if (config->servers[0].proxy_port == 0 || config->servers[0].proxy_port > 65535) {
		errno = EINVAL;
		return -1;
	}

	if (ioctl(fd, MUTEX_PROXY_IOC_SET_CONFIG, config) < 0) {
		return -1;
	}

	return 0;
}

/**
 * mprox_get_config - Retrieve current proxy configuration
 */
int mprox_get_config(int fd, struct mutex_proxy_config *config)
{
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (!config) {
		errno = EINVAL;
		return -1;
	}

	if (ioctl(fd, MUTEX_PROXY_IOC_GET_CONFIG, config) < 0) {
		return -1;
	}

	return 0;
}

/**
 * mprox_get_stats - Get proxy statistics
 */
int mprox_get_stats(int fd, struct mutex_proxy_stats *stats)
{
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (!stats) {
		errno = EINVAL;
		return -1;
	}

	if (ioctl(fd, MUTEX_PROXY_IOC_GET_STATS, stats) < 0) {
		return -1;
	}

	return 0;
}

/**
 * mprox_set_socks5 - Configure SOCKS5 proxy
 */
int mprox_set_socks5(int fd, const char *addr, uint16_t port)
{
	struct mutex_proxy_config config = {0};
	struct in_addr ipv4;
	struct in6_addr ipv6;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	config.version = 1;
	config.num_servers = 1;
	config.selection_strategy = PROXY_SELECT_ROUND_ROBIN;
	config.current_server = 0;

	config.servers[0].proxy_type = PROXY_TYPE_SOCKS5;
	config.servers[0].proxy_port = port;
	config.servers[0].flags = PROXY_CONFIG_ACTIVE;
	config.servers[0].priority = 1;

	/* Try to parse as IPv4 first */
	if (inet_pton(AF_INET, addr, &ipv4) == 1) {
		memcpy(config.servers[0].proxy_addr, &ipv4, 4);
	} else if (inet_pton(AF_INET6, addr, &ipv6) == 1) {
		/* Parse as IPv6 */
		config.servers[0].flags |= PROXY_CONFIG_IPV6;
		memcpy(config.servers[0].proxy_addr, &ipv6, 16);
	} else {
		errno = EINVAL;
		return -1;
	}

	return mprox_set_config(fd, &config);
}

/**
 * mprox_set_http - Configure HTTP/HTTPS proxy
 */
int mprox_set_http(int fd, const char *addr, uint16_t port, int use_https)
{
	struct mutex_proxy_config config = {0};
	struct in_addr ipv4;
	struct in6_addr ipv6;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	config.version = 1;
	config.num_servers = 1;
	config.selection_strategy = PROXY_SELECT_ROUND_ROBIN;
	config.current_server = 0;

	config.servers[0].proxy_type = use_https ? PROXY_TYPE_HTTPS : PROXY_TYPE_HTTP;
	config.servers[0].proxy_port = port;
	config.servers[0].flags = PROXY_CONFIG_ACTIVE;
	config.servers[0].priority = 1;

	/* Try to parse as IPv4 first */
	if (inet_pton(AF_INET, addr, &ipv4) == 1) {
		memcpy(config.servers[0].proxy_addr, &ipv4, 4);
	} else if (inet_pton(AF_INET6, addr, &ipv6) == 1) {
		/* Parse as IPv6 */
		config.servers[0].flags |= PROXY_CONFIG_IPV6;
		memcpy(config.servers[0].proxy_addr, &ipv6, 16);
	} else {
		errno = EINVAL;
		return -1;
	}

	return mprox_set_config(fd, &config);
}

/**
 * mprox_wait_event - Wait for proxy events
 */
int mprox_wait_event(int fd, int timeout_ms)
{
	struct pollfd pfd;
	int ret;

	if (fd < 0) {
		errno = EBADF;
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	ret = poll(&pfd, 1, timeout_ms);
	if (ret < 0) {
		return -1;
	}

	if (ret == 0) {
		/* Timeout */
		return 0;
	}

	if (pfd.revents & POLLIN) {
		return 1;
	}

	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		errno = EIO;
		return -1;
	}

	return 0;
}

/**
 * mprox_is_enabled - Check if proxy is enabled
 */
int mprox_is_enabled(int fd)
{
	struct mutex_proxy_config config;

	if (mprox_get_config(fd, &config) < 0) {
		return -1;
	}

	/* Check if config has been set */
	if (config.num_servers == 0 || config.servers[0].proxy_type == 0) {
		return 0;
	}

	return 1;
}

/**
 * mprox_reset_stats - Reset statistics counters
 */
int mprox_reset_stats(int fd)
{
	/* This would require a new ioctl command in the kernel
	 * For now, not implemented
	 */
	(void)fd;
	errno = ENOSYS;
	return -1;
}

/**
 * mprox_get_version - Get library version
 */
void mprox_get_version(int *major, int *minor, int *patch)
{
	if (major)
		*major = LIBMUTEX_VERSION_MAJOR;
	if (minor)
		*minor = LIBMUTEX_VERSION_MINOR;
	if (patch)
		*patch = LIBMUTEX_VERSION_PATCH;
}

/**
 * mprox_strerror - Convert MUTEX error code to string
 */
const char *mprox_strerror(int errnum)
{
	/* Handle MUTEX-specific errors */
	if (errnum <= -1000 && errnum >= -1002) {
		return mutex_error_messages[-errnum];
	}

	/* Fall back to standard strerror */
	return strerror(errnum);
}
