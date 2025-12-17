/* SPDX-License-Identifier: LGPL-2.1 OR BSD-3-Clause */
/*
 * libmutex.h - MUTEX userspace library header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This library provides a high-level C API for interacting with the
 * MUTEX kernel-level proxy through file descriptors.
 */

#ifndef _LIBMUTEX_H
#define _LIBMUTEX_H

#include <stdint.h>
#include <sys/types.h>
#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include the kernel UAPI header */
#include "../../../linux/include/uapi/linux/mutex_proxy.h"

/*
 * Error codes (in addition to standard errno)
 */
#define EMUTEX_NOTSUPP		-1000	/* Operation not supported */
#define EMUTEX_BADCONFIG	-1001	/* Invalid configuration */
#define EMUTEX_NOPROXY		-1002	/* No proxy configured */

/*
 * Library version
 */
#define LIBMUTEX_VERSION_MAJOR	0
#define LIBMUTEX_VERSION_MINOR	1
#define LIBMUTEX_VERSION_PATCH	0

/**
 * mprox_create - Create a new proxy file descriptor
 * @flags: Creation flags (MUTEX_PROXY_CLOEXEC, MUTEX_PROXY_NONBLOCK, etc.)
 *
 * This function is a wrapper around the mutex_proxy_create() system call.
 * It returns a file descriptor that can be used for all proxy operations.
 *
 * Return: File descriptor on success, -1 on error with errno set
 */
int mprox_create(unsigned int flags);

/**
 * mprox_enable - Enable proxy for this file descriptor
 * @fd: Proxy file descriptor
 *
 * Activates the proxy configuration. After this call, traffic from the
 * owning process (or all processes if GLOBAL flag set) will be proxied.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_enable(int fd);

/**
 * mprox_disable - Disable proxy for this file descriptor
 * @fd: Proxy file descriptor
 *
 * Deactivates the proxy. Traffic will use direct connections.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_disable(int fd);

/**
 * mprox_set_config - Configure proxy settings
 * @fd: Proxy file descriptor
 * @config: Pointer to configuration structure
 *
 * Sets the proxy configuration (type, address, port, etc.).
 * Configuration takes effect immediately if proxy is enabled.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_set_config(int fd, const struct mutex_proxy_config *config);

/**
 * mprox_get_config - Retrieve current proxy configuration
 * @fd: Proxy file descriptor
 * @config: Pointer to configuration structure (output)
 *
 * Retrieves the current proxy configuration.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_get_config(int fd, struct mutex_proxy_config *config);

/**
 * mprox_get_stats - Get proxy statistics
 * @fd: Proxy file descriptor
 * @stats: Pointer to statistics structure (output)
 *
 * Retrieves current statistics (bytes, packets, connections).
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_get_stats(int fd, struct mutex_proxy_stats *stats);

/**
 * mprox_set_socks5 - Configure SOCKS5 proxy
 * @fd: Proxy file descriptor
 * @addr: Proxy server address (IPv4 or IPv6)
 * @port: Proxy server port
 *
 * Convenience function to set up a SOCKS5 proxy.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_set_socks5(int fd, const char *addr, uint16_t port);

/**
 * mprox_set_http - Configure HTTP/HTTPS proxy
 * @fd: Proxy file descriptor
 * @addr: Proxy server address (IPv4 or IPv6)
 * @port: Proxy server port
 * @use_https: 1 for HTTPS, 0 for HTTP
 *
 * Convenience function to set up an HTTP/HTTPS proxy.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_set_http(int fd, const char *addr, uint16_t port, int use_https);

/**
 * mprox_wait_event - Wait for proxy events
 * @fd: Proxy file descriptor
 * @timeout_ms: Timeout in milliseconds (-1 for infinite)
 *
 * Waits for events on the proxy fd (statistics updates, errors, etc.).
 * This uses poll() internally and can be integrated with epoll/select.
 *
 * Return: 1 if event occurred, 0 on timeout, -1 on error with errno set
 */
int mprox_wait_event(int fd, int timeout_ms);

/**
 * mprox_is_enabled - Check if proxy is enabled
 * @fd: Proxy file descriptor
 *
 * Checks the current enabled status of the proxy.
 *
 * Return: 1 if enabled, 0 if disabled, -1 on error with errno set
 */
int mprox_is_enabled(int fd);

/**
 * mprox_reset_stats - Reset statistics counters
 * @fd: Proxy file descriptor
 *
 * Resets all statistics counters to zero.
 *
 * Return: 0 on success, -1 on error with errno set
 */
int mprox_reset_stats(int fd);

/**
 * mprox_get_version - Get library version
 * @major: Pointer to major version (output, can be NULL)
 * @minor: Pointer to minor version (output, can be NULL)
 * @patch: Pointer to patch version (output, can be NULL)
 *
 * Returns the library version.
 */
void mprox_get_version(int *major, int *minor, int *patch);

/**
 * mprox_strerror - Convert MUTEX error code to string
 * @errnum: Error number (can be EMUTEX_* or standard errno)
 *
 * Returns a string describing the error.
 *
 * Return: Error description string
 */
const char *mprox_strerror(int errnum);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMUTEX_H */
