/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MUTEX Protocol Detection Userspace API Header
 *
 * Userspace interface for configuring and querying the MUTEX
 * protocol detection module.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#ifndef MUTEX_PROTOCOL_DETECT_API_H
#define MUTEX_PROTOCOL_DETECT_API_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include userspace-compatible type definitions */
#include "../module/mutex_protocol_detect_types.h"

/* API Error codes */
#define PROTO_API_SUCCESS      0
#define PROTO_API_ERROR       -1
#define PROTO_API_INVALID_FD  -2
#define PROTO_API_INVALID_ARG -3
#define PROTO_API_NO_DEVICE   -4
#define PROTO_API_PERMISSION  -5

/**
 * mutex_proto_open() - Open protocol detection device
 *
 * Returns: File descriptor on success, negative error code on failure
 */
int mutex_proto_open(void);

/**
 * mutex_proto_close() - Close protocol detection device
 * @fd: File descriptor from mutex_proto_open()
 */
void mutex_proto_close(int fd);

/**
 * mutex_proto_enable() - Enable protocol detection
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_enable(int fd);

/**
 * mutex_proto_disable() - Disable protocol detection
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_disable(int fd);

/**
 * mutex_proto_add_rule() - Add a protocol detection rule
 * @fd: File descriptor
 * @rule: Detection rule to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_add_rule(int fd, const struct protocol_rule *rule);

/**
 * mutex_proto_del_rule() - Remove a protocol detection rule
 * @fd: File descriptor
 * @protocol: Protocol type to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_del_rule(int fd, enum protocol_type protocol);

/**
 * mutex_proto_clear_rules() - Clear all detection rules
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_clear_rules(int fd);

/**
 * mutex_proto_add_route() - Add a protocol routing rule
 * @fd: File descriptor
 * @rule: Routing rule to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_add_route(int fd, const struct protocol_routing_rule *rule);

/**
 * mutex_proto_del_route() - Remove a protocol routing rule
 * @fd: File descriptor
 * @priority: Priority of rule to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_del_route(int fd, uint32_t priority);

/**
 * mutex_proto_clear_routes() - Clear all routing rules
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_clear_routes(int fd);

/**
 * mutex_proto_set_depth() - Set inspection depth
 * @fd: File descriptor
 * @depth: Maximum bytes to inspect per packet
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_set_depth(int fd, uint32_t depth);

/**
 * mutex_proto_set_timeout() - Set connection timeout
 * @fd: File descriptor
 * @timeout: Timeout in seconds
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_set_timeout(int fd, uint32_t timeout);

/**
 * mutex_proto_set_default_action() - Set default routing action
 * @fd: File descriptor
 * @action: Default action for unmatched protocols
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_set_default_action(int fd, enum routing_action action);

/**
 * mutex_proto_get_stats() - Get protocol detection statistics
 * @fd: File descriptor
 * @stats: Output buffer for statistics
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_get_stats(int fd, struct protocol_detection_stats *stats);

/**
 * mutex_proto_reset_stats() - Reset all statistics
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_reset_stats(int fd);

/**
 * mutex_proto_flush_cache() - Flush connection cache
 * @fd: File descriptor
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_proto_flush_cache(int fd);

/* Helper functions for creating rules */

/**
 * mutex_proto_create_port_rule() - Create a simple port-based detection rule
 * @protocol: Protocol type
 * @port: Port number
 * @transport: IPPROTO_TCP or IPPROTO_UDP
 * @rule: Output rule structure
 */
void mutex_proto_create_port_rule(enum protocol_type protocol,
				  uint16_t port,
				  uint8_t transport,
				  struct protocol_rule *rule);

/**
 * mutex_proto_create_pattern_rule() - Create a pattern-based detection rule
 * @protocol: Protocol type
 * @pattern: Pattern data
 * @pattern_len: Length of pattern
 * @offset: Offset in packet
 * @rule: Output rule structure
 */
void mutex_proto_create_pattern_rule(enum protocol_type protocol,
				     const uint8_t *pattern,
				     size_t pattern_len,
				     size_t offset,
				     struct protocol_rule *rule);

/**
 * mutex_proto_create_routing_rule() - Create a protocol routing rule
 * @protocol: Protocol type (PROTO_UNKNOWN for all protocols)
 * @action: Routing action
 * @priority: Rule priority (higher = evaluated first)
 * @rule: Output rule structure
 */
void mutex_proto_create_routing_rule(enum protocol_type protocol,
				     enum routing_action action,
				     uint32_t priority,
				     struct protocol_routing_rule *rule);

/**
 * mutex_proto_create_host_routing_rule() - Create routing rule with host pattern
 * @protocol: Protocol type
 * @host_pattern: Host pattern to match (substring)
 * @action: Routing action
 * @priority: Rule priority
 * @rule: Output rule structure
 */
void mutex_proto_create_host_routing_rule(enum protocol_type protocol,
					  const char *host_pattern,
					  enum routing_action action,
					  uint32_t priority,
					  struct protocol_routing_rule *rule);

/* Utility functions */

/**
 * mutex_proto_print_stats() - Print statistics to stdout
 * @stats: Statistics structure
 */
void mutex_proto_print_stats(const struct protocol_detection_stats *stats);

/**
 * mutex_proto_get_error_string() - Get error message for error code
 * @error_code: Error code from API function
 *
 * Returns: Human-readable error string
 */
const char *mutex_proto_get_error_string(int error_code);

#ifdef __cplusplus
}
#endif

#endif /* MUTEX_PROTOCOL_DETECT_API_H */
