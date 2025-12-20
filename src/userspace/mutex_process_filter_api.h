/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Process Filter Configuration API (Userspace)
 *
 * Userspace library for configuring process-based filtering rules
 * via ioctl/write operations on proxy file descriptors.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#ifndef _MUTEX_PROCESS_FILTER_API_H
#define _MUTEX_PROCESS_FILTER_API_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* ========== Constants ========== */

#define MUTEX_PROCESS_FILTER_MAX_RULES		128
#define MUTEX_PROCESS_FILTER_MAX_PATH_LEN	256
#define MUTEX_PROCESS_FILTER_MAX_CGROUP_LEN	256
#define MUTEX_PROCESS_FILTER_MAX_COMM_LEN	16

/* ========== Enumerations ========== */

/**
 * enum mutex_process_filter_mode - Process filtering mode
 */
enum mutex_process_filter_mode {
	MUTEX_PROCESS_FILTER_NONE = 0,
	MUTEX_PROCESS_FILTER_WHITELIST,
	MUTEX_PROCESS_FILTER_BLACKLIST,
	MUTEX_PROCESS_FILTER_CGROUP,
	MUTEX_PROCESS_FILTER_OWNER
};

/**
 * enum mutex_process_match_type - Process matching criteria
 */
enum mutex_process_match_type {
	MUTEX_PROCESS_MATCH_PID = 0,
	MUTEX_PROCESS_MATCH_UID,
	MUTEX_PROCESS_MATCH_GID,
	MUTEX_PROCESS_MATCH_COMM,
	MUTEX_PROCESS_MATCH_PATH,
	MUTEX_PROCESS_MATCH_CGROUP
};

/**
 * enum mutex_process_scope - Process filtering scope
 */
enum mutex_process_scope {
	MUTEX_PROCESS_SCOPE_CURRENT = 0,
	MUTEX_PROCESS_SCOPE_TREE,
	MUTEX_PROCESS_SCOPE_SESSION,
	MUTEX_PROCESS_SCOPE_GROUP
};

/* ========== Structures ========== */

/**
 * struct mutex_process_filter_rule - Single process filtering rule
 */
struct mutex_process_filter_rule {
	uint32_t type;			/* enum mutex_process_match_type */
	uint32_t enabled;		/* bool */
	uint32_t scope;			/* enum mutex_process_scope */
	uint32_t padding;

	union {
		/* PID match */
		struct {
			pid_t pid;
		} pid;

		/* UID match */
		struct {
			uid_t uid;
		} uid;

		/* GID match */
		struct {
			gid_t gid;
		} gid;

		/* Command name match */
		struct {
			char comm[MUTEX_PROCESS_FILTER_MAX_COMM_LEN];
			uint32_t exact_match;
		} comm;

		/* Executable path match */
		struct {
			char path[MUTEX_PROCESS_FILTER_MAX_PATH_LEN];
			uint32_t exact_match;
		} path;

		/* Cgroup match */
		struct {
			char cgroup[MUTEX_PROCESS_FILTER_MAX_CGROUP_LEN];
			uint32_t exact_match;
		} cgroup;
	} match;
};

/**
 * struct mutex_process_filter_config - Process filter configuration
 */
struct mutex_process_filter_config {
	uint32_t mode;			/* enum mutex_process_filter_mode */
	uint32_t include_children;	/* bool */
	uint32_t include_threads;	/* bool */
	uint32_t rule_count;
	struct mutex_process_filter_rule rules[MUTEX_PROCESS_FILTER_MAX_RULES];
};

/**
 * struct mutex_process_filter_stats - Filter statistics
 */
struct mutex_process_filter_stats {
	uint64_t packets_matched;
	uint64_t packets_filtered;
	uint64_t processes_checked;
	uint64_t cache_hits;
	uint64_t cache_misses;
};

/* ========== IOCTL Commands ========== */

#define MUTEX_IOCTL_MAGIC	'M'

#define MUTEX_IOCTL_SET_FILTER_MODE	_IOW(MUTEX_IOCTL_MAGIC, 30, uint32_t)
#define MUTEX_IOCTL_GET_FILTER_MODE	_IOR(MUTEX_IOCTL_MAGIC, 31, uint32_t)
#define MUTEX_IOCTL_ADD_FILTER_RULE	_IOW(MUTEX_IOCTL_MAGIC, 32, struct mutex_process_filter_rule)
#define MUTEX_IOCTL_REMOVE_FILTER_RULE	_IOW(MUTEX_IOCTL_MAGIC, 33, uint32_t)
#define MUTEX_IOCTL_CLEAR_FILTER_RULES	_IO(MUTEX_IOCTL_MAGIC, 34)
#define MUTEX_IOCTL_GET_FILTER_CONFIG	_IOR(MUTEX_IOCTL_MAGIC, 35, struct mutex_process_filter_config)
#define MUTEX_IOCTL_SET_FILTER_CONFIG	_IOW(MUTEX_IOCTL_MAGIC, 36, struct mutex_process_filter_config)
#define MUTEX_IOCTL_CAPTURE_OWNER	_IO(MUTEX_IOCTL_MAGIC, 37)
#define MUTEX_IOCTL_GET_FILTER_STATS	_IOR(MUTEX_IOCTL_MAGIC, 38, struct mutex_process_filter_stats)
#define MUTEX_IOCTL_RESET_FILTER_STATS	_IO(MUTEX_IOCTL_MAGIC, 39)
#define MUTEX_IOCTL_INVALIDATE_CACHE	_IOW(MUTEX_IOCTL_MAGIC, 40, pid_t)

/* ========== API Functions ========== */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * mutex_process_filter_set_mode() - Set filtering mode
 * @fd: Proxy file descriptor
 * @mode: Filtering mode to set
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_set_mode(int fd, enum mutex_process_filter_mode mode);

/**
 * mutex_process_filter_get_mode() - Get current filtering mode
 * @fd: Proxy file descriptor
 *
 * Returns: Filter mode on success, -1 on error (errno set)
 */
int mutex_process_filter_get_mode(int fd);

/**
 * mutex_process_filter_add_rule() - Add filtering rule
 * @fd: Proxy file descriptor
 * @rule: Rule to add
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_add_rule(int fd, const struct mutex_process_filter_rule *rule);

/**
 * mutex_process_filter_remove_rule() - Remove filtering rule by index
 * @fd: Proxy file descriptor
 * @index: Rule index to remove
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_remove_rule(int fd, uint32_t index);

/**
 * mutex_process_filter_clear_rules() - Clear all filtering rules
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_clear_rules(int fd);

/**
 * mutex_process_filter_get_config() - Get current filter configuration
 * @fd: Proxy file descriptor
 * @config: Output configuration structure
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_get_config(int fd, struct mutex_process_filter_config *config);

/**
 * mutex_process_filter_set_config() - Set complete filter configuration
 * @fd: Proxy file descriptor
 * @config: Configuration to set
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_set_config(int fd, const struct mutex_process_filter_config *config);

/**
 * mutex_process_filter_capture_owner() - Capture current process as owner
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_capture_owner(int fd);

/**
 * mutex_process_filter_get_stats() - Get filtering statistics
 * @fd: Proxy file descriptor
 * @stats: Output statistics structure
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_get_stats(int fd, struct mutex_process_filter_stats *stats);

/**
 * mutex_process_filter_reset_stats() - Reset filtering statistics
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_reset_stats(int fd);

/**
 * mutex_process_filter_invalidate_cache() - Invalidate filter cache
 * @fd: Proxy file descriptor
 * @pid: Process ID to invalidate (0 for all)
 *
 * Returns: 0 on success, -1 on error (errno set)
 */
int mutex_process_filter_invalidate_cache(int fd, pid_t pid);

/* ========== Helper Functions ========== */

/**
 * mutex_process_filter_create_pid_rule() - Create PID-based rule
 * @rule: Output rule structure
 * @pid: Process ID to match
 * @scope: Scope (current or tree)
 */
void mutex_process_filter_create_pid_rule(struct mutex_process_filter_rule *rule,
					  pid_t pid,
					  enum mutex_process_scope scope);

/**
 * mutex_process_filter_create_uid_rule() - Create UID-based rule
 * @rule: Output rule structure
 * @uid: User ID to match
 */
void mutex_process_filter_create_uid_rule(struct mutex_process_filter_rule *rule,
					  uid_t uid);

/**
 * mutex_process_filter_create_gid_rule() - Create GID-based rule
 * @rule: Output rule structure
 * @gid: Group ID to match
 */
void mutex_process_filter_create_gid_rule(struct mutex_process_filter_rule *rule,
					  gid_t gid);

/**
 * mutex_process_filter_create_comm_rule() - Create command name rule
 * @rule: Output rule structure
 * @comm: Command name to match
 * @exact_match: true for exact match, false for substring
 */
void mutex_process_filter_create_comm_rule(struct mutex_process_filter_rule *rule,
					   const char *comm,
					   bool exact_match);

/**
 * mutex_process_filter_create_path_rule() - Create executable path rule
 * @rule: Output rule structure
 * @path: Path to match
 * @exact_match: true for exact match, false for prefix
 */
void mutex_process_filter_create_path_rule(struct mutex_process_filter_rule *rule,
					   const char *path,
					   bool exact_match);

/**
 * mutex_process_filter_create_cgroup_rule() - Create cgroup rule
 * @rule: Output rule structure
 * @cgroup: Cgroup path to match
 * @exact_match: true for exact match, false for prefix
 */
void mutex_process_filter_create_cgroup_rule(struct mutex_process_filter_rule *rule,
					     const char *cgroup,
					     bool exact_match);

/**
 * mutex_process_filter_mode_name() - Get string name of mode
 * @mode: Filter mode
 *
 * Returns: String name
 */
const char *mutex_process_filter_mode_name(enum mutex_process_filter_mode mode);

/**
 * mutex_process_filter_match_type_name() - Get string name of match type
 * @type: Match type
 *
 * Returns: String name
 */
const char *mutex_process_filter_match_type_name(enum mutex_process_match_type type);

/**
 * mutex_process_filter_scope_name() - Get string name of scope
 * @scope: Scope
 *
 * Returns: String name
 */
const char *mutex_process_filter_scope_name(enum mutex_process_scope scope);

#ifdef __cplusplus
}
#endif

#endif /* _MUTEX_PROCESS_FILTER_API_H */
