/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Process Filtering Support
 *
 * This file defines structures and functions for per-process proxy rules
 * via file descriptor ownership. Supports process-based filtering, cgroup
 * integration, and executable path matching.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#ifndef _MUTEX_PROCESS_FILTER_H
#define _MUTEX_PROCESS_FILTER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/* ========== Constants ========== */

#define PROCESS_FILTER_MAX_RULES	128
#define PROCESS_FILTER_MAX_PATH_LEN	256
#define PROCESS_FILTER_MAX_CGROUP_LEN	256
#define PROCESS_FILTER_MAX_COMM_LEN	TASK_COMM_LEN

/* ========== Enumerations ========== */

/**
 * enum process_filter_mode - Process filtering mode
 * @PROCESS_FILTER_NONE: No process filtering (all processes)
 * @PROCESS_FILTER_WHITELIST: Only whitelisted processes are proxied
 * @PROCESS_FILTER_BLACKLIST: All except blacklisted processes are proxied
 * @PROCESS_FILTER_CGROUP: Filter by cgroup membership
 * @PROCESS_FILTER_OWNER: Only process that created fd (and optionally children)
 */
enum process_filter_mode {
	PROCESS_FILTER_NONE,
	PROCESS_FILTER_WHITELIST,
	PROCESS_FILTER_BLACKLIST,
	PROCESS_FILTER_CGROUP,
	PROCESS_FILTER_OWNER
};

/**
 * enum process_match_type - Process matching criteria
 * @PROCESS_MATCH_PID: Match by process ID
 * @PROCESS_MATCH_UID: Match by user ID
 * @PROCESS_MATCH_GID: Match by group ID
 * @PROCESS_MATCH_COMM: Match by command name (comm)
 * @PROCESS_MATCH_PATH: Match by executable path
 * @PROCESS_MATCH_CGROUP: Match by cgroup path
 */
enum process_match_type {
	PROCESS_MATCH_PID,
	PROCESS_MATCH_UID,
	PROCESS_MATCH_GID,
	PROCESS_MATCH_COMM,
	PROCESS_MATCH_PATH,
	PROCESS_MATCH_CGROUP
};

/**
 * enum process_scope - Process filtering scope
 * @PROCESS_SCOPE_CURRENT: Only the specific process
 * @PROCESS_SCOPE_TREE: Process and all its children
 * @PROCESS_SCOPE_SESSION: Process session
 * @PROCESS_SCOPE_GROUP: Process group
 */
enum process_scope {
	PROCESS_SCOPE_CURRENT,
	PROCESS_SCOPE_TREE,
	PROCESS_SCOPE_SESSION,
	PROCESS_SCOPE_GROUP
};

/* ========== Structures ========== */

/**
 * struct process_credentials - Process credential information
 * @pid: Process ID
 * @tgid: Thread group ID (main thread PID)
 * @ppid: Parent process ID
 * @uid: User ID (real)
 * @euid: Effective user ID
 * @gid: Group ID (real)
 * @egid: Effective group ID
 * @sid: Session ID
 * @pgid: Process group ID
 * @comm: Command name (process name)
 * @exe_path: Full path to executable
 * @cgroup_path: Cgroup path
 * @created: Timestamp when credentials were captured (jiffies)
 */
struct process_credentials {
	pid_t pid;
	pid_t tgid;
	pid_t ppid;
	kuid_t uid;
	kuid_t euid;
	kgid_t gid;
	kgid_t egid;
	pid_t sid;
	pid_t pgid;
	char comm[PROCESS_FILTER_MAX_COMM_LEN];
	char exe_path[PROCESS_FILTER_MAX_PATH_LEN];
	char cgroup_path[PROCESS_FILTER_MAX_CGROUP_LEN];
	unsigned long created;
};

/**
 * struct process_filter_rule - Single process filtering rule
 * @type: Type of match to perform
 * @enabled: Whether this rule is active
 * @scope: Scope of filtering (current, tree, session, group)
 * @match: Match criteria based on type
 */
struct process_filter_rule {
	enum process_match_type type;
	bool enabled;
	enum process_scope scope;

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
			char comm[PROCESS_FILTER_MAX_COMM_LEN];
			bool exact_match;	/* vs substring match */
		} comm;

		/* Executable path match */
		struct {
			char path[PROCESS_FILTER_MAX_PATH_LEN];
			bool exact_match;	/* vs prefix match */
		} path;

		/* Cgroup match */
		struct {
			char cgroup[PROCESS_FILTER_MAX_CGROUP_LEN];
			bool exact_match;	/* vs prefix match */
		} cgroup;
	} match;
};

/**
 * struct process_filter_config - Process filtering configuration
 * @mode: Filtering mode (none, whitelist, blacklist, cgroup, owner)
 * @owner_creds: Credentials of fd owner (for OWNER mode)
 * @include_children: Apply to child processes (OWNER mode)
 * @include_threads: Apply to all threads in thread group
 * @rules: Array of filtering rules
 * @rule_count: Number of active rules
 * @lock: Protects configuration changes
 */
struct process_filter_config {
	enum process_filter_mode mode;
	struct process_credentials owner_creds;
	bool include_children;
	bool include_threads;
	struct process_filter_rule rules[PROCESS_FILTER_MAX_RULES];
	int rule_count;
	spinlock_t lock;
};

/**
 * struct process_filter_context - Per-fd process filtering context
 * @config: Filtering configuration
 * @fd: Associated file descriptor (-1 if not set)
 * @refcount: Reference count
 * @stats: Filtering statistics
 */
struct process_filter_context {
	struct process_filter_config config;
	int fd;
	refcount_t refcount;

	/* Statistics */
	atomic64_t packets_matched;
	atomic64_t packets_filtered;
	atomic64_t processes_checked;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
};

/**
 * struct process_cache_entry - Cached process filtering decision
 * @pid: Process ID
 * @decision: Whether process matched filter (true = matched/allowed)
 * @timestamp: When decision was made (jiffies)
 * @list: List linkage
 */
struct process_cache_entry {
	pid_t pid;
	bool decision;
	unsigned long timestamp;
	struct list_head list;
};

/**
 * struct process_hierarchy_info - Process hierarchy information
 * @pid: Process ID
 * @ppid: Parent process ID
 * @depth: Depth in process tree from original process
 * @is_child_of: Check if child of another PID
 * @list: List linkage
 */
struct process_hierarchy_info {
	pid_t pid;
	pid_t ppid;
	int depth;
	struct list_head list;
};

/* ========== Core Functions ========== */

/**
 * process_filter_context_alloc() - Allocate process filter context
 * @fd: Associated file descriptor
 *
 * Creates a new process filtering context for a file descriptor.
 *
 * Returns: Pointer to context on success, NULL on failure
 */
struct process_filter_context *process_filter_context_alloc(int fd);

/**
 * process_filter_context_free() - Free process filter context
 * @ctx: Context to free
 */
void process_filter_context_free(struct process_filter_context *ctx);

/**
 * process_filter_context_get() - Increment reference count
 * @ctx: Context to reference
 */
void process_filter_context_get(struct process_filter_context *ctx);

/**
 * process_filter_context_put() - Decrement reference count
 * @ctx: Context to dereference
 */
void process_filter_context_put(struct process_filter_context *ctx);

/* ========== Configuration Functions ========== */

/**
 * process_filter_set_mode() - Set filtering mode
 * @ctx: Process filter context
 * @mode: Filtering mode to set
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_set_mode(struct process_filter_context *ctx,
			    enum process_filter_mode mode);

/**
 * process_filter_add_rule() - Add filtering rule
 * @ctx: Process filter context
 * @rule: Rule to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_add_rule(struct process_filter_context *ctx,
			    const struct process_filter_rule *rule);

/**
 * process_filter_remove_rule() - Remove filtering rule by index
 * @ctx: Process filter context
 * @index: Rule index to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_remove_rule(struct process_filter_context *ctx, int index);

/**
 * process_filter_clear_rules() - Clear all filtering rules
 * @ctx: Process filter context
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_clear_rules(struct process_filter_context *ctx);

/**
 * process_filter_capture_owner() - Capture current process as owner
 * @ctx: Process filter context
 *
 * Captures credentials of current process as fd owner.
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_capture_owner(struct process_filter_context *ctx);

/* ========== Filtering Functions ========== */

/**
 * process_filter_should_proxy() - Check if process should be proxied
 * @ctx: Process filter context
 * @skb: Packet to check (may be NULL for direct PID check)
 *
 * Main filtering decision function. Checks if the current process
 * (or process associated with skb) should have its traffic proxied.
 *
 * Returns: true if should proxy, false otherwise
 */
bool process_filter_should_proxy(struct process_filter_context *ctx,
				 struct sk_buff *skb);

/**
 * process_filter_check_pid() - Check if specific PID should be proxied
 * @ctx: Process filter context
 * @pid: Process ID to check
 *
 * Returns: true if should proxy, false otherwise
 */
bool process_filter_check_pid(struct process_filter_context *ctx, pid_t pid);

/**
 * process_filter_match_rule() - Check if process matches rule
 * @rule: Rule to check against
 * @creds: Process credentials
 *
 * Returns: true if process matches rule, false otherwise
 */
bool process_filter_match_rule(const struct process_filter_rule *rule,
			       const struct process_credentials *creds);

/* ========== Process Credential Functions ========== */

/**
 * process_filter_get_credentials() - Get credentials for current process
 * @creds: Output credentials structure
 *
 * Captures full credential information for current process.
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_get_credentials(struct process_credentials *creds);

/**
 * process_filter_get_pid_credentials() - Get credentials for specific PID
 * @pid: Process ID to query
 * @creds: Output credentials structure
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_get_pid_credentials(pid_t pid,
				       struct process_credentials *creds);

/**
 * process_filter_get_exe_path() - Get executable path for process
 * @task: Task structure
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_get_exe_path(struct task_struct *task, char *buf,
				size_t buflen);

/* ========== Process Hierarchy Functions ========== */

/**
 * process_filter_is_child_of() - Check if process is child of another
 * @child_pid: Potential child PID
 * @parent_pid: Potential parent PID
 *
 * Walks process tree to determine if child_pid is descendant of parent_pid.
 *
 * Returns: true if child_pid is child/descendant of parent_pid
 */
bool process_filter_is_child_of(pid_t child_pid, pid_t parent_pid);

/**
 * process_filter_is_in_session() - Check if process is in same session
 * @pid: Process ID to check
 * @sid: Session ID
 *
 * Returns: true if process is in session
 */
bool process_filter_is_in_session(pid_t pid, pid_t sid);

/**
 * process_filter_is_in_group() - Check if process is in same process group
 * @pid: Process ID to check
 * @pgid: Process group ID
 *
 * Returns: true if process is in group
 */
bool process_filter_is_in_group(pid_t pid, pid_t pgid);

/**
 * process_filter_get_process_tree() - Build process tree from PID
 * @root_pid: Root of tree
 * @tree: Output list of hierarchy info
 * @max_depth: Maximum depth to traverse (-1 for unlimited)
 *
 * Returns: Number of processes in tree, negative on error
 */
int process_filter_get_process_tree(pid_t root_pid, struct list_head *tree,
				    int max_depth);

/* ========== Cgroup Functions ========== */

/**
 * process_filter_get_cgroup_path() - Get cgroup path for task
 * @task: Task structure
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: 0 on success, negative error code on failure
 */
int process_filter_get_cgroup_path(struct task_struct *task, char *buf,
				   size_t buflen);

/**
 * process_filter_is_in_cgroup() - Check if process is in cgroup
 * @pid: Process ID
 * @cgroup_path: Cgroup path to check
 * @exact_match: true for exact match, false for prefix match
 *
 * Returns: true if process is in cgroup
 */
bool process_filter_is_in_cgroup(pid_t pid, const char *cgroup_path,
				 bool exact_match);

/* ========== Cache Functions ========== */

/**
 * process_filter_cache_lookup() - Look up cached filtering decision
 * @ctx: Process filter context
 * @pid: Process ID
 * @decision: Output decision (if found)
 *
 * Returns: true if found in cache, false otherwise
 */
bool process_filter_cache_lookup(struct process_filter_context *ctx,
				 pid_t pid, bool *decision);

/**
 * process_filter_cache_insert() - Insert filtering decision into cache
 * @ctx: Process filter context
 * @pid: Process ID
 * @decision: Filtering decision
 */
void process_filter_cache_insert(struct process_filter_context *ctx,
				 pid_t pid, bool decision);

/**
 * process_filter_cache_invalidate() - Invalidate cached entry
 * @ctx: Process filter context
 * @pid: Process ID (0 to invalidate all)
 */
void process_filter_cache_invalidate(struct process_filter_context *ctx,
				     pid_t pid);

/* ========== Statistics Functions ========== */

/**
 * process_filter_get_stats() - Get filtering statistics
 * @ctx: Process filter context
 * @packets_matched: Output matched packet count
 * @packets_filtered: Output filtered packet count
 * @processes_checked: Output process check count
 * @cache_hits: Output cache hit count
 * @cache_misses: Output cache miss count
 */
void process_filter_get_stats(struct process_filter_context *ctx,
			      u64 *packets_matched, u64 *packets_filtered,
			      u64 *processes_checked, u64 *cache_hits,
			      u64 *cache_misses);

/**
 * process_filter_reset_stats() - Reset filtering statistics
 * @ctx: Process filter context
 */
void process_filter_reset_stats(struct process_filter_context *ctx);

/* ========== Utility Functions ========== */

/**
 * process_filter_mode_name() - Get string name of filter mode
 * @mode: Filter mode
 *
 * Returns: String name of mode
 */
const char *process_filter_mode_name(enum process_filter_mode mode);

/**
 * process_filter_match_type_name() - Get string name of match type
 * @type: Match type
 *
 * Returns: String name of type
 */
const char *process_filter_match_type_name(enum process_match_type type);

/**
 * process_filter_scope_name() - Get string name of scope
 * @scope: Scope
 *
 * Returns: String name of scope
 */
const char *process_filter_scope_name(enum process_scope scope);

/* ========== Module Functions ========== */

/**
 * mutex_process_filter_init() - Initialize process filtering subsystem
 *
 * Returns: 0 on success, negative error code on failure
 */
int mutex_process_filter_init(void);

/**
 * mutex_process_filter_exit() - Clean up process filtering subsystem
 */
void mutex_process_filter_exit(void);

#endif /* _MUTEX_PROCESS_FILTER_H */
