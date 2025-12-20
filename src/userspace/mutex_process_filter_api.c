// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Process Filter Configuration API Implementation (Userspace)
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "mutex_process_filter_api.h"

/* ========== Core API Functions ========== */

int mutex_process_filter_set_mode(int fd, enum mutex_process_filter_mode mode)
{
	uint32_t m = (uint32_t)mode;
	return ioctl(fd, MUTEX_IOCTL_SET_FILTER_MODE, &m);
}

int mutex_process_filter_get_mode(int fd)
{
	uint32_t mode;
	int ret;

	ret = ioctl(fd, MUTEX_IOCTL_GET_FILTER_MODE, &mode);
	if (ret < 0)
		return -1;

	return (int)mode;
}

int mutex_process_filter_add_rule(int fd, const struct mutex_process_filter_rule *rule)
{
	if (!rule) {
		errno = EINVAL;
		return -1;
	}

	return ioctl(fd, MUTEX_IOCTL_ADD_FILTER_RULE, rule);
}

int mutex_process_filter_remove_rule(int fd, uint32_t index)
{
	return ioctl(fd, MUTEX_IOCTL_REMOVE_FILTER_RULE, &index);
}

int mutex_process_filter_clear_rules(int fd)
{
	return ioctl(fd, MUTEX_IOCTL_CLEAR_FILTER_RULES);
}

int mutex_process_filter_get_config(int fd, struct mutex_process_filter_config *config)
{
	if (!config) {
		errno = EINVAL;
		return -1;
	}

	return ioctl(fd, MUTEX_IOCTL_GET_FILTER_CONFIG, config);
}

int mutex_process_filter_set_config(int fd, const struct mutex_process_filter_config *config)
{
	if (!config) {
		errno = EINVAL;
		return -1;
	}

	return ioctl(fd, MUTEX_IOCTL_SET_FILTER_CONFIG, config);
}

int mutex_process_filter_capture_owner(int fd)
{
	return ioctl(fd, MUTEX_IOCTL_CAPTURE_OWNER);
}

int mutex_process_filter_get_stats(int fd, struct mutex_process_filter_stats *stats)
{
	if (!stats) {
		errno = EINVAL;
		return -1;
	}

	return ioctl(fd, MUTEX_IOCTL_GET_FILTER_STATS, stats);
}

int mutex_process_filter_reset_stats(int fd)
{
	return ioctl(fd, MUTEX_IOCTL_RESET_FILTER_STATS);
}

int mutex_process_filter_invalidate_cache(int fd, pid_t pid)
{
	return ioctl(fd, MUTEX_IOCTL_INVALIDATE_CACHE, &pid);
}

/* ========== Helper Functions ========== */

void mutex_process_filter_create_pid_rule(struct mutex_process_filter_rule *rule,
					  pid_t pid,
					  enum mutex_process_scope scope)
{
	if (!rule)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_PID;
	rule->enabled = 1;
	rule->scope = scope;
	rule->match.pid.pid = pid;
}

void mutex_process_filter_create_uid_rule(struct mutex_process_filter_rule *rule,
					  uid_t uid)
{
	if (!rule)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_UID;
	rule->enabled = 1;
	rule->scope = MUTEX_PROCESS_SCOPE_CURRENT;
	rule->match.uid.uid = uid;
}

void mutex_process_filter_create_gid_rule(struct mutex_process_filter_rule *rule,
					  gid_t gid)
{
	if (!rule)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_GID;
	rule->enabled = 1;
	rule->scope = MUTEX_PROCESS_SCOPE_CURRENT;
	rule->match.gid.gid = gid;
}

void mutex_process_filter_create_comm_rule(struct mutex_process_filter_rule *rule,
					   const char *comm,
					   bool exact_match)
{
	if (!rule || !comm)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_COMM;
	rule->enabled = 1;
	rule->scope = MUTEX_PROCESS_SCOPE_CURRENT;
	strncpy(rule->match.comm.comm, comm, MUTEX_PROCESS_FILTER_MAX_COMM_LEN - 1);
	rule->match.comm.exact_match = exact_match ? 1 : 0;
}

void mutex_process_filter_create_path_rule(struct mutex_process_filter_rule *rule,
					   const char *path,
					   bool exact_match)
{
	if (!rule || !path)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_PATH;
	rule->enabled = 1;
	rule->scope = MUTEX_PROCESS_SCOPE_CURRENT;
	strncpy(rule->match.path.path, path, MUTEX_PROCESS_FILTER_MAX_PATH_LEN - 1);
	rule->match.path.exact_match = exact_match ? 1 : 0;
}

void mutex_process_filter_create_cgroup_rule(struct mutex_process_filter_rule *rule,
					     const char *cgroup,
					     bool exact_match)
{
	if (!rule || !cgroup)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->type = MUTEX_PROCESS_MATCH_CGROUP;
	rule->enabled = 1;
	rule->scope = MUTEX_PROCESS_SCOPE_CURRENT;
	strncpy(rule->match.cgroup.cgroup, cgroup, MUTEX_PROCESS_FILTER_MAX_CGROUP_LEN - 1);
	rule->match.cgroup.exact_match = exact_match ? 1 : 0;
}

/* ========== Utility Functions ========== */

const char *mutex_process_filter_mode_name(enum mutex_process_filter_mode mode)
{
	switch (mode) {
	case MUTEX_PROCESS_FILTER_NONE:
		return "none";
	case MUTEX_PROCESS_FILTER_WHITELIST:
		return "whitelist";
	case MUTEX_PROCESS_FILTER_BLACKLIST:
		return "blacklist";
	case MUTEX_PROCESS_FILTER_CGROUP:
		return "cgroup";
	case MUTEX_PROCESS_FILTER_OWNER:
		return "owner";
	default:
		return "unknown";
	}
}

const char *mutex_process_filter_match_type_name(enum mutex_process_match_type type)
{
	switch (type) {
	case MUTEX_PROCESS_MATCH_PID:
		return "pid";
	case MUTEX_PROCESS_MATCH_UID:
		return "uid";
	case MUTEX_PROCESS_MATCH_GID:
		return "gid";
	case MUTEX_PROCESS_MATCH_COMM:
		return "comm";
	case MUTEX_PROCESS_MATCH_PATH:
		return "path";
	case MUTEX_PROCESS_MATCH_CGROUP:
		return "cgroup";
	default:
		return "unknown";
	}
}

const char *mutex_process_filter_scope_name(enum mutex_process_scope scope)
{
	switch (scope) {
	case MUTEX_PROCESS_SCOPE_CURRENT:
		return "current";
	case MUTEX_PROCESS_SCOPE_TREE:
		return "tree";
	case MUTEX_PROCESS_SCOPE_SESSION:
		return "session";
	case MUTEX_PROCESS_SCOPE_GROUP:
		return "group";
	default:
		return "unknown";
	}
}
