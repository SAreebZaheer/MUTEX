// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Process Filtering Implementation
 *
 * Implements per-process proxy rules via file descriptor ownership.
 * Supports process-based filtering, cgroup integration, and executable
 * path matching with caching for performance.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "mutex_process_filter.h"

/* ========== Module Parameters ========== */

static unsigned int cache_timeout_secs = 30;
module_param(cache_timeout_secs, uint, 0644);
MODULE_PARM_DESC(cache_timeout_secs, "Process filter cache timeout in seconds");

static unsigned int max_cache_entries = 256;
module_param(max_cache_entries, uint, 0644);
MODULE_PARM_DESC(max_cache_entries, "Maximum number of cached filter decisions");

/* ========== Cache Management ========== */

struct process_filter_cache {
	struct list_head entries;
	spinlock_t lock;
	int count;
};

static struct process_filter_cache global_cache;

/* ========== Context Management ========== */

/**
 * process_filter_context_alloc() - Allocate process filter context
 */
struct process_filter_context *process_filter_context_alloc(int fd)
{
	struct process_filter_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->fd = fd;
	spin_lock_init(&ctx->config.lock);
	refcount_set(&ctx->refcount, 1);

	/* Initialize default mode */
	ctx->config.mode = PROCESS_FILTER_NONE;
	ctx->config.include_children = false;
	ctx->config.include_threads = true;
	ctx->config.rule_count = 0;

	/* Initialize statistics */
	atomic64_set(&ctx->packets_matched, 0);
	atomic64_set(&ctx->packets_filtered, 0);
	atomic64_set(&ctx->processes_checked, 0);
	atomic64_set(&ctx->cache_hits, 0);
	atomic64_set(&ctx->cache_misses, 0);

	pr_debug("process_filter: allocated context for fd=%d\n", fd);
	return ctx;
}
EXPORT_SYMBOL_GPL(process_filter_context_alloc);

/**
 * process_filter_context_free() - Free process filter context
 */
void process_filter_context_free(struct process_filter_context *ctx)
{
	if (!ctx)
		return;

	pr_debug("process_filter: freeing context fd=%d\n", ctx->fd);
	kfree(ctx);
}
EXPORT_SYMBOL_GPL(process_filter_context_free);

/**
 * process_filter_context_get() - Increment reference count
 */
void process_filter_context_get(struct process_filter_context *ctx)
{
	if (ctx)
		refcount_inc(&ctx->refcount);
}
EXPORT_SYMBOL_GPL(process_filter_context_get);

/**
 * process_filter_context_put() - Decrement reference count
 */
void process_filter_context_put(struct process_filter_context *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->refcount))
		process_filter_context_free(ctx);
}
EXPORT_SYMBOL_GPL(process_filter_context_put);

/* ========== Configuration Functions ========== */

/**
 * process_filter_set_mode() - Set filtering mode
 */
int process_filter_set_mode(struct process_filter_context *ctx,
			    enum process_filter_mode mode)
{
	unsigned long flags;

	if (!ctx)
		return -EINVAL;

	if (mode < PROCESS_FILTER_NONE || mode > PROCESS_FILTER_OWNER)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.lock, flags);
	ctx->config.mode = mode;
	spin_unlock_irqrestore(&ctx->config.lock, flags);

	pr_debug("process_filter: set mode to %s for fd=%d\n",
		 process_filter_mode_name(mode), ctx->fd);

	return 0;
}
EXPORT_SYMBOL_GPL(process_filter_set_mode);

/**
 * process_filter_add_rule() - Add filtering rule
 */
int process_filter_add_rule(struct process_filter_context *ctx,
			    const struct process_filter_rule *rule)
{
	unsigned long flags;
	int ret = 0;

	if (!ctx || !rule)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.lock, flags);

	if (ctx->config.rule_count >= PROCESS_FILTER_MAX_RULES) {
		ret = -ENOSPC;
		goto out;
	}

	memcpy(&ctx->config.rules[ctx->config.rule_count], rule,
	       sizeof(*rule));
	ctx->config.rule_count++;

	pr_debug("process_filter: added rule %d (type=%s) for fd=%d\n",
		 ctx->config.rule_count - 1,
		 process_filter_match_type_name(rule->type), ctx->fd);

out:
	spin_unlock_irqrestore(&ctx->config.lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(process_filter_add_rule);

/**
 * process_filter_remove_rule() - Remove filtering rule by index
 */
int process_filter_remove_rule(struct process_filter_context *ctx, int index)
{
	unsigned long flags;
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.lock, flags);

	if (index < 0 || index >= ctx->config.rule_count) {
		ret = -EINVAL;
		goto out;
	}

	/* Shift rules down */
	if (index < ctx->config.rule_count - 1) {
		memmove(&ctx->config.rules[index],
			&ctx->config.rules[index + 1],
			(ctx->config.rule_count - index - 1) *
			sizeof(struct process_filter_rule));
	}

	ctx->config.rule_count--;
	pr_debug("process_filter: removed rule %d for fd=%d\n", index, ctx->fd);

out:
	spin_unlock_irqrestore(&ctx->config.lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(process_filter_remove_rule);

/**
 * process_filter_clear_rules() - Clear all filtering rules
 */
int process_filter_clear_rules(struct process_filter_context *ctx)
{
	unsigned long flags;

	if (!ctx)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.lock, flags);
	ctx->config.rule_count = 0;
	spin_unlock_irqrestore(&ctx->config.lock, flags);

	pr_debug("process_filter: cleared all rules for fd=%d\n", ctx->fd);
	return 0;
}
EXPORT_SYMBOL_GPL(process_filter_clear_rules);

/**
 * process_filter_capture_owner() - Capture current process as owner
 */
int process_filter_capture_owner(struct process_filter_context *ctx)
{
	unsigned long flags;
	int ret;

	if (!ctx)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.lock, flags);
	ret = process_filter_get_credentials(&ctx->config.owner_creds);
	spin_unlock_irqrestore(&ctx->config.lock, flags);

	if (ret == 0) {
		pr_debug("process_filter: captured owner pid=%d comm=%s for fd=%d\n",
			 ctx->config.owner_creds.pid,
			 ctx->config.owner_creds.comm, ctx->fd);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(process_filter_capture_owner);

/* ========== Process Credential Functions ========== */

/**
 * process_filter_get_exe_path() - Get executable path for process
 */
int process_filter_get_exe_path(struct task_struct *task, char *buf,
				size_t buflen)
{
	struct mm_struct *mm;
	struct file *exe_file;
	char *pathname;
	char *tmp;
	int ret = -ENOENT;

	if (!task || !buf || buflen == 0)
		return -EINVAL;

	/* Get mm struct */
	mm = get_task_mm(task);
	if (!mm)
		return -ENOENT;

	/* Get executable file */
	exe_file = get_mm_exe_file(mm);
	mmput(mm);

	if (!exe_file)
		return -ENOENT;

	/* Allocate temporary buffer for d_path */
	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		fput(exe_file);
		return -ENOMEM;
	}

	/* Get path */
	pathname = d_path(&exe_file->f_path, tmp, PATH_MAX);
	if (!IS_ERR(pathname)) {
		size_t len = strlen(pathname);
		if (len < buflen) {
			strncpy(buf, pathname, buflen - 1);
			buf[buflen - 1] = '\0';
			ret = 0;
		} else {
			ret = -ENAMETOOLONG;
		}
	} else {
		ret = PTR_ERR(pathname);
	}

	kfree(tmp);
	fput(exe_file);
	return ret;
}
EXPORT_SYMBOL_GPL(process_filter_get_exe_path);

/**
 * process_filter_get_cgroup_path() - Get cgroup path for task
 */
int process_filter_get_cgroup_path(struct task_struct *task, char *buf,
				   size_t buflen)
{
	struct cgroup *cgrp;
	char *path;
	int ret = 0;

	if (!task || !buf || buflen == 0)
		return -EINVAL;

#ifdef CONFIG_CGROUPS
	rcu_read_lock();
	cgrp = task_cgroup(task, 0);  /* Get from first hierarchy */
	if (cgrp) {
		/* Try to get cgroup path */
		path = cgroup_path_ns(cgrp, &init_cgroup_ns);
		if (path) {
			strncpy(buf, path, buflen - 1);
			buf[buflen - 1] = '\0';
			kfree(path);
		} else {
			strncpy(buf, "/", buflen);
			ret = -ENOMEM;
		}
	} else {
		strncpy(buf, "/", buflen);
		ret = -ENOENT;
	}
	rcu_read_unlock();
#else
	strncpy(buf, "/", buflen);
	ret = -ENOSYS;
#endif

	return ret;
}
EXPORT_SYMBOL_GPL(process_filter_get_cgroup_path);

/**
 * process_filter_get_credentials() - Get credentials for current process
 */
int process_filter_get_credentials(struct process_credentials *creds)
{
	struct task_struct *task = current;
	const struct cred *cred;
	int ret;

	if (!creds)
		return -EINVAL;

	memset(creds, 0, sizeof(*creds));

	/* Basic process IDs */
	creds->pid = task_pid_nr(task);
	creds->tgid = task_tgid_nr(task);
	creds->ppid = task_ppid_nr(task);
	creds->sid = task_session_nr(task);
	creds->pgid = task_pgrp_nr(task);

	/* Credentials */
	rcu_read_lock();
	cred = __task_cred(task);
	creds->uid = cred->uid;
	creds->euid = cred->euid;
	creds->gid = cred->gid;
	creds->egid = cred->egid;
	rcu_read_unlock();

	/* Command name */
	get_task_comm(creds->comm, task);

	/* Executable path */
	ret = process_filter_get_exe_path(task, creds->exe_path,
					  PROCESS_FILTER_MAX_PATH_LEN);
	if (ret < 0)
		creds->exe_path[0] = '\0';

	/* Cgroup path */
	ret = process_filter_get_cgroup_path(task, creds->cgroup_path,
					     PROCESS_FILTER_MAX_CGROUP_LEN);
	if (ret < 0)
		creds->cgroup_path[0] = '\0';

	/* Timestamp */
	creds->created = jiffies;

	return 0;
}
EXPORT_SYMBOL_GPL(process_filter_get_credentials);

/**
 * process_filter_get_pid_credentials() - Get credentials for specific PID
 */
int process_filter_get_pid_credentials(pid_t pid,
				       struct process_credentials *creds)
{
	struct task_struct *task;
	const struct cred *cred;
	int ret = 0;

	if (!creds)
		return -EINVAL;

	memset(creds, 0, sizeof(*creds));

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/* Get task reference */
	get_task_struct(task);
	rcu_read_unlock();

	/* Basic process IDs */
	creds->pid = task_pid_nr(task);
	creds->tgid = task_tgid_nr(task);
	creds->ppid = task_ppid_nr(task);
	creds->sid = task_session_nr(task);
	creds->pgid = task_pgrp_nr(task);

	/* Credentials */
	rcu_read_lock();
	cred = __task_cred(task);
	creds->uid = cred->uid;
	creds->euid = cred->euid;
	creds->gid = cred->gid;
	creds->egid = cred->egid;
	rcu_read_unlock();

	/* Command name */
	get_task_comm(creds->comm, task);

	/* Executable path */
	ret = process_filter_get_exe_path(task, creds->exe_path,
					  PROCESS_FILTER_MAX_PATH_LEN);
	if (ret < 0)
		creds->exe_path[0] = '\0';

	/* Cgroup path */
	ret = process_filter_get_cgroup_path(task, creds->cgroup_path,
					     PROCESS_FILTER_MAX_CGROUP_LEN);
	if (ret < 0)
		creds->cgroup_path[0] = '\0';

	/* Timestamp */
	creds->created = jiffies;

	put_task_struct(task);
	return 0;
}
EXPORT_SYMBOL_GPL(process_filter_get_pid_credentials);

/* ========== Process Hierarchy Functions ========== */

/**
 * process_filter_is_child_of() - Check if process is child of another
 */
bool process_filter_is_child_of(pid_t child_pid, pid_t parent_pid)
{
	struct task_struct *task;
	pid_t current_ppid;
	bool is_child = false;
	int depth = 0;
	const int max_depth = 100;  /* Prevent infinite loops */

	if (child_pid == parent_pid)
		return true;

	rcu_read_lock();
	task = find_task_by_vpid(child_pid);
	if (!task) {
		rcu_read_unlock();
		return false;
	}

	/* Walk up parent chain */
	while (task && depth < max_depth) {
		current_ppid = task_ppid_nr(task);

		if (current_ppid == parent_pid) {
			is_child = true;
			break;
		}

		if (current_ppid == 0 || current_ppid == 1)
			break;

		task = find_task_by_vpid(current_ppid);
		depth++;
	}

	rcu_read_unlock();
	return is_child;
}
EXPORT_SYMBOL_GPL(process_filter_is_child_of);

/**
 * process_filter_is_in_session() - Check if process is in same session
 */
bool process_filter_is_in_session(pid_t pid, pid_t sid)
{
	struct task_struct *task;
	pid_t task_sid;
	bool in_session = false;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		task_sid = task_session_nr(task);
		in_session = (task_sid == sid);
	}
	rcu_read_unlock();

	return in_session;
}
EXPORT_SYMBOL_GPL(process_filter_is_in_session);

/**
 * process_filter_is_in_group() - Check if process is in same process group
 */
bool process_filter_is_in_group(pid_t pid, pid_t pgid)
{
	struct task_struct *task;
	pid_t task_pgid;
	bool in_group = false;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task) {
		task_pgid = task_pgrp_nr(task);
		in_group = (task_pgid == pgid);
	}
	rcu_read_unlock();

	return in_group;
}
EXPORT_SYMBOL_GPL(process_filter_is_in_group);

/**
 * process_filter_get_process_tree() - Build process tree from PID
 */
int process_filter_get_process_tree(pid_t root_pid, struct list_head *tree,
				    int max_depth)
{
	/* Simplified implementation - full tree traversal would be complex */
	struct process_hierarchy_info *info;
	struct process_credentials creds;
	int ret;

	if (!tree)
		return -EINVAL;

	ret = process_filter_get_pid_credentials(root_pid, &creds);
	if (ret < 0)
		return ret;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->pid = creds.pid;
	info->ppid = creds.ppid;
	info->depth = 0;
	list_add_tail(&info->list, tree);

	return 1;  /* Only adding root for now */
}
EXPORT_SYMBOL_GPL(process_filter_get_process_tree);

/* ========== Cgroup Functions ========== */

/**
 * process_filter_is_in_cgroup() - Check if process is in cgroup
 */
bool process_filter_is_in_cgroup(pid_t pid, const char *cgroup_path,
				 bool exact_match)
{
	struct task_struct *task;
	char buf[PROCESS_FILTER_MAX_CGROUP_LEN];
	bool in_cgroup = false;
	int ret;

	if (!cgroup_path)
		return false;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return false;
	}

	get_task_struct(task);
	rcu_read_unlock();

	ret = process_filter_get_cgroup_path(task, buf, sizeof(buf));
	if (ret == 0) {
		if (exact_match)
			in_cgroup = (strcmp(buf, cgroup_path) == 0);
		else
			in_cgroup = (strncmp(buf, cgroup_path,
					     strlen(cgroup_path)) == 0);
	}

	put_task_struct(task);
	return in_cgroup;
}
EXPORT_SYMBOL_GPL(process_filter_is_in_cgroup);

/* ========== Rule Matching Functions ========== */

/**
 * process_filter_match_rule() - Check if process matches rule
 */
bool process_filter_match_rule(const struct process_filter_rule *rule,
			       const struct process_credentials *creds)
{
	if (!rule || !creds || !rule->enabled)
		return false;

	switch (rule->type) {
	case PROCESS_MATCH_PID:
		if (rule->scope == PROCESS_SCOPE_CURRENT)
			return creds->pid == rule->match.pid.pid;
		else if (rule->scope == PROCESS_SCOPE_TREE)
			return process_filter_is_child_of(creds->pid,
							   rule->match.pid.pid);
		break;

	case PROCESS_MATCH_UID:
		return uid_eq(creds->uid,
			      make_kuid(&init_user_ns, rule->match.uid.uid));

	case PROCESS_MATCH_GID:
		return gid_eq(creds->gid,
			      make_kgid(&init_user_ns, rule->match.gid.gid));

	case PROCESS_MATCH_COMM:
		if (rule->match.comm.exact_match)
			return strcmp(creds->comm, rule->match.comm.comm) == 0;
		else
			return strstr(creds->comm, rule->match.comm.comm) != NULL;

	case PROCESS_MATCH_PATH:
		if (rule->match.path.exact_match)
			return strcmp(creds->exe_path, rule->match.path.path) == 0;
		else
			return strncmp(creds->exe_path, rule->match.path.path,
				       strlen(rule->match.path.path)) == 0;

	case PROCESS_MATCH_CGROUP:
		return process_filter_is_in_cgroup(creds->pid,
						   rule->match.cgroup.cgroup,
						   rule->match.cgroup.exact_match);

	default:
		return false;
	}

	return false;
}
EXPORT_SYMBOL_GPL(process_filter_match_rule);

/* ========== Cache Functions ========== */

/**
 * process_filter_cache_lookup() - Look up cached filtering decision
 */
bool process_filter_cache_lookup(struct process_filter_context *ctx,
				 pid_t pid, bool *decision)
{
	struct process_cache_entry *entry;
	unsigned long flags;
	unsigned long timeout;
	bool found = false;

	if (!ctx || !decision)
		return false;

	timeout = jiffies - msecs_to_jiffies(cache_timeout_secs * 1000);

	spin_lock_irqsave(&global_cache.lock, flags);
	list_for_each_entry(entry, &global_cache.entries, list) {
		if (entry->pid == pid) {
			/* Check if entry is still valid */
			if (time_after(entry->timestamp, timeout)) {
				*decision = entry->decision;
				found = true;
				atomic64_inc(&ctx->cache_hits);
			} else {
				/* Entry expired */
				list_del(&entry->list);
				kfree(entry);
				global_cache.count--;
			}
			break;
		}
	}
	spin_unlock_irqrestore(&global_cache.lock, flags);

	if (!found)
		atomic64_inc(&ctx->cache_misses);

	return found;
}
EXPORT_SYMBOL_GPL(process_filter_cache_lookup);

/**
 * process_filter_cache_insert() - Insert filtering decision into cache
 */
void process_filter_cache_insert(struct process_filter_context *ctx,
				 pid_t pid, bool decision)
{
	struct process_cache_entry *entry;
	unsigned long flags;

	if (!ctx)
		return;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return;

	entry->pid = pid;
	entry->decision = decision;
	entry->timestamp = jiffies;

	spin_lock_irqsave(&global_cache.lock, flags);

	/* Remove oldest entry if cache is full */
	if (global_cache.count >= max_cache_entries) {
		struct process_cache_entry *old;
		old = list_first_entry(&global_cache.entries,
				       struct process_cache_entry, list);
		list_del(&old->list);
		kfree(old);
		global_cache.count--;
	}

	list_add_tail(&entry->list, &global_cache.entries);
	global_cache.count++;

	spin_unlock_irqrestore(&global_cache.lock, flags);
}
EXPORT_SYMBOL_GPL(process_filter_cache_insert);

/**
 * process_filter_cache_invalidate() - Invalidate cached entry
 */
void process_filter_cache_invalidate(struct process_filter_context *ctx,
				     pid_t pid)
{
	struct process_cache_entry *entry, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&global_cache.lock, flags);

	if (pid == 0) {
		/* Invalidate all entries */
		list_for_each_entry_safe(entry, tmp, &global_cache.entries, list) {
			list_del(&entry->list);
			kfree(entry);
		}
		global_cache.count = 0;
	} else {
		/* Invalidate specific entry */
		list_for_each_entry_safe(entry, tmp, &global_cache.entries, list) {
			if (entry->pid == pid) {
				list_del(&entry->list);
				kfree(entry);
				global_cache.count--;
				break;
			}
		}
	}

	spin_unlock_irqrestore(&global_cache.lock, flags);
}
EXPORT_SYMBOL_GPL(process_filter_cache_invalidate);

/* ========== Main Filtering Functions ========== */

/**
 * process_filter_check_pid() - Check if specific PID should be proxied
 */
bool process_filter_check_pid(struct process_filter_context *ctx, pid_t pid)
{
	struct process_credentials creds;
	unsigned long flags;
	bool should_proxy = false;
	bool cached_decision;
	int i, ret;

	if (!ctx)
		return false;

	atomic64_inc(&ctx->processes_checked);

	/* Check cache first */
	if (process_filter_cache_lookup(ctx, pid, &cached_decision))
		return cached_decision;

	/* Get process credentials */
	ret = process_filter_get_pid_credentials(pid, &creds);
	if (ret < 0)
		return false;

	spin_lock_irqsave(&ctx->config.lock, flags);

	switch (ctx->config.mode) {
	case PROCESS_FILTER_NONE:
		should_proxy = true;
		break;

	case PROCESS_FILTER_OWNER:
		/* Check if current process is owner or child */
		if (creds.pid == ctx->config.owner_creds.pid) {
			should_proxy = true;
		} else if (ctx->config.include_children) {
			should_proxy = process_filter_is_child_of(
				creds.pid, ctx->config.owner_creds.pid);
		}
		break;

	case PROCESS_FILTER_WHITELIST:
		/* Must match at least one rule */
		should_proxy = false;
		for (i = 0; i < ctx->config.rule_count; i++) {
			if (process_filter_match_rule(&ctx->config.rules[i],
						      &creds)) {
				should_proxy = true;
				break;
			}
		}
		break;

	case PROCESS_FILTER_BLACKLIST:
		/* Must not match any rule */
		should_proxy = true;
		for (i = 0; i < ctx->config.rule_count; i++) {
			if (process_filter_match_rule(&ctx->config.rules[i],
						      &creds)) {
				should_proxy = false;
				break;
			}
		}
		break;

	case PROCESS_FILTER_CGROUP:
		/* Check cgroup membership */
		should_proxy = false;
		for (i = 0; i < ctx->config.rule_count; i++) {
			if (ctx->config.rules[i].type == PROCESS_MATCH_CGROUP &&
			    process_filter_match_rule(&ctx->config.rules[i],
						      &creds)) {
				should_proxy = true;
				break;
			}
		}
		break;

	default:
		should_proxy = false;
		break;
	}

	spin_unlock_irqrestore(&ctx->config.lock, flags);

	/* Cache the decision */
	process_filter_cache_insert(ctx, pid, should_proxy);

	if (should_proxy)
		atomic64_inc(&ctx->packets_matched);
	else
		atomic64_inc(&ctx->packets_filtered);

	return should_proxy;
}
EXPORT_SYMBOL_GPL(process_filter_check_pid);

/**
 * process_filter_should_proxy() - Check if process should be proxied
 */
bool process_filter_should_proxy(struct process_filter_context *ctx,
				 struct sk_buff *skb)
{
	pid_t pid;

	if (!ctx)
		return false;

	/* If no filtering, allow all */
	if (ctx->config.mode == PROCESS_FILTER_NONE)
		return true;

	/* Get PID from current context or skb */
	if (skb && skb->sk && skb->sk->sk_socket &&
	    skb->sk->sk_socket->file) {
		/* Try to get PID from socket file */
		struct file *file = skb->sk->sk_socket->file;
		if (file->f_owner.pid)
			pid = pid_vnr(file->f_owner.pid);
		else
			pid = task_pid_nr(current);
	} else {
		pid = task_pid_nr(current);
	}

	return process_filter_check_pid(ctx, pid);
}
EXPORT_SYMBOL_GPL(process_filter_should_proxy);

/* ========== Statistics Functions ========== */

/**
 * process_filter_get_stats() - Get filtering statistics
 */
void process_filter_get_stats(struct process_filter_context *ctx,
			      u64 *packets_matched, u64 *packets_filtered,
			      u64 *processes_checked, u64 *cache_hits,
			      u64 *cache_misses)
{
	if (!ctx)
		return;

	if (packets_matched)
		*packets_matched = atomic64_read(&ctx->packets_matched);
	if (packets_filtered)
		*packets_filtered = atomic64_read(&ctx->packets_filtered);
	if (processes_checked)
		*processes_checked = atomic64_read(&ctx->processes_checked);
	if (cache_hits)
		*cache_hits = atomic64_read(&ctx->cache_hits);
	if (cache_misses)
		*cache_misses = atomic64_read(&ctx->cache_misses);
}
EXPORT_SYMBOL_GPL(process_filter_get_stats);

/**
 * process_filter_reset_stats() - Reset filtering statistics
 */
void process_filter_reset_stats(struct process_filter_context *ctx)
{
	if (!ctx)
		return;

	atomic64_set(&ctx->packets_matched, 0);
	atomic64_set(&ctx->packets_filtered, 0);
	atomic64_set(&ctx->processes_checked, 0);
	atomic64_set(&ctx->cache_hits, 0);
	atomic64_set(&ctx->cache_misses, 0);
}
EXPORT_SYMBOL_GPL(process_filter_reset_stats);

/* ========== Utility Functions ========== */

/**
 * process_filter_mode_name() - Get string name of filter mode
 */
const char *process_filter_mode_name(enum process_filter_mode mode)
{
	switch (mode) {
	case PROCESS_FILTER_NONE:
		return "none";
	case PROCESS_FILTER_WHITELIST:
		return "whitelist";
	case PROCESS_FILTER_BLACKLIST:
		return "blacklist";
	case PROCESS_FILTER_CGROUP:
		return "cgroup";
	case PROCESS_FILTER_OWNER:
		return "owner";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(process_filter_mode_name);

/**
 * process_filter_match_type_name() - Get string name of match type
 */
const char *process_filter_match_type_name(enum process_match_type type)
{
	switch (type) {
	case PROCESS_MATCH_PID:
		return "pid";
	case PROCESS_MATCH_UID:
		return "uid";
	case PROCESS_MATCH_GID:
		return "gid";
	case PROCESS_MATCH_COMM:
		return "comm";
	case PROCESS_MATCH_PATH:
		return "path";
	case PROCESS_MATCH_CGROUP:
		return "cgroup";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(process_filter_match_type_name);

/**
 * process_filter_scope_name() - Get string name of scope
 */
const char *process_filter_scope_name(enum process_scope scope)
{
	switch (scope) {
	case PROCESS_SCOPE_CURRENT:
		return "current";
	case PROCESS_SCOPE_TREE:
		return "tree";
	case PROCESS_SCOPE_SESSION:
		return "session";
	case PROCESS_SCOPE_GROUP:
		return "group";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(process_filter_scope_name);

/* ========== Module Init/Exit ========== */

/**
 * mutex_process_filter_init() - Initialize process filtering subsystem
 */
int mutex_process_filter_init(void)
{
	INIT_LIST_HEAD(&global_cache.entries);
	spin_lock_init(&global_cache.lock);
	global_cache.count = 0;

	pr_info("process_filter: initialized (cache_timeout=%us, max_entries=%u)\n",
		cache_timeout_secs, max_cache_entries);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_process_filter_init);

/**
 * mutex_process_filter_exit() - Clean up process filtering subsystem
 */
void mutex_process_filter_exit(void)
{
	struct process_cache_entry *entry, *tmp;

	/* Clear cache */
	list_for_each_entry_safe(entry, tmp, &global_cache.entries, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	pr_info("process_filter: exited\n");
}
EXPORT_SYMBOL_GPL(mutex_process_filter_exit);

MODULE_DESCRIPTION("MUTEX Process Filtering");
MODULE_AUTHOR("MUTEX Development Team");
MODULE_LICENSE("GPL v2");
