// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_proxy_core.c - MUTEX kernel-level proxy syscall implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This file implements the mutex_proxy_create() syscall that returns
 * a file descriptor for proxy control, following the "everything is a file"
 * paradigm similar to eventfd(), timerfd(), and signalfd().
 */

#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include "mutex_proxy.h"

/**
 * mutex_proxy_ctx_alloc - Allocate and initialize a new proxy context
 * @flags: Creation flags for the context
 *
 * Allocates a new mutex_proxy_context structure and initializes all fields.
 * Sets up spinlock, reference counting, owner credentials, and connection
 * tracking table.
 *
 * Return: Pointer to allocated context on success, NULL on failure
 */
struct mutex_proxy_context *mutex_proxy_ctx_alloc(unsigned int flags)
{
	struct mutex_proxy_context *ctx;
	unsigned int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		pr_err("mutex_proxy: failed to allocate context\n");
		return NULL;
	}

	/* Initialize spinlock for thread-safe access */
	spin_lock_init(&ctx->lock);

	/* Initialize atomic variables */
	atomic_set(&ctx->enabled, 0);
	atomic_set(&ctx->refcount, 1);

	/* Store owner process credentials */
	ctx->owner_pid = current->pid;
	ctx->owner_uid = current_uid();
	ctx->owner_gid = current_gid();
	ctx->flags = flags;

	/* Initialize configuration with defaults */
	ctx->config.version = 1;
	ctx->config.proxy_type = 0;
	ctx->config.proxy_port = 0;
	ctx->config.flags = 0;

	/* Initialize statistics to zero (already done by kzalloc) */

	/* Allocate connection tracking hash table */
	ctx->conn_table_size = 1024;
	ctx->conn_table = kzalloc(sizeof(struct hlist_head) *
				  ctx->conn_table_size, GFP_KERNEL);
	if (!ctx->conn_table) {
		pr_err("mutex_proxy: failed to allocate connection table\n");
		kfree(ctx);
		return NULL;
	}

	/* Initialize hash table buckets */
	for (i = 0; i < ctx->conn_table_size; i++)
		INIT_HLIST_HEAD(&ctx->conn_table[i]);

	pr_debug("mutex_proxy: allocated context for PID %d (UID %u, GID %u)\n",
		 ctx->owner_pid, from_kuid(&init_user_ns, ctx->owner_uid),
		 from_kgid(&init_user_ns, ctx->owner_gid));

	return ctx;
}

/**
 * mutex_proxy_ctx_get - Increment reference count on context
 * @ctx: Context to reference
 *
 * Increases the reference count on the context to prevent it from
 * being freed while still in use.
 */
void mutex_proxy_ctx_get(struct mutex_proxy_context *ctx)
{
	if (ctx)
		atomic_inc(&ctx->refcount);
}

/**
 * mutex_proxy_ctx_destroy_rcu - RCU callback for context destruction
 * @rcu: RCU head embedded in the context
 *
 * Called via RCU when it's safe to free the context memory.
 */
static void mutex_proxy_ctx_destroy_rcu(struct rcu_head *rcu)
{
	struct mutex_proxy_context *ctx = container_of(rcu,
					struct mutex_proxy_context, rcu);

	pr_debug("mutex_proxy: destroying context for PID %d\n", ctx->owner_pid);

	/* Free connection tracking table */
	if (ctx->conn_table)
		kfree(ctx->conn_table);

	/* Free the context itself */
	kfree(ctx);
}

/**
 * mutex_proxy_ctx_put - Decrement reference count and free if zero
 * @ctx: Context to dereference
 *
 * Decreases the reference count on the context. If the count reaches
 * zero, schedules the context for destruction via RCU.
 */
void mutex_proxy_ctx_put(struct mutex_proxy_context *ctx)
{
	if (!ctx)
		return;

	if (atomic_dec_and_test(&ctx->refcount)) {
		pr_debug("mutex_proxy: scheduling context destruction for PID %d\n",
			 ctx->owner_pid);
		call_rcu(&ctx->rcu, mutex_proxy_ctx_destroy_rcu);
	}
}

/**
 * sys_mutex_proxy_create - Create a new proxy control file descriptor
 * @flags: Creation flags (MUTEX_PROXY_CLOEXEC, MUTEX_PROXY_NONBLOCK, etc.)
 *
 * This syscall creates a file descriptor that can be used to control
 * kernel-level proxy behavior. It requires CAP_NET_ADMIN capability.
 *
 * Return: File descriptor on success, negative error code on failure
 */
SYSCALL_DEFINE1(mutex_proxy_create, unsigned int, flags)
{
	/* Check for CAP_NET_ADMIN capability */
	if (!capable(CAP_NET_ADMIN)) {
		pr_warn("mutex_proxy: Process %d (%s) lacks CAP_NET_ADMIN\n",
			current->pid, current->comm);
		return -EPERM;
	}

	/* Validate flags */
	if (flags & ~MUTEX_PROXY_ALL_FLAGS) {
		pr_warn("mutex_proxy: Invalid flags 0x%x from process %d\n",
			flags, current->pid);
		return -EINVAL;
	}

	/* TODO: Implement fd creation */
	pr_info("mutex_proxy: syscall invoked by process %d (%s) with flags 0x%x\n",
		current->pid, current->comm, flags);

	return -ENOSYS;
}
