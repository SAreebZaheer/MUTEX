/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_proxy.h - MUTEX kernel-level proxy module header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 */

#ifndef _MUTEX_PROXY_H
#define _MUTEX_PROXY_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include "../../linux/include/uapi/linux/mutex_proxy.h"

/**
 * struct mutex_proxy_context - Per-fd private data structure
 * @config: Proxy configuration (type, port, address, etc.)
 * @stats: Proxy statistics (bytes, packets, connections)
 * @lock: Spinlock protecting this structure
 * @enabled: Atomic flag indicating if proxy is enabled
 * @owner_pid: PID of process that created this fd
 * @owner_uid: UID of process that created this fd
 * @owner_gid: GID of process that created this fd
 * @flags: Creation flags (CLOEXEC, NONBLOCK, GLOBAL)
 * @conn_table: Hash table for connection tracking
 * @conn_table_size: Size of connection tracking hash table
 * @rcu: RCU head for safe destruction
 * @refcount: Reference counter for this context
 *
 * Each file descriptor has its own independent proxy configuration
 * stored in this structure. All accesses must be protected by the
 * spinlock for thread safety.
 */
struct mutex_proxy_context {
	struct mutex_proxy_config config;
	struct mutex_proxy_stats stats;

	spinlock_t lock;		/* Protects this structure */
	atomic_t enabled;		/* Is proxy enabled? */

	pid_t owner_pid;		/* Process that created fd */
	kuid_t owner_uid;		/* Owner's UID */
	kgid_t owner_gid;		/* Owner's GID */

	unsigned int flags;		/* Creation flags */

	/* Connection tracking */
	struct hlist_head *conn_table;
	unsigned int conn_table_size;

	/* Event notification support */
	wait_queue_head_t wait;		/* For poll/select/epoll */
	unsigned int event_count;	/* Event counter */

	struct rcu_head rcu;		/* For RCU-safe destruction */
	atomic_t refcount;		/* Reference counting */
};

/* Context management functions */
struct mutex_proxy_context *mutex_proxy_ctx_alloc(unsigned int flags);
void mutex_proxy_ctx_get(struct mutex_proxy_context *ctx);
void mutex_proxy_ctx_put(struct mutex_proxy_context *ctx);

/* System call prototype - mprox_create (syscall 471) */
asmlinkage long sys_mutex_proxy_create(unsigned int flags);

#endif /* _MUTEX_PROXY_H */
