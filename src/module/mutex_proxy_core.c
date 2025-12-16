// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_proxy_core.c - Multithreaded kernel-level proxy syscall implementation by MUTEX Team
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This file implements the mprox_create() syscall that returns
 * a file descriptor for proxy control, following the "everything is a file"
 * paradigm similar to eventfd(), timerfd(), and signalfd().
 * 
 * Each mention of MUTEX is a refference to the project name, not Mututal Exclusion, unless stated otherwise.
 */

#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/module.h>
#include "mutex_proxy.h"
#include "mutex_proxy_meta.h"

/* Forward declaration of file_operations - will be implemented incrementally */
static const struct file_operations mutex_proxy_fops;

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

	/* Initialize wait queue for poll() support */
	init_waitqueue_head(&ctx->wait);
	ctx->event_count = 0;

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
 * mutex_proxy_create_fd - Create file descriptor for proxy context
 * @ctx: Proxy context to associate with the fd
 * @flags: Creation flags (CLOEXEC, NONBLOCK, GLOBAL)
 *
 * Creates an anonymous inode file descriptor and associates it with the
 * given proxy context. This follows the same pattern as eventfd(), timerfd(),
 * and signalfd().
 *
 * The fd will appear as "[mutex_proxy]" in /proc/self/fd/.
 *
 * Return: File descriptor number on success, negative error code on failure
 */
static int mutex_proxy_create_fd(struct mutex_proxy_context *ctx,
				  unsigned int flags)
{
	int fd;
	int o_flags = O_RDWR;

	/* Convert proxy flags to file open flags */
	if (flags & MUTEX_PROXY_CLOEXEC)
		o_flags |= O_CLOEXEC;
	if (flags & MUTEX_PROXY_NONBLOCK)
		o_flags |= O_NONBLOCK;

	/*
	 * Create anonymous inode with our file_operations.
	 * The name "[mutex_proxy]" will be visible in /proc/PID/fd/
	 */
	fd = anon_inode_getfd("[mutex_proxy]", &mutex_proxy_fops,
			      ctx, o_flags);
	if (fd < 0) {
		pr_err("mutex_proxy: failed to create fd: %d\n", fd);
		return fd;
	}

	pr_debug("mutex_proxy: created fd %d for PID %d\n", fd, ctx->owner_pid);

	return fd;
}

/*
 * NOTE: The syscall implementation has been moved to linux/kernel/mutex_proxy.c
 * This module provides additional functionality that can be loaded dynamically,
 * while the core syscall is built into the kernel.
 */

/**
 * mutex_proxy_read - Read statistics from proxy file descriptor
 * @file: File structure for the fd
 * @buf: User buffer to read data into
 * @count: Number of bytes to read
 * @ppos: File position (unused, always reads from beginning)
 *
 * Returns the current proxy statistics to userspace. This is thread-safe
 * and uses a spinlock to protect the statistics structure. Supports partial
 * reads if the buffer is smaller than the statistics structure.
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t mutex_proxy_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_stats stats;
	size_t to_copy;
	unsigned long flags;

	if (!ctx)
		return -EINVAL;

	/* If already read everything, return EOF */
	if (*ppos >= sizeof(stats))
		return 0;

	/* Copy current statistics under lock */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&stats, &ctx->stats, sizeof(stats));
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Calculate how much to copy */
	to_copy = min(count, sizeof(stats) - (size_t)*ppos);

	/* Copy to userspace */
	if (copy_to_user(buf, ((char *)&stats) + *ppos, to_copy))
		return -EFAULT;

	*ppos += to_copy;

	pr_debug("mutex_proxy: read %zu bytes of statistics for PID %d\n",
		 to_copy, ctx->owner_pid);

	return to_copy;
}

/**
 * mutex_proxy_write - Write configuration to proxy file descriptor
 * @file: File structure for the fd
 * @buf: User buffer containing configuration data
 * @count: Number of bytes to write
 * @ppos: File position (unused, always writes to beginning)
 *
 * Updates the proxy configuration from userspace. This validates the
 * configuration (version, proxy type, port range) and atomically updates
 * the context under spinlock protection.
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t mutex_proxy_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_config new_config;
	unsigned long flags;

	if (!ctx)
		return -EINVAL;

	/* Only accept writes of exact config structure size */
	if (count != sizeof(struct mutex_proxy_config))
		return -EINVAL;

	/* Copy config from userspace */
	if (copy_from_user(&new_config, buf, sizeof(new_config)))
		return -EFAULT;

	/* Validate configuration */
	if (new_config.version != 1) {
		pr_warn("mutex_proxy: invalid config version %u\n",
			new_config.version);
		return -EINVAL;
	}

	if (new_config.proxy_type < 1 ||
	    new_config.proxy_type > PROXY_TYPE_MAX) {
		pr_warn("mutex_proxy: invalid proxy type %u\n",
			new_config.proxy_type);
		return -EINVAL;
	}

	if (new_config.proxy_port == 0 || new_config.proxy_port > 65535) {
		pr_warn("mutex_proxy: invalid proxy port %u\n",
			new_config.proxy_port);
		return -EINVAL;
	}

	/* Atomically update configuration under lock */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&ctx->config, &new_config, sizeof(new_config));
	spin_unlock_irqrestore(&ctx->lock, flags);

	pr_debug("mutex_proxy: updated config for PID %d (type=%u, port=%u)\n",
		 ctx->owner_pid, new_config.proxy_type, new_config.proxy_port);

	return sizeof(new_config);
}

/**
 * mutex_proxy_ioctl - ioctl handler for proxy file descriptor
 * @file: File structure for the fd
 * @cmd: ioctl command
 * @arg: ioctl argument
 *
 * Provides alternative control interface to read/write operations.
 * Supports ENABLE/DISABLE, SET_CONFIG/GET_CONFIG, and GET_STATS.
 *
 * Return: 0 on success, negative error code on failure
 */
static long mutex_proxy_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct mutex_proxy_context *ctx = file->private_data;
	void __user *argp = (void __user *)arg;
	struct mutex_proxy_config new_config;
	unsigned long flags;
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	switch (cmd) {
	case MUTEX_PROXY_IOC_ENABLE:
		atomic_set(&ctx->enabled, 1);
		pr_info("mutex_proxy: enabled for PID %d\n", ctx->owner_pid);
		break;

	case MUTEX_PROXY_IOC_DISABLE:
		atomic_set(&ctx->enabled, 0);
		pr_info("mutex_proxy: disabled for PID %d\n", ctx->owner_pid);
		break;

	case MUTEX_PROXY_IOC_SET_CONFIG:
		/* Copy config from userspace */
		if (copy_from_user(&new_config, argp, sizeof(new_config)))
			return -EFAULT;

		/* Validate configuration */
		if (new_config.version != 1) {
			pr_warn("mutex_proxy: ioctl: invalid config version %u\n",
				new_config.version);
			return -EINVAL;
		}

		if (new_config.proxy_type < 1 ||
		    new_config.proxy_type > PROXY_TYPE_MAX) {
			pr_warn("mutex_proxy: ioctl: invalid proxy type %u\n",
				new_config.proxy_type);
			return -EINVAL;
		}

		if (new_config.proxy_port == 0 || new_config.proxy_port > 65535) {
			pr_warn("mutex_proxy: ioctl: invalid proxy port %u\n",
				new_config.proxy_port);
			return -EINVAL;
		}

		/* Atomically update configuration */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&ctx->config, &new_config, sizeof(new_config));
		spin_unlock_irqrestore(&ctx->lock, flags);

		pr_debug("mutex_proxy: ioctl: updated config for PID %d\n",
			 ctx->owner_pid);
		break;

	case MUTEX_PROXY_IOC_GET_CONFIG:
		/* Copy config to userspace under lock */
		spin_lock_irqsave(&ctx->lock, flags);
		ret = copy_to_user(argp, &ctx->config, sizeof(ctx->config));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (ret)
			return -EFAULT;
		break;

	case MUTEX_PROXY_IOC_GET_STATS:
		/* Copy stats to userspace under lock */
		spin_lock_irqsave(&ctx->lock, flags);
		ret = copy_to_user(argp, &ctx->stats, sizeof(ctx->stats));
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (ret)
			return -EFAULT;
		break;

	default:
		pr_warn("mutex_proxy: unknown ioctl command 0x%x\n", cmd);
		return -ENOTTY;
	}

	return 0;
}

/**
 * mutex_proxy_poll - poll handler for proxy file descriptor
 * @file: File structure for the fd
 * @wait: poll_table for registration
 *
 * Implements poll/select/epoll support for the proxy fd.
 * Always readable (stats available) and writable (can accept config).
 * Signals POLLHUP when proxy is disabled.
 *
 * Return: Poll event mask
 */
static __poll_t mutex_proxy_poll(struct file *file, poll_table *wait)
{
	struct mutex_proxy_context *ctx = file->private_data;
	__poll_t events = 0;

	if (!ctx)
		return POLLERR;

	/* Register with wait queue */
	poll_wait(file, &ctx->wait, wait);

	/* Always readable - stats are always available */
	events |= POLLIN | POLLRDNORM;

	/* Always writable - can always accept configuration */
	events |= POLLOUT | POLLWRNORM;

	/* Signal hangup if proxy is disabled */
	if (!atomic_read(&ctx->enabled))
		events |= POLLHUP;

	pr_debug("mutex_proxy: poll() for PID %d, events=0x%x\n",
		 ctx->owner_pid, events);

	return events;
}

/**
 * mutex_proxy_release - Release handler for proxy file descriptor
 * @inode: Inode associated with the file
 * @file: File structure being released
 *
 * Called when the file descriptor is closed. This disables the proxy
 * and releases the reference to the context, which will be freed when
 * the reference count reaches zero.
 *
 * Return: 0 on success
 */
static int mutex_proxy_release(struct inode *inode, struct file *file)
{
	struct mutex_proxy_context *ctx = file->private_data;

	if (!ctx)
		return 0;

	pr_debug("mutex_proxy: releasing fd for PID %d\n", ctx->owner_pid);

	/* Disable proxy when fd is closed */
	atomic_set(&ctx->enabled, 0);

	/* Release our reference to the context */
	mutex_proxy_ctx_put(ctx);

	return 0;
}

/**
 * file_operations structure for proxy file descriptor
 *
 * This will be incrementally implemented with:
 * - release: Close/cleanup operations
 * - read: Return statistics
 * - write: Update configuration
 * - unlocked_ioctl: Control operations
 * - poll: Event notifications
 */
static const struct file_operations mutex_proxy_fops = {
	.owner			= THIS_MODULE,
	.release		= mutex_proxy_release,
	.read			= mutex_proxy_read,
	.write			= mutex_proxy_write,
	.unlocked_ioctl		= mutex_proxy_ioctl,
	.compat_ioctl		= mutex_proxy_ioctl,
	.poll			= mutex_proxy_poll,
	.llseek			= noop_llseek,
};

/**
 * mutex_proxy_init - Module initialization
 *
 * Called when the module is loaded. Currently just logs a message.
 * Future: Register netfilter hooks, initialize global state.
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init mutex_proxy_init(void)
{
	pr_info("mutex_proxy: module loaded\n");
	return 0;
}

/**
 * mutex_proxy_exit - Module cleanup
 *
 * Called when the module is unloaded. Cleans up all resources.
 * All active file descriptors should be closed before unloading.
 */
static void __exit mutex_proxy_exit(void)
{
	pr_info("mutex_proxy: module unloaded\n");
}

module_init(mutex_proxy_init);
module_exit(mutex_proxy_exit);

MODULE_LICENSE(MPX_LICENSE);
MODULE_AUTHOR(MPX_AUTHOR);
MODULE_DESCRIPTION(MPX_DESCRIPTION);
MODULE_VERSION(MPX_VERSION);
