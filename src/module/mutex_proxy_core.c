// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_proxy_core.c - MUTEX kernel-level proxy syscall implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This file implements the mprox_create() syscall that returns
 * a file descriptor for proxy control, following the "everything is a file"
 * paradigm similar to eventfd(), timerfd(), and signalfd().
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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include "mutex_proxy.h"
#include "mutex_proxy_meta.h"
#include "mutex_conn_track.h"

/* Forward declaration of file_operations - will be implemented incrementally */
static const struct file_operations mutex_proxy_fops;

/* Global list of all active proxy contexts */
static LIST_HEAD(proxy_contexts);
static DEFINE_SPINLOCK(proxy_contexts_lock);

/* Module parameter for debug logging */
static bool debug = false;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug logging");

/* Module parameters for runtime hook priority adjustment */
static int pre_routing_priority = MUTEX_PROXY_PRI_FIRST;
module_param(pre_routing_priority, int, 0644);
MODULE_PARM_DESC(pre_routing_priority, "Priority for PRE_ROUTING hook");

static int post_routing_priority = MUTEX_PROXY_PRI_LAST;
module_param(post_routing_priority, int, 0644);
MODULE_PARM_DESC(post_routing_priority, "Priority for POST_ROUTING hook");

static int local_out_priority = MUTEX_PROXY_PRI_FIRST;
module_param(local_out_priority, int, 0644);
MODULE_PARM_DESC(local_out_priority, "Priority for LOCAL_OUT hook");

/* Netfilter hook function declarations */
static unsigned int mutex_proxy_pre_routing(void *priv,
					     struct sk_buff *skb,
					     const struct nf_hook_state *state);
static unsigned int mutex_proxy_post_routing(void *priv,
					      struct sk_buff *skb,
					      const struct nf_hook_state *state);
static unsigned int mutex_proxy_local_out(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state);

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

	/* Initialize error counters */
	atomic64_set(&ctx->errors_invalid_packets, 0);
	atomic64_set(&ctx->errors_memory_alloc, 0);
	atomic64_set(&ctx->errors_protocol, 0);

	/* Store owner process credentials */
	ctx->owner_pid = current->pid;
	ctx->owner_uid = current_uid();
	ctx->owner_gid = current_gid();
	ctx->flags = flags;

	/* Initialize configuration with defaults */
	ctx->config.version = 1;
	ctx->config.num_servers = 0;
	ctx->config.selection_strategy = PROXY_SELECT_ROUND_ROBIN;
	ctx->config.current_server = 0;
	ctx->config.flags = 0;

	/* Initialize proxy selection state */
	ctx->next_server_index = 0;
	ctx->last_selection_jiffies = jiffies;

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

	/* Initialize list linkage */
	INIT_LIST_HEAD(&ctx->list);

	/* Add to global list of active contexts */
	spin_lock(&proxy_contexts_lock);
	list_add_rcu(&ctx->list, &proxy_contexts);
	spin_unlock(&proxy_contexts_lock);

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

	/* Clean up all connections for this context */
	mutex_conn_cleanup_context(ctx);

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

		/* Remove from global list before RCU destruction */
		spin_lock(&proxy_contexts_lock);
		list_del_rcu(&ctx->list);
		spin_unlock(&proxy_contexts_lock);

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
 * mutex_proxy_validate_server - Validate a single proxy server configuration
 * @server: Server configuration to validate
 *
 * Validates that the proxy server configuration has valid values for all fields.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_proxy_validate_server(const struct mutex_proxy_server *server)
{
	/* Check proxy type */
	if (server->proxy_type < 1 || server->proxy_type > PROXY_TYPE_MAX) {
		pr_warn("mutex_proxy: invalid proxy type %u\n", server->proxy_type);
		return -EINVAL;
	}

	/* Check proxy port */
	if (server->proxy_port == 0 || server->proxy_port > 65535) {
		pr_warn("mutex_proxy: invalid proxy port %u\n", server->proxy_port);
		return -EINVAL;
	}

	/* Validate IPv4 address (if not IPv6) */
	if (!(server->flags & PROXY_CONFIG_IPV6)) {
		/* Check if IPv4 address is not all zeros */
		if (server->proxy_addr[0] == 0 && server->proxy_addr[1] == 0 &&
		    server->proxy_addr[2] == 0 && server->proxy_addr[3] == 0) {
			pr_warn("mutex_proxy: invalid IPv4 address (all zeros)\n");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * mutex_proxy_validate_config - Validate entire proxy configuration
 * @config: Configuration to validate
 *
 * Validates the complete proxy configuration including all servers.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_proxy_validate_config(const struct mutex_proxy_config *config)
{
	unsigned int i;
	int ret;

	/* Check version */
	if (config->version != 1) {
		pr_warn("mutex_proxy: invalid config version %u\n", config->version);
		return -EINVAL;
	}

	/* Check number of servers */
	if (config->num_servers == 0) {
		pr_warn("mutex_proxy: no proxy servers configured\n");
		return -EINVAL;
	}

	if (config->num_servers > MUTEX_PROXY_MAX_SERVERS) {
		pr_warn("mutex_proxy: too many proxy servers (%u > %u)\n",
			config->num_servers, MUTEX_PROXY_MAX_SERVERS);
		return -EINVAL;
	}

	/* Check selection strategy */
	if (config->selection_strategy < PROXY_SELECT_ROUND_ROBIN ||
	    config->selection_strategy > PROXY_SELECT_RANDOM) {
		pr_warn("mutex_proxy: invalid selection strategy %u\n",
			config->selection_strategy);
		return -EINVAL;
	}

	/* Validate each server */
	for (i = 0; i < config->num_servers; i++) {
		ret = mutex_proxy_validate_server(&config->servers[i]);
		if (ret < 0) {
			pr_warn("mutex_proxy: server %u validation failed\n", i);
			return ret;
		}
	}

	return 0;
}

/**
 * mutex_proxy_select_server - Select next proxy server based on strategy
 * @ctx: Proxy context
 *
 * Selects the next proxy server to use based on the configured selection
 * strategy (round-robin, failover, random). Updates ctx->config.current_server.
 *
 * Must be called with ctx->lock held.
 *
 * Return: Index of selected server, or negative error code on failure
 */
int mutex_proxy_select_server(struct mutex_proxy_context *ctx)
{
	unsigned int i, selected;
	unsigned int num_active = 0;

	if (ctx->config.num_servers == 0) {
		pr_warn("mutex_proxy: no servers configured\n");
		return -ENOENT;
	}

	/* Count active servers */
	for (i = 0; i < ctx->config.num_servers; i++) {
		if (ctx->config.servers[i].flags & PROXY_CONFIG_ACTIVE)
			num_active++;
	}

	if (num_active == 0) {
		pr_warn("mutex_proxy: no active servers available\n");
		return -EHOSTUNREACH;
	}

	switch (ctx->config.selection_strategy) {
	case PROXY_SELECT_ROUND_ROBIN:
		/* Find next active server in round-robin fashion */
		selected = ctx->next_server_index;
		for (i = 0; i < ctx->config.num_servers; i++) {
			selected = (ctx->next_server_index + i) % ctx->config.num_servers;
			if (ctx->config.servers[selected].flags & PROXY_CONFIG_ACTIVE) {
				ctx->next_server_index = (selected + 1) % ctx->config.num_servers;
				ctx->config.current_server = selected;
				pr_debug("mutex_proxy: round-robin selected server %u\n", selected);
				return selected;
			}
		}
		break;

	case PROXY_SELECT_FAILOVER:
		/* Select first active server by priority */
		selected = 0;
		for (i = 0; i < ctx->config.num_servers; i++) {
			if (!(ctx->config.servers[i].flags & PROXY_CONFIG_ACTIVE))
				continue;

			if (selected == 0 ||
			    ctx->config.servers[i].priority < ctx->config.servers[selected].priority) {
				selected = i;
			}
		}
		ctx->config.current_server = selected;
		pr_debug("mutex_proxy: failover selected server %u (priority %u)\n",
			 selected, ctx->config.servers[selected].priority);
		return selected;

	case PROXY_SELECT_RANDOM:
		/* Select random active server */
		{
			unsigned int random_val;
			unsigned int active_count = 0;

			get_random_bytes(&random_val, sizeof(random_val));
			random_val %= num_active;

			for (i = 0; i < ctx->config.num_servers; i++) {
				if (!(ctx->config.servers[i].flags & PROXY_CONFIG_ACTIVE))
					continue;

				if (active_count == random_val) {
					ctx->config.current_server = i;
					pr_debug("mutex_proxy: random selected server %u\n", i);
					return i;
				}
				active_count++;
			}
		}
		break;

	default:
		pr_warn("mutex_proxy: unknown selection strategy %u\n",
			ctx->config.selection_strategy);
		return -EINVAL;
	}

	/* Should not reach here */
	return -EINVAL;
}

/**
 * mutex_proxy_read - Read configuration or statistics from proxy file descriptor
 * @file: File structure for the fd
 * @buf: User buffer to read data into
 * @count: Number of bytes to read
 * @ppos: File position (unused, always reads from beginning)
 *
 * Returns the current proxy configuration or statistics to userspace.
 * If count equals sizeof(stats), returns statistics; if count equals
 * sizeof(config), returns configuration. This is thread-safe and uses
 * a spinlock to protect the data structures.
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t mutex_proxy_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_stats stats;
	struct mutex_proxy_config config;
	size_t to_copy;
	unsigned long flags;
	void *data_ptr;
	size_t data_size;

	if (!ctx)
		return -EINVAL;

	/* Determine what to read based on count */
	if (count == sizeof(stats)) {
		/* Reading statistics */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&stats, &ctx->stats, sizeof(stats));
		spin_unlock_irqrestore(&ctx->lock, flags);

		data_ptr = &stats;
		data_size = sizeof(stats);
	} else if (count == sizeof(config) || count >= sizeof(config)) {
		/* Reading configuration */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&config, &ctx->config, sizeof(config));
		spin_unlock_irqrestore(&ctx->lock, flags);

		data_ptr = &config;
		data_size = sizeof(config);
	} else {
		/* Invalid size */
		pr_warn("mutex_proxy: invalid read size %zu (expected %zu or %zu)\n",
			count, sizeof(stats), sizeof(config));
		return -EINVAL;
	}

	/* If already read everything, return EOF */
	if (*ppos >= data_size)
		return 0;

	/* Calculate how much to copy */
	to_copy = min(count, data_size - (size_t)*ppos);

	/* Copy to userspace */
	if (copy_to_user(buf, ((char *)data_ptr) + *ppos, to_copy))
		return -EFAULT;

	*ppos += to_copy;

	pr_debug("mutex_proxy: read %zu bytes for PID %d\n", to_copy, ctx->owner_pid);

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
 * complete configuration (version, proxy servers, selection strategy)
 * and atomically updates the context under spinlock protection.
 * Supports multiple proxy servers with automatic selection.
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t mutex_proxy_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct mutex_proxy_context *ctx = file->private_data;
	struct mutex_proxy_config new_config;
	unsigned long flags;
	int ret;

	if (!ctx)
		return -EINVAL;

	/* Only accept writes of exact config structure size */
	if (count != sizeof(struct mutex_proxy_config))
		return -EINVAL;

	/* Copy config from userspace */
	if (copy_from_user(&new_config, buf, sizeof(new_config)))
		return -EFAULT;

	/* Validate configuration */
	ret = mutex_proxy_validate_config(&new_config);
	if (ret < 0) {
		pr_warn("mutex_proxy: configuration validation failed\n");
		return ret;
	}

	/* Atomically update configuration under lock */
	spin_lock_irqsave(&ctx->lock, flags);
	memcpy(&ctx->config, &new_config, sizeof(new_config));

	/* Reset selection state */
	ctx->next_server_index = 0;
	ctx->last_selection_jiffies = jiffies;

	/* Select initial server */
	ret = mutex_proxy_select_server(ctx);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (ret < 0) {
		pr_warn("mutex_proxy: failed to select server: %d\n", ret);
		return ret;
	}

	pr_info("mutex_proxy: updated config for PID %d (%u servers, strategy=%u)\n",
		ctx->owner_pid, new_config.num_servers, new_config.selection_strategy);

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
		pr_info("mutex_proxy: enabled hook processing for PID %d (fd will intercept packets when context list implemented)\n",
			ctx->owner_pid);
		break;

	case MUTEX_PROXY_IOC_DISABLE:
		atomic_set(&ctx->enabled, 0);
		pr_info("mutex_proxy: disabled hook processing for PID %d (packets will bypass this fd's rules)\n",
			ctx->owner_pid);
		break;

	case MUTEX_PROXY_IOC_SET_CONFIG:
		/* Copy config from userspace */
		if (copy_from_user(&new_config, argp, sizeof(new_config)))
			return -EFAULT;

		/* Validate configuration */
		ret = mutex_proxy_validate_config(&new_config);
		if (ret < 0) {
			pr_warn("mutex_proxy: ioctl: configuration validation failed\n");
			return ret;
		}

		/* Atomically update configuration */
		spin_lock_irqsave(&ctx->lock, flags);
		memcpy(&ctx->config, &new_config, sizeof(new_config));

		/* Reset selection state */
		ctx->next_server_index = 0;
		ctx->last_selection_jiffies = jiffies;

		/* Select initial server */
		ret = mutex_proxy_select_server(ctx);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (ret < 0) {
			pr_warn("mutex_proxy: ioctl: failed to select server: %d\n", ret);
			return ret;
		}

		pr_info("mutex_proxy: ioctl: updated config for PID %d\n", ctx->owner_pid);
		ret = 0;
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

/* Netfilter hook operations - priorities set at module init */
static struct nf_hook_ops nf_hooks[] = {
	{
		.hook		= mutex_proxy_pre_routing,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		/* Priority set in mutex_proxy_init() */
		/* PRE_ROUTING: First to see packets before NAT/routing decision */
	},
	{
		.hook		= mutex_proxy_post_routing,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		/* Priority set in mutex_proxy_init() */
		/* POST_ROUTING: Last to modify packets before they leave system */
	},
	{
		.hook		= mutex_proxy_local_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		/* Priority set in mutex_proxy_init() */
		/* LOCAL_OUT: First to intercept locally generated connections */
	},
};

/**
 * struct packet_info - Protocol-independent packet information
 * @protocol: IP protocol number (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
 * @saddr: Source IP address
 * @daddr: Destination IP address
 * @sport: Source port (TCP/UDP only)
 * @dport: Destination port (TCP/UDP only)
 * @icmp_type: ICMP type (ICMP only)
 * @icmp_code: ICMP code (ICMP only)
 */
struct packet_info {
	u8 protocol;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	u8 icmp_type;
	u8 icmp_code;
};

/**
 * extract_tcp_info - Extract TCP packet information
 * @skb: Socket buffer
 * @iph: IP header
 * @info: Output packet information structure
 *
 * Return: true on success, false on error
 */
static bool extract_tcp_info(struct sk_buff *skb, struct iphdr *iph,
			      struct packet_info *info)
{
	struct tcphdr *tcph;

	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return false;

	tcph = tcp_hdr(skb);
	if (!tcph)
		return false;

	info->protocol = IPPROTO_TCP;
	info->saddr = iph->saddr;
	info->daddr = iph->daddr;
	info->sport = tcph->source;
	info->dport = tcph->dest;

	return true;
}

/**
 * extract_udp_info - Extract UDP packet information
 * @skb: Socket buffer
 * @iph: IP header
 * @info: Output packet information structure
 *
 * Return: true on success, false on error
 */
static bool extract_udp_info(struct sk_buff *skb, struct iphdr *iph,
			      struct packet_info *info)
{
	struct udphdr *udph;

	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
		return false;

	udph = udp_hdr(skb);
	if (!udph)
		return false;

	info->protocol = IPPROTO_UDP;
	info->saddr = iph->saddr;
	info->daddr = iph->daddr;
	info->sport = udph->source;
	info->dport = udph->dest;

	return true;
}

/**
 * extract_icmp_info - Extract ICMP packet information
 * @skb: Socket buffer
 * @iph: IP header
 * @info: Output packet information structure
 *
 * Return: true on success, false on error
 */
static bool extract_icmp_info(struct sk_buff *skb, struct iphdr *iph,
			       struct packet_info *info)
{
	struct icmphdr *icmph;

	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct icmphdr)))
		return false;

	icmph = icmp_hdr(skb);
	if (!icmph)
		return false;

	info->protocol = IPPROTO_ICMP;
	info->saddr = iph->saddr;
	info->daddr = iph->daddr;
	info->icmp_type = icmph->type;
	info->icmp_code = icmph->code;
	info->sport = 0;
	info->dport = 0;

	return true;
}

/**
 * extract_packet_info - Extract protocol-specific packet information
 * @skb: Socket buffer
 * @info: Output packet information structure
 *
 * Dispatches to protocol-specific extraction functions based on IP protocol.
 *
 * Return: true on success, false on error or unsupported protocol
 */
static bool extract_packet_info(struct sk_buff *skb, struct packet_info *info)
{
	struct iphdr *iph;

	if (!skb)
		return false;

	iph = ip_hdr(skb);
	if (!iph)
		return false;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		return extract_tcp_info(skb, iph, info);
	case IPPROTO_UDP:
		return extract_udp_info(skb, iph, info);
	case IPPROTO_ICMP:
		return extract_icmp_info(skb, iph, info);
	default:
		pr_debug("mutex_proxy: unsupported protocol %u\n", iph->protocol);
		return false;
	}
}

/**
 * mutex_proxy_should_intercept - Check if packet should be proxied
 * @skb: Socket buffer containing the packet
 *
 * Determines if the current packet matches any active proxy configuration.
 * Currently a placeholder that always returns false.
 *
 * Return: true if packet should be proxied, false otherwise
 */
static bool mutex_proxy_should_intercept(struct sk_buff *skb)
{
	struct packet_info info;
	struct mutex_proxy_context *ctx;

	/* Extract packet information (supports TCP/UDP/ICMP) */
	if (!extract_packet_info(skb, &info))
		return false;

	/* Check all active proxy contexts to see if any want to intercept this packet */
	rcu_read_lock();
	list_for_each_entry_rcu(ctx, &proxy_contexts, list) {
		/* Skip disabled contexts */
		if (!atomic_read(&ctx->enabled))
			continue;

		/* TODO: Add sophisticated matching logic
		 * - Match packet against ctx->config rules (dest port/addr)
		 * - Check protocol filtering (TCP/UDP/ICMP)
		 * - Check if packet is from/to process owning this ctx
		 * For now, any enabled context causes interception
		 */

		/* Found at least one enabled context */
		rcu_read_unlock();
		return true;
	}
	rcu_read_unlock();

	return false;
}

/**
 * mutex_proxy_pre_routing - Netfilter hook for incoming packets
 * @priv: Private data (unused)
 * @skb: Socket buffer containing the packet
 * @state: Netfilter hook state
 *
 * Called for all incoming packets before routing decision.
 * This is where we intercept incoming connections that need to be proxied.
 *
 * Return: NF_ACCEPT to continue processing, NF_DROP to drop packet
 */
static unsigned int mutex_proxy_pre_routing(void *priv,
					     struct sk_buff *skb,
					     const struct nf_hook_state *state)
{
	struct packet_info info;

	/* Validate skb - NULL check */
	if (unlikely(!skb)) {
		pr_err_ratelimited("mutex_proxy: PRE_ROUTING - NULL skb\n");
		return NF_ACCEPT;
	}

	/* Extract packet information (handles TCP/UDP/ICMP) */
	if (unlikely(!extract_packet_info(skb, &info))) {
		/* Unsupported protocol or malformed packet - early exit */
		pr_debug_ratelimited("mutex_proxy: PRE_ROUTING - failed to extract packet info\n");
		return NF_ACCEPT;
	}

	/* Check if this packet should be proxied - early exit for non-proxied */
	if (likely(!mutex_proxy_should_intercept(skb))) {
		/* Most packets won't be proxied - fast path */
		return NF_ACCEPT;
	}

	/* Mark packet for proxy handling */
	skb->mark = 0x1;  /* Custom mark for proxied packets */
	if (debug)
		pr_info("mutex_proxy: PRE_ROUTING - marked packet for proxying\n");

	/* Protocol-specific debug logging */
	switch (info.protocol) {
	case IPPROTO_TCP:
		pr_debug("mutex_proxy: PRE_ROUTING TCP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_UDP:
		pr_debug("mutex_proxy: PRE_ROUTING UDP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_ICMP:
		pr_debug("mutex_proxy: PRE_ROUTING ICMP - src=%pI4 dst=%pI4 type=%u code=%u\n",
			 &info.saddr, &info.daddr,
			 info.icmp_type, info.icmp_code);
		break;
	}

	return NF_ACCEPT;
}

/**
 * mutex_proxy_post_routing - Netfilter hook for outgoing packets
 * @priv: Private data (unused)
 * @skb: Socket buffer containing the packet
 * @state: Netfilter hook state
 *
 * Called for all outgoing packets after routing decision.
 * This is where we can modify packets before they leave the system.
 *
 * Return: NF_ACCEPT to continue processing, NF_DROP to drop packet
 */
static unsigned int mutex_proxy_post_routing(void *priv,
					      struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	struct packet_info info;

	/* Validate skb - NULL check */
	if (unlikely(!skb)) {
		pr_err_ratelimited("mutex_proxy: POST_ROUTING - NULL skb\n");
		return NF_ACCEPT;
	}

	/* Extract packet information */
	if (!extract_packet_info(skb, &info)) {
		pr_debug_ratelimited("mutex_proxy: POST_ROUTING - failed to extract packet info\n");
		return NF_ACCEPT;
	}

	/* Check if packet is marked for proxying */
	if (skb->mark == 0x1) {
		if (debug)
			pr_info("mutex_proxy: POST_ROUTING - processing marked packet\n");
		/* TODO: Rewrite packet headers
		 * - Replace source address/port with proxy server
		 * - Update checksums
		 */
	}

	/* Protocol-specific debug logging */
	switch (info.protocol) {
	case IPPROTO_TCP:
		pr_debug("mutex_proxy: POST_ROUTING TCP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_UDP:
		pr_debug("mutex_proxy: POST_ROUTING UDP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_ICMP:
		pr_debug("mutex_proxy: POST_ROUTING ICMP - src=%pI4 dst=%pI4 type=%u code=%u\n",
			 &info.saddr, &info.daddr,
			 info.icmp_type, info.icmp_code);
		break;
	}

	return NF_ACCEPT;
}

/**
 * mutex_proxy_local_out - Netfilter hook for locally generated packets
 * @priv: Private data (unused)
 * @skb: Socket buffer containing the packet
 * @state: Netfilter hook state
 *
 * Called for packets originating from this machine.
 * This is where we intercept locally initiated connections.
 *
 * Return: NF_ACCEPT to continue processing, NF_DROP to drop packet
 */
static unsigned int mutex_proxy_local_out(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	struct packet_info info;

	/* Validate skb - NULL check */
	if (unlikely(!skb)) {
		pr_err_ratelimited("mutex_proxy: LOCAL_OUT - NULL skb\n");
		return NF_ACCEPT;
	}

	/* Extract packet information */
	if (!extract_packet_info(skb, &info)) {
		pr_debug_ratelimited("mutex_proxy: LOCAL_OUT - failed to extract packet info\n");
		return NF_ACCEPT;
	}

	/* Check if originating process has active proxy fd */
	if (mutex_proxy_should_intercept(skb)) {
		/* Mark for proxying */
		skb->mark = 0x1;
		if (debug)
			pr_info("mutex_proxy: LOCAL_OUT - marked local packet for proxying\n");
	}

	/* Protocol-specific debug logging */
	switch (info.protocol) {
	case IPPROTO_TCP:
		pr_debug("mutex_proxy: LOCAL_OUT TCP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_UDP:
		pr_debug("mutex_proxy: LOCAL_OUT UDP - src=%pI4:%u dst=%pI4:%u\n",
			 &info.saddr, ntohs(info.sport),
			 &info.daddr, ntohs(info.dport));
		break;
	case IPPROTO_ICMP:
		pr_debug("mutex_proxy: LOCAL_OUT ICMP - src=%pI4 dst=%pI4 type=%u code=%u\n",
			 &info.saddr, &info.daddr,
			 info.icmp_type, info.icmp_code);
		break;
	}

	return NF_ACCEPT;
}

/**
 * mutex_proxy_init - Module initialization
 *
 * Called when the module is loaded. Registers netfilter hooks to intercept
 * network traffic at key points in the packet processing pipeline.
 * Hook priorities can be adjusted via module parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init mutex_proxy_init(void)
{
	int ret;

	pr_info("mutex_proxy: initializing module\n");

	/* Validate and set hook priorities from module parameters */
	if (pre_routing_priority < NF_IP_PRI_FIRST || pre_routing_priority > NF_IP_PRI_LAST) {
		pr_warn("mutex_proxy: invalid pre_routing_priority %d, using default %d\n",
			pre_routing_priority, MUTEX_PROXY_PRI_FIRST);
		pre_routing_priority = MUTEX_PROXY_PRI_FIRST;
	}

	if (post_routing_priority < NF_IP_PRI_FIRST || post_routing_priority > NF_IP_PRI_LAST) {
		pr_warn("mutex_proxy: invalid post_routing_priority %d, using default %d\n",
			post_routing_priority, MUTEX_PROXY_PRI_LAST);
		post_routing_priority = MUTEX_PROXY_PRI_LAST;
	}

	if (local_out_priority < NF_IP_PRI_FIRST || local_out_priority > NF_IP_PRI_LAST) {
		pr_warn("mutex_proxy: invalid local_out_priority %d, using default %d\n",
			local_out_priority, MUTEX_PROXY_PRI_FIRST);
		local_out_priority = MUTEX_PROXY_PRI_FIRST;
	}

	/* Set priorities in hook operations */
	nf_hooks[0].priority = pre_routing_priority;
	nf_hooks[1].priority = post_routing_priority;
	nf_hooks[2].priority = local_out_priority;

	pr_info("mutex_proxy: hook priorities - PRE_ROUTING:%d POST_ROUTING:%d LOCAL_OUT:%d\n",
		pre_routing_priority, post_routing_priority, local_out_priority);

	/* Initialize connection tracking subsystem */
	ret = mutex_conn_track_init();
	if (ret) {
		pr_err("mutex_proxy: failed to initialize connection tracking: %d\n", ret);
		return ret;
	}
	pr_info("mutex_proxy: connection tracking initialized\n");

	/* Register netfilter hooks */
	ret = nf_register_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
	if (ret) {
		pr_err("mutex_proxy: failed to register netfilter hooks: %d\n", ret);
		mutex_conn_track_exit();
		return ret;
	}

	pr_info("mutex_proxy: registered %zu netfilter hooks\n", ARRAY_SIZE(nf_hooks));
	pr_info("mutex_proxy: module loaded successfully\n");

	return 0;
}

/**
 * mutex_proxy_exit - Module cleanup
 *
 * Called when the module is unloaded. Unregisters netfilter hooks and
 * cleans up all resources. All active file descriptors should be closed
 * before unloading.
 */
static void __exit mutex_proxy_exit(void)
{
	pr_info("mutex_proxy: unloading module\n");

	/* Unregister netfilter hooks */
	nf_unregister_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
	pr_info("mutex_proxy: unregistered netfilter hooks\n");

	/* Cleanup connection tracking */
	mutex_conn_track_exit();
	pr_info("mutex_proxy: connection tracking cleaned up\n");

	pr_info("mutex_proxy: module unloaded successfully\n");
}

module_init(mutex_proxy_init);
module_exit(mutex_proxy_exit);

MODULE_LICENSE(MPX_LICENSE);
MODULE_AUTHOR(MPX_AUTHOR);
MODULE_DESCRIPTION(MPX_DESCRIPTION);
MODULE_VERSION(MPX_VERSION);
