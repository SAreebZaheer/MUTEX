// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_conn_track.c - MUTEX connection tracking implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements connection state tracking for proxied connections.
 * It maintains a hash table of active connections, tracks original and proxied
 * addresses, and handles connection lifecycle management with automatic
 * garbage collection.
 *
 * PERFORMANCE OPTIMIZATIONS (Branch 13):
 * - Uses optimized hash functions from mutex_perf_opt for better distribution
 * - Integrates per-CPU connection cache for fast lookups
 * - Uses slab cache allocation from connection pool
 * - RCU-protected reads for hot path lock-free access
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include "mutex_conn_track.h"
#include "mutex_perf_opt.h"

/* Global connection tracking table */
static struct conn_track_table *global_conn_table = NULL;

/* Forward declarations for internal functions */
static void conn_timeout_handler(struct timer_list *t);
static void conn_gc_handler(struct timer_list *t);

/**
 * mutex_conn_track_init - Initialize connection tracking subsystem
 *
 * Allocates and initializes the global connection tracking table.
 * Sets up hash table buckets, per-bucket locks, and garbage collection timer.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_conn_track_init(void)
{
	unsigned int i;

	if (global_conn_table) {
		pr_warn("mutex_conn_track: already initialized\n");
		return -EEXIST;
	}

	global_conn_table = kzalloc(sizeof(*global_conn_table), GFP_KERNEL);
	if (!global_conn_table) {
		pr_err("mutex_conn_track: failed to allocate connection table\n");
		return -ENOMEM;
	}

	/* Initialize hash table buckets */
	for (i = 0; i < CONN_TRACK_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&global_conn_table->buckets[i]);
		spin_lock_init(&global_conn_table->locks[i]);
	}

	/* Initialize global connection list */
	INIT_LIST_HEAD(&global_conn_table->conn_list);
	spin_lock_init(&global_conn_table->list_lock);

	/* Initialize connection counter */
	atomic_set(&global_conn_table->count, 0);

	/* Set up garbage collection timer */
	timer_setup(&global_conn_table->gc_timer, conn_gc_handler, 0);
	mod_timer(&global_conn_table->gc_timer,
		  jiffies + msecs_to_jiffies(CONN_GC_INTERVAL * 1000));

	pr_info("mutex_conn_track: initialized with %u buckets\n",
		CONN_TRACK_HASH_SIZE);

	return 0;
}

/**
 * mutex_conn_track_exit - Clean up connection tracking subsystem
 *
 * Stops garbage collection timer, removes all connections, and frees
 * the global connection tracking table.
 */
void mutex_conn_track_exit(void)
{
	struct mutex_conn_entry *conn, *tmp;
	unsigned int i;

	if (!global_conn_table)
		return;

	/* Stop garbage collection timer */
	timer_delete_sync(&global_conn_table->gc_timer);

	pr_info("mutex_conn_track: cleaning up %d connections\n",
		atomic_read(&global_conn_table->count));

	/* Remove all connections from hash table */
	for (i = 0; i < CONN_TRACK_HASH_SIZE; i++) {
		struct hlist_node *tmp_node;
		struct mutex_conn_entry *entry;

		spin_lock_bh(&global_conn_table->locks[i]);
		hlist_for_each_entry_safe(entry, tmp_node,
					   &global_conn_table->buckets[i],
					   hash_node) {
			hlist_del_init(&entry->hash_node);
			timer_delete_sync(&entry->timer);
			mutex_conn_put(entry);
		}
		spin_unlock_bh(&global_conn_table->locks[i]);
	}

	/* Clean up global list */
	spin_lock_bh(&global_conn_table->list_lock);
	list_for_each_entry_safe(conn, tmp, &global_conn_table->conn_list,
				 list_node) {
		list_del_init(&conn->list_node);
	}
	spin_unlock_bh(&global_conn_table->list_lock);

	kfree(global_conn_table);
	global_conn_table = NULL;

	pr_info("mutex_conn_track: shutdown complete\n");
}

/**
 * mutex_conn_create - Create a new connection entry
 * @tuple: Connection 5-tuple identifying the connection
 * @ctx: Owning proxy context
 *
 * Allocates and initializes a new connection tracking entry.
 * Inserts it into the hash table and global connection list.
 *
 * Return: Pointer to new entry on success, NULL on failure
 */
struct mutex_conn_entry *mutex_conn_create(const struct conn_tuple *tuple,
					   void *ctx)
{
	struct mutex_conn_entry *conn;
	u32 hash;
	unsigned int cpu = smp_processor_id();

	if (!global_conn_table || !tuple || !ctx) {
		pr_err("mutex_conn_track: invalid parameters for create\n");
		return NULL;
	}

	/* Check connection limit */
	if (atomic_read(&global_conn_table->count) >= CONN_MAX_PER_CONTEXT) {
		pr_warn("mutex_conn_track: connection limit reached\n");
		return NULL;
	}

	/* Allocate from performance-optimized pool (Branch 13) */
	conn = mutex_perf_conn_alloc();
	if (!conn) {
		/* Fallback to regular allocation */
		conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
		if (!conn) {
			pr_err("mutex_conn_track: failed to allocate connection\n");
			mutex_perf_stats_inc_dropped(cpu);
			return NULL;
		}
	}

	/* Initialize connection tuple */
	memcpy(&conn->tuple, tuple, sizeof(conn->tuple));

	/* Initialize statistics */
	atomic64_set(&conn->stats.bytes_sent, 0);
	atomic64_set(&conn->stats.bytes_received, 0);
	atomic64_set(&conn->stats.packets_sent, 0);
	atomic64_set(&conn->stats.packets_received, 0);
	conn->stats.created_time = jiffies;
	conn->stats.last_seen = jiffies;

	/* Set initial state */
	conn->state = CONN_STATE_NEW;

	/* Determine protocol */
	switch (tuple->protocol) {
	case IPPROTO_TCP:
		conn->proto = CONN_PROTO_TCP;
		break;
	case IPPROTO_UDP:
		conn->proto = CONN_PROTO_UDP;
		break;
	case IPPROTO_ICMP:
		conn->proto = CONN_PROTO_ICMP;
		break;
	default:
		conn->proto = CONN_PROTO_OTHER;
		break;
	}

	/* Initialize locks and reference counting */
	spin_lock_init(&conn->lock);
	atomic_set(&conn->refcount, 1);

	/* Initialize timeout timer */
	timer_setup(&conn->timer, conn_timeout_handler, 0);

	/* Set owning context */
	conn->ctx = ctx;

	/* Initialize sequence number deltas */
	conn->seq_delta = 0;
	conn->ack_delta = 0;
	conn->flags = 0;

	/* Compute optimized hash (Branch 13) */
	hash = mutex_perf_hash_tuple(tuple);

	/* Insert into hash table */
	spin_lock_bh(&global_conn_table->locks[hash % CONN_TRACK_HASH_SIZE]);
	hlist_add_head_rcu(&conn->hash_node,
			   &global_conn_table->buckets[hash % CONN_TRACK_HASH_SIZE]);
	spin_unlock_bh(&global_conn_table->locks[hash % CONN_TRACK_HASH_SIZE]);

	/* Add to per-CPU cache for fast lookup (Branch 13) */
	mutex_perf_cache_insert(hash, conn);

	/* Add to global connection list */
	spin_lock_bh(&global_conn_table->list_lock);
	list_add(&conn->list_node, &global_conn_table->conn_list);
	spin_unlock_bh(&global_conn_table->list_lock);

	/* Increment global counter */
	atomic_inc(&global_conn_table->count);

	pr_debug("mutex_conn_track: created connection (proto=%u, state=%u, hash=0x%x)\n",
		 conn->proto, conn->state, hash);

	return conn;
	atomic_inc(&global_conn_table->count);

	pr_debug("mutex_conn_track: created connection (proto=%u, state=%u)\n",
		 conn->proto, conn->state);

	return conn;
}

/**
 * mutex_conn_lookup - Find connection by tuple
 * @tuple: Connection 5-tuple to search for
 *
 * Searches the hash table for a connection matching the given tuple.
 * Increments reference count if found to prevent deletion.
 * Uses per-CPU cache and RCU for performance (Branch 13).
 *
 * Return: Pointer to entry on success, NULL if not found
 */
struct mutex_conn_entry *mutex_conn_lookup(const struct conn_tuple *tuple)
{
	struct mutex_conn_entry *conn;
	u32 hash;
	bool found = false;
	unsigned int cpu = smp_processor_id();
	int chain_length = 0;
	ktime_t start;

	if (!global_conn_table || !tuple)
		return NULL;

	/* Profile lookup time (Branch 13) */
	mutex_perf_profile_start(&start);

	/* Try per-CPU cache first (Branch 13) */
	hash = mutex_perf_hash_tuple(tuple);
	conn = mutex_perf_cache_lookup(hash);
	if (conn) {
		/* Cache hit - verify tuple matches */
		bool match = true;
		if (conn->tuple.protocol != tuple->protocol ||
		    conn->tuple.is_ipv6 != tuple->is_ipv6 ||
		    conn->tuple.src_port != tuple->src_port ||
		    conn->tuple.dst_port != tuple->dst_port) {
			match = false;
		} else if (tuple->is_ipv6) {
			if (memcmp(&conn->tuple.src_addr.v6, &tuple->src_addr.v6,
				   sizeof(struct in6_addr)) != 0 ||
			    memcmp(&conn->tuple.dst_addr.v6, &tuple->dst_addr.v6,
				   sizeof(struct in6_addr)) != 0)
				match = false;
		} else {
			if (conn->tuple.src_addr.v4 != tuple->src_addr.v4 ||
			    conn->tuple.dst_addr.v4 != tuple->dst_addr.v4)
				match = false;
		}

		if (match) {
			atomic_inc(&conn->refcount);
			mutex_perf_stats_add_time(cpu,
						  mutex_perf_profile_end(start));
			return conn;
		}
		/* Cache entry stale - invalidate */
		mutex_perf_cache_invalidate(hash);
	}

	/* Cache miss - look up in hash table with RCU (Branch 13) */
	rcu_read_lock();
	hash = hash % CONN_TRACK_HASH_SIZE;

	hlist_for_each_entry_rcu(conn, &global_conn_table->buckets[hash],
				 hash_node) {
		chain_length++;

		/* Compare connection tuples */
		if (conn->tuple.protocol != tuple->protocol)
			continue;
		if (conn->tuple.is_ipv6 != tuple->is_ipv6)
			continue;
		if (conn->tuple.src_port != tuple->src_port)
			continue;
		if (conn->tuple.dst_port != tuple->dst_port)
			continue;

		/* Compare addresses based on IP version */
		if (tuple->is_ipv6) {
			if (memcmp(&conn->tuple.src_addr.v6,
				   &tuple->src_addr.v6,
				   sizeof(struct in6_addr)) != 0)
				continue;
			if (memcmp(&conn->tuple.dst_addr.v6,
				   &tuple->dst_addr.v6,
				   sizeof(struct in6_addr)) != 0)
				continue;
		} else {
			if (conn->tuple.src_addr.v4 != tuple->src_addr.v4)
				continue;
			if (conn->tuple.dst_addr.v4 != tuple->dst_addr.v4)
				continue;
		}

		/* Found matching connection */
		atomic_inc(&conn->refcount);
		found = true;

		/* Add to cache for next lookup (Branch 13) */
		mutex_perf_cache_insert(mutex_perf_hash_tuple(tuple), conn);
		break;
	}

	rcu_read_unlock();

	/* Update hash statistics (Branch 13) */
	mutex_perf_hash_stats_update(chain_length);
	mutex_perf_stats_add_time(cpu, mutex_perf_profile_end(start));

	return found ? conn : NULL;
}

/**
 * mutex_conn_get - Increment connection reference count
 * @conn: Connection entry
 *
 * Increments the reference count to prevent deletion while in use.
 * Must be paired with mutex_conn_put().
 */
void mutex_conn_get(struct mutex_conn_entry *conn)
{
	if (conn)
		atomic_inc(&conn->refcount);
}

/**
 * mutex_conn_put - Decrement connection reference count
 * @conn: Connection entry
 *
 * Decrements reference count. If count reaches zero, schedules
 * the connection for RCU-safe deletion.
 */
void mutex_conn_put(struct mutex_conn_entry *conn)
{
	if (!conn)
		return;

	if (atomic_dec_and_test(&conn->refcount)) {
		/* Last reference - free the connection */
		timer_delete_sync(&conn->timer);

		/* Use performance-optimized free (Branch 13) */
		mutex_perf_conn_free(conn);
	}
}

/**
 * mutex_conn_delete - Remove connection from tracking
 * @conn: Connection entry to delete
 *
 * Removes connection from hash table and global list.
 * Decrements reference count (connection freed when count reaches zero).
 */
void mutex_conn_delete(struct mutex_conn_entry *conn)
{
	u32 hash;

	if (!conn || !global_conn_table)
		return;

	hash = mutex_conn_hash(&conn->tuple);

	/* Remove from hash table */
	spin_lock_bh(&global_conn_table->locks[hash]);
	if (!hlist_unhashed(&conn->hash_node)) {
		hlist_del_init(&conn->hash_node);
	}
	spin_unlock_bh(&global_conn_table->locks[hash]);

	/* Remove from global list */
	spin_lock_bh(&global_conn_table->list_lock);
	if (!list_empty(&conn->list_node)) {
		list_del_init(&conn->list_node);
	}
	spin_unlock_bh(&global_conn_table->list_lock);

	/* Decrement global counter */
	atomic_dec(&global_conn_table->count);

	/* Cancel timeout timer */
	timer_delete_sync(&conn->timer);

	pr_debug("mutex_conn_track: deleted connection\n");

	/* Decrement reference count (may free) */
	mutex_conn_put(conn);
}

/**
 * mutex_conn_set_state - Update connection state
 * @conn: Connection entry
 * @new_state: New state to set
 *
 * Updates the connection state and adjusts timeout accordingly.
 * Protected by connection's spinlock.
 */
void mutex_conn_set_state(struct mutex_conn_entry *conn,
			  enum conn_state new_state)
{
	unsigned int timeout_sec;
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	if (conn->state != new_state) {
		pr_debug("mutex_conn_track: state transition %u -> %u\n",
			 conn->state, new_state);

		conn->state = new_state;

		/* Update timeout based on new state */
		timeout_sec = mutex_conn_get_timeout(conn->proto, new_state);
		conn->timeout = jiffies + msecs_to_jiffies(timeout_sec * 1000);
		mod_timer(&conn->timer, conn->timeout);
	}

	spin_unlock_irqrestore(&conn->lock, flags);
}

/**
 * mutex_conn_refresh - Refresh connection timeout
 * @conn: Connection entry
 *
 * Updates last_seen timestamp and resets timeout timer.
 * Called whenever a packet for this connection is processed.
 */
void mutex_conn_refresh(struct mutex_conn_entry *conn)
{
	unsigned int timeout_sec;
	unsigned long flags;

	if (!conn)
		return;

	spin_lock_irqsave(&conn->lock, flags);

	conn->stats.last_seen = jiffies;

	/* Reset timeout timer */
	timeout_sec = mutex_conn_get_timeout(conn->proto, conn->state);
	conn->timeout = jiffies + msecs_to_jiffies(timeout_sec * 1000);
	mod_timer(&conn->timer, conn->timeout);

	spin_unlock_irqrestore(&conn->lock, flags);
}

/**
 * mutex_conn_update_stats - Update connection statistics
 * @conn: Connection entry
 * @bytes: Number of bytes transferred
 * @packets: Number of packets transferred
 * @is_tx: True for transmitted data, false for received
 *
 * Atomically updates connection statistics for transmitted or
 * received data.
 */
void mutex_conn_update_stats(struct mutex_conn_entry *conn,
			     u64 bytes, u64 packets, bool is_tx)
{
	if (!conn)
		return;

	if (is_tx) {
		atomic64_add(bytes, &conn->stats.bytes_sent);
		atomic64_add(packets, &conn->stats.packets_sent);
	} else {
		atomic64_add(bytes, &conn->stats.bytes_received);
		atomic64_add(packets, &conn->stats.packets_received);
	}

	/* Refresh connection on activity */
	mutex_conn_refresh(conn);
}

/**
 * mutex_conn_cleanup_context - Clean up all connections for a context
 * @ctx: Proxy context
 *
 * Removes all connections associated with the given context.
 * Called when a proxy fd is closed.
 */
void mutex_conn_cleanup_context(void *ctx)
{
	struct mutex_conn_entry *conn, *tmp;
	int cleaned = 0;

	if (!ctx || !global_conn_table)
		return;

	pr_info("mutex_conn_track: cleaning up connections for context %p\n",
		ctx);

	/* Walk through all connections in global list */
	spin_lock_bh(&global_conn_table->list_lock);
	list_for_each_entry_safe(conn, tmp, &global_conn_table->conn_list,
				 list_node) {
		if (conn->ctx == ctx) {
			/* Remove from list (will be deleted fully later) */
			list_del_init(&conn->list_node);
			cleaned++;

			/* Mark for deletion */
			spin_unlock_bh(&global_conn_table->list_lock);
			mutex_conn_delete(conn);
			spin_lock_bh(&global_conn_table->list_lock);
		}
	}
	spin_unlock_bh(&global_conn_table->list_lock);

	pr_info("mutex_conn_track: cleaned up %d connections for context %p\n",
		cleaned, ctx);
}

/**
 * conn_timeout_handler - Handle connection timeout
 * @t: Timer that fired
 *
 * Called when a connection's timeout expires. Removes the connection
 * from tracking.
 */
static void conn_timeout_handler(struct timer_list *t)
{
	struct mutex_conn_entry *conn;

	conn = timer_container_of(conn, t, timer);
	if (!conn)
		return;

	pr_debug("mutex_conn_track: connection timed out (state=%u)\n",
		 conn->state);

	/* Remove connection from tracking */
	mutex_conn_delete(conn);
}

/**
 * conn_gc_handler - Garbage collection handler
 * @t: Timer that fired
 *
 * Periodically scans connection table for stale connections.
 * Removes connections that have exceeded their timeout.
 */
static void conn_gc_handler(struct timer_list *t)
{
	struct mutex_conn_entry *conn, *tmp;
	unsigned long now = jiffies;
	int removed = 0;

	/* Suppress unused parameter warning */
	(void)t;

	if (!global_conn_table)
		return;

	pr_debug("mutex_conn_track: garbage collection started (%d conns)\n",
		 atomic_read(&global_conn_table->count));

	/* Scan all connections */
	spin_lock_bh(&global_conn_table->list_lock);
	list_for_each_entry_safe(conn, tmp, &global_conn_table->conn_list,
				 list_node) {
		/* Check if connection has timed out */
		if (time_after(now, conn->timeout)) {
			list_del_init(&conn->list_node);
			removed++;

			/* Delete outside of lock */
			spin_unlock_bh(&global_conn_table->list_lock);
			mutex_conn_delete(conn);
			spin_lock_bh(&global_conn_table->list_lock);
		}
	}
	spin_unlock_bh(&global_conn_table->list_lock);

	if (removed > 0) {
		pr_info("mutex_conn_track: garbage collection removed %d stale connections\n",
			removed);
	}

	/* Reschedule garbage collection */
	mod_timer(&global_conn_table->gc_timer,
		  jiffies + msecs_to_jiffies(CONN_GC_INTERVAL * 1000));
}

/**
 * mutex_conn_lookup_by_skb - Find connection by packet
 * @skb: Packet to extract tuple from
 *
 * Extracts the 5-tuple from a packet and looks up the connection.
 *
 * Return: Pointer to connection entry on success, NULL if not found
 */
struct mutex_conn_entry *mutex_conn_lookup_by_skb(struct sk_buff *skb)
{
	struct conn_tuple tuple;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	if (!skb)
		return NULL;

	memset(&tuple, 0, sizeof(tuple));

	iph = ip_hdr(skb);
	if (!iph)
		return NULL;

	tuple.src_addr.v4 = iph->saddr;
	tuple.dst_addr.v4 = iph->daddr;
	tuple.protocol = iph->protocol;
	tuple.is_ipv6 = false;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return NULL;
		tuple.src_port = tcph->source;
		tuple.dst_port = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return NULL;
		tuple.src_port = udph->source;
		tuple.dst_port = udph->dest;
	} else {
		tuple.src_port = 0;
		tuple.dst_port = 0;
	}

	return mutex_conn_lookup(&tuple);
}

/**
 * mutex_conn_alloc_from_skb - Create connection from packet
 * @skb: Packet to extract tuple from
 *
 * Creates a new connection entry from packet 5-tuple.
 *
 * Return: Pointer to new entry on success, NULL on failure
 */
struct mutex_conn_entry *mutex_conn_alloc_from_skb(struct sk_buff *skb)
{
	struct conn_tuple tuple;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	if (!skb)
		return NULL;

	memset(&tuple, 0, sizeof(tuple));

	iph = ip_hdr(skb);
	if (!iph)
		return NULL;

	tuple.src_addr.v4 = iph->saddr;
	tuple.dst_addr.v4 = iph->daddr;
	tuple.protocol = iph->protocol;
	tuple.is_ipv6 = false;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return NULL;
		tuple.src_port = tcph->source;
		tuple.dst_port = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return NULL;
		tuple.src_port = udph->source;
		tuple.dst_port = udph->dest;
	} else {
		tuple.src_port = 0;
		tuple.dst_port = 0;
	}

	return mutex_conn_create(&tuple, NULL);
}

/* Export symbols for use by other modules */
EXPORT_SYMBOL_GPL(mutex_conn_track_init);
EXPORT_SYMBOL_GPL(mutex_conn_track_exit);
EXPORT_SYMBOL_GPL(mutex_conn_create);
EXPORT_SYMBOL_GPL(mutex_conn_lookup);
EXPORT_SYMBOL_GPL(mutex_conn_get);
EXPORT_SYMBOL_GPL(mutex_conn_put);
EXPORT_SYMBOL_GPL(mutex_conn_delete);
EXPORT_SYMBOL_GPL(mutex_conn_set_state);
EXPORT_SYMBOL_GPL(mutex_conn_refresh);
EXPORT_SYMBOL_GPL(mutex_conn_update_stats);
EXPORT_SYMBOL_GPL(mutex_conn_cleanup_context);
EXPORT_SYMBOL_GPL(mutex_conn_lookup_by_skb);
EXPORT_SYMBOL_GPL(mutex_conn_alloc_from_skb);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Team");
MODULE_DESCRIPTION("MUTEX connection tracking subsystem");
