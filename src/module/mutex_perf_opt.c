// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_perf_opt.c - MUTEX performance optimization implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements comprehensive performance optimizations for the
 * MUTEX proxy including per-CPU data structures, RCU for lock-free reads,
 * connection pooling with slab caches, zero-copy packet handling, and
 * packet batching support.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/prefetch.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "mutex_perf_opt.h"
#include "mutex_conn_track.h"
#include "mutex_proxy.h"

/* Module parameters */
bool perf_enable_batching = true;
module_param(perf_enable_batching, bool, 0644);
MODULE_PARM_DESC(perf_enable_batching, "Enable packet batching optimization");

bool perf_enable_zero_copy = true;
module_param(perf_enable_zero_copy, bool, 0644);
MODULE_PARM_DESC(perf_enable_zero_copy, "Enable zero-copy packet handling");

bool perf_enable_rcu = true;
module_param(perf_enable_rcu, bool, 0644);
MODULE_PARM_DESC(perf_enable_rcu, "Enable RCU for lock-free reads");

unsigned int perf_batch_size = PERF_BATCH_SIZE;
module_param(perf_batch_size, uint, 0644);
MODULE_PARM_DESC(perf_batch_size, "Maximum packets per batch");

unsigned int perf_cache_size = PERF_MAX_CPU_CONNS;
module_param(perf_cache_size, uint, 0644);
MODULE_PARM_DESC(perf_cache_size, "Per-CPU connection cache size");

/* Global performance context */
struct perf_optimization_context *global_perf_ctx = NULL;

/* Forward declarations */
static void perf_rcu_config_free(struct rcu_head *rcu);

/**
 * mutex_perf_init - Initialize performance optimization subsystem
 *
 * Allocates and initializes all performance optimization structures including
 * per-CPU statistics, connection cache, memory pool, and RCU configuration.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_perf_init(void)
{
	int cpu;
	struct perf_per_cpu_stats *cpu_stats;

	if (global_perf_ctx) {
		pr_warn("mutex_perf: already initialized\n");
		return -EEXIST;
	}

	/* Allocate main context */
	global_perf_ctx = kzalloc(sizeof(*global_perf_ctx), GFP_KERNEL);
	if (!global_perf_ctx) {
		pr_err("mutex_perf: failed to allocate context\n");
		return -ENOMEM;
	}

	/* Allocate per-CPU statistics */
	global_perf_ctx->per_cpu_stats = alloc_percpu(struct perf_per_cpu_stats);
	if (!global_perf_ctx->per_cpu_stats) {
		pr_err("mutex_perf: failed to allocate per-CPU stats\n");
		kfree(global_perf_ctx);
		global_perf_ctx = NULL;
		return -ENOMEM;
	}

	/* Initialize per-CPU statistics */
	for_each_possible_cpu(cpu) {
		cpu_stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
		atomic64_set(&cpu_stats->packets_processed, 0);
		atomic64_set(&cpu_stats->packets_dropped, 0);
		atomic64_set(&cpu_stats->bytes_processed, 0);
		atomic64_set(&cpu_stats->cache_hits, 0);
		atomic64_set(&cpu_stats->cache_misses, 0);
		atomic64_set(&cpu_stats->rcu_grace_periods, 0);
		atomic64_set(&cpu_stats->lock_acquisitions, 0);
		atomic64_set(&cpu_stats->lock_contentions, 0);
		atomic64_set(&cpu_stats->alloc_fast, 0);
		atomic64_set(&cpu_stats->alloc_slow, 0);
		cpu_stats->processing_time_ns = 0;
		cpu_stats->last_updated = ktime_get();
	}

	/* Allocate per-CPU connection cache */
	global_perf_ctx->conn_cache = alloc_percpu(struct perf_conn_cache_entry);
	if (!global_perf_ctx->conn_cache) {
		pr_err("mutex_perf: failed to allocate per-CPU cache\n");
		free_percpu(global_perf_ctx->per_cpu_stats);
		kfree(global_perf_ctx);
		global_perf_ctx = NULL;
		return -ENOMEM;
	}

	/* Initialize connection cache */
	for_each_possible_cpu(cpu) {
		struct perf_conn_cache_entry *cache;
		cache = per_cpu_ptr(global_perf_ctx->conn_cache, cpu);
		cache->tuple_hash = 0;
		RCU_INIT_POINTER(cache->conn, NULL);
		atomic_set(&cache->access_count, 0);
		cache->last_used = jiffies;
		cache->cpu = cpu;
		cache->valid = false;
	}

	/* Initialize connection pool */
	if (mutex_perf_conn_pool_init() < 0) {
		pr_err("mutex_perf: failed to initialize connection pool\n");
		free_percpu(global_perf_ctx->conn_cache);
		free_percpu(global_perf_ctx->per_cpu_stats);
		kfree(global_perf_ctx);
		global_perf_ctx = NULL;
		return -ENOMEM;
	}

	/* Initialize hash statistics */
	atomic64_set(&global_perf_ctx->hash_stats.lookups, 0);
	atomic64_set(&global_perf_ctx->hash_stats.collisions, 0);
	atomic_set(&global_perf_ctx->hash_stats.max_chain_length, 0);
	atomic_set(&global_perf_ctx->hash_stats.avg_chain_length, 0);
	atomic_set(&global_perf_ctx->hash_stats.bucket_usage, 0);

	/* Initialize RCU configuration */
	RCU_INIT_POINTER(global_perf_ctx->rcu_config, NULL);

	/* Set optimization flags */
	global_perf_ctx->batch_enabled = perf_enable_batching;
	global_perf_ctx->zero_copy_enabled = perf_enable_zero_copy;
	global_perf_ctx->rcu_enabled = perf_enable_rcu;
	global_perf_ctx->initialized = true;

	pr_info("mutex_perf: initialized (batching=%s, zero-copy=%s, rcu=%s)\n",
		global_perf_ctx->batch_enabled ? "on" : "off",
		global_perf_ctx->zero_copy_enabled ? "on" : "off",
		global_perf_ctx->rcu_enabled ? "on" : "off");

	return 0;
}

/**
 * mutex_perf_exit - Clean up performance optimization subsystem
 *
 * Frees all allocated resources including per-CPU data, connection pool,
 * and RCU configuration. Waits for RCU grace period before freeing.
 */
void mutex_perf_exit(void)
{
	struct perf_rcu_config *rcu_cfg;

	if (!global_perf_ctx)
		return;

	pr_info("mutex_perf: shutting down\n");

	global_perf_ctx->initialized = false;

	/* Free RCU configuration */
	rcu_cfg = rcu_dereference_protected(global_perf_ctx->rcu_config, 1);
	if (rcu_cfg) {
		RCU_INIT_POINTER(global_perf_ctx->rcu_config, NULL);
		synchronize_rcu();
		kfree(rcu_cfg);
	}

	/* Clean up connection pool */
	mutex_perf_conn_pool_exit();

	/* Free per-CPU data */
	if (global_perf_ctx->conn_cache)
		free_percpu(global_perf_ctx->conn_cache);

	if (global_perf_ctx->per_cpu_stats)
		free_percpu(global_perf_ctx->per_cpu_stats);

	kfree(global_perf_ctx);
	global_perf_ctx = NULL;

	pr_info("mutex_perf: shutdown complete\n");
}

/* ========================================================================
 * Per-CPU Statistics Functions
 * ======================================================================== */

/**
 * mutex_perf_stats_inc_packets - Increment packet counter
 * @cpu: CPU number
 * @bytes: Number of bytes processed
 *
 * Increments per-CPU packet and byte counters.
 */
void mutex_perf_stats_inc_packets(unsigned int cpu, u64 bytes)
{
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
	atomic64_inc(&stats->packets_processed);
	atomic64_add(bytes, &stats->bytes_processed);
	stats->last_updated = ktime_get();
}

/**
 * mutex_perf_stats_inc_dropped - Increment dropped packet counter
 * @cpu: CPU number
 *
 * Increments per-CPU dropped packet counter.
 */
void mutex_perf_stats_inc_dropped(unsigned int cpu)
{
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
	atomic64_inc(&stats->packets_dropped);
	stats->last_updated = ktime_get();
}

/**
 * mutex_perf_stats_cache_hit - Record cache hit
 * @cpu: CPU number
 *
 * Increments cache hit counter for performance monitoring.
 */
void mutex_perf_stats_cache_hit(unsigned int cpu)
{
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
	atomic64_inc(&stats->cache_hits);
}

/**
 * mutex_perf_stats_cache_miss - Record cache miss
 * @cpu: CPU number
 *
 * Increments cache miss counter for performance monitoring.
 */
void mutex_perf_stats_cache_miss(unsigned int cpu)
{
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
	atomic64_inc(&stats->cache_misses);
}

/**
 * mutex_perf_stats_add_time - Add processing time
 * @cpu: CPU number
 * @ns: Time in nanoseconds
 *
 * Adds processing time to per-CPU statistics.
 */
void mutex_perf_stats_add_time(unsigned int cpu, u64 ns)
{
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
	stats->processing_time_ns += ns;
}

/**
 * mutex_perf_get_cpu_stats - Get per-CPU statistics
 * @cpu: CPU number
 *
 * Returns pointer to per-CPU statistics structure.
 */
struct perf_per_cpu_stats *mutex_perf_get_cpu_stats(unsigned int cpu)
{
	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return NULL;

	return per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
}

/**
 * mutex_perf_aggregate_stats - Aggregate all CPU stats
 * @stats: Output statistics structure
 *
 * Aggregates statistics from all CPUs into a single structure.
 */
void mutex_perf_aggregate_stats(struct mutex_proxy_stats *stats)
{
	int cpu;
	struct perf_per_cpu_stats *cpu_stats;
	u64 total_packets = 0, total_bytes = 0, total_dropped = 0;

	if (!global_perf_ctx || !global_perf_ctx->initialized || !stats)
		return;

	for_each_possible_cpu(cpu) {
		cpu_stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
		total_packets += atomic64_read(&cpu_stats->packets_processed);
		total_bytes += atomic64_read(&cpu_stats->bytes_processed);
		total_dropped += atomic64_read(&cpu_stats->packets_dropped);
	}

	stats->packets_sent = total_packets;
	stats->bytes_sent = total_bytes;
	/* Note: dropped packets tracked separately in main stats */
}

/* ========================================================================
 * Connection Cache Functions
 * ======================================================================== */

/**
 * mutex_perf_cache_lookup - Look up connection in per-CPU cache
 * @hash: Connection tuple hash
 *
 * Fast lookup in per-CPU cache to avoid hash table access.
 * Returns connection entry if found in cache, NULL otherwise.
 */
struct mutex_conn_entry *mutex_perf_cache_lookup(u32 hash)
{
	struct perf_conn_cache_entry *cache;
	struct mutex_conn_entry *conn;
	unsigned int cpu;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return NULL;

	cpu = mutex_perf_get_cpu();
	cache = per_cpu_ptr(global_perf_ctx->conn_cache, cpu);

	/* Check if cache entry is valid and matches hash */
	if (cache->valid && cache->tuple_hash == hash) {
		rcu_read_lock();
		conn = rcu_dereference(cache->conn);
		if (conn) {
			atomic_inc(&cache->access_count);
			cache->last_used = jiffies;
			mutex_perf_stats_cache_hit(cpu);
			rcu_read_unlock();
			return conn;
		}
		rcu_read_unlock();
	}

	mutex_perf_stats_cache_miss(cpu);
	return NULL;
}

/**
 * mutex_perf_cache_insert - Insert connection into per-CPU cache
 * @hash: Connection tuple hash
 * @conn: Connection entry to cache
 *
 * Inserts connection entry into per-CPU cache for fast future lookups.
 */
void mutex_perf_cache_insert(u32 hash, struct mutex_conn_entry *conn)
{
	struct perf_conn_cache_entry *cache;
	unsigned int cpu;

	if (!global_perf_ctx || !global_perf_ctx->initialized || !conn)
		return;

	cpu = mutex_perf_get_cpu();
	cache = per_cpu_ptr(global_perf_ctx->conn_cache, cpu);

	cache->tuple_hash = hash;
	rcu_assign_pointer(cache->conn, conn);
	atomic_set(&cache->access_count, 1);
	cache->last_used = jiffies;
	cache->valid = true;
}

/**
 * mutex_perf_cache_invalidate - Invalidate cache entry
 * @hash: Connection tuple hash
 *
 * Invalidates cache entry matching the given hash.
 */
void mutex_perf_cache_invalidate(u32 hash)
{
	struct perf_conn_cache_entry *cache;
	int cpu;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	for_each_possible_cpu(cpu) {
		cache = per_cpu_ptr(global_perf_ctx->conn_cache, cpu);
		if (cache->valid && cache->tuple_hash == hash) {
			cache->valid = false;
			RCU_INIT_POINTER(cache->conn, NULL);
		}
	}
}

/**
 * mutex_perf_cache_clear_all - Clear all cache entries
 *
 * Invalidates all per-CPU cache entries. Use when resetting proxy.
 */
void mutex_perf_cache_clear_all(void)
{
	struct perf_conn_cache_entry *cache;
	int cpu;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	for_each_possible_cpu(cpu) {
		cache = per_cpu_ptr(global_perf_ctx->conn_cache, cpu);
		cache->valid = false;
		RCU_INIT_POINTER(cache->conn, NULL);
		atomic_set(&cache->access_count, 0);
	}
}

/* ========================================================================
 * Connection Pool (Slab Cache) Functions
 * ======================================================================== */

/**
 * mutex_perf_conn_pool_init - Initialize connection memory pool
 *
 * Creates slab cache for efficient connection entry allocation.
 * Returns 0 on success, negative error code on failure.
 */
int mutex_perf_conn_pool_init(void)
{
	struct perf_conn_pool *pool;

	if (!global_perf_ctx)
		return -EINVAL;

	pool = &global_perf_ctx->conn_pool;

	/* Create slab cache for connection entries */
	pool->cache = kmem_cache_create("mutex_conn_cache",
					sizeof(struct mutex_conn_entry),
					0,
					SLAB_HWCACHE_ALIGN | SLAB_PANIC,
					NULL);
	if (!pool->cache) {
		pr_err("mutex_perf: failed to create slab cache\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&pool->free_list);
	spin_lock_init(&pool->lock);
	atomic_set(&pool->alloc_count, 0);
	atomic_set(&pool->free_count, 0);
	atomic_set(&pool->peak_usage, 0);

	pr_info("mutex_perf: connection pool initialized\n");
	return 0;
}

/**
 * mutex_perf_conn_pool_exit - Clean up connection memory pool
 *
 * Destroys slab cache and frees any remaining entries.
 */
void mutex_perf_conn_pool_exit(void)
{
	struct perf_conn_pool *pool;
	struct mutex_conn_entry *entry, *tmp;

	if (!global_perf_ctx)
		return;

	pool = &global_perf_ctx->conn_pool;

	if (!pool->cache)
		return;

	/* Free any remaining entries in free list */
	spin_lock_bh(&pool->lock);
	list_for_each_entry_safe(entry, tmp, &pool->free_list, list_node) {
		list_del(&entry->list_node);
		kmem_cache_free(pool->cache, entry);
	}
	spin_unlock_bh(&pool->lock);

	/* Destroy slab cache */
	kmem_cache_destroy(pool->cache);
	pool->cache = NULL;

	pr_info("mutex_perf: connection pool destroyed (alloc=%d, free=%d, peak=%d)\n",
		atomic_read(&pool->alloc_count),
		atomic_read(&pool->free_count),
		atomic_read(&pool->peak_usage));
}

/**
 * mutex_perf_conn_alloc - Allocate connection entry from pool
 *
 * Fast allocation from slab cache. Falls back to kmem_cache_alloc
 * if free list is empty.
 *
 * Returns pointer to allocated entry or NULL on failure.
 */
struct mutex_conn_entry *mutex_perf_conn_alloc(void)
{
	struct perf_conn_pool *pool;
	struct mutex_conn_entry *conn;
	unsigned int cpu;
	int current_usage, peak;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return NULL;

	pool = &global_perf_ctx->conn_pool;
	cpu = mutex_perf_get_cpu();

	/* Try to get from free list first */
	spin_lock_bh(&pool->lock);
	if (!list_empty(&pool->free_list)) {
		conn = list_first_entry(&pool->free_list,
					struct mutex_conn_entry,
					list_node);
		list_del(&conn->list_node);
		spin_unlock_bh(&pool->lock);

		/* Fast path allocation */
		atomic64_inc(&per_cpu_ptr(global_perf_ctx->per_cpu_stats,
					  cpu)->alloc_fast);
	} else {
		spin_unlock_bh(&pool->lock);

		/* Slow path - allocate from slab cache */
		conn = kmem_cache_zalloc(pool->cache, GFP_ATOMIC);
		if (!conn)
			return NULL;

		atomic64_inc(&per_cpu_ptr(global_perf_ctx->per_cpu_stats,
					  cpu)->alloc_slow);
	}

	/* Update statistics */
	current_usage = atomic_inc_return(&pool->alloc_count) -
			atomic_read(&pool->free_count);
	peak = atomic_read(&pool->peak_usage);
	if (current_usage > peak)
		atomic_cmpxchg(&pool->peak_usage, peak, current_usage);

	return conn;
}

/**
 * mutex_perf_conn_free - Free connection entry to pool
 * @conn: Connection entry to free
 *
 * Returns connection entry to pool for reuse. Adds to free list
 * up to a maximum, then frees to slab cache.
 */
void mutex_perf_conn_free(struct mutex_conn_entry *conn)
{
	struct perf_conn_pool *pool;

	if (!global_perf_ctx || !global_perf_ctx->initialized || !conn)
		return;

	pool = &global_perf_ctx->conn_pool;

	/* Zero out the entry for reuse */
	memset(conn, 0, sizeof(*conn));

	/* Add to free list if not too many cached */
	spin_lock_bh(&pool->lock);
	if (atomic_read(&pool->free_count) < PERF_CONN_CACHE_SIZE) {
		list_add(&conn->list_node, &pool->free_list);
		atomic_inc(&pool->free_count);
		spin_unlock_bh(&pool->lock);
	} else {
		spin_unlock_bh(&pool->lock);
		/* Free list full, return to slab cache */
		kmem_cache_free(pool->cache, conn);
	}
}

/* ========================================================================
 * RCU Configuration Functions
 * ======================================================================== */

/**
 * perf_rcu_config_free - RCU callback to free configuration
 * @rcu: RCU head from configuration structure
 *
 * Called after RCU grace period to safely free old configuration.
 */
static void perf_rcu_config_free(struct rcu_head *rcu)
{
	struct perf_rcu_config *cfg;
	unsigned int cpu;

	cfg = container_of(rcu, struct perf_rcu_config, rcu);
	kfree(cfg);

	/* Increment grace period counter */
	if (global_perf_ctx && global_perf_ctx->initialized) {
		cpu = mutex_perf_get_cpu();
		atomic64_inc(&per_cpu_ptr(global_perf_ctx->per_cpu_stats,
					  cpu)->rcu_grace_periods);
	}
}

/**
 * mutex_perf_config_read - Read current configuration (RCU-protected)
 *
 * Returns current proxy configuration using RCU for lock-free read.
 * Caller must be in RCU read-side critical section.
 */
struct mutex_proxy_config *mutex_perf_config_read(void)
{
	struct perf_rcu_config *cfg;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return NULL;

	if (!global_perf_ctx->rcu_enabled)
		return NULL;

	cfg = rcu_dereference(global_perf_ctx->rcu_config);
	if (!cfg)
		return NULL;

	return &cfg->proxy_config;
}

/**
 * mutex_perf_config_update - Update configuration (RCU-protected)
 * @new_config: New configuration to apply
 *
 * Updates proxy configuration using RCU for lock-free readers.
 * Old configuration is freed after grace period.
 */
void mutex_perf_config_update(const struct mutex_proxy_config *new_config)
{
	struct perf_rcu_config *new_cfg, *old_cfg;

	if (!global_perf_ctx || !global_perf_ctx->initialized || !new_config)
		return;

	if (!global_perf_ctx->rcu_enabled)
		return;

	/* Allocate new configuration */
	new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
	if (!new_cfg) {
		pr_err("mutex_perf: failed to allocate RCU config\n");
		return;
	}

	/* Copy configuration */
	memcpy(&new_cfg->proxy_config, new_config, sizeof(*new_config));
	atomic_set(&new_cfg->version,
		   atomic_read(&global_perf_ctx->rcu_config ?
			       &rcu_dereference_protected(
				       global_perf_ctx->rcu_config, 1)->version : 0) + 1);
	new_cfg->timestamp = ktime_get();

	/* Replace old configuration */
	old_cfg = rcu_dereference_protected(global_perf_ctx->rcu_config, 1);
	rcu_assign_pointer(global_perf_ctx->rcu_config, new_cfg);

	/* Free old configuration after grace period */
	if (old_cfg)
		call_rcu(&old_cfg->rcu, perf_rcu_config_free);
}

/**
 * mutex_perf_config_sync - Wait for RCU grace period
 *
 * Blocks until all RCU readers have finished. Use when you need
 * to ensure all readers have seen an update.
 */
void mutex_perf_config_sync(void)
{
	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	if (!global_perf_ctx->rcu_enabled)
		return;

	synchronize_rcu();
}

/* ========================================================================
 * Hash Table Optimization Functions
 * ======================================================================== */

/**
 * mutex_perf_hash_tuple - Compute hash of connection tuple
 * @tuple: Connection tuple to hash
 *
 * Fast hash function using jhash for good distribution.
 * Returns 32-bit hash value.
 */
u32 mutex_perf_hash_tuple(const struct conn_tuple *tuple)
{
	u32 hash;

	if (!tuple)
		return 0;

	/* Use jhash for good hash distribution */
	if (tuple->is_ipv6) {
		hash = jhash2((u32 *)&tuple->src_addr.v6,
			      sizeof(struct in6_addr) / sizeof(u32),
			      PERF_HASH_SEED);
		hash = jhash2((u32 *)&tuple->dst_addr.v6,
			      sizeof(struct in6_addr) / sizeof(u32), hash);
	} else {
		hash = jhash_2words(tuple->src_addr.v4,
				    tuple->dst_addr.v4,
				    PERF_HASH_SEED);
	}

	/* Mix in ports and protocol */
	hash = jhash_3words(tuple->src_port, tuple->dst_port,
			    tuple->protocol, hash);

	/* Update lookup counter */
	if (global_perf_ctx && global_perf_ctx->initialized)
		atomic64_inc(&global_perf_ctx->hash_stats.lookups);

	return hash;
}

/**
 * mutex_perf_hash_combine - Combine two hash values
 * @h1: First hash value
 * @h2: Second hash value
 *
 * Combines two hash values into one. Useful for incremental hashing.
 */
u32 mutex_perf_hash_combine(u32 h1, u32 h2)
{
	return jhash_2words(h1, h2, PERF_HASH_SEED);
}

/**
 * mutex_perf_hash_stats_update - Update hash table statistics
 * @chain_length: Length of chain just traversed
 *
 * Updates hash table performance statistics after a lookup.
 */
void mutex_perf_hash_stats_update(int chain_length)
{
	int max_chain, avg_chain;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	/* Update max chain length */
	max_chain = atomic_read(&global_perf_ctx->hash_stats.max_chain_length);
	if (chain_length > max_chain)
		atomic_cmpxchg(&global_perf_ctx->hash_stats.max_chain_length,
			       max_chain, chain_length);

	/* Update collision counter if chain length > 1 */
	if (chain_length > 1)
		atomic64_inc(&global_perf_ctx->hash_stats.collisions);

	/* Update average (scaled by 1000 for precision) */
	avg_chain = atomic_read(&global_perf_ctx->hash_stats.avg_chain_length);
	atomic_set(&global_perf_ctx->hash_stats.avg_chain_length,
		   (avg_chain * 99 + chain_length * 1000) / 100);
}

/**
 * mutex_perf_hash_stats_reset - Reset hash table statistics
 *
 * Resets all hash table performance counters to zero.
 */
void mutex_perf_hash_stats_reset(void)
{
	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	atomic64_set(&global_perf_ctx->hash_stats.lookups, 0);
	atomic64_set(&global_perf_ctx->hash_stats.collisions, 0);
	atomic_set(&global_perf_ctx->hash_stats.max_chain_length, 0);
	atomic_set(&global_perf_ctx->hash_stats.avg_chain_length, 0);
	atomic_set(&global_perf_ctx->hash_stats.bucket_usage, 0);
}

/* ========================================================================
 * Zero-Copy Packet Handling Functions
 * ======================================================================== */

/**
 * mutex_perf_skb_clone_light - Lightweight SKB clone
 * @skb: Socket buffer to clone
 *
 * Creates lightweight clone of SKB sharing packet data.
 * Much faster than full skb_copy().
 *
 * Returns cloned SKB or NULL on failure.
 */
struct sk_buff *mutex_perf_skb_clone_light(struct sk_buff *skb)
{
	struct sk_buff *clone;

	if (!skb || !global_perf_ctx || !global_perf_ctx->zero_copy_enabled)
		return NULL;

	/* Use skb_clone for lightweight copy */
	clone = skb_clone(skb, GFP_ATOMIC);
	if (!clone)
		return NULL;

	return clone;
}

/**
 * mutex_perf_skb_linearize_needed - Check if linearization needed
 * @skb: Socket buffer to check
 *
 * Checks if SKB needs linearization for processing.
 * Returns 1 if linearization needed, 0 otherwise.
 */
int mutex_perf_skb_linearize_needed(struct sk_buff *skb)
{
	if (!skb)
		return 0;

	/* Check if SKB is already linear */
	if (skb_is_nonlinear(skb))
		return 1;

	return 0;
}

/**
 * mutex_perf_skb_mark_owned - Mark SKB as owned by proxy
 * @skb: Socket buffer to mark
 *
 * Marks SKB as owned by proxy module. This is a placeholder
 * for future ownership tracking.
 */
void mutex_perf_skb_mark_owned(struct sk_buff *skb)
{
	if (!skb)
		return;

	/* Mark SKB - could use skb->cb for metadata */
	/* For now, just a placeholder */
}

/* ========================================================================
 * Packet Batching Functions
 * ======================================================================== */

/**
 * mutex_perf_batch_alloc - Allocate packet batch structure
 *
 * Allocates batch structure for processing multiple packets.
 * Returns allocated batch or NULL on failure.
 */
struct perf_packet_batch *mutex_perf_batch_alloc(void)
{
	struct perf_packet_batch *batch;

	if (!global_perf_ctx || !global_perf_ctx->batch_enabled)
		return NULL;

	batch = kzalloc(sizeof(*batch), GFP_ATOMIC);
	if (!batch)
		return NULL;

	batch->count = 0;
	batch->cpu = mutex_perf_get_cpu();
	batch->start_time = ktime_get();

	return batch;
}

/**
 * mutex_perf_batch_free - Free packet batch
 * @batch: Batch to free
 *
 * Frees batch structure and any remaining packets.
 */
void mutex_perf_batch_free(struct perf_packet_batch *batch)
{
	unsigned int i;

	if (!batch)
		return;

	/* Free any remaining SKBs */
	for (i = 0; i < batch->count; i++) {
		if (batch->skbs[i])
			kfree_skb(batch->skbs[i]);
	}

	kfree(batch);
}

/**
 * mutex_perf_batch_add - Add packet to batch
 * @batch: Batch to add to
 * @skb: Socket buffer to add
 *
 * Adds packet to batch for later processing.
 * Returns 1 if batch is full, 0 otherwise, negative on error.
 */
int mutex_perf_batch_add(struct perf_packet_batch *batch, struct sk_buff *skb)
{
	if (!batch || !skb)
		return -EINVAL;

	if (batch->count >= PERF_BATCH_SIZE)
		return 1; /* Batch full */

	batch->skbs[batch->count++] = skb;

	return (batch->count >= perf_batch_size) ? 1 : 0;
}

/**
 * mutex_perf_batch_process - Process all packets in batch
 * @batch: Batch to process
 *
 * Processes all packets in batch together for efficiency.
 * Returns number of packets processed.
 */
int mutex_perf_batch_process(struct perf_packet_batch *batch)
{
	unsigned int i;
	int processed = 0;

	if (!batch)
		return 0;

	/* Process each packet in batch */
	for (i = 0; i < batch->count; i++) {
		if (batch->skbs[i]) {
			/* Process packet here */
			/* For now, just count it */
			processed++;
			batch->skbs[i] = NULL;
		}
	}

	batch->count = 0;
	return processed;
}

/**
 * mutex_perf_batch_flush - Flush batch immediately
 * @batch: Batch to flush
 *
 * Processes and flushes all packets in batch immediately.
 */
void mutex_perf_batch_flush(struct perf_packet_batch *batch)
{
	if (!batch)
		return;

	mutex_perf_batch_process(batch);
	batch->count = 0;
}

/* ========================================================================
 * Profiling and Debugging Functions
 * ======================================================================== */

/**
 * mutex_perf_profile_start - Start profiling section
 * @start: Pointer to store start time
 *
 * Records start time for profiling a code section.
 */
void mutex_perf_profile_start(ktime_t *start)
{
	if (start)
		*start = ktime_get();
}

/**
 * mutex_perf_profile_end - End profiling section
 * @start: Start time from mutex_perf_profile_start
 *
 * Returns elapsed time in nanoseconds since start.
 */
u64 mutex_perf_profile_end(ktime_t start)
{
	return ktime_to_ns(ktime_sub(ktime_get(), start));
}

/**
 * mutex_perf_dump_stats - Dump all performance statistics
 *
 * Prints detailed performance statistics to kernel log.
 */
void mutex_perf_dump_stats(void)
{
	int cpu;
	struct perf_per_cpu_stats *stats;
	u64 total_packets = 0, total_bytes = 0;
	u64 total_dropped = 0, total_cache_hits = 0, total_cache_misses = 0;

	if (!global_perf_ctx || !global_perf_ctx->initialized) {
		pr_info("mutex_perf: not initialized\n");
		return;
	}

	pr_info("========== MUTEX Performance Statistics ==========\n");

	/* Per-CPU statistics */
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);

		u64 packets = atomic64_read(&stats->packets_processed);
		u64 bytes = atomic64_read(&stats->bytes_processed);
		u64 dropped = atomic64_read(&stats->packets_dropped);
		u64 hits = atomic64_read(&stats->cache_hits);
		u64 misses = atomic64_read(&stats->cache_misses);

		if (packets > 0) {
			u64 hit_rate = (hits + misses > 0) ?
				       (hits * 100) / (hits + misses) : 0;
			pr_info("CPU %d: packets=%llu, bytes=%llu, dropped=%llu, "
				"cache_hits=%llu, cache_misses=%llu, hit_rate=%llu%%\n",
				cpu, packets, bytes, dropped, hits, misses, hit_rate);
		}

		total_packets += packets;
		total_bytes += bytes;
		total_dropped += dropped;
		total_cache_hits += hits;
		total_cache_misses += misses;
	}

	/* Aggregate statistics */
	pr_info("Total: packets=%llu, bytes=%llu, dropped=%llu\n",
		total_packets, total_bytes, total_dropped);
	{
		u64 total_hit_rate = (total_cache_hits + total_cache_misses > 0) ?
			(total_cache_hits * 100) / (total_cache_hits + total_cache_misses) : 0;
		pr_info("Cache: hits=%llu, misses=%llu, hit_rate=%llu%%\n",
			total_cache_hits, total_cache_misses, total_hit_rate);
	}

	/* Hash table statistics */
	{
		int avg_chain_scaled = atomic_read(&global_perf_ctx->hash_stats.avg_chain_length);
		pr_info("Hash table: lookups=%llu, collisions=%llu, "
			"max_chain=%d, avg_chain=%d.%03d\n",
			atomic64_read(&global_perf_ctx->hash_stats.lookups),
			atomic64_read(&global_perf_ctx->hash_stats.collisions),
			atomic_read(&global_perf_ctx->hash_stats.max_chain_length),
			avg_chain_scaled / 1000, avg_chain_scaled % 1000);
	}

	/* Connection pool statistics */
	pr_info("Conn pool: alloc=%d, free=%d, peak=%d\n",
		atomic_read(&global_perf_ctx->conn_pool.alloc_count),
		atomic_read(&global_perf_ctx->conn_pool.free_count),
		atomic_read(&global_perf_ctx->conn_pool.peak_usage));

	pr_info("==================================================\n");
}

/**
 * mutex_perf_reset_stats - Reset all performance statistics
 *
 * Resets all performance counters to zero.
 */
void mutex_perf_reset_stats(void)
{
	int cpu;
	struct perf_per_cpu_stats *stats;

	if (!global_perf_ctx || !global_perf_ctx->initialized)
		return;

	/* Reset per-CPU statistics */
	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(global_perf_ctx->per_cpu_stats, cpu);
		atomic64_set(&stats->packets_processed, 0);
		atomic64_set(&stats->packets_dropped, 0);
		atomic64_set(&stats->bytes_processed, 0);
		atomic64_set(&stats->cache_hits, 0);
		atomic64_set(&stats->cache_misses, 0);
		atomic64_set(&stats->rcu_grace_periods, 0);
		atomic64_set(&stats->lock_acquisitions, 0);
		atomic64_set(&stats->lock_contentions, 0);
		atomic64_set(&stats->alloc_fast, 0);
		atomic64_set(&stats->alloc_slow, 0);
		stats->processing_time_ns = 0;
	}

	/* Reset hash statistics */
	mutex_perf_hash_stats_reset();

	/* Reset connection pool statistics */
	atomic_set(&global_perf_ctx->conn_pool.alloc_count, 0);
	atomic_set(&global_perf_ctx->conn_pool.free_count, 0);
	atomic_set(&global_perf_ctx->conn_pool.peak_usage, 0);

	pr_info("mutex_perf: statistics reset\n");
}

EXPORT_SYMBOL_GPL(mutex_perf_init);
EXPORT_SYMBOL_GPL(mutex_perf_exit);
EXPORT_SYMBOL_GPL(mutex_perf_stats_inc_packets);
EXPORT_SYMBOL_GPL(mutex_perf_stats_inc_dropped);
EXPORT_SYMBOL_GPL(mutex_perf_cache_lookup);
EXPORT_SYMBOL_GPL(mutex_perf_cache_insert);
EXPORT_SYMBOL_GPL(mutex_perf_conn_alloc);
EXPORT_SYMBOL_GPL(mutex_perf_conn_free);
EXPORT_SYMBOL_GPL(mutex_perf_config_read);
EXPORT_SYMBOL_GPL(mutex_perf_config_update);
EXPORT_SYMBOL_GPL(mutex_perf_hash_tuple);
EXPORT_SYMBOL_GPL(mutex_perf_dump_stats);
EXPORT_SYMBOL_GPL(mutex_perf_reset_stats);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Team");
MODULE_DESCRIPTION("MUTEX Performance Optimization Module");
