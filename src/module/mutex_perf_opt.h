/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_perf_opt.h - MUTEX performance optimization header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This header provides performance optimization structures and APIs
 * for the MUTEX kernel proxy module, including per-CPU data structures,
 * RCU support, connection pooling, and zero-copy packet handling.
 */

#ifndef _MUTEX_PERF_OPT_H
#define _MUTEX_PERF_OPT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include "../../linux/include/uapi/linux/mutex_proxy.h"

/* Forward declarations */
struct mutex_conn_entry;
struct conn_tuple;
struct mutex_proxy_stats;

/* Performance tuning constants */
#define PERF_CONN_CACHE_SIZE		4096	/* Slab cache size */
#define PERF_BATCH_SIZE			32	/* Max packets per batch */
#define PERF_HASH_SEED			0x9e3779b9	/* Golden ratio */
#define PERF_MAX_CPU_CONNS		1024	/* Max per-CPU connections */

/**
 * struct perf_per_cpu_stats - Per-CPU statistics
 * @packets_processed: Total packets processed on this CPU
 * @packets_dropped: Packets dropped on this CPU
 * @bytes_processed: Total bytes processed on this CPU
 * @cache_hits: Connection cache hits
 * @cache_misses: Connection cache misses
 * @rcu_grace_periods: RCU grace period waits
 * @lock_acquisitions: Number of lock acquisitions
 * @lock_contentions: Number of lock contentions
 * @alloc_fast: Fast path allocations (from cache)
 * @alloc_slow: Slow path allocations (from kernel)
 * @processing_time_ns: Total processing time in nanoseconds
 * @last_updated: Last update timestamp
 *
 * Per-CPU statistics to avoid cache line bouncing and lock contention.
 * Each CPU maintains its own copy of these statistics.
 */
struct perf_per_cpu_stats {
	atomic64_t packets_processed;
	atomic64_t packets_dropped;
	atomic64_t bytes_processed;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic64_t rcu_grace_periods;
	atomic64_t lock_acquisitions;
	atomic64_t lock_contentions;
	atomic64_t alloc_fast;
	atomic64_t alloc_slow;
	u64 processing_time_ns;
	ktime_t last_updated;
} ____cacheline_aligned;

/**
 * struct perf_conn_cache_entry - Cached connection entry
 * @tuple_hash: Hash of connection tuple for quick lookup
 * @conn: Pointer to actual connection entry
 * @access_count: Number of times accessed (for LRU)
 * @last_used: Last access timestamp
 * @cpu: CPU this entry is cached on
 * @valid: Entry is valid
 *
 * Per-CPU connection cache to reduce hash table lookups.
 */
struct perf_conn_cache_entry {
	u32 tuple_hash;
	struct mutex_conn_entry __rcu *conn;
	atomic_t access_count;
	unsigned long last_used;
	int cpu;
	bool valid;
} ____cacheline_aligned;

/**
 * struct perf_conn_pool - Connection entry memory pool
 * @cache: Slab cache for fast allocation
 * @free_list: List of pre-allocated entries
 * @lock: Protects free_list
 * @alloc_count: Total allocations from pool
 * @free_count: Total frees to pool
 * @peak_usage: Peak number of entries in use
 *
 * Memory pool using slab cache for efficient connection entry allocation.
 */
struct perf_conn_pool {
	struct kmem_cache *cache;
	struct list_head free_list;
	spinlock_t lock;
	atomic_t alloc_count;
	atomic_t free_count;
	atomic_t peak_usage;
};

/**
 * struct perf_packet_batch - Batch of packets for processing
 * @skbs: Array of socket buffers
 * @count: Number of packets in batch
 * @cpu: CPU this batch is for
 * @start_time: Batch processing start time
 *
 * Batch processing structure to reduce per-packet overhead.
 */
struct perf_packet_batch {
	struct sk_buff *skbs[PERF_BATCH_SIZE];
	unsigned int count;
	int cpu;
	ktime_t start_time;
};

/**
 * struct perf_rcu_config - RCU-protected configuration
 * @proxy_config: Current proxy configuration
 * @rcu: RCU head for safe updates
 * @version: Configuration version number
 * @timestamp: Last update timestamp
 *
 * RCU-protected proxy configuration for lock-free reads in hot path.
 */
struct perf_rcu_config {
	struct mutex_proxy_config proxy_config;
	struct rcu_head rcu;
	atomic_t version;
	ktime_t timestamp;
};

/**
 * struct perf_hash_stats - Hash table performance statistics
 * @lookups: Total hash lookups
 * @collisions: Hash collisions
 * @max_chain_length: Maximum chain length encountered
 * @avg_chain_length: Average chain length (scaled by 1000)
 * @bucket_usage: Number of non-empty buckets
 *
 * Statistics for hash table performance monitoring.
 */
struct perf_hash_stats {
	atomic64_t lookups;
	atomic64_t collisions;
	atomic_t max_chain_length;
	atomic_t avg_chain_length;
	atomic_t bucket_usage;
};

/**
 * struct perf_optimization_context - Main performance context
 * @per_cpu_stats: Per-CPU statistics array
 * @conn_cache: Per-CPU connection cache
 * @conn_pool: Connection entry memory pool
 * @rcu_config: RCU-protected configuration
 * @hash_stats: Hash table statistics
 * @batch_enabled: Packet batching is enabled
 * @zero_copy_enabled: Zero-copy mode enabled
 * @rcu_enabled: RCU optimization enabled
 * @initialized: Context is initialized
 *
 * Main context structure for all performance optimizations.
 */
struct perf_optimization_context {
	struct perf_per_cpu_stats __percpu *per_cpu_stats;
	struct perf_conn_cache_entry __percpu *conn_cache;
	struct perf_conn_pool conn_pool;
	struct perf_rcu_config __rcu *rcu_config;
	struct perf_hash_stats hash_stats;
	bool batch_enabled;
	bool zero_copy_enabled;
	bool rcu_enabled;
	bool initialized;
};

/* Global performance context */
extern struct perf_optimization_context *global_perf_ctx;

/* Initialization and cleanup */
int mutex_perf_init(void);
void mutex_perf_exit(void);

/* Per-CPU statistics */
void mutex_perf_stats_inc_packets(unsigned int cpu, u64 bytes);
void mutex_perf_stats_inc_dropped(unsigned int cpu);
void mutex_perf_stats_cache_hit(unsigned int cpu);
void mutex_perf_stats_cache_miss(unsigned int cpu);
void mutex_perf_stats_add_time(unsigned int cpu, u64 ns);
struct perf_per_cpu_stats *mutex_perf_get_cpu_stats(unsigned int cpu);
void mutex_perf_aggregate_stats(struct mutex_proxy_stats *stats);

/* Connection cache */
struct mutex_conn_entry *mutex_perf_cache_lookup(u32 hash);
void mutex_perf_cache_insert(u32 hash, struct mutex_conn_entry *conn);
void mutex_perf_cache_invalidate(u32 hash);
void mutex_perf_cache_clear_all(void);

/* Connection pool (slab cache) */
struct mutex_conn_entry *mutex_perf_conn_alloc(void);
void mutex_perf_conn_free(struct mutex_conn_entry *conn);
int mutex_perf_conn_pool_init(void);
void mutex_perf_conn_pool_exit(void);

/* RCU-protected configuration */
struct mutex_proxy_config *mutex_perf_config_read(void);
void mutex_perf_config_update(const struct mutex_proxy_config *new_config);
void mutex_perf_config_sync(void);

/* Hash table optimization */
u32 mutex_perf_hash_tuple(const struct conn_tuple *tuple);
u32 mutex_perf_hash_combine(u32 h1, u32 h2);
void mutex_perf_hash_stats_update(int chain_length);
void mutex_perf_hash_stats_reset(void);

/* Zero-copy packet handling */
struct sk_buff *mutex_perf_skb_clone_light(struct sk_buff *skb);
int mutex_perf_skb_linearize_needed(struct sk_buff *skb);
void mutex_perf_skb_mark_owned(struct sk_buff *skb);

/* Packet batching */
struct perf_packet_batch *mutex_perf_batch_alloc(void);
void mutex_perf_batch_free(struct perf_packet_batch *batch);
int mutex_perf_batch_add(struct perf_packet_batch *batch, struct sk_buff *skb);
int mutex_perf_batch_process(struct perf_packet_batch *batch);
void mutex_perf_batch_flush(struct perf_packet_batch *batch);

/* Profiling and debugging */
void mutex_perf_profile_start(ktime_t *start);
u64 mutex_perf_profile_end(ktime_t start);
void mutex_perf_dump_stats(void);
void mutex_perf_reset_stats(void);

/* Inline fast-path helpers */

/**
 * mutex_perf_likely_hit - Hint for likely cache hit
 * @condition: Condition to evaluate
 *
 * Compiler hint that cache hit is likely.
 */
static inline bool mutex_perf_likely_hit(bool condition)
{
	return likely(condition);
}

/**
 * mutex_perf_prefetch - Prefetch data into cache
 * @ptr: Pointer to prefetch
 *
 * Prefetch data to reduce cache misses.
 */
static inline void mutex_perf_prefetch(const void *ptr)
{
	prefetch(ptr);
}

/**
 * mutex_perf_get_cpu - Get current CPU number
 *
 * Returns current CPU number for per-CPU data access.
 */
static inline unsigned int mutex_perf_get_cpu(void)
{
	return smp_processor_id();
}

/**
 * mutex_perf_timestamp - Get high-resolution timestamp
 *
 * Returns current time with nanosecond precision for profiling.
 */
static inline ktime_t mutex_perf_timestamp(void)
{
	return ktime_get();
}

/* Module parameters for runtime tuning */
extern bool perf_enable_batching;
extern bool perf_enable_zero_copy;
extern bool perf_enable_rcu;
extern unsigned int perf_batch_size;
extern unsigned int perf_cache_size;

#endif /* _MUTEX_PERF_OPT_H */
