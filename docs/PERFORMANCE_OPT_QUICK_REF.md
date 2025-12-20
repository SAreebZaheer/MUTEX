# Performance Optimization Quick Reference

## Quick Start

### Enable Performance Optimizations
```bash
# Load module with all optimizations enabled (default)
sudo insmod mutex_proxy.ko

# Load with specific optimizations
sudo insmod mutex_proxy.ko \
    perf_enable_batching=1 \
    perf_enable_zero_copy=1 \
    perf_enable_rcu=1 \
    perf_batch_size=32

# Check module loaded
lsmod | grep mutex_proxy
dmesg | grep "performance optimization initialized"
```

### Runtime Tuning
```bash
# Enable/disable features at runtime
echo 1 > /sys/module/mutex_proxy/parameters/perf_enable_batching
echo 1 > /sys/module/mutex_proxy/parameters/perf_enable_zero_copy
echo 1 > /sys/module/mutex_proxy/parameters/perf_enable_rcu

# Adjust batch size
echo 16 > /sys/module/mutex_proxy/parameters/perf_batch_size

# Adjust cache size
echo 512 > /sys/module/mutex_proxy/parameters/perf_cache_size
```

---

## API Quick Reference

### Per-CPU Statistics

```c
#include "mutex_perf_opt.h"

/* Increment packet counter */
unsigned int cpu = smp_processor_id();
mutex_perf_stats_inc_packets(cpu, bytes);

/* Record dropped packet */
mutex_perf_stats_inc_dropped(cpu);

/* Record cache hit/miss */
mutex_perf_stats_cache_hit(cpu);
mutex_perf_stats_cache_miss(cpu);

/* Add processing time */
mutex_perf_stats_add_time(cpu, time_ns);

/* Get CPU stats */
struct perf_per_cpu_stats *stats = mutex_perf_get_cpu_stats(cpu);

/* Aggregate all CPU stats */
struct mutex_proxy_stats total_stats;
mutex_perf_aggregate_stats(&total_stats);
```

### Connection Cache

```c
/* Fast lookup from per-CPU cache */
u32 hash = mutex_perf_hash_tuple(&tuple);
struct mutex_conn_entry *conn = mutex_perf_cache_lookup(hash);

if (conn) {
    /* Cache hit - use connection */
    process_connection(conn);
} else {
    /* Cache miss - look up in hash table */
    conn = mutex_conn_lookup(&tuple);

    if (conn) {
        /* Add to cache for next time */
        mutex_perf_cache_insert(hash, conn);
    }
}

/* Invalidate stale cache entry */
mutex_perf_cache_invalidate(hash);

/* Clear all cache entries */
mutex_perf_cache_clear_all();
```

### Memory Pool (Slab Cache)

```c
/* Allocate connection from pool (fast) */
struct mutex_conn_entry *conn = mutex_perf_conn_alloc();
if (!conn) {
    /* Allocation failed */
    return -ENOMEM;
}

/* Initialize connection */
init_connection(conn);

/* Use connection */
process_connection(conn);

/* Free connection back to pool */
mutex_perf_conn_free(conn);
```

### RCU Configuration

```c
/* Read configuration (lock-free) */
rcu_read_lock();
struct mutex_proxy_config *config = mutex_perf_config_read();
if (config) {
    /* Use configuration */
    proxy_addr = config->proxy_addr;
}
rcu_read_unlock();

/* Update configuration (writer) */
struct mutex_proxy_config new_config;
/* ... fill in new_config ... */
mutex_perf_config_update(&new_config);

/* Wait for all readers to see update */
mutex_perf_config_sync();
```

### Hash Optimization

```c
/* Compute optimized hash */
u32 hash = mutex_perf_hash_tuple(&tuple);

/* Combine multiple hash values */
u32 combined = mutex_perf_hash_combine(hash1, hash2);

/* Update hash statistics */
int chain_length = traverse_hash_chain(&buckets[hash]);
mutex_perf_hash_stats_update(chain_length);

/* Reset hash statistics */
mutex_perf_hash_stats_reset();
```

### Zero-Copy Packet Handling

```c
/* Lightweight clone (shares packet data) */
struct sk_buff *clone = mutex_perf_skb_clone_light(skb);
if (!clone) {
    /* Clone failed, fallback to copy */
    clone = skb_copy(skb, GFP_ATOMIC);
}

/* Check if linearization needed */
if (mutex_perf_skb_linearize_needed(skb)) {
    if (skb_linearize(skb) != 0) {
        /* Linearization failed */
        return -ENOMEM;
    }
}

/* Mark SKB as owned by proxy */
mutex_perf_skb_mark_owned(skb);
```

### Packet Batching

```c
/* Allocate batch */
struct perf_packet_batch *batch = mutex_perf_batch_alloc();
if (!batch) {
    /* Batching not available */
    return process_packet_immediately(skb);
}

/* Add packets to batch */
for (each packet) {
    int ret = mutex_perf_batch_add(batch, skb);
    if (ret == 1) {
        /* Batch full - process now */
        mutex_perf_batch_process(batch);
    }
}

/* Flush remaining packets */
mutex_perf_batch_flush(batch);

/* Free batch */
mutex_perf_batch_free(batch);
```

### Profiling

```c
/* Profile a code section */
ktime_t start;
mutex_perf_profile_start(&start);

/* ... code to profile ... */
do_expensive_operation();

u64 elapsed_ns = mutex_perf_profile_end(start);
pr_info("Operation took %llu ns\n", elapsed_ns);

/* Add to per-CPU statistics */
unsigned int cpu = smp_processor_id();
mutex_perf_stats_add_time(cpu, elapsed_ns);
```

### Performance Monitoring

```c
/* Dump all performance statistics */
mutex_perf_dump_stats();

/* Reset all counters */
mutex_perf_reset_stats();

/* Get specific CPU stats */
unsigned int cpu = 0;
struct perf_per_cpu_stats *stats = mutex_perf_get_cpu_stats(cpu);

pr_info("CPU %d: packets=%llu, cache_hits=%llu, cache_misses=%llu\n",
        cpu,
        atomic64_read(&stats->packets_processed),
        atomic64_read(&stats->cache_hits),
        atomic64_read(&stats->cache_misses));

/* Calculate cache hit rate */
u64 hits = atomic64_read(&stats->cache_hits);
u64 misses = atomic64_read(&stats->cache_misses);
double hit_rate = (hits * 100.0) / (hits + misses);
pr_info("Cache hit rate: %.2f%%\n", hit_rate);
```

---

## Common Patterns

### Pattern 1: Fast Connection Lookup

```c
static struct mutex_conn_entry *fast_lookup(const struct conn_tuple *tuple)
{
    struct mutex_conn_entry *conn;
    u32 hash;
    unsigned int cpu = smp_processor_id();
    ktime_t start;

    /* Start profiling */
    mutex_perf_profile_start(&start);

    /* Compute hash */
    hash = mutex_perf_hash_tuple(tuple);

    /* Try cache first */
    conn = mutex_perf_cache_lookup(hash);
    if (conn) {
        mutex_perf_stats_cache_hit(cpu);
        goto out;
    }

    /* Cache miss - lookup in table */
    conn = mutex_conn_lookup(tuple);
    if (conn) {
        /* Add to cache */
        mutex_perf_cache_insert(hash, conn);
        mutex_perf_stats_cache_miss(cpu);
    }

out:
    /* Record time */
    mutex_perf_stats_add_time(cpu, mutex_perf_profile_end(start));
    return conn;
}
```

### Pattern 2: Fast Connection Creation

```c
static struct mutex_conn_entry *fast_create(const struct conn_tuple *tuple)
{
    struct mutex_conn_entry *conn;
    unsigned int cpu = smp_processor_id();

    /* Allocate from pool */
    conn = mutex_perf_conn_alloc();
    if (!conn) {
        mutex_perf_stats_inc_dropped(cpu);
        return NULL;
    }

    /* Initialize connection */
    memcpy(&conn->tuple, tuple, sizeof(*tuple));
    atomic_set(&conn->refcount, 1);
    /* ... more initialization ... */

    /* Insert into hash table */
    u32 hash = mutex_perf_hash_tuple(tuple);
    insert_into_hash_table(hash, conn);

    /* Add to cache */
    mutex_perf_cache_insert(hash, conn);

    return conn;
}
```

### Pattern 3: RCU-Protected Configuration Read

```c
static int get_proxy_address(struct conn_tuple *tuple, __be32 *proxy_addr)
{
    struct mutex_proxy_config *config;
    int ret = 0;

    rcu_read_lock();

    config = mutex_perf_config_read();
    if (!config) {
        ret = -ENOENT;
        goto out;
    }

    /* Read configuration without locks */
    *proxy_addr = config->proxy_servers[0].addr.v4;

out:
    rcu_read_unlock();
    return ret;
}
```

### Pattern 4: Batch Packet Processing

```c
static void process_packets_batch(struct sk_buff **skbs, int count)
{
    struct perf_packet_batch *batch;
    int i;

    /* Allocate batch */
    batch = mutex_perf_batch_alloc();
    if (!batch) {
        /* Fallback to individual processing */
        for (i = 0; i < count; i++)
            process_single_packet(skbs[i]);
        return;
    }

    /* Add all packets to batch */
    for (i = 0; i < count; i++) {
        if (mutex_perf_batch_add(batch, skbs[i]) == 1) {
            /* Batch full - process and continue */
            mutex_perf_batch_process(batch);
        }
    }

    /* Process remaining */
    mutex_perf_batch_flush(batch);
    mutex_perf_batch_free(batch);
}
```

---

## Performance Tips

### 1. Minimize Cache Misses
- Access data sequentially when possible
- Keep frequently accessed data on same cache line
- Use prefetch hints for predictable access patterns
```c
mutex_perf_prefetch(&conn->tuple);
/* ... do other work ... */
/* Now access conn->tuple (likely in cache) */
```

### 2. Avoid Lock Contention
- Use per-CPU data structures when possible
- Use RCU for read-heavy workloads
- Keep critical sections short
```c
/* BAD: Long critical section */
spin_lock(&lock);
do_lots_of_work();
spin_unlock(&lock);

/* GOOD: Short critical section */
prepare_data();
spin_lock(&lock);
update_shared_data();
spin_unlock(&lock);
post_process();
```

### 3. Batch Operations
- Process multiple items together
- Amortize overhead across batch
- Flush batches periodically
```c
/* Process 32 packets in one go */
if (batch_count >= 32)
    process_batch();
```

### 4. Use Cache Effectively
- Verify cache entries before use
- Invalidate stale entries promptly
- Monitor cache hit rate
```c
/* Check cache hit rate periodically */
if (hit_rate < 80.0) {
    pr_warn("Low cache hit rate: %.2f%%\n", hit_rate);
    /* Consider increasing cache size */
}
```

### 5. Profile Regularly
- Measure before and after optimizations
- Focus on hot paths
- Use profiling data to guide optimization
```c
mutex_perf_dump_stats();  /* Check where time is spent */
```

---

## Debugging

### Check Initialization
```bash
dmesg | grep mutex_perf
# Should see: "mutex_perf: initialized"
```

### Monitor Statistics
```bash
# View current statistics in kernel log
echo 1 > /proc/sys/kernel/printk
# Then trigger statistics dump via ioctl or signal
```

### Verify Optimizations Active
```c
/* In code, check flags */
if (global_perf_ctx && global_perf_ctx->batch_enabled) {
    pr_info("Batching is enabled\n");
}
```

### Common Issues

**Issue**: Low cache hit rate
```c
Solution: Increase cache size or use multi-entry cache
```

**Issue**: High lock contention
```c
Solution: Enable RCU optimizations
```

**Issue**: Memory allocation failures
```c
Solution: Increase slab cache size or add more to free list
```

---

## Module Parameters Summary

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `perf_enable_batching` | bool | true | Enable packet batching |
| `perf_enable_zero_copy` | bool | true | Enable zero-copy packet handling |
| `perf_enable_rcu` | bool | true | Enable RCU optimizations |
| `perf_batch_size` | uint | 32 | Maximum packets per batch |
| `perf_cache_size` | uint | 1024 | Per-CPU connection cache size |

---

## Expected Performance Gains

| Optimization | Improvement | Use Case |
|--------------|-------------|----------|
| Per-CPU Cache | 3-10x | Connection lookups |
| Slab Cache | 10-20x | Connection allocation |
| RCU | 2-5x | Read-heavy workloads |
| Zero-Copy | 20-30% | Packet processing |
| Batching | 2-3x | Bulk traffic |

---

## Further Reading

- [Branch 13 Full Summary](BRANCH_13_SUMMARY.md)
- [Linux Kernel RCU Documentation](https://www.kernel.org/doc/html/latest/RCU/)
- [Per-CPU Variables](https://www.kernel.org/doc/html/latest/core-api/local_ops.html)
- [Slab Allocator](https://www.kernel.org/doc/html/latest/core-api/mm-api.html)

---

*Last Updated: December 21, 2025*  
*Version: 1.0*
