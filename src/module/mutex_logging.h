/*
 * MUTEX Logging Framework
 *
 * Comprehensive logging system with structured logging, rate limiting,
 * context-aware logging, and filtering capabilities.
 */

#ifndef MUTEX_LOGGING_H
#define MUTEX_LOGGING_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* Log Levels */
#define MUTEX_LOG_DEBUG    0
#define MUTEX_LOG_INFO     1
#define MUTEX_LOG_WARN     2
#define MUTEX_LOG_ERROR    3
#define MUTEX_LOG_CRITICAL 4

/* Log Categories */
#define MUTEX_LOG_CAT_GENERAL     0x0001
#define MUTEX_LOG_CAT_NETWORK     0x0002
#define MUTEX_LOG_CAT_CONNECTION  0x0004
#define MUTEX_LOG_CAT_PROXY       0x0008
#define MUTEX_LOG_CAT_SECURITY    0x0010
#define MUTEX_LOG_CAT_PERFORMANCE 0x0020
#define MUTEX_LOG_CAT_ERROR       0x0040
#define MUTEX_LOG_CAT_DNS         0x0080
#define MUTEX_LOG_CAT_PROTOCOL    0x0100
#define MUTEX_LOG_CAT_STATS       0x0200
#define MUTEX_LOG_CAT_ALL         0xFFFF

/* Log Destinations */
#define MUTEX_LOG_DEST_PRINTK  0x01
#define MUTEX_LOG_DEST_BUFFER  0x02
#define MUTEX_LOG_DEST_SYSLOG  0x04

/* Maximum sizes */
#define MUTEX_LOG_MAX_MSG      512
#define MUTEX_LOG_MAX_CONTEXT  128
#define MUTEX_LOG_BUFFER_SIZE  4096
#define MUTEX_LOG_MAX_ENTRIES  1000

/*
 * Log Entry Structure
 * Represents a single log entry in the circular buffer
 */
struct log_entry {
	struct list_head list;
	ktime_t timestamp;
	unsigned int level;
	unsigned int category;
	char context[MUTEX_LOG_MAX_CONTEXT];
	char message[MUTEX_LOG_MAX_MSG];
	pid_t pid;
	int cpu;
	unsigned long sequence;
};

/*
 * Rate Limiter
 * Token bucket algorithm for rate limiting log messages
 */
struct log_rate_limiter {
	spinlock_t lock;
	unsigned int tokens;
	unsigned int max_tokens;
	unsigned int refill_rate;     /* tokens per second */
	ktime_t last_refill;
	unsigned long messages_dropped;
};

/*
 * Log Filter
 * Controls which log messages are processed
 */
struct log_filter {
	unsigned int min_level;       /* Minimum log level to process */
	unsigned int categories;      /* Bitmask of enabled categories */
	bool enabled;                 /* Master enable/disable */
};

/*
 * Connection Context
 * Per-connection logging context for correlation
 */
struct log_conn_context {
	struct list_head list;
	unsigned long conn_id;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	u8 protocol;
	char label[64];
	atomic_t refcount;
	ktime_t created;
};

/*
 * Log Buffer
 * Circular buffer for storing log entries
 */
struct log_buffer {
	struct list_head entries;
	spinlock_t lock;
	unsigned int count;
	unsigned int max_entries;
	unsigned long sequence;
	unsigned long total_entries;
	unsigned long entries_dropped;
};

/*
 * Log Statistics
 */
struct log_stats {
	atomic64_t total_messages;
	atomic64_t messages_by_level[5];  /* One for each level */
	atomic64_t messages_dropped;
	atomic64_t rate_limited;
	atomic64_t buffer_full;
	atomic64_t allocation_failures;
};

/*
 * Logging Context
 * Main logging framework state
 */
struct mutex_log_context {
	struct log_filter filter;
	struct log_rate_limiter rate_limiter;
	struct log_buffer buffer;
	struct log_stats stats;
	struct list_head conn_contexts;
	spinlock_t conn_lock;
	unsigned int destinations;
	bool initialized;
};

/* Global logging context */
extern struct mutex_log_context *g_log_ctx;

/*
 * Initialization and Cleanup
 */
int mutex_log_init(void);
void mutex_log_destroy(void);

/*
 * Configuration
 */
int mutex_log_set_level(unsigned int level);
int mutex_log_set_categories(unsigned int categories);
int mutex_log_enable_category(unsigned int category);
int mutex_log_disable_category(unsigned int category);
int mutex_log_set_destinations(unsigned int destinations);
int mutex_log_set_rate_limit(unsigned int tokens_per_sec, unsigned int max_tokens);
void mutex_log_enable(void);
void mutex_log_disable(void);

/*
 * Core Logging Functions
 */
void mutex_log_message(unsigned int level, unsigned int category,
		       const char *context, const char *fmt, ...);

/* Convenience macros for different log levels */
#define mutex_log_debug(category, context, fmt, ...) \
	mutex_log_message(MUTEX_LOG_DEBUG, category, context, fmt, ##__VA_ARGS__)

#define mutex_log_info(category, context, fmt, ...) \
	mutex_log_message(MUTEX_LOG_INFO, category, context, fmt, ##__VA_ARGS__)

#define mutex_log_warn(category, context, fmt, ...) \
	mutex_log_message(MUTEX_LOG_WARN, category, context, fmt, ##__VA_ARGS__)

#define mutex_log_error(category, context, fmt, ...) \
	mutex_log_message(MUTEX_LOG_ERROR, category, context, fmt, ##__VA_ARGS__)

#define mutex_log_critical(category, context, fmt, ...) \
	mutex_log_message(MUTEX_LOG_CRITICAL, category, context, fmt, ##__VA_ARGS__)

/* Category-specific logging macros */
#define mutex_log_net(level, context, fmt, ...) \
	mutex_log_message(level, MUTEX_LOG_CAT_NETWORK, context, fmt, ##__VA_ARGS__)

#define mutex_log_conn(level, context, fmt, ...) \
	mutex_log_message(level, MUTEX_LOG_CAT_CONNECTION, context, fmt, ##__VA_ARGS__)

#define mutex_log_proxy(level, context, fmt, ...) \
	mutex_log_message(level, MUTEX_LOG_CAT_PROXY, context, fmt, ##__VA_ARGS__)

#define mutex_log_security(level, context, fmt, ...) \
	mutex_log_message(level, MUTEX_LOG_CAT_SECURITY, context, fmt, ##__VA_ARGS__)

#define mutex_log_perf(level, context, fmt, ...) \
	mutex_log_message(level, MUTEX_LOG_CAT_PERFORMANCE, context, fmt, ##__VA_ARGS__)

/*
 * Connection Context Management
 */
struct log_conn_context *mutex_log_conn_create(unsigned long conn_id,
						__be32 src_ip, __be32 dst_ip,
						__be16 src_port, __be16 dst_port,
						u8 protocol, const char *label);
void mutex_log_conn_get(struct log_conn_context *ctx);
void mutex_log_conn_put(struct log_conn_context *ctx);
struct log_conn_context *mutex_log_conn_find(unsigned long conn_id);
void mutex_log_conn_destroy(struct log_conn_context *ctx);

/*
 * Buffer Management
 */
int mutex_log_get_entries(struct log_entry *entries, unsigned int max_entries,
			  unsigned int min_level, unsigned int categories);
void mutex_log_clear_buffer(void);
unsigned int mutex_log_get_buffer_count(void);

/*
 * Statistics
 */
void mutex_log_get_stats(struct log_stats *stats);
void mutex_log_reset_stats(void);

/*
 * Export Functions (for userspace access via procfs/sysfs)
 */
int mutex_log_export_text(char *buffer, size_t size);
int mutex_log_export_json(char *buffer, size_t size);

/*
 * Rate Limiting Helpers
 */
bool mutex_log_rate_limit_check(struct log_rate_limiter *limiter);
void mutex_log_rate_limiter_refill(struct log_rate_limiter *limiter);

/*
 * Formatting Helpers
 */
const char *mutex_log_level_to_string(unsigned int level);
const char *mutex_log_category_to_string(unsigned int category);

/*
 * Helper function to create connection context string
 */
static inline void mutex_log_format_conn_context(char *buffer, size_t size,
						 __be32 src_ip, __be32 dst_ip,
						 __be16 src_port, __be16 dst_port,
						 u8 protocol)
{
	snprintf(buffer, size, "%pI4:%u->%pI4:%u (proto:%u)",
		 &src_ip, ntohs(src_port), &dst_ip, ntohs(dst_port), protocol);
}

/*
 * Debug helper to dump log buffer
 */
void mutex_log_dump_buffer(void);

#endif /* MUTEX_LOGGING_H */
