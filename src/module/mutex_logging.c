/*
 * MUTEX Logging Framework Implementation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <stdarg.h>

#include "mutex_logging.h"

/* Global logging context */
struct mutex_log_context *g_log_ctx = NULL;

/* Module parameters for default configuration */
static unsigned int log_level = MUTEX_LOG_INFO;
module_param(log_level, uint, 0644);
MODULE_PARM_DESC(log_level, "Default log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=CRITICAL)");

static unsigned int log_categories = MUTEX_LOG_CAT_ALL;
module_param(log_categories, uint, 0644);
MODULE_PARM_DESC(log_categories, "Enabled log categories bitmask");

static unsigned int log_rate_limit = 100;
module_param(log_rate_limit, uint, 0644);
MODULE_PARM_DESC(log_rate_limit, "Maximum log messages per second (0=unlimited)");

static unsigned int log_buffer_size = MUTEX_LOG_MAX_ENTRIES;
module_param(log_buffer_size, uint, 0644);
MODULE_PARM_DESC(log_buffer_size, "Size of log buffer");

/* Proc filesystem entry */
static struct proc_dir_entry *mutex_log_proc = NULL;

/*
 * Level to String Conversion
 */
const char *mutex_log_level_to_string(unsigned int level)
{
	switch (level) {
	case MUTEX_LOG_DEBUG:    return "DEBUG";
	case MUTEX_LOG_INFO:     return "INFO";
	case MUTEX_LOG_WARN:     return "WARN";
	case MUTEX_LOG_ERROR:    return "ERROR";
	case MUTEX_LOG_CRITICAL: return "CRITICAL";
	default:                 return "UNKNOWN";
	}
}

/*
 * Category to String Conversion
 */
const char *mutex_log_category_to_string(unsigned int category)
{
	switch (category) {
	case MUTEX_LOG_CAT_GENERAL:     return "GENERAL";
	case MUTEX_LOG_CAT_NETWORK:     return "NETWORK";
	case MUTEX_LOG_CAT_CONNECTION:  return "CONNECTION";
	case MUTEX_LOG_CAT_PROXY:       return "PROXY";
	case MUTEX_LOG_CAT_SECURITY:    return "SECURITY";
	case MUTEX_LOG_CAT_PERFORMANCE: return "PERFORMANCE";
	case MUTEX_LOG_CAT_ERROR:       return "ERROR";
	case MUTEX_LOG_CAT_DNS:         return "DNS";
	case MUTEX_LOG_CAT_PROTOCOL:    return "PROTOCOL";
	case MUTEX_LOG_CAT_STATS:       return "STATS";
	default:                        return "UNKNOWN";
	}
}

/*
 * Rate Limiter: Refill tokens
 */
void mutex_log_rate_limiter_refill(struct log_rate_limiter *limiter)
{
	ktime_t now = ktime_get();
	s64 elapsed_ms;
	unsigned int new_tokens;
	unsigned long flags;

	if (!limiter || limiter->refill_rate == 0)
		return;

	spin_lock_irqsave(&limiter->lock, flags);

	elapsed_ms = ktime_ms_delta(now, limiter->last_refill);
	if (elapsed_ms < 1000) {
		spin_unlock_irqrestore(&limiter->lock, flags);
		return;
	}

	/* Calculate new tokens based on elapsed time */
	new_tokens = (elapsed_ms * limiter->refill_rate) / 1000;

	limiter->tokens = min(limiter->tokens + new_tokens, limiter->max_tokens);
	limiter->last_refill = now;

	spin_unlock_irqrestore(&limiter->lock, flags);
}

/*
 * Rate Limiter: Check if message can be logged
 */
bool mutex_log_rate_limit_check(struct log_rate_limiter *limiter)
{
	unsigned long flags;
	bool allowed = true;

	if (!limiter || limiter->refill_rate == 0)
		return true;  /* No rate limiting */

	/* Refill tokens first */
	mutex_log_rate_limiter_refill(limiter);

	spin_lock_irqsave(&limiter->lock, flags);

	if (limiter->tokens > 0) {
		limiter->tokens--;
		allowed = true;
	} else {
		limiter->messages_dropped++;
		allowed = false;
	}

	spin_unlock_irqrestore(&limiter->lock, flags);

	return allowed;
}

/*
 * Add entry to log buffer
 */
static int log_buffer_add_entry(struct log_buffer *buffer, struct log_entry *entry)
{
	struct log_entry *new_entry, *oldest;
	unsigned long flags;

	if (!buffer || !entry)
		return -EINVAL;

	new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
	if (!new_entry) {
		atomic64_inc(&g_log_ctx->stats.allocation_failures);
		return -ENOMEM;
	}

	memcpy(new_entry, entry, sizeof(*new_entry));
	INIT_LIST_HEAD(&new_entry->list);

	spin_lock_irqsave(&buffer->lock, flags);

	/* If buffer is full, remove oldest entry */
	if (buffer->count >= buffer->max_entries) {
		if (!list_empty(&buffer->entries)) {
			oldest = list_first_entry(&buffer->entries,
						  struct log_entry, list);
			list_del(&oldest->list);
			kfree(oldest);
			buffer->count--;
			buffer->entries_dropped++;
			atomic64_inc(&g_log_ctx->stats.buffer_full);
		}
	}

	/* Add new entry to tail (most recent) */
	new_entry->sequence = buffer->sequence++;
	list_add_tail(&new_entry->list, &buffer->entries);
	buffer->count++;
	buffer->total_entries++;

	spin_unlock_irqrestore(&buffer->lock, flags);

	return 0;
}

/*
 * Core Logging Function
 */
void mutex_log_message(unsigned int level, unsigned int category,
		       const char *context, const char *fmt, ...)
{
	struct log_entry entry;
	va_list args;
	char msg_buffer[MUTEX_LOG_MAX_MSG];
	int ret;

	if (!g_log_ctx || !g_log_ctx->initialized)
		return;

	/* Check if logging is enabled */
	if (!g_log_ctx->filter.enabled)
		return;

	/* Check log level */
	if (level < g_log_ctx->filter.min_level)
		return;

	/* Check category filter */
	if (!(category & g_log_ctx->filter.categories))
		return;

	/* Check rate limit */
	if (!mutex_log_rate_limit_check(&g_log_ctx->rate_limiter)) {
		atomic64_inc(&g_log_ctx->stats.rate_limited);
		return;
	}

	/* Format the message */
	va_start(args, fmt);
	vsnprintf(msg_buffer, sizeof(msg_buffer), fmt, args);
	va_end(args);

	/* Prepare log entry */
	memset(&entry, 0, sizeof(entry));
	entry.timestamp = ktime_get();
	entry.level = level;
	entry.category = category;
	entry.pid = current->pid;
	entry.cpu = smp_processor_id();

	if (context)
		strscpy(entry.context, context, sizeof(entry.context));
	strscpy(entry.message, msg_buffer, sizeof(entry.message));

	/* Update statistics */
	atomic64_inc(&g_log_ctx->stats.total_messages);
	if (level < 5)
		atomic64_inc(&g_log_ctx->stats.messages_by_level[level]);

	/* Output to printk if enabled */
	if (g_log_ctx->destinations & MUTEX_LOG_DEST_PRINTK) {
		if (context && context[0])
			printk(KERN_INFO "MUTEX [%s][%s] %s: %s\n",
			       mutex_log_level_to_string(level),
			       mutex_log_category_to_string(category),
			       context, msg_buffer);
		else
			printk(KERN_INFO "MUTEX [%s][%s] %s\n",
			       mutex_log_level_to_string(level),
			       mutex_log_category_to_string(category),
			       msg_buffer);
	}

	/* Add to buffer if enabled */
	if (g_log_ctx->destinations & MUTEX_LOG_DEST_BUFFER) {
		ret = log_buffer_add_entry(&g_log_ctx->buffer, &entry);
		if (ret < 0)
			atomic64_inc(&g_log_ctx->stats.messages_dropped);
	}
}

/*
 * Configuration Functions
 */
int mutex_log_set_level(unsigned int level)
{
	if (!g_log_ctx)
		return -EINVAL;

	if (level > MUTEX_LOG_CRITICAL)
		return -EINVAL;

	g_log_ctx->filter.min_level = level;
	return 0;
}

int mutex_log_set_categories(unsigned int categories)
{
	if (!g_log_ctx)
		return -EINVAL;

	g_log_ctx->filter.categories = categories;
	return 0;
}

int mutex_log_enable_category(unsigned int category)
{
	if (!g_log_ctx)
		return -EINVAL;

	g_log_ctx->filter.categories |= category;
	return 0;
}

int mutex_log_disable_category(unsigned int category)
{
	if (!g_log_ctx)
		return -EINVAL;

	g_log_ctx->filter.categories &= ~category;
	return 0;
}

int mutex_log_set_destinations(unsigned int destinations)
{
	if (!g_log_ctx)
		return -EINVAL;

	g_log_ctx->destinations = destinations;
	return 0;
}

int mutex_log_set_rate_limit(unsigned int tokens_per_sec, unsigned int max_tokens)
{
	unsigned long flags;

	if (!g_log_ctx)
		return -EINVAL;

	spin_lock_irqsave(&g_log_ctx->rate_limiter.lock, flags);
	g_log_ctx->rate_limiter.refill_rate = tokens_per_sec;
	g_log_ctx->rate_limiter.max_tokens = max_tokens;
	g_log_ctx->rate_limiter.tokens = max_tokens;
	spin_unlock_irqrestore(&g_log_ctx->rate_limiter.lock, flags);

	return 0;
}

void mutex_log_enable(void)
{
	if (g_log_ctx)
		g_log_ctx->filter.enabled = true;
}

void mutex_log_disable(void)
{
	if (g_log_ctx)
		g_log_ctx->filter.enabled = false;
}

/*
 * Connection Context Management
 */
struct log_conn_context *mutex_log_conn_create(unsigned long conn_id,
						__be32 src_ip, __be32 dst_ip,
						__be16 src_port, __be16 dst_port,
						u8 protocol, const char *label)
{
	struct log_conn_context *ctx;
	unsigned long flags;

	if (!g_log_ctx)
		return NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->list);
	ctx->conn_id = conn_id;
	ctx->src_ip = src_ip;
	ctx->dst_ip = dst_ip;
	ctx->src_port = src_port;
	ctx->dst_port = dst_port;
	ctx->protocol = protocol;
	if (label)
		strscpy(ctx->label, label, sizeof(ctx->label));
	atomic_set(&ctx->refcount, 1);
	ctx->created = ktime_get();

	spin_lock_irqsave(&g_log_ctx->conn_lock, flags);
	list_add(&ctx->list, &g_log_ctx->conn_contexts);
	spin_unlock_irqrestore(&g_log_ctx->conn_lock, flags);

	return ctx;
}

void mutex_log_conn_get(struct log_conn_context *ctx)
{
	if (ctx)
		atomic_inc(&ctx->refcount);
}

void mutex_log_conn_put(struct log_conn_context *ctx)
{
	if (!ctx)
		return;

	if (atomic_dec_and_test(&ctx->refcount))
		mutex_log_conn_destroy(ctx);
}

struct log_conn_context *mutex_log_conn_find(unsigned long conn_id)
{
	struct log_conn_context *ctx, *found = NULL;
	unsigned long flags;

	if (!g_log_ctx)
		return NULL;

	spin_lock_irqsave(&g_log_ctx->conn_lock, flags);
	list_for_each_entry(ctx, &g_log_ctx->conn_contexts, list) {
		if (ctx->conn_id == conn_id) {
			found = ctx;
			mutex_log_conn_get(ctx);
			break;
		}
	}
	spin_unlock_irqrestore(&g_log_ctx->conn_lock, flags);

	return found;
}

void mutex_log_conn_destroy(struct log_conn_context *ctx)
{
	unsigned long flags;

	if (!ctx || !g_log_ctx)
		return;

	spin_lock_irqsave(&g_log_ctx->conn_lock, flags);
	list_del(&ctx->list);
	spin_unlock_irqrestore(&g_log_ctx->conn_lock, flags);

	kfree(ctx);
}

/*
 * Buffer Management
 */
int mutex_log_get_entries(struct log_entry *entries, unsigned int max_entries,
			  unsigned int min_level, unsigned int categories)
{
	struct log_entry *entry;
	unsigned int count = 0;
	unsigned long flags;

	if (!g_log_ctx || !entries || max_entries == 0)
		return -EINVAL;

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	list_for_each_entry(entry, &g_log_ctx->buffer.entries, list) {
		if (count >= max_entries)
			break;

		/* Apply filters */
		if (entry->level < min_level)
			continue;
		if (!(entry->category & categories))
			continue;

		memcpy(&entries[count], entry, sizeof(*entry));
		count++;
	}

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	return count;
}

void mutex_log_clear_buffer(void)
{
	struct log_entry *entry, *tmp;
	unsigned long flags;

	if (!g_log_ctx)
		return;

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	list_for_each_entry_safe(entry, tmp, &g_log_ctx->buffer.entries, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	g_log_ctx->buffer.count = 0;

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);
}

unsigned int mutex_log_get_buffer_count(void)
{
	unsigned int count;
	unsigned long flags;

	if (!g_log_ctx)
		return 0;

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);
	count = g_log_ctx->buffer.count;
	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	return count;
}

/*
 * Statistics
 */
void mutex_log_get_stats(struct log_stats *stats)
{
	int i;

	if (!g_log_ctx || !stats)
		return;

	memset(stats, 0, sizeof(*stats));

	atomic64_set(&stats->total_messages,
		     atomic64_read(&g_log_ctx->stats.total_messages));

	for (i = 0; i < 5; i++) {
		atomic64_set(&stats->messages_by_level[i],
			     atomic64_read(&g_log_ctx->stats.messages_by_level[i]));
	}

	atomic64_set(&stats->messages_dropped,
		     atomic64_read(&g_log_ctx->stats.messages_dropped));
	atomic64_set(&stats->rate_limited,
		     atomic64_read(&g_log_ctx->stats.rate_limited));
	atomic64_set(&stats->buffer_full,
		     atomic64_read(&g_log_ctx->stats.buffer_full));
	atomic64_set(&stats->allocation_failures,
		     atomic64_read(&g_log_ctx->stats.allocation_failures));
}

void mutex_log_reset_stats(void)
{
	int i;

	if (!g_log_ctx)
		return;

	atomic64_set(&g_log_ctx->stats.total_messages, 0);
	for (i = 0; i < 5; i++)
		atomic64_set(&g_log_ctx->stats.messages_by_level[i], 0);
	atomic64_set(&g_log_ctx->stats.messages_dropped, 0);
	atomic64_set(&g_log_ctx->stats.rate_limited, 0);
	atomic64_set(&g_log_ctx->stats.buffer_full, 0);
	atomic64_set(&g_log_ctx->stats.allocation_failures, 0);
}

/*
 * Export to Text
 */
int mutex_log_export_text(char *buffer, size_t size)
{
	struct log_entry *entry;
	unsigned long flags;
	size_t offset = 0;
	int ret;

	if (!g_log_ctx || !buffer || size == 0)
		return -EINVAL;

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	list_for_each_entry(entry, &g_log_ctx->buffer.entries, list) {
		if (offset >= size - 256)  /* Leave room for entry */
			break;

		ret = snprintf(buffer + offset, size - offset,
			       "[%lld] [%s][%s] CPU:%d PID:%d %s%s%s\n",
			       ktime_to_ms(entry->timestamp),
			       mutex_log_level_to_string(entry->level),
			       mutex_log_category_to_string(entry->category),
			       entry->cpu, entry->pid,
			       entry->context[0] ? entry->context : "",
			       entry->context[0] ? ": " : "",
			       entry->message);

		if (ret > 0)
			offset += ret;
	}

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	return offset;
}

/*
 * Export to JSON
 */
int mutex_log_export_json(char *buffer, size_t size)
{
	struct log_entry *entry;
	unsigned long flags;
	size_t offset = 0;
	int ret;
	bool first = true;

	if (!g_log_ctx || !buffer || size == 0)
		return -EINVAL;

	offset = snprintf(buffer, size, "{\"logs\":[\n");

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	list_for_each_entry(entry, &g_log_ctx->buffer.entries, list) {
		if (offset >= size - 512)  /* Leave room for entry */
			break;

		ret = snprintf(buffer + offset, size - offset,
			       "%s{\"seq\":%lu,\"ts\":%lld,\"level\":\"%s\","
			       "\"category\":\"%s\",\"cpu\":%d,\"pid\":%d,"
			       "\"context\":\"%s\",\"message\":\"%s\"}",
			       first ? "" : ",\n",
			       entry->sequence,
			       ktime_to_ms(entry->timestamp),
			       mutex_log_level_to_string(entry->level),
			       mutex_log_category_to_string(entry->category),
			       entry->cpu, entry->pid,
			       entry->context, entry->message);

		if (ret > 0) {
			offset += ret;
			first = false;
		}
	}

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	if (offset < size - 16)
		offset += snprintf(buffer + offset, size - offset, "\n]}\n");

	return offset;
}

/*
 * Dump buffer (for debugging)
 */
void mutex_log_dump_buffer(void)
{
	struct log_entry *entry;
	unsigned long flags;
	int count = 0;

	if (!g_log_ctx)
		return;

	printk(KERN_INFO "MUTEX Log Buffer Dump:\n");

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	list_for_each_entry(entry, &g_log_ctx->buffer.entries, list) {
		printk(KERN_INFO "  [%d] [%lld] [%s][%s] %s: %s\n",
		       count++,
		       ktime_to_ms(entry->timestamp),
		       mutex_log_level_to_string(entry->level),
		       mutex_log_category_to_string(entry->category),
		       entry->context, entry->message);
	}

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	printk(KERN_INFO "Total entries: %d\n", count);
}

/*
 * Proc filesystem support
 */
static int mutex_log_proc_show(struct seq_file *m, void *v)
{
	struct log_entry *entry;
	struct log_stats stats;
	unsigned long flags;
	int i;

	if (!g_log_ctx)
		return 0;

	/* Show statistics */
	mutex_log_get_stats(&stats);

	seq_printf(m, "MUTEX Logging Statistics:\n");
	seq_printf(m, "  Total Messages: %lld\n",
		   atomic64_read(&stats.total_messages));
	seq_printf(m, "  By Level:\n");
	seq_printf(m, "    DEBUG: %lld\n",
		   atomic64_read(&stats.messages_by_level[MUTEX_LOG_DEBUG]));
	seq_printf(m, "    INFO: %lld\n",
		   atomic64_read(&stats.messages_by_level[MUTEX_LOG_INFO]));
	seq_printf(m, "    WARN: %lld\n",
		   atomic64_read(&stats.messages_by_level[MUTEX_LOG_WARN]));
	seq_printf(m, "    ERROR: %lld\n",
		   atomic64_read(&stats.messages_by_level[MUTEX_LOG_ERROR]));
	seq_printf(m, "    CRITICAL: %lld\n",
		   atomic64_read(&stats.messages_by_level[MUTEX_LOG_CRITICAL]));
	seq_printf(m, "  Messages Dropped: %lld\n",
		   atomic64_read(&stats.messages_dropped));
	seq_printf(m, "  Rate Limited: %lld\n",
		   atomic64_read(&stats.rate_limited));
	seq_printf(m, "  Buffer Full: %lld\n",
		   atomic64_read(&stats.buffer_full));
	seq_printf(m, "  Allocation Failures: %lld\n",
		   atomic64_read(&stats.allocation_failures));

	seq_printf(m, "\nConfiguration:\n");
	seq_printf(m, "  Enabled: %s\n",
		   g_log_ctx->filter.enabled ? "yes" : "no");
	seq_printf(m, "  Min Level: %s\n",
		   mutex_log_level_to_string(g_log_ctx->filter.min_level));
	seq_printf(m, "  Categories: 0x%04x\n",
		   g_log_ctx->filter.categories);
	seq_printf(m, "  Destinations: 0x%02x\n",
		   g_log_ctx->destinations);
	seq_printf(m, "  Rate Limit: %u tokens/sec (max: %u)\n",
		   g_log_ctx->rate_limiter.refill_rate,
		   g_log_ctx->rate_limiter.max_tokens);

	seq_printf(m, "\nBuffer Info:\n");
	seq_printf(m, "  Current Entries: %u\n", g_log_ctx->buffer.count);
	seq_printf(m, "  Max Entries: %u\n", g_log_ctx->buffer.max_entries);
	seq_printf(m, "  Total Entries: %lu\n", g_log_ctx->buffer.total_entries);
	seq_printf(m, "  Entries Dropped: %lu\n", g_log_ctx->buffer.entries_dropped);

	seq_printf(m, "\nRecent Log Entries:\n");
	seq_printf(m, "%-20s %-8s %-12s %-32s %s\n",
		   "Timestamp", "Level", "Category", "Context", "Message");
	seq_printf(m, "%s\n", "------------------------------------------------------------"
			      "------------------------------------------------------------");

	spin_lock_irqsave(&g_log_ctx->buffer.lock, flags);

	/* Show last 50 entries */
	i = 0;
	list_for_each_entry(entry, &g_log_ctx->buffer.entries, list) {
		if (i++ >= 50)
			break;

		seq_printf(m, "%-20lld %-8s %-12s %-32s %s\n",
			   ktime_to_ms(entry->timestamp),
			   mutex_log_level_to_string(entry->level),
			   mutex_log_category_to_string(entry->category),
			   entry->context[0] ? entry->context : "-",
			   entry->message);
	}

	spin_unlock_irqrestore(&g_log_ctx->buffer.lock, flags);

	return 0;
}

static int mutex_log_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mutex_log_proc_show, NULL);
}

static const struct proc_ops mutex_log_proc_ops = {
	.proc_open = mutex_log_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * Initialization
 */
int mutex_log_init(void)
{
	if (g_log_ctx) {
		pr_warn("MUTEX logging already initialized\n");
		return -EEXIST;
	}

	g_log_ctx = kzalloc(sizeof(*g_log_ctx), GFP_KERNEL);
	if (!g_log_ctx)
		return -ENOMEM;

	/* Initialize filter */
	g_log_ctx->filter.min_level = log_level;
	g_log_ctx->filter.categories = log_categories;
	g_log_ctx->filter.enabled = true;

	/* Initialize rate limiter */
	spin_lock_init(&g_log_ctx->rate_limiter.lock);
	g_log_ctx->rate_limiter.refill_rate = log_rate_limit;
	g_log_ctx->rate_limiter.max_tokens = log_rate_limit * 2;
	g_log_ctx->rate_limiter.tokens = g_log_ctx->rate_limiter.max_tokens;
	g_log_ctx->rate_limiter.last_refill = ktime_get();
	g_log_ctx->rate_limiter.messages_dropped = 0;

	/* Initialize buffer */
	INIT_LIST_HEAD(&g_log_ctx->buffer.entries);
	spin_lock_init(&g_log_ctx->buffer.lock);
	g_log_ctx->buffer.count = 0;
	g_log_ctx->buffer.max_entries = log_buffer_size;
	g_log_ctx->buffer.sequence = 0;
	g_log_ctx->buffer.total_entries = 0;
	g_log_ctx->buffer.entries_dropped = 0;

	/* Initialize statistics */
	memset(&g_log_ctx->stats, 0, sizeof(g_log_ctx->stats));

	/* Initialize connection contexts */
	INIT_LIST_HEAD(&g_log_ctx->conn_contexts);
	spin_lock_init(&g_log_ctx->conn_lock);

	/* Set default destinations */
	g_log_ctx->destinations = MUTEX_LOG_DEST_PRINTK | MUTEX_LOG_DEST_BUFFER;

	g_log_ctx->initialized = true;

	/* Create proc entry */
	mutex_log_proc = proc_create("mutex_log", 0444, NULL, &mutex_log_proc_ops);
	if (!mutex_log_proc)
		pr_warn("Failed to create /proc/mutex_log\n");

	pr_info("MUTEX logging framework initialized (level=%s, rate_limit=%u/s)\n",
		mutex_log_level_to_string(log_level), log_rate_limit);

	/* Log a test message */
	mutex_log_info(MUTEX_LOG_CAT_GENERAL, "init",
		       "Logging framework started successfully");

	return 0;
}

/*
 * Cleanup
 */
void mutex_log_destroy(void)
{
	struct log_conn_context *ctx, *ctx_tmp;
	unsigned long flags;

	if (!g_log_ctx)
		return;

	mutex_log_info(MUTEX_LOG_CAT_GENERAL, "cleanup",
		       "Shutting down logging framework");

	/* Remove proc entry */
	if (mutex_log_proc) {
		proc_remove(mutex_log_proc);
		mutex_log_proc = NULL;
	}

	/* Disable logging */
	g_log_ctx->initialized = false;
	g_log_ctx->filter.enabled = false;

	/* Clean up connection contexts */
	spin_lock_irqsave(&g_log_ctx->conn_lock, flags);
	list_for_each_entry_safe(ctx, ctx_tmp, &g_log_ctx->conn_contexts, list) {
		list_del(&ctx->list);
		kfree(ctx);
	}
	spin_unlock_irqrestore(&g_log_ctx->conn_lock, flags);

	/* Clear log buffer */
	mutex_log_clear_buffer();

	/* Free context */
	kfree(g_log_ctx);
	g_log_ctx = NULL;

	pr_info("MUTEX logging framework destroyed\n");
}

EXPORT_SYMBOL(mutex_log_init);
EXPORT_SYMBOL(mutex_log_destroy);
EXPORT_SYMBOL(mutex_log_message);
EXPORT_SYMBOL(mutex_log_set_level);
EXPORT_SYMBOL(mutex_log_set_categories);
EXPORT_SYMBOL(mutex_log_enable_category);
EXPORT_SYMBOL(mutex_log_disable_category);
EXPORT_SYMBOL(mutex_log_conn_create);
EXPORT_SYMBOL(mutex_log_conn_get);
EXPORT_SYMBOL(mutex_log_conn_put);
EXPORT_SYMBOL(mutex_log_conn_find);
EXPORT_SYMBOL(mutex_log_get_stats);
EXPORT_SYMBOL(mutex_log_export_text);
EXPORT_SYMBOL(mutex_log_export_json);
