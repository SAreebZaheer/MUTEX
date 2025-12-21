// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX Error Recovery and Handling Module - Implementation
 *
 * Provides robust error handling and recovery mechanisms.
 *
 * Copyright (C) 2025 MUTEX Team
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "mutex_error.h"

/* Static helper function declarations */
static void health_check_worker(struct work_struct *work);
static void retry_worker(struct work_struct *work);
static void cleanup_old_errors(struct error_recovery_ctx *ctx);

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

/**
 * error_recovery_init - Initialize error recovery context
 * @ctx: Error recovery context
 *
 * Return: 0 on success, negative error code on failure
 */
int error_recovery_init(struct error_recovery_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	/* Initialize statistics */
	atomic64_set(&ctx->error_stats.total_errors, 0);
	atomic64_set(&ctx->error_stats.connection_errors, 0);
	atomic64_set(&ctx->error_stats.proxy_errors, 0);
	atomic64_set(&ctx->error_stats.network_errors, 0);
	atomic64_set(&ctx->error_stats.memory_errors, 0);
	atomic64_set(&ctx->error_stats.timeout_errors, 0);
	atomic64_set(&ctx->error_stats.protocol_errors, 0);
	atomic64_set(&ctx->error_stats.recoveries_attempted, 0);
	atomic64_set(&ctx->error_stats.recoveries_succeeded, 0);
	atomic64_set(&ctx->error_stats.failovers_performed, 0);
	ctx->error_stats.last_error_time = ktime_get();

	/* Initialize lists */
	INIT_LIST_HEAD(&ctx->error_log);
	INIT_LIST_HEAD(&ctx->retry_list);
	INIT_LIST_HEAD(&ctx->health_list);

	/* Initialize locks */
	spin_lock_init(&ctx->error_log_lock);
	spin_lock_init(&ctx->retry_lock);
	spin_lock_init(&ctx->health_lock);

	/* Initialize counters */
	atomic_set(&ctx->error_log_count, 0);
	atomic_set(&ctx->retry_count, 0);

	/* Set default configuration */
	ctx->config.retry_enabled = true;
	ctx->config.failover_enabled = true;
	ctx->config.max_retry_count = ERROR_MAX_RETRY_COUNT;
	ctx->config.retry_delay_ms = ERROR_RETRY_DELAY_MS;
	ctx->config.backoff_enabled = true;
	ctx->config.backoff_multiplier = ERROR_BACKOFF_MULTIPLIER;
	ctx->config.max_backoff_ms = ERROR_MAX_BACKOFF_MS;
	ctx->config.health_check_enabled = true;
	ctx->config.health_check_interval_ms = ERROR_HEALTH_CHECK_INTERVAL_MS;
	ctx->config.degradation_enabled = true;
	ctx->config.recovery_strategy = RECOVERY_STRATEGY_CONSERVATIVE;

	/* Create workqueue for health checks */
	ctx->health_workqueue = alloc_workqueue("mutex_health_wq",
						WQ_UNBOUND, 0);
	if (!ctx->health_workqueue) {
		pr_err("Failed to create health check workqueue\n");
		return -ENOMEM;
	}

	ctx->enabled = false;

	pr_info("Error recovery initialized\n");
	return 0;
}

/**
 * error_recovery_destroy - Destroy error recovery context
 * @ctx: Error recovery context
 */
void error_recovery_destroy(struct error_recovery_ctx *ctx)
{
	struct error_record *error, *tmp_error;
	struct retry_context *retry, *tmp_retry;
	struct proxy_health *health, *tmp_health;

	if (!ctx)
		return;

	/* Stop recovery first */
	error_recovery_stop(ctx);

	/* Destroy workqueue */
	if (ctx->health_workqueue) {
		destroy_workqueue(ctx->health_workqueue);
		ctx->health_workqueue = NULL;
	}

	/* Free error log */
	spin_lock(&ctx->error_log_lock);
	list_for_each_entry_safe(error, tmp_error, &ctx->error_log, list) {
		list_del(&error->list);
		kfree(error);
	}
	spin_unlock(&ctx->error_log_lock);

	/* Free retry contexts */
	spin_lock(&ctx->retry_lock);
	list_for_each_entry_safe(retry, tmp_retry, &ctx->retry_list, list) {
		cancel_delayed_work_sync(&retry->work);
		list_del(&retry->list);
		kfree(retry);
	}
	spin_unlock(&ctx->retry_lock);

	/* Free health records */
	spin_lock(&ctx->health_lock);
	list_for_each_entry_safe(health, tmp_health, &ctx->health_list, list) {
		list_del(&health->list);
		kfree(health);
	}
	spin_unlock(&ctx->health_lock);

	pr_info("Error recovery destroyed\n");
}

/**
 * error_recovery_start - Start error recovery system
 * @ctx: Error recovery context
 *
 * Return: 0 on success, negative error code on failure
 */
int error_recovery_start(struct error_recovery_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->enabled)
		return 0;

	/* Initialize health check work */
	if (ctx->config.health_check_enabled) {
		INIT_DELAYED_WORK(&ctx->health_work, health_check_worker);
		queue_delayed_work(ctx->health_workqueue, &ctx->health_work,
				   msecs_to_jiffies(ctx->config.health_check_interval_ms));
	}

	ctx->enabled = true;
	pr_info("Error recovery started\n");
	return 0;
}

/**
 * error_recovery_stop - Stop error recovery system
 * @ctx: Error recovery context
 */
void error_recovery_stop(struct error_recovery_ctx *ctx)
{
	if (!ctx || !ctx->enabled)
		return;

	ctx->enabled = false;

	/* Cancel health check work */
	if (ctx->config.health_check_enabled)
		cancel_delayed_work_sync(&ctx->health_work);

	pr_info("Error recovery stopped\n");
}

/* ============================================================================
 * Error Logging
 * ============================================================================ */

/**
 * error_log_event - Log an error event
 * @ctx: Error recovery context
 * @error_type: Type of error
 * @severity: Error severity
 * @conn_id: Connection ID
 * @proxy_id: Proxy ID
 * @error_code: Error code
 * @message: Error message
 *
 * Return: 0 on success, negative error code on failure
 */
int error_log_event(struct error_recovery_ctx *ctx, u8 error_type,
		    u8 severity, u64 conn_id, u32 proxy_id,
		    int error_code, const char *message)
{
	struct error_record *record;

	if (!ctx || !message)
		return -EINVAL;

	/* Check if log is full */
	if (atomic_read(&ctx->error_log_count) >= ERROR_MAX_ERROR_LOG) {
		cleanup_old_errors(ctx);
	}

	record = kzalloc(sizeof(*record), GFP_ATOMIC);
	if (!record)
		return -ENOMEM;

	record->timestamp = ktime_get();
	record->error_type = error_type;
	record->severity = severity;
	record->conn_id = conn_id;
	record->proxy_id = proxy_id;
	record->error_code = error_code;
	strncpy(record->message, message, sizeof(record->message) - 1);
	record->recovery_action = 0;
	record->recovery_success = false;

	spin_lock(&ctx->error_log_lock);
	list_add_tail(&record->list, &ctx->error_log);
	atomic_inc(&ctx->error_log_count);
	spin_unlock(&ctx->error_log_lock);

	/* Update statistics */
	error_stats_update(ctx, error_type);
	ctx->error_stats.last_error_time = record->timestamp;

	pr_debug("Error logged: type=%u severity=%u code=%d msg='%s'\n",
		 error_type, severity, error_code, message);

	return 0;
}

/**
 * error_get_recent - Get recent error records
 * @ctx: Error recovery context
 * @records: Buffer for error records
 * @max_count: Maximum records to retrieve
 *
 * Return: Number of records retrieved, negative on error
 */
int error_get_recent(struct error_recovery_ctx *ctx,
		     struct error_record *records, u32 max_count)
{
	struct error_record *error;
	u32 count = 0;

	if (!ctx || !records || max_count == 0)
		return -EINVAL;

	spin_lock(&ctx->error_log_lock);
	list_for_each_entry_reverse(error, &ctx->error_log, list) {
		if (count >= max_count)
			break;
		memcpy(&records[count], error, sizeof(*error));
		count++;
	}
	spin_unlock(&ctx->error_log_lock);

	return count;
}

/**
 * error_clear_log - Clear error log
 * @ctx: Error recovery context
 */
void error_clear_log(struct error_recovery_ctx *ctx)
{
	struct error_record *error, *tmp;

	if (!ctx)
		return;

	spin_lock(&ctx->error_log_lock);
	list_for_each_entry_safe(error, tmp, &ctx->error_log, list) {
		list_del(&error->list);
		kfree(error);
	}
	atomic_set(&ctx->error_log_count, 0);
	spin_unlock(&ctx->error_log_lock);

	pr_debug("Error log cleared\n");
}

/* ============================================================================
 * Error Statistics
 * ============================================================================ */

/**
 * error_stats_update - Update error statistics
 * @ctx: Error recovery context
 * @error_type: Type of error
 */
void error_stats_update(struct error_recovery_ctx *ctx, u8 error_type)
{
	if (!ctx)
		return;

	atomic64_inc(&ctx->error_stats.total_errors);

	switch (error_type) {
	case ERROR_TYPE_CONNECTION:
		atomic64_inc(&ctx->error_stats.connection_errors);
		break;
	case ERROR_TYPE_PROXY:
		atomic64_inc(&ctx->error_stats.proxy_errors);
		break;
	case ERROR_TYPE_NETWORK:
		atomic64_inc(&ctx->error_stats.network_errors);
		break;
	case ERROR_TYPE_MEMORY:
		atomic64_inc(&ctx->error_stats.memory_errors);
		break;
	case ERROR_TYPE_TIMEOUT:
		atomic64_inc(&ctx->error_stats.timeout_errors);
		break;
	case ERROR_TYPE_PROTOCOL:
		atomic64_inc(&ctx->error_stats.protocol_errors);
		break;
	}
}

/**
 * error_stats_recovery_attempted - Increment recovery attempt counter
 * @ctx: Error recovery context
 */
void error_stats_recovery_attempted(struct error_recovery_ctx *ctx)
{
	if (ctx)
		atomic64_inc(&ctx->error_stats.recoveries_attempted);
}

/**
 * error_stats_recovery_succeeded - Increment recovery success counter
 * @ctx: Error recovery context
 */
void error_stats_recovery_succeeded(struct error_recovery_ctx *ctx)
{
	if (ctx)
		atomic64_inc(&ctx->error_stats.recoveries_succeeded);
}

/**
 * error_stats_failover_performed - Increment failover counter
 * @ctx: Error recovery context
 */
void error_stats_failover_performed(struct error_recovery_ctx *ctx)
{
	if (ctx)
		atomic64_inc(&ctx->error_stats.failovers_performed);
}

/**
 * error_stats_get_snapshot - Get error statistics snapshot
 * @ctx: Error recovery context
 * @snapshot: Statistics snapshot structure
 *
 * Return: 0 on success, negative error code on failure
 */
int error_stats_get_snapshot(struct error_recovery_ctx *ctx,
			      struct error_stats *snapshot)
{
	if (!ctx || !snapshot)
		return -EINVAL;

	memcpy(snapshot, &ctx->error_stats, sizeof(*snapshot));
	return 0;
}

/* ============================================================================
 * Connection Recovery
 * ============================================================================ */

/**
 * error_retry_connection - Retry a failed connection
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 * @error_type: Type of error
 *
 * Return: 0 on success, negative error code on failure
 */
int error_retry_connection(struct error_recovery_ctx *ctx, u64 conn_id,
			    u8 error_type)
{
	struct retry_context *retry_ctx;

	if (!ctx || !ctx->config.retry_enabled)
		return -EINVAL;

	retry_ctx = kzalloc(sizeof(*retry_ctx), GFP_KERNEL);
	if (!retry_ctx)
		return -ENOMEM;

	retry_ctx->conn_id = conn_id;
	atomic_set(&retry_ctx->retry_count, 0);
	retry_ctx->last_retry_time = ktime_get();
	retry_ctx->next_retry_delay = ctx->config.retry_delay_ms;
	retry_ctx->max_retries = ctx->config.max_retry_count;
	retry_ctx->error_type = error_type;

	INIT_DELAYED_WORK(&retry_ctx->work, retry_worker);

	spin_lock(&ctx->retry_lock);
	list_add(&retry_ctx->list, &ctx->retry_list);
	atomic_inc(&ctx->retry_count);
	spin_unlock(&ctx->retry_lock);

	/* Schedule retry */
	queue_delayed_work(ctx->health_workqueue, &retry_ctx->work,
			   msecs_to_jiffies(retry_ctx->next_retry_delay));

	error_stats_recovery_attempted(ctx);

	pr_debug("Connection retry scheduled: conn_id=%llu delay=%u ms\n",
		 conn_id, retry_ctx->next_retry_delay);

	return 0;
}

/**
 * error_cancel_retry - Cancel retry for a connection
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_cancel_retry(struct error_recovery_ctx *ctx, u64 conn_id)
{
	struct retry_context *retry, *tmp;
	int found = 0;

	if (!ctx)
		return -EINVAL;

	spin_lock(&ctx->retry_lock);
	list_for_each_entry_safe(retry, tmp, &ctx->retry_list, list) {
		if (retry->conn_id == conn_id) {
			cancel_delayed_work_sync(&retry->work);
			list_del(&retry->list);
			atomic_dec(&ctx->retry_count);
			kfree(retry);
			found = 1;
			break;
		}
	}
	spin_unlock(&ctx->retry_lock);

	return found ? 0 : -ENOENT;
}

/**
 * error_should_retry - Check if connection should be retried
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 * @error_type: Type of error
 *
 * Return: true if should retry, false otherwise
 */
bool error_should_retry(struct error_recovery_ctx *ctx, u64 conn_id,
			u8 error_type)
{
	struct retry_context *retry;
	bool should_retry = false;

	if (!ctx || !ctx->config.retry_enabled)
		return false;

	spin_lock(&ctx->retry_lock);
	list_for_each_entry(retry, &ctx->retry_list, list) {
		if (retry->conn_id == conn_id) {
			should_retry = atomic_read(&retry->retry_count) <
				       retry->max_retries;
			break;
		}
	}
	spin_unlock(&ctx->retry_lock);

	return should_retry;
}

/**
 * error_get_retry_delay - Get retry delay for connection
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 *
 * Return: Retry delay in milliseconds
 */
u32 error_get_retry_delay(struct error_recovery_ctx *ctx, u64 conn_id)
{
	struct retry_context *retry;
	u32 delay = 0;

	if (!ctx)
		return 0;

	spin_lock(&ctx->retry_lock);
	list_for_each_entry(retry, &ctx->retry_list, list) {
		if (retry->conn_id == conn_id) {
			delay = retry->next_retry_delay;
			break;
		}
	}
	spin_unlock(&ctx->retry_lock);

	return delay;
}

/* ============================================================================
 * Proxy Failover
 * ============================================================================ */

/**
 * error_proxy_health_update - Update proxy health status
 * @ctx: Error recovery context
 * @proxy_id: Proxy identifier
 * @success: Whether operation succeeded
 * @latency_ms: Operation latency
 *
 * Return: 0 on success, negative error code on failure
 */
int error_proxy_health_update(struct error_recovery_ctx *ctx, u32 proxy_id,
			       bool success, u32 latency_ms)
{
	struct proxy_health *health;
	bool found = false;

	if (!ctx)
		return -EINVAL;

	spin_lock(&ctx->health_lock);

	/* Find or create health record */
	list_for_each_entry(health, &ctx->health_list, list) {
		if (health->proxy_id == proxy_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		health = kzalloc(sizeof(*health), GFP_ATOMIC);
		if (!health) {
			spin_unlock(&ctx->health_lock);
			return -ENOMEM;
		}
		health->proxy_id = proxy_id;
		health->is_healthy = true;
		atomic_set(&health->consecutive_failures, 0);
		atomic64_set(&health->failure_count, 0);
		atomic64_set(&health->success_count, 0);
		list_add(&health->list, &ctx->health_list);
	}

	/* Update health record */
	if (success) {
		health->last_success_time = ktime_get();
		atomic64_inc(&health->success_count);
		atomic_set(&health->consecutive_failures, 0);
		health->is_healthy = true;

		/* Update average latency */
		if (health->avg_latency_ms == 0)
			health->avg_latency_ms = latency_ms;
		else
			health->avg_latency_ms =
				(health->avg_latency_ms + latency_ms) / 2;
	} else {
		health->last_failure_time = ktime_get();
		atomic64_inc(&health->failure_count);
		atomic_inc(&health->consecutive_failures);

		/* Mark unhealthy after 3 consecutive failures */
		if (atomic_read(&health->consecutive_failures) >= 3)
			health->is_healthy = false;
	}

	health->health_check_time = ktime_get();

	spin_unlock(&ctx->health_lock);

	return 0;
}

/**
 * error_proxy_is_healthy - Check if proxy is healthy
 * @ctx: Error recovery context
 * @proxy_id: Proxy identifier
 *
 * Return: true if healthy, false otherwise
 */
bool error_proxy_is_healthy(struct error_recovery_ctx *ctx, u32 proxy_id)
{
	struct proxy_health *health;
	bool is_healthy = true; /* Assume healthy if no record */

	if (!ctx)
		return false;

	spin_lock(&ctx->health_lock);
	list_for_each_entry(health, &ctx->health_list, list) {
		if (health->proxy_id == proxy_id) {
			is_healthy = health->is_healthy;
			break;
		}
	}
	spin_unlock(&ctx->health_lock);

	return is_healthy;
}

/**
 * error_select_healthy_proxy - Select a healthy proxy
 * @ctx: Error recovery context
 * @proxy_id: Pointer to store selected proxy ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_select_healthy_proxy(struct error_recovery_ctx *ctx, u32 *proxy_id)
{
	struct proxy_health *health, *best = NULL;
	u32 best_latency = U32_MAX;

	if (!ctx || !proxy_id)
		return -EINVAL;

	spin_lock(&ctx->health_lock);

	/* Find healthy proxy with best latency */
	list_for_each_entry(health, &ctx->health_list, list) {
		if (health->is_healthy && health->avg_latency_ms < best_latency) {
			best = health;
			best_latency = health->avg_latency_ms;
		}
	}

	if (best) {
		*proxy_id = best->proxy_id;
		spin_unlock(&ctx->health_lock);
		return 0;
	}

	spin_unlock(&ctx->health_lock);
	return -ENOENT;
}

/**
 * error_perform_failover - Perform proxy failover
 * @ctx: Error recovery context
 * @failed_proxy_id: Failed proxy ID
 * @new_proxy_id: Pointer to store new proxy ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_perform_failover(struct error_recovery_ctx *ctx, u32 failed_proxy_id,
			    u32 *new_proxy_id)
{
	int ret;

	if (!ctx || !ctx->config.failover_enabled || !new_proxy_id)
		return -EINVAL;

	/* Mark failed proxy as unhealthy */
	error_proxy_health_update(ctx, failed_proxy_id, false, 0);

	/* Select healthy proxy */
	ret = error_select_healthy_proxy(ctx, new_proxy_id);
	if (ret < 0) {
		pr_err("No healthy proxy available for failover\n");
		return ret;
	}

	error_stats_failover_performed(ctx);

	pr_info("Proxy failover: %u -> %u\n", failed_proxy_id, *new_proxy_id);

	return 0;
}

/* ============================================================================
 * Network Interruption Handling
 * ============================================================================ */

/**
 * error_handle_network_interruption - Handle network interruption
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_handle_network_interruption(struct error_recovery_ctx *ctx,
				       u64 conn_id)
{
	if (!ctx)
		return -EINVAL;

	error_log_event(ctx, ERROR_TYPE_NETWORK, ERROR_SEVERITY_HIGH,
			conn_id, 0, -ENETUNREACH, "Network interruption");

	/* Attempt retry if enabled */
	if (ctx->config.retry_enabled)
		return error_retry_connection(ctx, conn_id, ERROR_TYPE_NETWORK);

	return 0;
}

/**
 * error_handle_timeout - Handle connection timeout
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_handle_timeout(struct error_recovery_ctx *ctx, u64 conn_id)
{
	if (!ctx)
		return -EINVAL;

	error_log_event(ctx, ERROR_TYPE_TIMEOUT, ERROR_SEVERITY_MEDIUM,
			conn_id, 0, -ETIMEDOUT, "Connection timeout");

	/* Attempt retry if enabled */
	if (ctx->config.retry_enabled)
		return error_retry_connection(ctx, conn_id, ERROR_TYPE_TIMEOUT);

	return 0;
}

/**
 * error_handle_connection_reset - Handle connection reset
 * @ctx: Error recovery context
 * @conn_id: Connection ID
 *
 * Return: 0 on success, negative error code on failure
 */
int error_handle_connection_reset(struct error_recovery_ctx *ctx, u64 conn_id)
{
	if (!ctx)
		return -EINVAL;

	error_log_event(ctx, ERROR_TYPE_CONNECTION, ERROR_SEVERITY_HIGH,
			conn_id, 0, -ECONNRESET, "Connection reset");

	/* Attempt retry if enabled */
	if (ctx->config.retry_enabled)
		return error_retry_connection(ctx, conn_id,
					      ERROR_TYPE_CONNECTION);

	return 0;
}

/* ============================================================================
 * State Recovery (Stubs)
 * ============================================================================ */

int error_save_connection_state(struct error_recovery_ctx *ctx, u64 conn_id,
				void *state, size_t state_size)
{
	/* Stub implementation */
	return 0;
}

int error_restore_connection_state(struct error_recovery_ctx *ctx, u64 conn_id,
				    void *state, size_t state_size)
{
	/* Stub implementation */
	return 0;
}

int error_invalidate_connection_state(struct error_recovery_ctx *ctx,
				       u64 conn_id)
{
	/* Stub implementation */
	return 0;
}

/* ============================================================================
 * Memory Pressure Handling
 * ============================================================================ */

int error_handle_memory_pressure(struct error_recovery_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	error_log_event(ctx, ERROR_TYPE_MEMORY, ERROR_SEVERITY_CRITICAL,
			0, 0, -ENOMEM, "Memory pressure detected");

	/* Cleanup old errors */
	cleanup_old_errors(ctx);

	return 0;
}

bool error_should_allocate(struct error_recovery_ctx *ctx, size_t size)
{
	/* Simple heuristic: allow if size is reasonable */
	return size < (1024 * 1024); /* 1 MB limit */
}

int error_emergency_free_memory(struct error_recovery_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	/* Clear error log to free memory */
	error_clear_log(ctx);

	return 0;
}

/* ============================================================================
 * Graceful Degradation (Stubs)
 * ============================================================================ */

int error_enter_degraded_mode(struct error_recovery_ctx *ctx, u8 reason)
{
	/* Stub implementation */
	if (!ctx)
		return -EINVAL;

	pr_warn("Entering degraded mode: reason=%u\n", reason);
	return 0;
}

int error_exit_degraded_mode(struct error_recovery_ctx *ctx)
{
	/* Stub implementation */
	if (!ctx)
		return -EINVAL;

	pr_info("Exiting degraded mode\n");
	return 0;
}

bool error_is_degraded_mode(struct error_recovery_ctx *ctx)
{
	/* Stub implementation */
	return false;
}

int error_get_degradation_level(struct error_recovery_ctx *ctx)
{
	/* Stub implementation */
	return 0;
}

/* ============================================================================
 * Recovery Actions
 * ============================================================================ */

int error_execute_recovery_action(struct error_recovery_ctx *ctx,
				   u8 error_type, u64 conn_id,
				   u8 recovery_action)
{
	if (!ctx)
		return -EINVAL;

	switch (recovery_action) {
	case RECOVERY_ACTION_RETRY:
		return error_retry_connection(ctx, conn_id, error_type);
	case RECOVERY_ACTION_FAILOVER:
		/* Failover logic handled elsewhere */
		return 0;
	case RECOVERY_ACTION_RESET:
		/* Reset connection state */
		return 0;
	case RECOVERY_ACTION_BYPASS:
		/* Bypass proxy */
		return 0;
	default:
		return -EINVAL;
	}
}

u8 error_determine_recovery_action(struct error_recovery_ctx *ctx,
				    u8 error_type, u8 severity)
{
	if (!ctx)
		return 0;

	/* Determine action based on error type and severity */
	if (severity >= ERROR_SEVERITY_CRITICAL)
		return RECOVERY_ACTION_FAILOVER;

	switch (error_type) {
	case ERROR_TYPE_CONNECTION:
	case ERROR_TYPE_NETWORK:
	case ERROR_TYPE_TIMEOUT:
		return RECOVERY_ACTION_RETRY;
	case ERROR_TYPE_PROXY:
		return RECOVERY_ACTION_FAILOVER;
	default:
		return RECOVERY_ACTION_LOG;
	}
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

int error_config_set(struct error_recovery_ctx *ctx,
		     struct recovery_config *config)
{
	if (!ctx || !config)
		return -EINVAL;

	memcpy(&ctx->config, config, sizeof(*config));
	pr_info("Error recovery configuration updated\n");
	return 0;
}

int error_config_get(struct error_recovery_ctx *ctx,
		     struct recovery_config *config)
{
	if (!ctx || !config)
		return -EINVAL;

	memcpy(config, &ctx->config, sizeof(*config));
	return 0;
}

int error_config_update_retry(struct error_recovery_ctx *ctx, bool enabled,
			       u32 max_retries)
{
	if (!ctx)
		return -EINVAL;

	ctx->config.retry_enabled = enabled;
	ctx->config.max_retry_count = max_retries;
	return 0;
}

int error_config_update_failover(struct error_recovery_ctx *ctx, bool enabled)
{
	if (!ctx)
		return -EINVAL;

	ctx->config.failover_enabled = enabled;
	return 0;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

const char *error_type_to_string(u8 error_type)
{
	switch (error_type) {
	case ERROR_TYPE_CONNECTION:
		return "CONNECTION";
	case ERROR_TYPE_PROXY:
		return "PROXY";
	case ERROR_TYPE_NETWORK:
		return "NETWORK";
	case ERROR_TYPE_MEMORY:
		return "MEMORY";
	case ERROR_TYPE_TIMEOUT:
		return "TIMEOUT";
	case ERROR_TYPE_PROTOCOL:
		return "PROTOCOL";
	case ERROR_TYPE_CHECKSUM:
		return "CHECKSUM";
	case ERROR_TYPE_STATE:
		return "STATE";
	default:
		return "UNKNOWN";
	}
}

const char *error_severity_to_string(u8 severity)
{
	switch (severity) {
	case ERROR_SEVERITY_LOW:
		return "LOW";
	case ERROR_SEVERITY_MEDIUM:
		return "MEDIUM";
	case ERROR_SEVERITY_HIGH:
		return "HIGH";
	case ERROR_SEVERITY_CRITICAL:
		return "CRITICAL";
	default:
		return "UNKNOWN";
	}
}

bool error_is_recoverable(u8 error_type, int error_code)
{
	/* Determine if error is recoverable */
	switch (error_type) {
	case ERROR_TYPE_CONNECTION:
	case ERROR_TYPE_NETWORK:
	case ERROR_TYPE_TIMEOUT:
		return true;
	case ERROR_TYPE_MEMORY:
	case ERROR_TYPE_STATE:
		return false;
	default:
		return true;
	}
}

u8 error_classify_error(int error_code)
{
	/* Classify error based on error code */
	switch (error_code) {
	case -ECONNREFUSED:
	case -ECONNRESET:
	case -ECONNABORTED:
		return ERROR_TYPE_CONNECTION;
	case -ENETUNREACH:
	case -EHOSTUNREACH:
		return ERROR_TYPE_NETWORK;
	case -ETIMEDOUT:
		return ERROR_TYPE_TIMEOUT;
	case -ENOMEM:
		return ERROR_TYPE_MEMORY;
	case -EPROTO:
	case -EBADMSG:
		return ERROR_TYPE_PROTOCOL;
	default:
		return ERROR_TYPE_CONNECTION;
	}
}

/* ============================================================================
 * Worker Functions
 * ============================================================================ */

static void health_check_worker(struct work_struct *work)
{
	struct error_recovery_ctx *ctx;

	ctx = container_of(work, struct error_recovery_ctx, health_work.work);

	/* Perform health checks on proxies */
	/* This is a placeholder for actual health check logic */

	/* Reschedule if still enabled */
	if (ctx->enabled && ctx->config.health_check_enabled) {
		queue_delayed_work(ctx->health_workqueue, &ctx->health_work,
				   msecs_to_jiffies(ctx->config.health_check_interval_ms));
	}
}

static void retry_worker(struct work_struct *work)
{
	struct retry_context *retry_ctx;
	struct delayed_work *dwork;

	dwork = container_of(work, struct delayed_work, work);
	retry_ctx = container_of(dwork, struct retry_context, work);

	/* Increment retry count */
	atomic_inc(&retry_ctx->retry_count);

	/* Attempt reconnection */
	/* This is a placeholder for actual retry logic */

	pr_debug("Retry attempt: conn_id=%llu retry=%d\n",
		 retry_ctx->conn_id, atomic_read(&retry_ctx->retry_count));

	/* Calculate next delay with exponential backoff */
	if (atomic_read(&retry_ctx->retry_count) < retry_ctx->max_retries) {
		retry_ctx->next_retry_delay *= ERROR_BACKOFF_MULTIPLIER;
		if (retry_ctx->next_retry_delay > ERROR_MAX_BACKOFF_MS)
			retry_ctx->next_retry_delay = ERROR_MAX_BACKOFF_MS;

		/* Schedule next retry */
		retry_ctx->last_retry_time = ktime_get();
		queue_delayed_work(system_wq, &retry_ctx->work,
				   msecs_to_jiffies(retry_ctx->next_retry_delay));
	}
}

static void cleanup_old_errors(struct error_recovery_ctx *ctx)
{
	struct error_record *error, *tmp;
	int removed = 0;
	int target = ERROR_MAX_ERROR_LOG / 2;

	spin_lock(&ctx->error_log_lock);

	/* Remove oldest half of errors */
	list_for_each_entry_safe(error, tmp, &ctx->error_log, list) {
		if (removed >= target)
			break;
		list_del(&error->list);
		kfree(error);
		atomic_dec(&ctx->error_log_count);
		removed++;
	}

	spin_unlock(&ctx->error_log_lock);

	pr_debug("Cleaned up %d old error records\n", removed);
}
