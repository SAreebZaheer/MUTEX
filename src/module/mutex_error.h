/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX Error Recovery and Handling Module - Header File
 *
 * Provides robust error handling, connection recovery, automatic failover,
 * and graceful degradation for the MUTEX kernel-level proxy system.
 *
 * Features:
 * - Connection recovery with automatic retry
 * - Proxy failover with health checking
 * - Network interruption handling
 * - Packet retransmission logic
 * - State recovery after errors
 * - Memory pressure handling
 * - Graceful degradation strategies
 *
 * Copyright (C) 2025 MUTEX Team
 */

#ifndef _MUTEX_ERROR_H
#define _MUTEX_ERROR_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/workqueue.h>

/* Error Recovery Version */
#define MUTEX_ERROR_VERSION		1

/* Error Types */
#define ERROR_TYPE_CONNECTION		0x01
#define ERROR_TYPE_PROXY		0x02
#define ERROR_TYPE_NETWORK		0x04
#define ERROR_TYPE_MEMORY		0x08
#define ERROR_TYPE_TIMEOUT		0x10
#define ERROR_TYPE_PROTOCOL		0x20
#define ERROR_TYPE_CHECKSUM		0x40
#define ERROR_TYPE_STATE		0x80

/* Recovery Actions */
#define RECOVERY_ACTION_RETRY		0x01
#define RECOVERY_ACTION_FAILOVER	0x02
#define RECOVERY_ACTION_RESET		0x04
#define RECOVERY_ACTION_BYPASS		0x08
#define RECOVERY_ACTION_LOG		0x10
#define RECOVERY_ACTION_ALERT		0x20

/* Error Severity Levels */
#define ERROR_SEVERITY_LOW		1
#define ERROR_SEVERITY_MEDIUM		2
#define ERROR_SEVERITY_HIGH		3
#define ERROR_SEVERITY_CRITICAL		4

/* Recovery Strategies */
#define RECOVERY_STRATEGY_AGGRESSIVE	0x01
#define RECOVERY_STRATEGY_CONSERVATIVE	0x02
#define RECOVERY_STRATEGY_MINIMAL	0x04

/* Constants */
#define ERROR_MAX_RETRY_COUNT		3
#define ERROR_RETRY_DELAY_MS		1000
#define ERROR_BACKOFF_MULTIPLIER	2
#define ERROR_MAX_BACKOFF_MS		30000
#define ERROR_HEALTH_CHECK_INTERVAL_MS	5000
#define ERROR_MAX_ERROR_LOG		1000

/**
 * struct error_stats - Error statistics
 * @total_errors: Total errors encountered
 * @connection_errors: Connection-related errors
 * @proxy_errors: Proxy-related errors
 * @network_errors: Network errors
 * @memory_errors: Memory allocation errors
 * @timeout_errors: Timeout errors
 * @protocol_errors: Protocol errors
 * @recoveries_attempted: Recovery attempts
 * @recoveries_succeeded: Successful recoveries
 * @failovers_performed: Proxy failovers
 * @last_error_time: Timestamp of last error
 */
struct error_stats {
	atomic64_t total_errors;
	atomic64_t connection_errors;
	atomic64_t proxy_errors;
	atomic64_t network_errors;
	atomic64_t memory_errors;
	atomic64_t timeout_errors;
	atomic64_t protocol_errors;
	atomic64_t recoveries_attempted;
	atomic64_t recoveries_succeeded;
	atomic64_t failovers_performed;
	ktime_t last_error_time;
};

/**
 * struct error_record - Error event record
 * @list: List node
 * @timestamp: Error timestamp
 * @error_type: Type of error
 * @severity: Error severity level
 * @conn_id: Connection ID (if applicable)
 * @proxy_id: Proxy ID (if applicable)
 * @error_code: Specific error code
 * @message: Error description
 * @recovery_action: Action taken for recovery
 * @recovery_success: Whether recovery succeeded
 */
struct error_record {
	struct list_head list;
	ktime_t timestamp;
	u8 error_type;
	u8 severity;
	u64 conn_id;
	u32 proxy_id;
	int error_code;
	char message[256];
	u8 recovery_action;
	bool recovery_success;
};

/**
 * struct retry_context - Retry state for connection
 * @list: List node
 * @conn_id: Connection identifier
 * @retry_count: Number of retries attempted
 * @last_retry_time: Timestamp of last retry
 * @next_retry_delay: Delay before next retry (ms)
 * @max_retries: Maximum retry attempts
 * @error_type: Type of error being retried
 * @work: Delayed work for retry
 */
struct retry_context {
	struct list_head list;
	u64 conn_id;
	atomic_t retry_count;
	ktime_t last_retry_time;
	u32 next_retry_delay;
	u32 max_retries;
	u8 error_type;
	struct delayed_work work;
};

/**
 * struct proxy_health - Proxy server health status
 * @list: List node
 * @proxy_id: Proxy identifier
 * @is_healthy: Health status
 * @consecutive_failures: Consecutive failure count
 * @last_success_time: Last successful connection
 * @last_failure_time: Last failed connection
 * @failure_count: Total failure count
 * @success_count: Total success count
 * @avg_latency_ms: Average latency
 * @health_check_time: Last health check timestamp
 */
struct proxy_health {
	struct list_head list;
	u32 proxy_id;
	bool is_healthy;
	atomic_t consecutive_failures;
	ktime_t last_success_time;
	ktime_t last_failure_time;
	atomic64_t failure_count;
	atomic64_t success_count;
	u32 avg_latency_ms;
	ktime_t health_check_time;
};

/**
 * struct recovery_config - Recovery configuration
 * @retry_enabled: Enable automatic retry
 * @failover_enabled: Enable proxy failover
 * @max_retry_count: Maximum retry attempts
 * @retry_delay_ms: Initial retry delay
 * @backoff_enabled: Enable exponential backoff
 * @backoff_multiplier: Backoff multiplier
 * @max_backoff_ms: Maximum backoff delay
 * @health_check_enabled: Enable proxy health checks
 * @health_check_interval_ms: Health check interval
 * @degradation_enabled: Enable graceful degradation
 * @recovery_strategy: Recovery strategy flags
 */
struct recovery_config {
	bool retry_enabled;
	bool failover_enabled;
	u32 max_retry_count;
	u32 retry_delay_ms;
	bool backoff_enabled;
	u32 backoff_multiplier;
	u32 max_backoff_ms;
	bool health_check_enabled;
	u32 health_check_interval_ms;
	bool degradation_enabled;
	u8 recovery_strategy;
};

/**
 * struct error_recovery_ctx - Error recovery context
 * @error_stats: Error statistics
 * @error_log: List of error records
 * @retry_list: List of retry contexts
 * @health_list: List of proxy health status
 * @config: Recovery configuration
 * @error_log_lock: Error log lock
 * @retry_lock: Retry list lock
 * @health_lock: Health list lock
 * @error_log_count: Number of error records
 * @retry_count: Number of active retries
 * @health_workqueue: Workqueue for health checks
 * @health_work: Delayed work for health checks
 * @enabled: Recovery system enabled
 */
struct error_recovery_ctx {
	struct error_stats error_stats;
	struct list_head error_log;
	struct list_head retry_list;
	struct list_head health_list;
	struct recovery_config config;
	spinlock_t error_log_lock;
	spinlock_t retry_lock;
	spinlock_t health_lock;
	atomic_t error_log_count;
	atomic_t retry_count;
	struct workqueue_struct *health_workqueue;
	struct delayed_work health_work;
	bool enabled;
};

/* Error Recovery Initialization and Cleanup */
int error_recovery_init(struct error_recovery_ctx *ctx);
void error_recovery_destroy(struct error_recovery_ctx *ctx);
int error_recovery_start(struct error_recovery_ctx *ctx);
void error_recovery_stop(struct error_recovery_ctx *ctx);

/* Error Logging */
int error_log_event(struct error_recovery_ctx *ctx, u8 error_type,
		    u8 severity, u64 conn_id, u32 proxy_id,
		    int error_code, const char *message);
int error_get_recent(struct error_recovery_ctx *ctx,
		     struct error_record *records, u32 max_count);
void error_clear_log(struct error_recovery_ctx *ctx);

/* Error Statistics */
void error_stats_update(struct error_recovery_ctx *ctx, u8 error_type);
void error_stats_recovery_attempted(struct error_recovery_ctx *ctx);
void error_stats_recovery_succeeded(struct error_recovery_ctx *ctx);
void error_stats_failover_performed(struct error_recovery_ctx *ctx);
int error_stats_get_snapshot(struct error_recovery_ctx *ctx,
			      struct error_stats *snapshot);

/* Connection Recovery */
int error_retry_connection(struct error_recovery_ctx *ctx, u64 conn_id,
			    u8 error_type);
int error_cancel_retry(struct error_recovery_ctx *ctx, u64 conn_id);
bool error_should_retry(struct error_recovery_ctx *ctx, u64 conn_id,
			u8 error_type);
u32 error_get_retry_delay(struct error_recovery_ctx *ctx, u64 conn_id);

/* Proxy Failover */
int error_proxy_health_update(struct error_recovery_ctx *ctx, u32 proxy_id,
			       bool success, u32 latency_ms);
bool error_proxy_is_healthy(struct error_recovery_ctx *ctx, u32 proxy_id);
int error_select_healthy_proxy(struct error_recovery_ctx *ctx, u32 *proxy_id);
int error_perform_failover(struct error_recovery_ctx *ctx, u32 failed_proxy_id,
			    u32 *new_proxy_id);

/* Network Interruption Handling */
int error_handle_network_interruption(struct error_recovery_ctx *ctx,
				       u64 conn_id);
int error_handle_timeout(struct error_recovery_ctx *ctx, u64 conn_id);
int error_handle_connection_reset(struct error_recovery_ctx *ctx, u64 conn_id);

/* State Recovery */
int error_save_connection_state(struct error_recovery_ctx *ctx, u64 conn_id,
				void *state, size_t state_size);
int error_restore_connection_state(struct error_recovery_ctx *ctx, u64 conn_id,
				    void *state, size_t state_size);
int error_invalidate_connection_state(struct error_recovery_ctx *ctx,
				       u64 conn_id);

/* Memory Pressure Handling */
int error_handle_memory_pressure(struct error_recovery_ctx *ctx);
bool error_should_allocate(struct error_recovery_ctx *ctx, size_t size);
int error_emergency_free_memory(struct error_recovery_ctx *ctx);

/* Graceful Degradation */
int error_enter_degraded_mode(struct error_recovery_ctx *ctx, u8 reason);
int error_exit_degraded_mode(struct error_recovery_ctx *ctx);
bool error_is_degraded_mode(struct error_recovery_ctx *ctx);
int error_get_degradation_level(struct error_recovery_ctx *ctx);

/* Recovery Actions */
int error_execute_recovery_action(struct error_recovery_ctx *ctx,
				   u8 error_type, u64 conn_id,
				   u8 recovery_action);
u8 error_determine_recovery_action(struct error_recovery_ctx *ctx,
				    u8 error_type, u8 severity);

/* Configuration */
int error_config_set(struct error_recovery_ctx *ctx,
		     struct recovery_config *config);
int error_config_get(struct error_recovery_ctx *ctx,
		     struct recovery_config *config);
int error_config_update_retry(struct error_recovery_ctx *ctx, bool enabled,
			       u32 max_retries);
int error_config_update_failover(struct error_recovery_ctx *ctx, bool enabled);

/* Helper Functions */
const char *error_type_to_string(u8 error_type);
const char *error_severity_to_string(u8 severity);
bool error_is_recoverable(u8 error_type, int error_code);
u8 error_classify_error(int error_code);

#endif /* _MUTEX_ERROR_H */
