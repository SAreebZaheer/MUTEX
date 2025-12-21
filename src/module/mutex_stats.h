/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX Statistics and Monitoring Module - Header File
 *
 * Provides comprehensive statistics collection and monitoring for kernel-level
 * proxy operations with per-connection, per-fd, and global metrics.
 *
 * Features:
 * - Per-connection statistics tracked by owning fd
 * - Per-fd aggregate statistics (bandwidth, packet counts, latency)
 * - Global system-wide statistics
 * - Real-time monitoring with poll/select support
 * - Statistics export via read/ioctl operations
 * - JSON-formatted output for dashboards
 * - Anomaly detection and alerts
 * - Statistics persistence across fd lifecycle
 * - Multi-fd aggregation support
 *
 * Copyright (C) 2025 MUTEX Team
 */

#ifndef _MUTEX_STATS_H
#define _MUTEX_STATS_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/in6.h>

/* Statistics Version */
#define MUTEX_STATS_VERSION		1

/* Statistics Flags */
#define STATS_FLAG_ACTIVE		0x01
#define STATS_FLAG_ANOMALY		0x02
#define STATS_FLAG_THRESHOLD_EXCEEDED	0x04
#define STATS_FLAG_PERSISTENT		0x08

/* Alert Types */
#define ALERT_TYPE_HIGH_LATENCY		0x01
#define ALERT_TYPE_HIGH_ERROR_RATE	0x02
#define ALERT_TYPE_BANDWIDTH_SPIKE	0x04
#define ALERT_TYPE_CONNECTION_FLOOD	0x08
#define ALERT_TYPE_PACKET_DROP		0x10

/* Statistics Export Formats */
#define STATS_FORMAT_JSON		0
#define STATS_FORMAT_BINARY		1
#define STATS_FORMAT_CSV		2

/* Thresholds */
#define STATS_HIGH_LATENCY_THRESHOLD_MS	500
#define STATS_HIGH_ERROR_RATE_THRESHOLD	10	/* percent */
#define STATS_MAX_ALERTS		1000

/**
 * struct connection_stats - Per-connection statistics
 * @list: List node for tracking
 * @conn_id: Connection identifier
 * @start_time: Connection start timestamp
 * @last_activity: Last activity timestamp
 * @bytes_sent: Total bytes sent
 * @bytes_received: Total bytes received
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @retransmits: Number of retransmissions
 * @errors: Number of errors
 * @avg_latency_us: Average latency in microseconds
 * @min_latency_us: Minimum latency
 * @max_latency_us: Maximum latency
 * @state: Connection state
 * @flags: Connection flags
 */
struct connection_stats {
	struct list_head list;
	u64 conn_id;
	ktime_t start_time;
	ktime_t last_activity;
	atomic64_t bytes_sent;
	atomic64_t bytes_received;
	atomic64_t packets_sent;
	atomic64_t packets_received;
	atomic_t retransmits;
	atomic_t errors;
	u32 avg_latency_us;
	u32 min_latency_us;
	u32 max_latency_us;
	u8 state;
	u32 flags;
};

/**
 * struct fd_stats - Per-fd aggregate statistics
 * @connections: List of active connections
 * @conn_count: Number of active connections
 * @total_connections: Total connections created
 * @bytes_sent: Total bytes sent across all connections
 * @bytes_received: Total bytes received across all connections
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @packets_dropped: Total packets dropped
 * @errors: Total errors
 * @retransmits: Total retransmissions
 * @avg_latency_us: Average latency across all connections
 * @peak_bandwidth_sent: Peak outbound bandwidth (bytes/sec)
 * @peak_bandwidth_recv: Peak inbound bandwidth (bytes/sec)
 * @uptime_ms: FD uptime in milliseconds
 * @last_update: Last statistics update timestamp
 * @lock: Statistics lock
 * @flags: Statistics flags
 */
struct fd_stats {
	struct list_head connections;
	atomic_t conn_count;
	atomic64_t total_connections;
	atomic64_t bytes_sent;
	atomic64_t bytes_received;
	atomic64_t packets_sent;
	atomic64_t packets_received;
	atomic64_t packets_dropped;
	atomic64_t errors;
	atomic64_t retransmits;
	atomic_t avg_latency_us;
	atomic64_t peak_bandwidth_sent;
	atomic64_t peak_bandwidth_recv;
	u64 uptime_ms;
	ktime_t last_update;
	spinlock_t lock;
	u32 flags;
};

/**
 * struct global_stats - Global system-wide statistics
 * @total_fds: Total file descriptors created
 * @active_fds: Currently active file descriptors
 * @total_connections: Total connections across all fds
 * @active_connections: Currently active connections
 * @bytes_sent: Total bytes sent system-wide
 * @bytes_received: Total bytes received system-wide
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @packets_dropped: Total packets dropped
 * @errors: Total errors
 * @retransmits: Total retransmissions
 * @cache_hits: Total cache hits (DNS, routing, etc.)
 * @cache_misses: Total cache misses
 * @avg_latency_us: System-wide average latency
 * @uptime_ms: System uptime in milliseconds
 * @last_update: Last update timestamp
 */
struct global_stats {
	atomic64_t total_fds;
	atomic_t active_fds;
	atomic64_t total_connections;
	atomic_t active_connections;
	atomic64_t bytes_sent;
	atomic64_t bytes_received;
	atomic64_t packets_sent;
	atomic64_t packets_received;
	atomic64_t packets_dropped;
	atomic64_t errors;
	atomic64_t retransmits;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic_t avg_latency_us;
	u64 uptime_ms;
	ktime_t last_update;
};

/**
 * struct stats_alert - Statistics alert notification
 * @list: List node
 * @timestamp: Alert timestamp
 * @type: Alert type
 * @severity: Severity level (0-10)
 * @fd_id: File descriptor ID
 * @conn_id: Connection ID (if applicable)
 * @message: Alert message
 * @value: Alert value
 * @threshold: Threshold that was exceeded
 */
struct stats_alert {
	struct list_head list;
	ktime_t timestamp;
	u8 type;
	u8 severity;
	u32 fd_id;
	u64 conn_id;
	char message[256];
	u64 value;
	u64 threshold;
};

/**
 * struct stats_threshold - Configurable thresholds
 * @latency_ms: High latency threshold in milliseconds
 * @error_rate_percent: Error rate threshold (percentage)
 * @bandwidth_mbps: Bandwidth spike threshold in Mbps
 * @connections_per_sec: Connection rate threshold
 * @packet_drop_rate: Packet drop rate threshold (percentage)
 */
struct stats_threshold {
	u32 latency_ms;
	u8 error_rate_percent;
	u32 bandwidth_mbps;
	u32 connections_per_sec;
	u8 packet_drop_rate;
};

/**
 * struct stats_monitor - Statistics monitoring context
 * @fd_stats: Per-fd statistics
 * @alerts: List of alerts
 * @alert_lock: Alert list lock
 * @alert_count: Number of alerts
 * @max_alerts: Maximum alerts to keep
 * @thresholds: Configurable thresholds
 * @monitoring_enabled: Monitoring enabled flag
 * @alert_enabled: Alerts enabled flag
 */
struct stats_monitor {
	struct fd_stats fd_stats;
	struct list_head alerts;
	spinlock_t alert_lock;
	atomic_t alert_count;
	u32 max_alerts;
	struct stats_threshold thresholds;
	bool monitoring_enabled;
	bool alert_enabled;
};

/**
 * struct stats_snapshot - Statistics snapshot for export
 * @version: Statistics version
 * @timestamp: Snapshot timestamp
 * @fd_id: File descriptor ID
 * @connections: Number of connections
 * @bytes_sent: Bytes sent
 * @bytes_received: Bytes received
 * @packets_sent: Packets sent
 * @packets_received: Packets received
 * @packets_dropped: Packets dropped
 * @errors: Errors
 * @retransmits: Retransmissions
 * @avg_latency_us: Average latency
 * @peak_bandwidth_sent: Peak outbound bandwidth
 * @peak_bandwidth_recv: Peak inbound bandwidth
 * @uptime_ms: Uptime in milliseconds
 */
struct stats_snapshot {
	u32 version;
	u64 timestamp;
	u32 fd_id;
	u32 connections;
	u64 bytes_sent;
	u64 bytes_received;
	u64 packets_sent;
	u64 packets_received;
	u64 packets_dropped;
	u64 errors;
	u64 retransmits;
	u32 avg_latency_us;
	u64 peak_bandwidth_sent;
	u64 peak_bandwidth_recv;
	u64 uptime_ms;
} __packed;

/* Statistics Initialization and Cleanup */
int stats_monitor_init(struct stats_monitor *monitor);
void stats_monitor_destroy(struct stats_monitor *monitor);
int stats_global_init(void);
void stats_global_destroy(void);

/* Connection Statistics */
struct connection_stats *stats_connection_create(struct stats_monitor *monitor,
						 u64 conn_id);
void stats_connection_destroy(struct stats_monitor *monitor,
			      struct connection_stats *conn_stats);
struct connection_stats *stats_connection_lookup(struct stats_monitor *monitor,
						 u64 conn_id);
void stats_connection_update(struct connection_stats *conn_stats,
			     u64 bytes_sent, u64 bytes_recv,
			     u32 latency_us);

/* FD Statistics */
void stats_fd_update(struct fd_stats *fd_stats, u64 bytes_sent,
		     u64 bytes_recv, u64 packets_sent, u64 packets_recv);
void stats_fd_update_latency(struct fd_stats *fd_stats, u32 latency_us);
void stats_fd_update_error(struct fd_stats *fd_stats);
void stats_fd_update_drop(struct fd_stats *fd_stats);
void stats_fd_calculate_bandwidth(struct fd_stats *fd_stats);
int stats_fd_get_snapshot(struct fd_stats *fd_stats,
			  struct stats_snapshot *snapshot);

/* Global Statistics */
void stats_global_update_fd(bool created);
void stats_global_update_connection(bool created);
void stats_global_update_traffic(u64 bytes_sent, u64 bytes_recv);
void stats_global_update_packets(u64 packets_sent, u64 packets_recv);
void stats_global_update_errors(u64 errors);
void stats_global_update_cache(bool hit);
int stats_global_get_snapshot(struct global_stats *snapshot);

/* Alert Management */
int stats_alert_create(struct stats_monitor *monitor, u8 type, u8 severity,
		       u64 conn_id, const char *message, u64 value,
		       u64 threshold);
int stats_alert_check_thresholds(struct stats_monitor *monitor,
				  struct connection_stats *conn_stats);
int stats_alert_get_all(struct stats_monitor *monitor, char *buffer,
			size_t buffer_size, u32 max_alerts);
void stats_alert_clear(struct stats_monitor *monitor);

/* Statistics Export */
int stats_export_json(struct stats_monitor *monitor, char *buffer,
		      size_t buffer_size);
int stats_export_binary(struct stats_monitor *monitor, void *buffer,
			size_t buffer_size);
int stats_export_csv(struct stats_monitor *monitor, char *buffer,
		     size_t buffer_size);

/* Statistics Aggregation */
int stats_aggregate_fds(struct stats_monitor **monitors, int count,
			struct stats_snapshot *aggregate);

/* Helper Functions */
u64 stats_calculate_bandwidth(u64 bytes, u64 time_ms);
u32 stats_calculate_avg_latency(u32 *latencies, int count);
u8 stats_calculate_error_rate(u64 errors, u64 total);
bool stats_check_threshold(u64 value, u64 threshold);

/* Procfs/Sysfs Interface */
int stats_procfs_init(void);
void stats_procfs_destroy(void);

#endif /* _MUTEX_STATS_H */
