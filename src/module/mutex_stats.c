// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX Statistics and Monitoring Module - Implementation
 *
 * Provides comprehensive statistics collection and monitoring.
 *
 * Copyright (C) 2025 MUTEX Team
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "mutex_stats.h"

/* Global statistics instance */
static struct global_stats g_stats;
static DEFINE_SPINLOCK(g_stats_lock);

/* Procfs directory */
static struct proc_dir_entry *mutex_proc_dir;
static struct proc_dir_entry *mutex_stats_proc;

/* ============================================================================
 * Statistics Initialization and Cleanup
 * ============================================================================ */

/**
 * stats_monitor_init - Initialize statistics monitor
 * @monitor: Monitor structure to initialize
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_monitor_init(struct stats_monitor *monitor)
{
	if (!monitor)
		return -EINVAL;

	/* Initialize FD statistics */
	INIT_LIST_HEAD(&monitor->fd_stats.connections);
	atomic_set(&monitor->fd_stats.conn_count, 0);
	atomic64_set(&monitor->fd_stats.total_connections, 0);
	atomic64_set(&monitor->fd_stats.bytes_sent, 0);
	atomic64_set(&monitor->fd_stats.bytes_received, 0);
	atomic64_set(&monitor->fd_stats.packets_sent, 0);
	atomic64_set(&monitor->fd_stats.packets_received, 0);
	atomic64_set(&monitor->fd_stats.packets_dropped, 0);
	atomic64_set(&monitor->fd_stats.errors, 0);
	atomic64_set(&monitor->fd_stats.retransmits, 0);
	atomic_set(&monitor->fd_stats.avg_latency_us, 0);
	atomic64_set(&monitor->fd_stats.peak_bandwidth_sent, 0);
	atomic64_set(&monitor->fd_stats.peak_bandwidth_recv, 0);
	monitor->fd_stats.uptime_ms = 0;
	monitor->fd_stats.last_update = ktime_get();
	spin_lock_init(&monitor->fd_stats.lock);
	monitor->fd_stats.flags = STATS_FLAG_ACTIVE;

	/* Initialize alerts */
	INIT_LIST_HEAD(&monitor->alerts);
	spin_lock_init(&monitor->alert_lock);
	atomic_set(&monitor->alert_count, 0);
	monitor->max_alerts = STATS_MAX_ALERTS;

	/* Initialize thresholds with defaults */
	monitor->thresholds.latency_ms = STATS_HIGH_LATENCY_THRESHOLD_MS;
	monitor->thresholds.error_rate_percent = STATS_HIGH_ERROR_RATE_THRESHOLD;
	monitor->thresholds.bandwidth_mbps = 1000; /* 1 Gbps */
	monitor->thresholds.connections_per_sec = 10000;
	monitor->thresholds.packet_drop_rate = 5; /* 5% */

	monitor->monitoring_enabled = true;
	monitor->alert_enabled = true;

	pr_debug("Statistics monitor initialized\n");
	return 0;
}

/**
 * stats_monitor_destroy - Destroy statistics monitor
 * @monitor: Monitor structure to destroy
 */
void stats_monitor_destroy(struct stats_monitor *monitor)
{
	struct connection_stats *conn_stats, *tmp_conn;
	struct stats_alert *alert, *tmp_alert;

	if (!monitor)
		return;

	/* Free connection statistics */
	spin_lock(&monitor->fd_stats.lock);
	list_for_each_entry_safe(conn_stats, tmp_conn,
				 &monitor->fd_stats.connections, list) {
		list_del(&conn_stats->list);
		kfree(conn_stats);
	}
	spin_unlock(&monitor->fd_stats.lock);

	/* Free alerts */
	spin_lock(&monitor->alert_lock);
	list_for_each_entry_safe(alert, tmp_alert, &monitor->alerts, list) {
		list_del(&alert->list);
		kfree(alert);
	}
	spin_unlock(&monitor->alert_lock);

	pr_debug("Statistics monitor destroyed\n");
}

/**
 * stats_global_init - Initialize global statistics
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_global_init(void)
{
	atomic64_set(&g_stats.total_fds, 0);
	atomic_set(&g_stats.active_fds, 0);
	atomic64_set(&g_stats.total_connections, 0);
	atomic_set(&g_stats.active_connections, 0);
	atomic64_set(&g_stats.bytes_sent, 0);
	atomic64_set(&g_stats.bytes_received, 0);
	atomic64_set(&g_stats.packets_sent, 0);
	atomic64_set(&g_stats.packets_received, 0);
	atomic64_set(&g_stats.packets_dropped, 0);
	atomic64_set(&g_stats.errors, 0);
	atomic64_set(&g_stats.retransmits, 0);
	atomic64_set(&g_stats.cache_hits, 0);
	atomic64_set(&g_stats.cache_misses, 0);
	atomic_set(&g_stats.avg_latency_us, 0);
	g_stats.uptime_ms = 0;
	g_stats.last_update = ktime_get();

	pr_info("Global statistics initialized\n");
	return 0;
}

/**
 * stats_global_destroy - Destroy global statistics
 */
void stats_global_destroy(void)
{
	pr_info("Global statistics destroyed\n");
}

/* ============================================================================
 * Connection Statistics
 * ============================================================================ */

/**
 * stats_connection_create - Create connection statistics
 * @monitor: Statistics monitor
 * @conn_id: Connection ID
 *
 * Return: Connection statistics structure, or NULL on failure
 */
struct connection_stats *stats_connection_create(struct stats_monitor *monitor,
						 u64 conn_id)
{
	struct connection_stats *conn_stats;

	if (!monitor)
		return NULL;

	conn_stats = kzalloc(sizeof(*conn_stats), GFP_KERNEL);
	if (!conn_stats)
		return NULL;

	conn_stats->conn_id = conn_id;
	conn_stats->start_time = ktime_get();
	conn_stats->last_activity = conn_stats->start_time;
	atomic64_set(&conn_stats->bytes_sent, 0);
	atomic64_set(&conn_stats->bytes_received, 0);
	atomic64_set(&conn_stats->packets_sent, 0);
	atomic64_set(&conn_stats->packets_received, 0);
	atomic_set(&conn_stats->retransmits, 0);
	atomic_set(&conn_stats->errors, 0);
	conn_stats->avg_latency_us = 0;
	conn_stats->min_latency_us = UINT_MAX;
	conn_stats->max_latency_us = 0;
	conn_stats->state = 0;
	conn_stats->flags = STATS_FLAG_ACTIVE;

	spin_lock(&monitor->fd_stats.lock);
	list_add(&conn_stats->list, &monitor->fd_stats.connections);
	atomic_inc(&monitor->fd_stats.conn_count);
	atomic64_inc(&monitor->fd_stats.total_connections);
	spin_unlock(&monitor->fd_stats.lock);

	/* Update global statistics */
	stats_global_update_connection(true);

	pr_debug("Connection statistics created: conn_id=%llu\n", conn_id);
	return conn_stats;
}

/**
 * stats_connection_destroy - Destroy connection statistics
 * @monitor: Statistics monitor
 * @conn_stats: Connection statistics to destroy
 */
void stats_connection_destroy(struct stats_monitor *monitor,
			      struct connection_stats *conn_stats)
{
	if (!monitor || !conn_stats)
		return;

	spin_lock(&monitor->fd_stats.lock);
	list_del(&conn_stats->list);
	atomic_dec(&monitor->fd_stats.conn_count);
	spin_unlock(&monitor->fd_stats.lock);

	kfree(conn_stats);

	/* Update global statistics */
	stats_global_update_connection(false);

	pr_debug("Connection statistics destroyed\n");
}

/**
 * stats_connection_lookup - Lookup connection statistics
 * @monitor: Statistics monitor
 * @conn_id: Connection ID
 *
 * Return: Connection statistics, or NULL if not found
 */
struct connection_stats *stats_connection_lookup(struct stats_monitor *monitor,
						 u64 conn_id)
{
	struct connection_stats *conn_stats;

	if (!monitor)
		return NULL;

	spin_lock(&monitor->fd_stats.lock);
	list_for_each_entry(conn_stats, &monitor->fd_stats.connections, list) {
		if (conn_stats->conn_id == conn_id) {
			spin_unlock(&monitor->fd_stats.lock);
			return conn_stats;
		}
	}
	spin_unlock(&monitor->fd_stats.lock);

	return NULL;
}

/**
 * stats_connection_update - Update connection statistics
 * @conn_stats: Connection statistics
 * @bytes_sent: Bytes sent in this update
 * @bytes_recv: Bytes received in this update
 * @latency_us: Latency in microseconds
 */
void stats_connection_update(struct connection_stats *conn_stats,
			     u64 bytes_sent, u64 bytes_recv,
			     u32 latency_us)
{
	if (!conn_stats)
		return;

	/* Update byte counters */
	atomic64_add(bytes_sent, &conn_stats->bytes_sent);
	atomic64_add(bytes_recv, &conn_stats->bytes_received);

	/* Update packet counters */
	if (bytes_sent > 0)
		atomic64_inc(&conn_stats->packets_sent);
	if (bytes_recv > 0)
		atomic64_inc(&conn_stats->packets_received);

	/* Update latency statistics */
	if (latency_us > 0) {
		u32 old_avg = conn_stats->avg_latency_us;
		u64 total_packets = atomic64_read(&conn_stats->packets_sent) +
				    atomic64_read(&conn_stats->packets_received);

		if (total_packets > 0) {
			/* Calculate running average */
			conn_stats->avg_latency_us =
				(old_avg * (total_packets - 1) + latency_us) /
				total_packets;
		}

		if (latency_us < conn_stats->min_latency_us)
			conn_stats->min_latency_us = latency_us;
		if (latency_us > conn_stats->max_latency_us)
			conn_stats->max_latency_us = latency_us;
	}

	conn_stats->last_activity = ktime_get();
}

/* ============================================================================
 * FD Statistics
 * ============================================================================ */

/**
 * stats_fd_update - Update FD statistics
 * @fd_stats: FD statistics
 * @bytes_sent: Bytes sent
 * @bytes_recv: Bytes received
 * @packets_sent: Packets sent
 * @packets_recv: Packets received
 */
void stats_fd_update(struct fd_stats *fd_stats, u64 bytes_sent,
		     u64 bytes_recv, u64 packets_sent, u64 packets_recv)
{
	if (!fd_stats)
		return;

	atomic64_add(bytes_sent, &fd_stats->bytes_sent);
	atomic64_add(bytes_recv, &fd_stats->bytes_received);
	atomic64_add(packets_sent, &fd_stats->packets_sent);
	atomic64_add(packets_recv, &fd_stats->packets_received);

	fd_stats->last_update = ktime_get();

	/* Update global statistics */
	stats_global_update_traffic(bytes_sent, bytes_recv);
	stats_global_update_packets(packets_sent, packets_recv);
}

/**
 * stats_fd_update_latency - Update FD latency statistics
 * @fd_stats: FD statistics
 * @latency_us: Latency in microseconds
 */
void stats_fd_update_latency(struct fd_stats *fd_stats, u32 latency_us)
{
	if (!fd_stats)
		return;

	/* Update running average */
	u32 old_avg = atomic_read(&fd_stats->avg_latency_us);
	u64 total_packets = atomic64_read(&fd_stats->packets_sent) +
			    atomic64_read(&fd_stats->packets_received);

	if (total_packets > 0) {
		u32 new_avg = (old_avg * (total_packets - 1) + latency_us) /
			      total_packets;
		atomic_set(&fd_stats->avg_latency_us, new_avg);
	}
}

/**
 * stats_fd_update_error - Update FD error count
 * @fd_stats: FD statistics
 */
void stats_fd_update_error(struct fd_stats *fd_stats)
{
	if (!fd_stats)
		return;

	atomic64_inc(&fd_stats->errors);
	stats_global_update_errors(1);
}

/**
 * stats_fd_update_drop - Update FD packet drop count
 * @fd_stats: FD statistics
 */
void stats_fd_update_drop(struct fd_stats *fd_stats)
{
	if (!fd_stats)
		return;

	atomic64_inc(&fd_stats->packets_dropped);
}

/**
 * stats_fd_calculate_bandwidth - Calculate FD bandwidth
 * @fd_stats: FD statistics
 */
void stats_fd_calculate_bandwidth(struct fd_stats *fd_stats)
{
	ktime_t now;
	s64 elapsed_ms;
	u64 bytes_sent, bytes_recv;
	u64 bandwidth_sent, bandwidth_recv;

	if (!fd_stats)
		return;

	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, fd_stats->last_update);

	if (elapsed_ms <= 0)
		return;

	bytes_sent = atomic64_read(&fd_stats->bytes_sent);
	bytes_recv = atomic64_read(&fd_stats->bytes_received);

	/* Calculate bandwidth in bytes/sec */
	bandwidth_sent = (bytes_sent * 1000) / elapsed_ms;
	bandwidth_recv = (bytes_recv * 1000) / elapsed_ms;

	/* Update peak bandwidth if higher */
	if (bandwidth_sent > atomic64_read(&fd_stats->peak_bandwidth_sent))
		atomic64_set(&fd_stats->peak_bandwidth_sent, bandwidth_sent);
	if (bandwidth_recv > atomic64_read(&fd_stats->peak_bandwidth_recv))
		atomic64_set(&fd_stats->peak_bandwidth_recv, bandwidth_recv);
}

/**
 * stats_fd_get_snapshot - Get FD statistics snapshot
 * @fd_stats: FD statistics
 * @snapshot: Snapshot structure to fill
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_fd_get_snapshot(struct fd_stats *fd_stats,
			  struct stats_snapshot *snapshot)
{
	ktime_t now;

	if (!fd_stats || !snapshot)
		return -EINVAL;

	now = ktime_get();

	snapshot->version = MUTEX_STATS_VERSION;
	snapshot->timestamp = ktime_to_ms(now);
	snapshot->fd_id = 0; /* Set by caller */
	snapshot->connections = atomic_read(&fd_stats->conn_count);
	snapshot->bytes_sent = atomic64_read(&fd_stats->bytes_sent);
	snapshot->bytes_received = atomic64_read(&fd_stats->bytes_received);
	snapshot->packets_sent = atomic64_read(&fd_stats->packets_sent);
	snapshot->packets_received = atomic64_read(&fd_stats->packets_received);
	snapshot->packets_dropped = atomic64_read(&fd_stats->packets_dropped);
	snapshot->errors = atomic64_read(&fd_stats->errors);
	snapshot->retransmits = atomic64_read(&fd_stats->retransmits);
	snapshot->avg_latency_us = atomic_read(&fd_stats->avg_latency_us);
	snapshot->peak_bandwidth_sent =
		atomic64_read(&fd_stats->peak_bandwidth_sent);
	snapshot->peak_bandwidth_recv =
		atomic64_read(&fd_stats->peak_bandwidth_recv);
	snapshot->uptime_ms = ktime_ms_delta(now,
					     fd_stats->last_update);

	return 0;
}

/* ============================================================================
 * Global Statistics
 * ============================================================================ */

/**
 * stats_global_update_fd - Update global FD count
 * @created: true if FD created, false if destroyed
 */
void stats_global_update_fd(bool created)
{
	spin_lock(&g_stats_lock);

	if (created) {
		atomic64_inc(&g_stats.total_fds);
		atomic_inc(&g_stats.active_fds);
	} else {
		atomic_dec(&g_stats.active_fds);
	}

	g_stats.last_update = ktime_get();
	spin_unlock(&g_stats_lock);
}

/**
 * stats_global_update_connection - Update global connection count
 * @created: true if connection created, false if destroyed
 */
void stats_global_update_connection(bool created)
{
	spin_lock(&g_stats_lock);

	if (created) {
		atomic64_inc(&g_stats.total_connections);
		atomic_inc(&g_stats.active_connections);
	} else {
		atomic_dec(&g_stats.active_connections);
	}

	g_stats.last_update = ktime_get();
	spin_unlock(&g_stats_lock);
}

/**
 * stats_global_update_traffic - Update global traffic statistics
 * @bytes_sent: Bytes sent
 * @bytes_recv: Bytes received
 */
void stats_global_update_traffic(u64 bytes_sent, u64 bytes_recv)
{
	atomic64_add(bytes_sent, &g_stats.bytes_sent);
	atomic64_add(bytes_recv, &g_stats.bytes_received);
}

/**
 * stats_global_update_packets - Update global packet statistics
 * @packets_sent: Packets sent
 * @packets_recv: Packets received
 */
void stats_global_update_packets(u64 packets_sent, u64 packets_recv)
{
	atomic64_add(packets_sent, &g_stats.packets_sent);
	atomic64_add(packets_recv, &g_stats.packets_received);
}

/**
 * stats_global_update_errors - Update global error count
 * @errors: Number of errors
 */
void stats_global_update_errors(u64 errors)
{
	atomic64_add(errors, &g_stats.errors);
}

/**
 * stats_global_update_cache - Update global cache statistics
 * @hit: true for cache hit, false for miss
 */
void stats_global_update_cache(bool hit)
{
	if (hit)
		atomic64_inc(&g_stats.cache_hits);
	else
		atomic64_inc(&g_stats.cache_misses);
}

/**
 * stats_global_get_snapshot - Get global statistics snapshot
 * @snapshot: Snapshot structure to fill
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_global_get_snapshot(struct global_stats *snapshot)
{
	if (!snapshot)
		return -EINVAL;

	spin_lock(&g_stats_lock);
	memcpy(snapshot, &g_stats, sizeof(*snapshot));
	spin_unlock(&g_stats_lock);

	return 0;
}

/* ============================================================================
 * Alert Management
 * ============================================================================ */

/**
 * stats_alert_create - Create statistics alert
 * @monitor: Statistics monitor
 * @type: Alert type
 * @severity: Severity level (0-10)
 * @conn_id: Connection ID
 * @message: Alert message
 * @value: Alert value
 * @threshold: Threshold that was exceeded
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_alert_create(struct stats_monitor *monitor, u8 type, u8 severity,
		       u64 conn_id, const char *message, u64 value,
		       u64 threshold)
{
	struct stats_alert *alert;

	if (!monitor || !monitor->alert_enabled)
		return 0;

	/* Check if we've reached max alerts */
	if (atomic_read(&monitor->alert_count) >= monitor->max_alerts) {
		/* Remove oldest alert */
		struct stats_alert *old_alert;

		spin_lock(&monitor->alert_lock);
		if (!list_empty(&monitor->alerts)) {
			old_alert = list_first_entry(&monitor->alerts,
						      struct stats_alert, list);
			list_del(&old_alert->list);
			kfree(old_alert);
			atomic_dec(&monitor->alert_count);
		}
		spin_unlock(&monitor->alert_lock);
	}

	alert = kzalloc(sizeof(*alert), GFP_ATOMIC);
	if (!alert)
		return -ENOMEM;

	alert->timestamp = ktime_get();
	alert->type = type;
	alert->severity = severity;
	alert->fd_id = 0; /* Set by caller */
	alert->conn_id = conn_id;
	strncpy(alert->message, message, sizeof(alert->message) - 1);
	alert->value = value;
	alert->threshold = threshold;

	spin_lock(&monitor->alert_lock);
	list_add_tail(&alert->list, &monitor->alerts);
	atomic_inc(&monitor->alert_count);
	spin_unlock(&monitor->alert_lock);

	pr_debug("Alert created: type=%u severity=%u message='%s'\n",
		 type, severity, message);
	return 0;
}

/**
 * stats_alert_check_thresholds - Check statistics against thresholds
 * @monitor: Statistics monitor
 * @conn_stats: Connection statistics
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_alert_check_thresholds(struct stats_monitor *monitor,
				  struct connection_stats *conn_stats)
{
	u32 latency_ms;
	u64 total_packets;
	u8 error_rate;

	if (!monitor || !conn_stats)
		return -EINVAL;

	/* Check latency threshold */
	latency_ms = conn_stats->avg_latency_us / 1000;
	if (latency_ms > monitor->thresholds.latency_ms) {
		stats_alert_create(monitor, ALERT_TYPE_HIGH_LATENCY, 7,
				   conn_stats->conn_id,
				   "High latency detected",
				   latency_ms,
				   monitor->thresholds.latency_ms);
	}

	/* Check error rate threshold */
	total_packets = atomic64_read(&conn_stats->packets_sent) +
			atomic64_read(&conn_stats->packets_received);
	if (total_packets > 0) {
		error_rate = (atomic_read(&conn_stats->errors) * 100) /
			     total_packets;
		if (error_rate > monitor->thresholds.error_rate_percent) {
			stats_alert_create(monitor, ALERT_TYPE_HIGH_ERROR_RATE,
					   8, conn_stats->conn_id,
					   "High error rate detected",
					   error_rate,
					   monitor->thresholds.error_rate_percent);
		}
	}

	return 0;
}

/**
 * stats_alert_get_all - Get all alerts
 * @monitor: Statistics monitor
 * @buffer: Buffer to store alerts
 * @buffer_size: Size of buffer
 * @max_alerts: Maximum alerts to return
 *
 * Return: Number of bytes written, or negative error code
 */
int stats_alert_get_all(struct stats_monitor *monitor, char *buffer,
			size_t buffer_size, u32 max_alerts)
{
	struct stats_alert *alert;
	size_t pos = 0;
	u32 count = 0;

	if (!monitor || !buffer)
		return -EINVAL;

	spin_lock(&monitor->alert_lock);

	list_for_each_entry(alert, &monitor->alerts, list) {
		int written;

		if (count >= max_alerts)
			break;

		written = snprintf(buffer + pos, buffer_size - pos,
				   "%lld,%u,%u,%llu,\"%s\",%llu,%llu\n",
				   ktime_to_ms(alert->timestamp),
				   alert->type, alert->severity,
				   alert->conn_id, alert->message,
				   alert->value, alert->threshold);

		if (written < 0 || pos + written >= buffer_size)
			break;

		pos += written;
		count++;
	}

	spin_unlock(&monitor->alert_lock);

	return pos;
}

/**
 * stats_alert_clear - Clear all alerts
 * @monitor: Statistics monitor
 */
void stats_alert_clear(struct stats_monitor *monitor)
{
	struct stats_alert *alert, *tmp;

	if (!monitor)
		return;

	spin_lock(&monitor->alert_lock);
	list_for_each_entry_safe(alert, tmp, &monitor->alerts, list) {
		list_del(&alert->list);
		kfree(alert);
	}
	atomic_set(&monitor->alert_count, 0);
	spin_unlock(&monitor->alert_lock);
}

/* ============================================================================
 * Statistics Export
 * ============================================================================ */

/**
 * stats_export_json - Export statistics as JSON
 * @monitor: Statistics monitor
 * @buffer: Buffer to store JSON
 * @buffer_size: Size of buffer
 *
 * Return: Number of bytes written, or negative error code
 */
int stats_export_json(struct stats_monitor *monitor, char *buffer,
		      size_t buffer_size)
{
	struct stats_snapshot snapshot;
	int written;

	if (!monitor || !buffer)
		return -EINVAL;

	stats_fd_get_snapshot(&monitor->fd_stats, &snapshot);

	written = snprintf(buffer, buffer_size,
			   "{\n"
			   "  \"version\": %u,\n"
			   "  \"timestamp\": %llu,\n"
			   "  \"connections\": %u,\n"
			   "  \"bytes_sent\": %llu,\n"
			   "  \"bytes_received\": %llu,\n"
			   "  \"packets_sent\": %llu,\n"
			   "  \"packets_received\": %llu,\n"
			   "  \"packets_dropped\": %llu,\n"
			   "  \"errors\": %llu,\n"
			   "  \"retransmits\": %llu,\n"
			   "  \"avg_latency_us\": %u,\n"
			   "  \"peak_bandwidth_sent\": %llu,\n"
			   "  \"peak_bandwidth_recv\": %llu,\n"
			   "  \"uptime_ms\": %llu\n"
			   "}\n",
			   snapshot.version, snapshot.timestamp,
			   snapshot.connections, snapshot.bytes_sent,
			   snapshot.bytes_received, snapshot.packets_sent,
			   snapshot.packets_received, snapshot.packets_dropped,
			   snapshot.errors, snapshot.retransmits,
			   snapshot.avg_latency_us, snapshot.peak_bandwidth_sent,
			   snapshot.peak_bandwidth_recv, snapshot.uptime_ms);

	return written > 0 ? written : -ENOMEM;
}

/**
 * stats_export_binary - Export statistics as binary
 * @monitor: Statistics monitor
 * @buffer: Buffer to store binary data
 * @buffer_size: Size of buffer
 *
 * Return: Number of bytes written, or negative error code
 */
int stats_export_binary(struct stats_monitor *monitor, void *buffer,
			size_t buffer_size)
{
	struct stats_snapshot snapshot;

	if (!monitor || !buffer || buffer_size < sizeof(snapshot))
		return -EINVAL;

	stats_fd_get_snapshot(&monitor->fd_stats, &snapshot);
	memcpy(buffer, &snapshot, sizeof(snapshot));

	return sizeof(snapshot);
}

/**
 * stats_export_csv - Export statistics as CSV
 * @monitor: Statistics monitor
 * @buffer: Buffer to store CSV
 * @buffer_size: Size of buffer
 *
 * Return: Number of bytes written, or negative error code
 */
int stats_export_csv(struct stats_monitor *monitor, char *buffer,
		     size_t buffer_size)
{
	struct stats_snapshot snapshot;
	int written;

	if (!monitor || !buffer)
		return -EINVAL;

	stats_fd_get_snapshot(&monitor->fd_stats, &snapshot);

	written = snprintf(buffer, buffer_size,
			   "timestamp,connections,bytes_sent,bytes_received,"
			   "packets_sent,packets_received,packets_dropped,"
			   "errors,retransmits,avg_latency_us,"
			   "peak_bandwidth_sent,peak_bandwidth_recv,uptime_ms\n"
			   "%llu,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u,"
			   "%llu,%llu,%llu\n",
			   snapshot.timestamp, snapshot.connections,
			   snapshot.bytes_sent, snapshot.bytes_received,
			   snapshot.packets_sent, snapshot.packets_received,
			   snapshot.packets_dropped, snapshot.errors,
			   snapshot.retransmits, snapshot.avg_latency_us,
			   snapshot.peak_bandwidth_sent,
			   snapshot.peak_bandwidth_recv, snapshot.uptime_ms);

	return written > 0 ? written : -ENOMEM;
}

/* ============================================================================
 * Statistics Aggregation
 * ============================================================================ */

/**
 * stats_aggregate_fds - Aggregate statistics from multiple FDs
 * @monitors: Array of monitor structures
 * @count: Number of monitors
 * @aggregate: Aggregate snapshot structure
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_aggregate_fds(struct stats_monitor **monitors, int count,
			struct stats_snapshot *aggregate)
{
	int i;

	if (!monitors || !aggregate || count <= 0)
		return -EINVAL;

	memset(aggregate, 0, sizeof(*aggregate));
	aggregate->version = MUTEX_STATS_VERSION;
	aggregate->timestamp = ktime_to_ms(ktime_get());

	for (i = 0; i < count; i++) {
		struct stats_snapshot snapshot;

		if (!monitors[i])
			continue;

		stats_fd_get_snapshot(&monitors[i]->fd_stats, &snapshot);

		aggregate->connections += snapshot.connections;
		aggregate->bytes_sent += snapshot.bytes_sent;
		aggregate->bytes_received += snapshot.bytes_received;
		aggregate->packets_sent += snapshot.packets_sent;
		aggregate->packets_received += snapshot.packets_received;
		aggregate->packets_dropped += snapshot.packets_dropped;
		aggregate->errors += snapshot.errors;
		aggregate->retransmits += snapshot.retransmits;

		/* Average latency across all FDs */
		if (snapshot.avg_latency_us > 0)
			aggregate->avg_latency_us =
				(aggregate->avg_latency_us + snapshot.avg_latency_us) / 2;

		/* Track maximum peak bandwidth */
		if (snapshot.peak_bandwidth_sent > aggregate->peak_bandwidth_sent)
			aggregate->peak_bandwidth_sent = snapshot.peak_bandwidth_sent;
		if (snapshot.peak_bandwidth_recv > aggregate->peak_bandwidth_recv)
			aggregate->peak_bandwidth_recv = snapshot.peak_bandwidth_recv;
	}

	return 0;
}

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * stats_calculate_bandwidth - Calculate bandwidth from bytes and time
 * @bytes: Number of bytes
 * @time_ms: Time in milliseconds
 *
 * Return: Bandwidth in bytes per second
 */
u64 stats_calculate_bandwidth(u64 bytes, u64 time_ms)
{
	if (time_ms == 0)
		return 0;

	return (bytes * 1000) / time_ms;
}

/**
 * stats_calculate_avg_latency - Calculate average latency
 * @latencies: Array of latency values
 * @count: Number of values
 *
 * Return: Average latency
 */
u32 stats_calculate_avg_latency(u32 *latencies, int count)
{
	u64 sum = 0;
	int i;

	if (!latencies || count <= 0)
		return 0;

	for (i = 0; i < count; i++)
		sum += latencies[i];

	return sum / count;
}

/**
 * stats_calculate_error_rate - Calculate error rate as percentage
 * @errors: Number of errors
 * @total: Total number of operations
 *
 * Return: Error rate percentage
 */
u8 stats_calculate_error_rate(u64 errors, u64 total)
{
	if (total == 0)
		return 0;

	return (errors * 100) / total;
}

/**
 * stats_check_threshold - Check if value exceeds threshold
 * @value: Value to check
 * @threshold: Threshold value
 *
 * Return: true if threshold exceeded, false otherwise
 */
bool stats_check_threshold(u64 value, u64 threshold)
{
	return value > threshold;
}

/* ============================================================================
 * Procfs Interface
 * ============================================================================ */

/**
 * stats_proc_show - Show statistics in procfs
 * @m: Seq file
 * @v: Private data
 *
 * Return: 0 on success
 */
static int stats_proc_show(struct seq_file *m, void *v)
{
	struct global_stats snapshot;

	stats_global_get_snapshot(&snapshot);

	seq_printf(m, "MUTEX Statistics\n");
	seq_printf(m, "================\n\n");
	seq_printf(m, "File Descriptors:\n");
	seq_printf(m, "  Total: %lld\n", atomic64_read(&snapshot.total_fds));
	seq_printf(m, "  Active: %d\n", atomic_read(&snapshot.active_fds));
	seq_printf(m, "\nConnections:\n");
	seq_printf(m, "  Total: %lld\n", atomic64_read(&snapshot.total_connections));
	seq_printf(m, "  Active: %d\n", atomic_read(&snapshot.active_connections));
	seq_printf(m, "\nTraffic:\n");
	seq_printf(m, "  Bytes Sent: %lld\n", atomic64_read(&snapshot.bytes_sent));
	seq_printf(m, "  Bytes Received: %lld\n", atomic64_read(&snapshot.bytes_received));
	seq_printf(m, "  Packets Sent: %lld\n", atomic64_read(&snapshot.packets_sent));
	seq_printf(m, "  Packets Received: %lld\n", atomic64_read(&snapshot.packets_received));
	seq_printf(m, "  Packets Dropped: %lld\n", atomic64_read(&snapshot.packets_dropped));
	seq_printf(m, "\nErrors:\n");
	seq_printf(m, "  Total Errors: %lld\n", atomic64_read(&snapshot.errors));
	seq_printf(m, "  Retransmissions: %lld\n", atomic64_read(&snapshot.retransmits));
	seq_printf(m, "\nCache:\n");
	seq_printf(m, "  Cache Hits: %lld\n", atomic64_read(&snapshot.cache_hits));
	seq_printf(m, "  Cache Misses: %lld\n", atomic64_read(&snapshot.cache_misses));
	seq_printf(m, "\nPerformance:\n");
	seq_printf(m, "  Avg Latency: %d us\n", atomic_read(&snapshot.avg_latency_us));

	return 0;
}

/**
 * stats_proc_open - Open procfs file
 * @inode: Inode
 * @file: File structure
 *
 * Return: 0 on success
 */
static int stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_proc_show, NULL);
}

static const struct proc_ops stats_proc_ops = {
	.proc_open = stats_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/**
 * stats_procfs_init - Initialize procfs interface
 *
 * Return: 0 on success, negative error code on failure
 */
int stats_procfs_init(void)
{
	mutex_proc_dir = proc_mkdir("mutex", NULL);
	if (!mutex_proc_dir) {
		pr_err("Failed to create /proc/mutex directory\n");
		return -ENOMEM;
	}

	mutex_stats_proc = proc_create("stats", 0444, mutex_proc_dir,
				       &stats_proc_ops);
	if (!mutex_stats_proc) {
		proc_remove(mutex_proc_dir);
		pr_err("Failed to create /proc/mutex/stats\n");
		return -ENOMEM;
	}

	pr_info("Procfs interface initialized at /proc/mutex/stats\n");
	return 0;
}

/**
 * stats_procfs_destroy - Destroy procfs interface
 */
void stats_procfs_destroy(void)
{
	if (mutex_stats_proc)
		proc_remove(mutex_stats_proc);
	if (mutex_proc_dir)
		proc_remove(mutex_proc_dir);

	pr_info("Procfs interface destroyed\n");
}
