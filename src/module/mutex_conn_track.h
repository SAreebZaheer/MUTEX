/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_conn_track.h - MUTEX connection tracking header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements connection state tracking for proxied connections.
 * It maintains a hash table of active connections, tracks original and proxied
 * addresses, and handles connection lifecycle management.
 */

#ifndef _MUTEX_CONN_TRACK_H
#define _MUTEX_CONN_TRACK_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/in6.h>

/* Connection tracking hash table size (must be power of 2) */
#define CONN_TRACK_HASH_SIZE	1024
#define CONN_TRACK_HASH_MASK	(CONN_TRACK_HASH_SIZE - 1)

/* Connection timeout values (in seconds) */
#define CONN_TIMEOUT_TCP_ESTABLISHED	7200	/* 2 hours */
#define CONN_TIMEOUT_TCP_SYN_SENT	120	/* 2 minutes */
#define CONN_TIMEOUT_TCP_FIN_WAIT	120	/* 2 minutes */
#define CONN_TIMEOUT_TCP_CLOSE_WAIT	60	/* 1 minute */
#define CONN_TIMEOUT_UDP		180	/* 3 minutes */
#define CONN_TIMEOUT_ICMP		30	/* 30 seconds */
#define CONN_TIMEOUT_OTHER		600	/* 10 minutes */

/* Garbage collection interval (in seconds) */
#define CONN_GC_INTERVAL		30	/* Run every 30 seconds */

/* Maximum connections per context */
#define CONN_MAX_PER_CONTEXT		65536

/**
 * enum conn_state - Connection state enumeration
 * @CONN_STATE_INVALID: Invalid/uninitialized state
 * @CONN_STATE_NEW: New connection, not yet established
 * @CONN_STATE_ESTABLISHING: Connection in progress (TCP SYN)
 * @CONN_STATE_ESTABLISHED: Connection fully established
 * @CONN_STATE_CLOSING: Connection closing (TCP FIN)
 * @CONN_STATE_CLOSED: Connection closed
 *
 * Tracks the lifecycle state of a connection through the proxy.
 */
enum conn_state {
	CONN_STATE_INVALID = 0,
	CONN_STATE_NEW,
	CONN_STATE_ESTABLISHING,
	CONN_STATE_ESTABLISHED,
	CONN_STATE_CLOSING,
	CONN_STATE_CLOSED,
};

/**
 * enum conn_proto - Connection protocol enumeration
 * @CONN_PROTO_TCP: TCP protocol
 * @CONN_PROTO_UDP: UDP protocol
 * @CONN_PROTO_ICMP: ICMP protocol
 * @CONN_PROTO_OTHER: Other/unknown protocol
 */
enum conn_proto {
	CONN_PROTO_TCP = 0,
	CONN_PROTO_UDP,
	CONN_PROTO_ICMP,
	CONN_PROTO_OTHER,
};

/**
 * union conn_addr - IPv4/IPv6 address union
 * @v4: IPv4 address
 * @v6: IPv6 address
 *
 * Unified address structure supporting both IPv4 and IPv6.
 */
union conn_addr {
	__be32 v4;
	struct in6_addr v6;
};

/**
 * struct conn_tuple - Connection 5-tuple identifier
 * @src_addr: Source IP address (client)
 * @dst_addr: Destination IP address (original target)
 * @src_port: Source port (client)
 * @dst_port: Destination port (original target)
 * @protocol: IP protocol (TCP, UDP, etc.)
 * @is_ipv6: True if IPv6, false if IPv4
 *
 * Uniquely identifies a connection in the network.
 */
struct conn_tuple {
	union conn_addr src_addr;
	union conn_addr dst_addr;
	__be16 src_port;
	__be16 dst_port;
	__u8 protocol;
	bool is_ipv6;
};

/**
 * struct conn_proxy_info - Proxy connection information
 * @proxy_addr: Proxy server IP address
 * @proxy_port: Proxy server port
 * @proxy_type: Type of proxy (SOCKS5, HTTP, etc.)
 * @proxy_state: Protocol-specific state machine state
 * @auth_sent: Authentication has been sent
 *
 * Stores information about the proxy being used for this connection.
 */
struct conn_proxy_info {
	union conn_addr proxy_addr;
	__be16 proxy_port;
	__u32 proxy_type;
	__u32 proxy_state;
	bool auth_sent;
};

/**
 * struct conn_stats - Per-connection statistics
 * @bytes_sent: Bytes sent to proxy
 * @bytes_received: Bytes received from proxy
 * @packets_sent: Packets sent to proxy
 * @packets_received: Packets received from proxy
 * @created_time: Time connection was created (jiffies)
 * @last_seen: Time of last packet (jiffies)
 *
 * Tracks statistics for an individual connection.
 */
struct conn_stats {
	atomic64_t bytes_sent;
	atomic64_t bytes_received;
	atomic64_t packets_sent;
	atomic64_t packets_received;
	unsigned long created_time;
	unsigned long last_seen;
};

/**
 * struct mutex_conn_entry - Connection tracking entry
 * @hash_node: Hash table linkage
 * @list_node: Global list linkage
 * @tuple: Original connection 5-tuple
 * @proxy: Proxy information
 * @stats: Connection statistics
 * @state: Current connection state
 * @proto: Connection protocol
 * @lock: Spinlock protecting this entry
 * @refcount: Reference counter
 * @timeout: Connection timeout (jiffies)
 * @timer: Timeout timer
 * @ctx: Pointer to owning proxy context
 * @seq_delta: TCP sequence number adjustment
 * @ack_delta: TCP acknowledgment number adjustment
 * @flags: Connection-specific flags
 *
 * Each active connection through the proxy has one of these entries.
 * Stored in a hash table for fast lookup.
 */
struct mutex_conn_entry {
	struct hlist_node hash_node;	/* Hash table linkage */
	struct list_head list_node;	/* Global list linkage */

	struct conn_tuple tuple;	/* Original connection identity */
	struct conn_proxy_info proxy;	/* Proxy information */
	struct conn_stats stats;	/* Connection statistics */

	enum conn_state state;		/* Connection state */
	enum conn_proto proto;		/* Protocol type */

	spinlock_t lock;		/* Protects this entry */
	atomic_t refcount;		/* Reference counting */

	unsigned long timeout;		/* Timeout in jiffies */
	struct timer_list timer;	/* Timeout timer */

	void *ctx;			/* Owning proxy context (opaque) */
	void *transparent_ctx;		/* Transparent proxy context */

	/* TCP-specific fields */
	__s32 seq_delta;		/* Sequence number adjustment */
	__s32 ack_delta;		/* Acknowledgment adjustment */

	__u32 flags;			/* Connection flags */
	__be32 proxy_addr;		/* Proxy server address */
	__be16 proxy_port;		/* Proxy server port */
};

/* Connection tracking table structure */
struct conn_track_table {
	struct hlist_head buckets[CONN_TRACK_HASH_SIZE];
	spinlock_t locks[CONN_TRACK_HASH_SIZE]; /* Per-bucket locks */
	atomic_t count;				/* Total connections */
	struct timer_list gc_timer;		/* Garbage collection timer */
	struct list_head conn_list;		/* List of all connections */
	spinlock_t list_lock;			/* Protects conn_list */
};

/* Connection tracking API functions */

/**
 * mutex_conn_track_init() - Initialize connection tracking subsystem
 *
 * Must be called during module initialization.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_conn_track_init(void);

/**
 * mutex_conn_track_exit() - Clean up connection tracking subsystem
 *
 * Must be called during module exit. Frees all resources.
 */
void mutex_conn_track_exit(void);

/**
 * mutex_conn_create() - Create a new connection entry
 * @tuple: Connection 5-tuple
 * @ctx: Owning proxy context
 *
 * Creates and inserts a new connection tracking entry.
 *
 * Return: Pointer to new entry on success, NULL on failure
 */
struct mutex_conn_entry *mutex_conn_create(const struct conn_tuple *tuple,
					   void *ctx);

/**
 * mutex_conn_lookup() - Find connection by tuple
 * @tuple: Connection 5-tuple to search for
 *
 * Looks up a connection in the hash table. Increments refcount if found.
 * Caller must call mutex_conn_put() when done.
 *
 * Return: Pointer to entry on success, NULL if not found
 */
struct mutex_conn_entry *mutex_conn_lookup(const struct conn_tuple *tuple);

/**
 * mutex_conn_get() - Increment connection reference count
 * @conn: Connection entry
 *
 * Increments the reference count to prevent deletion while in use.
 */
void mutex_conn_get(struct mutex_conn_entry *conn);

/**
 * mutex_conn_put() - Decrement connection reference count
 * @conn: Connection entry
 *
 * Decrements reference count. Frees entry if count reaches zero.
 */
void mutex_conn_put(struct mutex_conn_entry *conn);

/**
 * mutex_conn_delete() - Remove connection from tracking
 * @conn: Connection entry to delete
 *
 * Removes connection from hash table and decrements refcount.
 * Connection may not be freed immediately if other references exist.
 */
void mutex_conn_delete(struct mutex_conn_entry *conn);

/**
 * mutex_conn_set_state() - Update connection state
 * @conn: Connection entry
 * @new_state: New state to set
 *
 * Updates the connection state and adjusts timeout accordingly.
 */
void mutex_conn_set_state(struct mutex_conn_entry *conn,
			  enum conn_state new_state);

/**
 * mutex_conn_refresh() - Refresh connection timeout
 * @conn: Connection entry
 *
 * Updates last_seen timestamp and resets timeout timer.
 */
void mutex_conn_refresh(struct mutex_conn_entry *conn);

/**
 * mutex_conn_update_stats() - Update connection statistics
 * @conn: Connection entry
 * @bytes: Number of bytes
 * @packets: Number of packets
 * @is_tx: True for transmitted data, false for received
 *
 * Atomically updates connection and context statistics.
 */
void mutex_conn_update_stats(struct mutex_conn_entry *conn,
			     u64 bytes, u64 packets, bool is_tx);

/**
 * mutex_conn_cleanup_context() - Clean up all connections for a context
 * @ctx: Proxy context
 *
 * Removes all connections associated with the given context.
 * Called when a proxy fd is closed.
 */
void mutex_conn_cleanup_context(void *ctx);

/**
 * mutex_conn_lookup_by_skb() - Find connection by packet
 * @skb: Packet to extract tuple from
 *
 * Extracts 5-tuple from packet and looks up connection.
 *
 * Return: Pointer to entry on success, NULL if not found
 */
struct mutex_conn_entry *mutex_conn_lookup_by_skb(struct sk_buff *skb);

/**
 * mutex_conn_alloc_from_skb() - Create connection from packet
 * @skb: Packet to extract tuple from
 *
 * Creates a new connection entry from packet 5-tuple.
 *
 * Return: Pointer to new entry on success, NULL on failure
 */
struct mutex_conn_entry *mutex_conn_alloc_from_skb(struct sk_buff *skb);

/**
 * mutex_conn_hash() - Calculate hash for connection tuple
 * @tuple: Connection 5-tuple
 *
 * Return: Hash value (0 to CONN_TRACK_HASH_SIZE-1)
 */
static inline u32 mutex_conn_hash(const struct conn_tuple *tuple)
{
	u32 hash = 0;

	if (tuple->is_ipv6) {
		hash = jhash2((u32 *)&tuple->src_addr.v6, 4, 0);
		hash = jhash2((u32 *)&tuple->dst_addr.v6, 4, hash);
	} else {
		hash = jhash_2words(tuple->src_addr.v4, tuple->dst_addr.v4, 0);
	}

	hash = jhash_3words((__force u32)tuple->src_port << 16 |
			    (__force u32)tuple->dst_port,
			    tuple->protocol,
			    tuple->is_ipv6 ? 1 : 0,
			    hash);

	return hash & CONN_TRACK_HASH_MASK;
}

/**
 * mutex_conn_get_timeout() - Get timeout value for connection state
 * @proto: Protocol type
 * @state: Connection state
 *
 * Return: Timeout in seconds
 */
static inline unsigned int mutex_conn_get_timeout(enum conn_proto proto,
						  enum conn_state state)
{
	switch (proto) {
	case CONN_PROTO_TCP:
		switch (state) {
		case CONN_STATE_ESTABLISHING:
			return CONN_TIMEOUT_TCP_SYN_SENT;
		case CONN_STATE_ESTABLISHED:
			return CONN_TIMEOUT_TCP_ESTABLISHED;
		case CONN_STATE_CLOSING:
			return CONN_TIMEOUT_TCP_FIN_WAIT;
		case CONN_STATE_CLOSED:
			return CONN_TIMEOUT_TCP_CLOSE_WAIT;
		default:
			return CONN_TIMEOUT_TCP_SYN_SENT;
		}
	case CONN_PROTO_UDP:
		return CONN_TIMEOUT_UDP;
	case CONN_PROTO_ICMP:
		return CONN_TIMEOUT_ICMP;
	default:
		return CONN_TIMEOUT_OTHER;
	}
}

#endif /* _MUTEX_CONN_TRACK_H */
