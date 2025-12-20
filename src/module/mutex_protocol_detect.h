/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MUTEX Protocol Detection Header
 *
 * Intelligent protocol detection and routing for the MUTEX kernel proxy.
 * Implements deep packet inspection, heuristic analysis, SNI parsing,
 * and protocol-specific routing rules.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#ifndef MUTEX_PROTOCOL_DETECT_H
#define MUTEX_PROTOCOL_DETECT_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hashtable.h>

/* Protocol types detected by the module */
enum protocol_type {
	PROTO_UNKNOWN = 0,
	PROTO_HTTP,
	PROTO_HTTPS,
	PROTO_DNS,
	PROTO_SSH,
	PROTO_FTP,
	PROTO_SMTP,
	PROTO_POP3,
	PROTO_IMAP,
	PROTO_TELNET,
	PROTO_RDP,
	PROTO_VNC,
	PROTO_SOCKS4,
	PROTO_SOCKS5,
	PROTO_BITTORRENT,
	PROTO_QUIC,
	PROTO_RTSP,
	PROTO_SIP,
	PROTO_IRC,
	PROTO_XMPP,
	PROTO_OPENVPN,
	PROTO_WIREGUARD,
	PROTO_TLS_GENERIC,
	PROTO_DTLS,
	PROTO_MAX
};

/* Detection confidence level */
enum detection_confidence {
	CONFIDENCE_NONE = 0,
	CONFIDENCE_LOW = 1,      /* Heuristic match */
	CONFIDENCE_MEDIUM = 2,   /* Port + pattern match */
	CONFIDENCE_HIGH = 3,     /* Deep inspection match */
	CONFIDENCE_CERTAIN = 4   /* Protocol handshake verified */
};

/* Protocol detection methods */
enum detection_method {
	METHOD_PORT = 0x01,           /* Port-based detection */
	METHOD_PATTERN = 0x02,        /* Pattern matching */
	METHOD_HEURISTIC = 0x04,      /* Heuristic analysis */
	METHOD_DPI = 0x08,            /* Deep packet inspection */
	METHOD_SNI = 0x10,            /* SNI parsing for TLS */
	METHOD_HANDSHAKE = 0x20       /* Protocol handshake analysis */
};

/* Routing action for detected protocol */
enum routing_action {
	ACTION_PROXY = 0,        /* Route through proxy */
	ACTION_DIRECT,           /* Direct connection */
	ACTION_BLOCK,            /* Block the connection */
	ACTION_INSPECT,          /* Continue inspecting */
	ACTION_DEFAULT           /* Use default policy */
};

/* Maximum pattern size for DPI */
#define MAX_PATTERN_SIZE 64
#define MAX_SNI_SIZE 256
#define MAX_HOST_SIZE 256

/* Detection pattern for DPI */
struct protocol_pattern {
	u8 data[MAX_PATTERN_SIZE];
	size_t len;
	size_t offset;         /* Offset in packet where pattern should match */
	u32 match_mask;        /* Bitmask for wildcards in pattern */
};

/* Protocol detection rule */
struct protocol_rule {
	enum protocol_type protocol;
	u16 port_start;
	u16 port_end;
	u8 transport;          /* IPPROTO_TCP or IPPROTO_UDP */

	/* Detection patterns */
	struct protocol_pattern patterns[4];
	u32 num_patterns;

	/* Detection methods to use */
	u32 methods;

	/* Minimum confidence required */
	enum detection_confidence min_confidence;

	struct list_head list;
};

/* Routing rule based on protocol */
struct protocol_routing_rule {
	enum protocol_type protocol;
	enum routing_action action;

	/* Optional domain/host filter */
	char host_pattern[MAX_HOST_SIZE];
	bool has_host_pattern;

	/* Priority (higher = evaluated first) */
	u32 priority;

	/* Statistics */
	atomic64_t match_count;

	struct list_head list;
};

/* SNI information extracted from TLS ClientHello */
struct sni_info {
	char server_name[MAX_SNI_SIZE];
	u16 tls_version;
	bool valid;
};

/* Detection result for a packet/connection */
struct protocol_detection_result {
	enum protocol_type protocol;
	enum detection_confidence confidence;
	u32 detection_methods;  /* Bitmask of methods that matched */

	/* Additional information */
	union {
		struct sni_info sni;
		char http_host[MAX_HOST_SIZE];
	} info;

	/* Routing decision */
	enum routing_action action;

	/* Timestamps */
	u64 first_seen;
	u64 last_updated;
};

/* Connection protocol state */
struct protocol_conn_state {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	u8 protocol;  /* IP protocol */

	struct protocol_detection_result result;

	/* Flow direction tracking */
	u32 packets_seen;
	u32 bytes_seen;

	/* Cache this connection's detection */
	bool detection_complete;

	struct hlist_node hash_node;
	struct rcu_head rcu;
};

/* Internal protocol detection statistics (kernel-side with atomic counters) */
struct protocol_detection_internal_stats {
	/* Per-protocol counters */
	atomic64_t proto_detected[PROTO_MAX];
	atomic64_t proto_errors[PROTO_MAX];

	/* Detection method statistics */
	atomic64_t method_port_hits;
	atomic64_t method_pattern_hits;
	atomic64_t method_heuristic_hits;
	atomic64_t method_dpi_hits;
	atomic64_t method_sni_hits;
	atomic64_t method_handshake_hits;

	/* Routing statistics */
	atomic64_t routed_proxy;
	atomic64_t routed_direct;
	atomic64_t routed_blocked;

	/* Performance metrics */
	atomic64_t total_packets;
	atomic64_t total_inspections;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
};

/* Main protocol detection context */
struct protocol_detect_context {
	/* Configuration */
	bool enabled;
	u32 inspection_depth;      /* Max bytes to inspect per packet */
	u32 connection_timeout;    /* Seconds before purging stale entries */

	/* Detection rules */
	struct list_head rules;
	spinlock_t rules_lock;

	/* Routing rules */
	struct list_head routing_rules;
	spinlock_t routing_lock;

	/* Connection state cache */
	DECLARE_HASHTABLE(connections, 10);  /* 1024 buckets */
	spinlock_t conn_lock;

	/* Statistics (internal atomic counters) */
	struct protocol_detection_internal_stats stats;

	/* Defaults */
	enum routing_action default_action;
	enum detection_confidence min_confidence;
};

/* IOCTL command definitions */
#define PROTO_DETECT_IOC_MAGIC 'P'

/* Enable/disable protocol detection */
#define PROTO_DETECT_ENABLE      _IOW(PROTO_DETECT_IOC_MAGIC, 1, int)
#define PROTO_DETECT_DISABLE     _IO(PROTO_DETECT_IOC_MAGIC, 2)

/* Add/remove detection rule */
#define PROTO_DETECT_ADD_RULE    _IOW(PROTO_DETECT_IOC_MAGIC, 3, struct protocol_rule)
#define PROTO_DETECT_DEL_RULE    _IOW(PROTO_DETECT_IOC_MAGIC, 4, enum protocol_type)
#define PROTO_DETECT_CLEAR_RULES _IO(PROTO_DETECT_IOC_MAGIC, 5)

/* Add/remove routing rule */
#define PROTO_DETECT_ADD_ROUTE   _IOW(PROTO_DETECT_IOC_MAGIC, 6, struct protocol_routing_rule)
#define PROTO_DETECT_DEL_ROUTE   _IOW(PROTO_DETECT_IOC_MAGIC, 7, u32)
#define PROTO_DETECT_CLEAR_ROUTES _IO(PROTO_DETECT_IOC_MAGIC, 8)

/* Configuration */
#define PROTO_DETECT_SET_DEPTH   _IOW(PROTO_DETECT_IOC_MAGIC, 9, u32)
#define PROTO_DETECT_SET_TIMEOUT _IOW(PROTO_DETECT_IOC_MAGIC, 10, u32)
#define PROTO_DETECT_SET_DEFAULT _IOW(PROTO_DETECT_IOC_MAGIC, 11, enum routing_action)

/* Query operations */
#define PROTO_DETECT_GET_STATS   _IOR(PROTO_DETECT_IOC_MAGIC, 12, struct protocol_detection_stats)
#define PROTO_DETECT_RESET_STATS _IO(PROTO_DETECT_IOC_MAGIC, 13)

/* Cache management */
#define PROTO_DETECT_FLUSH_CACHE _IO(PROTO_DETECT_IOC_MAGIC, 14)

/* Function declarations */

/**
 * protocol_detect_init() - Initialize protocol detection context
 *
 * Returns: Pointer to initialized context or NULL on error
 */
struct protocol_detect_context *protocol_detect_init(void);

/**
 * protocol_detect_cleanup() - Clean up protocol detection context
 * @ctx: Protocol detection context
 */
void protocol_detect_cleanup(struct protocol_detect_context *ctx);

/**
 * protocol_detect_packet() - Detect protocol for a packet
 * @ctx: Protocol detection context
 * @skb: Socket buffer containing the packet
 * @result: Output parameter for detection result
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_detect_packet(struct protocol_detect_context *ctx,
			   struct sk_buff *skb,
			   struct protocol_detection_result *result);

/**
 * protocol_get_routing_action() - Get routing action for detected protocol
 * @ctx: Protocol detection context
 * @result: Detection result
 *
 * Returns: Routing action for the protocol
 */
enum routing_action protocol_get_routing_action(
	struct protocol_detect_context *ctx,
	const struct protocol_detection_result *result);

/**
 * protocol_add_rule() - Add a protocol detection rule
 * @ctx: Protocol detection context
 * @rule: Detection rule to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_add_rule(struct protocol_detect_context *ctx,
		      const struct protocol_rule *rule);

/**
 * protocol_del_rule() - Remove a protocol detection rule
 * @ctx: Protocol detection context
 * @protocol: Protocol type to remove rule for
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_del_rule(struct protocol_detect_context *ctx,
		      enum protocol_type protocol);

/**
 * protocol_add_routing_rule() - Add a protocol routing rule
 * @ctx: Protocol detection context
 * @rule: Routing rule to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_add_routing_rule(struct protocol_detect_context *ctx,
			      const struct protocol_routing_rule *rule);

/**
 * protocol_del_routing_rule() - Remove a protocol routing rule
 * @ctx: Protocol detection context
 * @priority: Priority of rule to remove
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_del_routing_rule(struct protocol_detect_context *ctx, u32 priority);

/**
 * protocol_detect_sni() - Extract SNI from TLS ClientHello
 * @data: Packet payload data
 * @len: Length of payload
 * @sni: Output SNI information
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_detect_sni(const u8 *data, size_t len, struct sni_info *sni);

/**
 * protocol_detect_http_host() - Extract Host header from HTTP request
 * @data: Packet payload data
 * @len: Length of payload
 * @host: Output buffer for host (MAX_HOST_SIZE)
 *
 * Returns: 0 on success, negative error code on failure
 */
int protocol_detect_http_host(const u8 *data, size_t len, char *host);

/**
 * protocol_name() - Get human-readable protocol name
 * @protocol: Protocol type
 *
 * Returns: String name of protocol
 */
const char *protocol_name(enum protocol_type protocol);

/**
 * protocol_confidence_name() - Get human-readable confidence level name
 * @confidence: Confidence level
 *
 * Returns: String name of confidence level
 */
const char *protocol_confidence_name(enum detection_confidence confidence);

/**
 * protocol_action_name() - Get human-readable action name
 * @action: Routing action
 *
 * Returns: String name of routing action
 */
const char *protocol_action_name(enum routing_action action);

/**
 * struct protocol_detection_stats - Userspace-compatible statistics
 * (exported to userspace with u64 counters)
 */
struct protocol_detection_stats {
	/* Per-protocol counters */
	u64 proto_detected[PROTO_MAX];
	u64 proto_errors[PROTO_MAX];

	/* Detection method statistics */
	u64 method_port_hits;
	u64 method_pattern_hits;
	u64 method_heuristic_hits;
	u64 method_dpi_hits;
	u64 method_sni_hits;
	u64 method_handshake_hits;

	/* Routing statistics */
	u64 routed_proxy;
	u64 routed_direct;
	u64 routed_blocked;

	/* Performance metrics */
	u64 total_packets;
	u64 total_inspections;
	u64 cache_hits;
	u64 cache_misses;
};

/**
 * protocol_detect_get_stats() - Get current statistics
 * @ctx: Protocol detection context
 * @stats: Output buffer for statistics
 */
void protocol_detect_get_stats(struct protocol_detect_context *ctx,
			       struct protocol_detection_stats *stats);

/**
 * protocol_detect_reset_stats() - Reset all statistics
 * @ctx: Protocol detection context
 */
void protocol_detect_reset_stats(struct protocol_detect_context *ctx);

/**
 * protocol_detect_flush_cache() - Flush connection state cache
 * @ctx: Protocol detection context
 */
void protocol_detect_flush_cache(struct protocol_detect_context *ctx);

#endif /* MUTEX_PROTOCOL_DETECT_H */
