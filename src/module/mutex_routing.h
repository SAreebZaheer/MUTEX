/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_routing.h - MUTEX advanced routing header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements advanced routing and policy-based routing for the
 * MUTEX proxy system, including multiple routing tables, policy rules,
 * load balancing, failover, and geographic routing.
 */

#ifndef _MUTEX_ROUTING_H
#define _MUTEX_ROUTING_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/rbtree.h>

/* Maximum routing tables */
#define ROUTING_MAX_TABLES		256
#define ROUTING_DEFAULT_TABLE		0
#define ROUTING_MAIN_TABLE		254
#define ROUTING_LOCAL_TABLE		255

/* Maximum routing rules */
#define ROUTING_MAX_RULES		1024

/* Maximum proxy servers for load balancing */
#define ROUTING_MAX_SERVERS		64

/* Routing cache size */
#define ROUTING_CACHE_SIZE		4096
#define ROUTING_CACHE_TIMEOUT_MS	60000	/* 1 minute */

/* Load balancing algorithms */
enum routing_lb_algorithm {
	ROUTING_LB_ROUND_ROBIN = 0,	/* Round-robin */
	ROUTING_LB_LEAST_CONN,		/* Least connections */
	ROUTING_LB_WEIGHTED,		/* Weighted distribution */
	ROUTING_LB_RANDOM,		/* Random selection */
	ROUTING_LB_HASH,		/* Hash-based */
	ROUTING_LB_LEAST_LATENCY,	/* Lowest latency */
};

/* Failover strategies */
enum routing_failover_strategy {
	ROUTING_FAILOVER_NONE = 0,	/* No failover */
	ROUTING_FAILOVER_PASSIVE,	/* Switch on failure */
	ROUTING_FAILOVER_ACTIVE,	/* Active health checks */
	ROUTING_FAILOVER_BACKUP,	/* Designated backup */
};

/* Routing policy match criteria */
enum routing_policy_match {
	ROUTING_MATCH_SRC_ADDR = (1 << 0),	/* Match source address */
	ROUTING_MATCH_DST_ADDR = (1 << 1),	/* Match destination address */
	ROUTING_MATCH_SRC_PORT = (1 << 2),	/* Match source port */
	ROUTING_MATCH_DST_PORT = (1 << 3),	/* Match destination port */
	ROUTING_MATCH_PROTOCOL = (1 << 4),	/* Match IP protocol */
	ROUTING_MATCH_MARK = (1 << 5),		/* Match packet mark */
	ROUTING_MATCH_UID = (1 << 6),		/* Match UID */
	ROUTING_MATCH_GID = (1 << 7),		/* Match GID */
	ROUTING_MATCH_IFACE = (1 << 8),		/* Match interface */
	ROUTING_MATCH_GEOIP = (1 << 9),		/* Match geographic location */
};

/* Routing actions */
enum routing_action {
	ROUTING_ACTION_FORWARD = 0,	/* Forward to proxy */
	ROUTING_ACTION_DROP,		/* Drop packet */
	ROUTING_ACTION_ACCEPT,		/* Accept without proxy */
	ROUTING_ACTION_REJECT,		/* Reject with ICMP */
	ROUTING_ACTION_TABLE,		/* Lookup in table */
};

/**
 * union routing_addr - IPv4/IPv6 address union
 * @v4: IPv4 address
 * @v6: IPv6 address
 */
union routing_addr {
	__be32 v4;
	struct in6_addr v6;
};

/**
 * struct routing_prefix - Network prefix for matching
 * @addr: Network address
 * @prefix_len: Prefix length (CIDR notation)
 * @is_ipv6: True if IPv6, false if IPv4
 */
struct routing_prefix {
	union routing_addr addr;
	__u8 prefix_len;
	bool is_ipv6;
};

/**
 * struct routing_server - Proxy server for routing
 * @id: Server identifier
 * @addr: Server address
 * @port: Server port
 * @weight: Weight for weighted load balancing
 * @priority: Priority (lower is higher priority)
 * @max_connections: Maximum concurrent connections
 * @current_connections: Current connection count
 * @total_connections: Total connections served
 * @failures: Number of consecutive failures
 * @last_failure: Timestamp of last failure
 * @avg_latency_ms: Average latency in milliseconds
 * @is_active: Server is active and available
 * @is_backup: Server is a backup
 * @health_check_enabled: Health checks enabled
 * @lock: Spinlock for this server
 * @list: List linkage
 *
 * Represents a proxy server in the routing system.
 */
struct routing_server {
	__u32 id;
	union routing_addr addr;
	__be16 port;
	__u32 weight;
	__u32 priority;
	__u32 max_connections;
	atomic_t current_connections;
	atomic64_t total_connections;
	atomic_t failures;
	unsigned long last_failure;
	__u32 avg_latency_ms;
	bool is_active;
	bool is_backup;
	bool health_check_enabled;
	bool is_ipv6;
	spinlock_t lock;
	struct list_head list;
};

/**
 * struct routing_server_group - Group of servers for load balancing
 * @name: Group name
 * @lb_algorithm: Load balancing algorithm
 * @failover_strategy: Failover strategy
 * @num_servers: Number of servers in group
 * @servers: List of servers
 * @next_rr_index: Next index for round-robin
 * @lock: Spinlock for this group
 * @list: List linkage
 *
 * A group of proxy servers with load balancing and failover.
 */
struct routing_server_group {
	char name[64];
	enum routing_lb_algorithm lb_algorithm;
	enum routing_failover_strategy failover_strategy;
	atomic_t num_servers;
	struct list_head servers;
	atomic_t next_rr_index;
	spinlock_t lock;
	struct list_head list;
};

/**
 * struct routing_policy_rule - Policy-based routing rule
 * @id: Rule identifier
 * @priority: Rule priority (lower is higher priority)
 * @match_flags: Match criteria flags
 * @src_prefix: Source address prefix
 * @dst_prefix: Destination address prefix
 * @src_port_min: Minimum source port
 * @src_port_max: Maximum source port
 * @dst_port_min: Minimum destination port
 * @dst_port_max: Maximum destination port
 * @protocol: IP protocol to match
 * @mark: Packet mark to match
 * @uid: UID to match
 * @gid: GID to match
 * @iface_name: Interface name to match
 * @geoip_country: Country code for GeoIP matching
 * @action: Routing action
 * @target_table: Target routing table (for TABLE action)
 * @target_group: Target server group
 * @packets_matched: Packets matched by this rule
 * @bytes_matched: Bytes matched by this rule
 * @last_match: Timestamp of last match
 * @enabled: Rule is enabled
 * @list: List linkage
 *
 * A policy-based routing rule for packet classification.
 */
struct routing_policy_rule {
	__u32 id;
	__u32 priority;
	__u32 match_flags;
	struct routing_prefix src_prefix;
	struct routing_prefix dst_prefix;
	__be16 src_port_min;
	__be16 src_port_max;
	__be16 dst_port_min;
	__be16 dst_port_max;
	__u8 protocol;
	__u32 mark;
	kuid_t uid;
	kgid_t gid;
	char iface_name[IFNAMSIZ];
	char geoip_country[4];
	enum routing_action action;
	__u32 target_table;
	struct routing_server_group *target_group;
	atomic64_t packets_matched;
	atomic64_t bytes_matched;
	unsigned long last_match;
	bool enabled;
	struct list_head list;
};

/**
 * struct routing_table_entry - Routing table entry
 * @dst_prefix: Destination prefix
 * @server_group: Target server group
 * @metric: Route metric
 * @flags: Route flags
 * @packets: Packets routed via this entry
 * @bytes: Bytes routed via this entry
 * @node: Red-black tree node
 *
 * An entry in a routing table.
 */
struct routing_table_entry {
	struct routing_prefix dst_prefix;
	struct routing_server_group *server_group;
	__u32 metric;
	__u32 flags;
	atomic64_t packets;
	atomic64_t bytes;
	struct rb_node node;
};

/**
 * struct routing_table - Routing table
 * @id: Table identifier
 * @name: Table name
 * @entries: Red-black tree of routing entries
 * @num_entries: Number of entries
 * @default_group: Default server group
 * @lock: RWLock for this table
 * @list: List linkage
 *
 * A routing table containing destination-based routes.
 */
struct routing_table {
	__u32 id;
	char name[64];
	struct rb_root entries;
	atomic_t num_entries;
	struct routing_server_group *default_group;
	rwlock_t lock;
	struct list_head list;
};

/**
 * struct routing_cache_entry - Cached routing decision
 * @key_hash: Hash of packet 5-tuple
 * @server: Selected server
 * @timestamp: Cache entry timestamp
 * @hits: Number of cache hits
 * @hlist: Hash list node
 *
 * A cached routing decision for fast lookup.
 */
struct routing_cache_entry {
	__u32 key_hash;
	struct routing_server *server;
	unsigned long timestamp;
	atomic_t hits;
	struct hlist_node hlist;
};

/**
 * struct routing_context - Routing context for packet classification
 * @skb: Socket buffer
 * @src_addr: Source address
 * @dst_addr: Destination address
 * @src_port: Source port
 * @dst_port: Destination port
 * @protocol: IP protocol
 * @mark: Packet mark
 * @uid: Owner UID
 * @gid: Owner GID
 * @iface: Input interface
 * @is_ipv6: IPv6 packet
 *
 * Context information for routing decision.
 */
struct routing_context {
	struct sk_buff *skb;
	union routing_addr src_addr;
	union routing_addr dst_addr;
	__be16 src_port;
	__be16 dst_port;
	__u8 protocol;
	__u32 mark;
	kuid_t uid;
	kgid_t gid;
	struct net_device *iface;
	bool is_ipv6;
};

/**
 * struct routing_statistics - Routing statistics
 * @packets_routed: Total packets routed
 * @bytes_routed: Total bytes routed
 * @cache_hits: Routing cache hits
 * @cache_misses: Routing cache misses
 * @policy_matches: Policy rule matches
 * @table_lookups: Routing table lookups
 * @lb_selections: Load balancer selections
 * @failovers: Failover events
 * @health_checks: Health check probes
 */
struct routing_statistics {
	atomic64_t packets_routed;
	atomic64_t bytes_routed;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic64_t policy_matches;
	atomic64_t table_lookups;
	atomic64_t lb_selections;
	atomic64_t failovers;
	atomic64_t health_checks;
};

/* Function prototypes */

/* Routing table management */
struct routing_table *routing_table_create(__u32 id, const char *name);
void routing_table_destroy(struct routing_table *table);
int routing_table_add_entry(struct routing_table *table,
			     const struct routing_prefix *prefix,
			     struct routing_server_group *group,
			     __u32 metric);
int routing_table_delete_entry(struct routing_table *table,
				const struct routing_prefix *prefix);
struct routing_table_entry *routing_table_lookup(struct routing_table *table,
						  const union routing_addr *addr,
						  bool is_ipv6);

/* Server group management */
struct routing_server_group *routing_group_create(const char *name,
						   enum routing_lb_algorithm lb_algo);
void routing_group_destroy(struct routing_server_group *group);
int routing_group_add_server(struct routing_server_group *group,
			      const union routing_addr *addr,
			      __be16 port,
			      __u32 weight,
			      bool is_ipv6);
int routing_group_remove_server(struct routing_server_group *group, __u32 id);
struct routing_server *routing_group_select_server(struct routing_server_group *group,
						    const struct routing_context *ctx);

/* Policy rule management */
struct routing_policy_rule *routing_rule_create(__u32 priority);
void routing_rule_destroy(struct routing_policy_rule *rule);
int routing_rule_add(struct routing_policy_rule *rule);
int routing_rule_delete(__u32 id);
struct routing_policy_rule *routing_rule_match(const struct routing_context *ctx);

/* Load balancing algorithms */
struct routing_server *routing_lb_round_robin(struct routing_server_group *group);
struct routing_server *routing_lb_least_conn(struct routing_server_group *group);
struct routing_server *routing_lb_weighted(struct routing_server_group *group);
struct routing_server *routing_lb_random(struct routing_server_group *group);
struct routing_server *routing_lb_hash(struct routing_server_group *group,
					const struct routing_context *ctx);
struct routing_server *routing_lb_least_latency(struct routing_server_group *group);

/* Failover management */
int routing_failover_mark_failed(struct routing_server *server);
int routing_failover_mark_recovered(struct routing_server *server);
bool routing_failover_is_available(struct routing_server *server);
struct routing_server *routing_failover_get_backup(struct routing_server_group *group);

/* Routing cache */
int routing_cache_init(void);
void routing_cache_destroy(void);
struct routing_server *routing_cache_lookup(const struct routing_context *ctx);
int routing_cache_insert(const struct routing_context *ctx,
			  struct routing_server *server);
void routing_cache_invalidate(void);

/* Routing decision */
struct routing_server *routing_lookup(const struct routing_context *ctx);
int routing_context_init(struct routing_context *ctx, struct sk_buff *skb);

/* Health checks */
int routing_health_check_init(void);
void routing_health_check_exit(void);
int routing_health_check_server(struct routing_server *server);

/* Statistics */
int routing_get_statistics(struct routing_statistics *stats);
void routing_reset_statistics(void);

/* GeoIP support */
int routing_geoip_init(void);
void routing_geoip_exit(void);
const char *routing_geoip_lookup(const union routing_addr *addr, bool is_ipv6);

/* Module initialization */
int routing_init(void);
void routing_exit(void);

#endif /* _MUTEX_ROUTING_H */
