/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Transparent Proxying Support
 *
 * This file defines structures and functions for transparent proxy
 * interception and redirection without application modification.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#ifndef _MUTEX_TRANSPARENT_H
#define _MUTEX_TRANSPARENT_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

/* ========== Forward Declarations ========== */

struct mutex_conn_entry;
struct socks_connection;
struct http_proxy_connection;

/* ========== Transparent Proxy Modes ========== */

enum transparent_mode {
	TRANSPARENT_MODE_DISABLED,      /* No transparent proxying */
	TRANSPARENT_MODE_PROCESS,       /* Per-process proxying */
	TRANSPARENT_MODE_GLOBAL,        /* System-wide proxying */
	TRANSPARENT_MODE_CGROUP         /* Cgroup-based proxying */
};

enum proxy_protocol_type {
	PROXY_PROTOCOL_AUTO,            /* Auto-detect */
	PROXY_PROTOCOL_SOCKS4,          /* SOCKS4 */
	PROXY_PROTOCOL_SOCKS5,          /* SOCKS5 */
	PROXY_PROTOCOL_HTTP,            /* HTTP CONNECT */
	PROXY_PROTOCOL_DIRECT           /* Direct connection (bypass) */
};

/* ========== Address Classification ========== */

enum addr_class {
	ADDR_CLASS_LOCAL,               /* Local/loopback address */
	ADDR_CLASS_PRIVATE,             /* Private network (RFC 1918) */
	ADDR_CLASS_PUBLIC,              /* Public internet address */
	ADDR_CLASS_MULTICAST,           /* Multicast address */
	ADDR_CLASS_LINK_LOCAL,          /* Link-local address */
	ADDR_CLASS_UNKNOWN              /* Unknown/invalid */
};

/* ========== Bypass Rules ========== */

#define BYPASS_RULE_MAX 32

enum bypass_match_type {
	BYPASS_MATCH_ADDR,              /* Match by address */
	BYPASS_MATCH_NETWORK,           /* Match by network/CIDR */
	BYPASS_MATCH_PORT,              /* Match by port */
	BYPASS_MATCH_PROTOCOL,          /* Match by protocol */
	BYPASS_MATCH_PROCESS            /* Match by process */
};

struct bypass_rule {
	enum bypass_match_type type;
	bool enabled;

	union {
		struct {
			__be32 addr;        /* IPv4 address */
			__be32 mask;        /* Network mask */
		} ipv4;

		struct {
			struct in6_addr addr;
			struct in6_addr mask;
		} ipv6;

		struct {
			__u16 port_start;
			__u16 port_end;
		} port;

		struct {
			__u8 protocol;      /* IPPROTO_TCP, IPPROTO_UDP */
		} proto;

		struct {
			pid_t pid;
			char comm[TASK_COMM_LEN];
		} process;
	} match;
};

struct bypass_rules {
	struct bypass_rule rules[BYPASS_RULE_MAX];
	int count;
	spinlock_t lock;

	/* Quick match flags */
	bool bypass_local;              /* Bypass local addresses */
	bool bypass_private;            /* Bypass private networks */
	bool bypass_multicast;          /* Bypass multicast */
};

/* ========== DNS Configuration ========== */

#define DNS_MAX_SERVERS 4

struct dns_config {
	bool intercept_dns;             /* Intercept DNS queries */
	bool proxy_dns;                 /* Send DNS through proxy */
	bool leak_prevention;           /* Prevent DNS leaks */

	/* DNS servers for direct queries */
	struct sockaddr_storage servers[DNS_MAX_SERVERS];
	int server_count;

	/* DNS cache (optional) */
	bool enable_cache;
	unsigned int cache_timeout;     /* Seconds */
};

/* ========== Transparent Proxy Configuration ========== */

struct transparent_config {
	enum transparent_mode mode;
	enum proxy_protocol_type protocol;

	/* Process filtering */
	pid_t target_pid;               /* 0 = any process */
	bool inherit_children;          /* Apply to child processes */

	/* Cgroup filtering (for TRANSPARENT_MODE_CGROUP) */
	char cgroup_path[256];

	/* Network filtering */
	struct bypass_rules bypass;

	/* DNS configuration */
	struct dns_config dns;

	/* Proxy selection */
	bool auto_select_proxy;         /* Auto-select SOCKS/HTTP */
	bool prefer_socks5;             /* Prefer SOCKS5 over HTTP */

	/* Connection settings */
	bool preserve_source_port;      /* Try to preserve source port */
	unsigned int connect_timeout;   /* Connection timeout (ms) */
	unsigned int idle_timeout;      /* Idle timeout (seconds) */

	/* Statistics */
	bool collect_stats;
	bool verbose_logging;
};

/* ========== NAT Translation ========== */

struct nat_entry {
	/* Original connection */
	__be32 orig_saddr;              /* Original source address */
	__be16 orig_sport;              /* Original source port */
	__be32 orig_daddr;              /* Original dest address */
	__be16 orig_dport;              /* Original dest port */

	/* Translated connection (to proxy) */
	__be32 trans_daddr;             /* Proxy address */
	__be16 trans_dport;             /* Proxy port */

	/* Reverse translation */
	__be32 proxy_reply_addr;        /* Proxy's reply source */
	__be16 proxy_reply_port;

	/* Metadata */
	__u8 protocol;                  /* IPPROTO_TCP or IPPROTO_UDP */
	unsigned long created;          /* Timestamp */
	unsigned long last_seen;        /* Last activity */

	/* Reference to connection tracking */
	struct mutex_conn_entry *conn;

	/* List linkage */
	struct hlist_node hnode;
	struct rcu_head rcu;
};

struct nat_table {
	struct hlist_head buckets[1024];
	spinlock_t locks[1024];
	atomic_t entry_count;
};

/* ========== Transparent Proxy Context ========== */

struct transparent_context {
	struct transparent_config config;

	/* NAT translation table */
	struct nat_table *nat;

	/* Proxy connections */
	enum proxy_protocol_type active_protocol;
	union {
		struct socks_connection *socks;
		struct http_proxy_connection *http;
	} proxy;

	/* Statistics */
	atomic64_t connections_intercepted;
	atomic64_t connections_proxied;
	atomic64_t connections_bypassed;
	atomic64_t connections_direct;
	atomic64_t dns_queries_intercepted;
	atomic64_t dns_queries_proxied;
	atomic64_t nat_entries_created;
	atomic64_t nat_lookups;
	atomic64_t bytes_proxied;
	atomic64_t errors;

	/* Timestamps */
	unsigned long created;
	unsigned long last_activity;

	/* Reference counting */
	refcount_t refcount;
	struct rcu_head rcu;
};

/* ========== Core Transparent Proxy Functions ========== */

/* Context Management */
struct transparent_context *transparent_context_alloc(void);
void transparent_context_free(struct transparent_context *ctx);
void transparent_context_get(struct transparent_context *ctx);
void transparent_context_put(struct transparent_context *ctx);

/* Configuration */
int transparent_set_config(struct transparent_context *ctx,
			   const struct transparent_config *config);
int transparent_get_config(struct transparent_context *ctx,
			   struct transparent_config *config);
int transparent_set_mode(struct transparent_context *ctx,
			 enum transparent_mode mode);

/* Bypass Rules */
int transparent_add_bypass_rule(struct transparent_context *ctx,
				const struct bypass_rule *rule);
int transparent_remove_bypass_rule(struct transparent_context *ctx, int index);
int transparent_clear_bypass_rules(struct transparent_context *ctx);
bool transparent_should_bypass(struct transparent_context *ctx,
			       struct sk_buff *skb);

/* Address Classification */
enum addr_class transparent_classify_ipv4(struct transparent_context *ctx,
					  __be32 addr);
enum addr_class transparent_classify_ipv6(struct transparent_context *ctx,
					  const struct in6_addr *addr);
bool transparent_is_local_address(__be32 addr);
bool transparent_is_private_address(__be32 addr);

/* Connection Interception */
int transparent_intercept_outbound(struct transparent_context *ctx,
				   struct sk_buff *skb,
				   struct mutex_conn_entry *conn);
int transparent_intercept_inbound(struct transparent_context *ctx,
				  struct sk_buff *skb,
				  struct mutex_conn_entry *conn);

/* Proxy Protocol Selection */
enum proxy_protocol_type transparent_select_protocol(
	struct transparent_context *ctx,
	struct sk_buff *skb);
int transparent_establish_proxy_connection(struct transparent_context *ctx,
					   struct mutex_conn_entry *conn,
					   enum proxy_protocol_type protocol);

/* DNS Handling */
int transparent_intercept_dns(struct transparent_context *ctx,
			      struct sk_buff *skb);
int transparent_proxy_dns_query(struct transparent_context *ctx,
				struct sk_buff *skb);
int transparent_handle_dns_response(struct transparent_context *ctx,
				    struct sk_buff *skb);

/* NAT Translation */
struct nat_entry *transparent_nat_create(struct transparent_context *ctx,
					 struct sk_buff *skb,
					 __be32 proxy_addr,
					 __be16 proxy_port);
struct nat_entry *transparent_nat_lookup_outbound(struct transparent_context *ctx,
						  __be32 saddr, __be16 sport,
						  __be32 daddr, __be16 dport,
						  __u8 protocol);
struct nat_entry *transparent_nat_lookup_inbound(struct transparent_context *ctx,
						 __be32 saddr, __be16 sport,
						 __be32 daddr, __be16 dport,
						 __u8 protocol);
void transparent_nat_delete(struct transparent_context *ctx,
			    struct nat_entry *entry);
void transparent_nat_cleanup(struct transparent_context *ctx);

/* Packet Rewriting */
int transparent_rewrite_outbound(struct transparent_context *ctx,
				 struct sk_buff *skb,
				 struct nat_entry *nat);
int transparent_rewrite_inbound(struct transparent_context *ctx,
				struct sk_buff *skb,
				struct nat_entry *nat);

/* Process Filtering */
bool transparent_should_intercept_process(struct transparent_context *ctx,
					  struct sk_buff *skb);
bool transparent_is_target_process(struct transparent_context *ctx, pid_t pid);
bool transparent_is_child_process(pid_t parent, pid_t child);

/* Integration Functions */
int transparent_attach_to_connection(struct mutex_conn_entry *conn,
				     struct transparent_context *ctx);
struct transparent_context *transparent_get_from_connection(
	struct mutex_conn_entry *conn);

/* Netfilter Hook Integration */
unsigned int transparent_nf_hook_in(void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state);
unsigned int transparent_nf_hook_out(void *priv,
				     struct sk_buff *skb,
				     const struct nf_hook_state *state);
unsigned int transparent_nf_hook_forward(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state);

/* ========== Statistics and Monitoring ========== */

struct transparent_statistics {
	atomic64_t total_intercepted;
	atomic64_t total_proxied;
	atomic64_t total_bypassed;
	atomic64_t total_direct;
	atomic64_t socks4_used;
	atomic64_t socks5_used;
	atomic64_t http_used;
	atomic64_t dns_intercepted;
	atomic64_t dns_proxied;
	atomic64_t nat_created;
	atomic64_t nat_expired;
	atomic64_t rewrite_errors;
	atomic64_t connection_errors;
};

extern struct transparent_statistics transparent_stats;

void transparent_stats_init(void);
void transparent_stats_print(void);
void transparent_stats_update(struct transparent_context *ctx);

/* ========== Utility Functions ========== */

const char *transparent_mode_name(enum transparent_mode mode);
const char *proxy_protocol_name(enum proxy_protocol_type protocol);
const char *addr_class_name(enum addr_class class);

/* Helper for checking if address is in network */
bool ipv4_addr_in_network(__be32 addr, __be32 network, __be32 mask);
bool ipv6_addr_in_network(const struct in6_addr *addr,
			  const struct in6_addr *network,
			  const struct in6_addr *mask);

/* ========== Module Initialization ========== */

int mutex_transparent_init(void);
void mutex_transparent_exit(void);

#endif /* _MUTEX_TRANSPARENT_H */
