/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX DNS Handling Module - Header File
 *
 * Provides intelligent DNS interception, caching, proxying, and leak prevention
 * for kernel-level proxy operations.
 *
 * Features:
 * - DNS request interception for processes with active proxy fd
 * - Per-fd DNS caching with LRU eviction
 * - DNS over proxy (SOCKS DNS) support
 * - DNS leak prevention
 * - Custom DNS server configuration per fd
 * - DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT) support
 * - DNS response validation
 * - Split-horizon DNS with per-fd rules
 * - Domain-based bypass rules
 * - DNS query logging
 *
 * Copyright (C) 2025 MUTEX Team
 */

#ifndef _MUTEX_DNS_H
#define _MUTEX_DNS_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/in6.h>

/* DNS Protocol Constants */
#define DNS_PORT			53
#define DNS_MAX_NAME_LEN		255
#define DNS_MAX_LABEL_LEN		63
#define DNS_HEADER_SIZE			12
#define DNS_MAX_PACKET_SIZE		512
#define DNS_EDNS0_MAX_SIZE		4096

/* DNS Cache Configuration */
#define DNS_CACHE_SIZE			1024
#define DNS_CACHE_BUCKETS		256
#define DNS_CACHE_MAX_TTL		86400	/* 24 hours */
#define DNS_CACHE_MIN_TTL		60	/* 1 minute */
#define DNS_CACHE_DEFAULT_TTL		300	/* 5 minutes */

/* DNS Query Types */
#define DNS_TYPE_A			1	/* IPv4 address */
#define DNS_TYPE_NS			2	/* Name server */
#define DNS_TYPE_CNAME			5	/* Canonical name */
#define DNS_TYPE_SOA			6	/* Start of authority */
#define DNS_TYPE_PTR			12	/* Pointer record */
#define DNS_TYPE_MX			15	/* Mail exchange */
#define DNS_TYPE_TXT			16	/* Text record */
#define DNS_TYPE_AAAA			28	/* IPv6 address */
#define DNS_TYPE_SRV			33	/* Service record */
#define DNS_TYPE_OPT			41	/* EDNS0 option */
#define DNS_TYPE_ANY			255	/* All records */

/* DNS Classes */
#define DNS_CLASS_IN			1	/* Internet */

/* DNS Response Codes */
#define DNS_RCODE_NOERROR		0	/* No error */
#define DNS_RCODE_FORMERR		1	/* Format error */
#define DNS_RCODE_SERVFAIL		2	/* Server failure */
#define DNS_RCODE_NXDOMAIN		3	/* Non-existent domain */
#define DNS_RCODE_NOTIMP		4	/* Not implemented */
#define DNS_RCODE_REFUSED		5	/* Query refused */

/* DNS Flags */
#define DNS_FLAG_QR			0x8000	/* Query/Response */
#define DNS_FLAG_AA			0x0400	/* Authoritative Answer */
#define DNS_FLAG_TC			0x0200	/* Truncated */
#define DNS_FLAG_RD			0x0100	/* Recursion Desired */
#define DNS_FLAG_RA			0x0080	/* Recursion Available */

/* DNS Transport Types */
#define DNS_TRANSPORT_UDP		0
#define DNS_TRANSPORT_TCP		1
#define DNS_TRANSPORT_DOH		2	/* DNS-over-HTTPS */
#define DNS_TRANSPORT_DOT		3	/* DNS-over-TLS */
#define DNS_TRANSPORT_SOCKS		4	/* DNS over SOCKS proxy */

/* DNS Query Flags */
#define DNS_QUERY_FLAG_CACHED		0x01
#define DNS_QUERY_FLAG_PROXIED		0x02
#define DNS_QUERY_FLAG_VALIDATED	0x04
#define DNS_QUERY_FLAG_LEAKED		0x08
#define DNS_QUERY_FLAG_BYPASS		0x10

/**
 * struct dns_header - DNS packet header (RFC 1035)
 * @id: Transaction ID
 * @flags: Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
 * @qdcount: Number of questions
 * @ancount: Number of answers
 * @nscount: Number of authority records
 * @arcount: Number of additional records
 */
struct dns_header {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
} __packed;

/**
 * struct dns_question - DNS question section
 * @qname: Domain name (variable length, null-terminated labels)
 * @qtype: Question type
 * @qclass: Question class
 */
struct dns_question {
	__be16 qtype;
	__be16 qclass;
} __packed;

/**
 * struct dns_rr - DNS resource record
 * @name: Domain name (variable length)
 * @type: Record type
 * @class: Record class
 * @ttl: Time to live
 * @rdlength: Resource data length
 * @rdata: Resource data (variable length)
 */
struct dns_rr {
	__be16 type;
	__be16 class;
	__be32 ttl;
	__be16 rdlength;
} __packed;

/**
 * struct dns_cache_entry - DNS cache entry
 * @hlist: Hash list node
 * @lru: LRU list node
 * @domain: Domain name (null-terminated)
 * @qtype: Query type
 * @addresses: Array of resolved addresses
 * @addr_count: Number of addresses
 * @ttl: Time to live (seconds)
 * @timestamp: Cache entry creation time (jiffies)
 * @hits: Number of cache hits
 * @flags: Entry flags
 */
struct dns_cache_entry {
	struct hlist_node hlist;
	struct list_head lru;
	char domain[DNS_MAX_NAME_LEN];
	u16 qtype;
	union {
		struct in_addr ipv4[8];
		struct in6_addr ipv6[8];
	} addresses;
	u8 addr_count;
	u32 ttl;
	unsigned long timestamp;
	atomic_t hits;
	u32 flags;
};

/**
 * struct dns_cache - DNS cache structure
 * @buckets: Hash table buckets
 * @lru_list: LRU eviction list
 * @lock: Cache lock
 * @size: Current cache size
 * @max_size: Maximum cache size
 * @hits: Total cache hits
 * @misses: Total cache misses
 * @evictions: Total evictions
 */
struct dns_cache {
	struct hlist_head buckets[DNS_CACHE_BUCKETS];
	struct list_head lru_list;
	spinlock_t lock;
	atomic_t size;
	u32 max_size;
	atomic64_t hits;
	atomic64_t misses;
	atomic64_t evictions;
};

/**
 * struct dns_server - DNS server configuration
 * @list: List node
 * @addr: Server address (IPv4 or IPv6)
 * @port: Server port
 * @transport: Transport type (UDP, TCP, DoH, DoT)
 * @priority: Server priority (lower is higher priority)
 * @failures: Failure count
 * @last_failure: Last failure timestamp
 * @is_ipv6: IPv6 flag
 */
struct dns_server {
	struct list_head list;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
	u16 port;
	u8 transport;
	u8 priority;
	atomic_t failures;
	unsigned long last_failure;
	bool is_ipv6;
};

/**
 * struct dns_bypass_rule - DNS bypass rule for specific domains
 * @list: List node
 * @domain: Domain pattern (supports wildcards: *.example.com)
 * @action: BYPASS or BLOCK
 * @hits: Number of hits
 */
struct dns_bypass_rule {
	struct list_head list;
	char domain[DNS_MAX_NAME_LEN];
	u8 action;
	atomic_t hits;
};

#define DNS_BYPASS_ACTION_ALLOW		0
#define DNS_BYPASS_ACTION_BLOCK		1

/**
 * struct dns_query_log - DNS query log entry
 * @list: List node
 * @timestamp: Query timestamp
 * @domain: Queried domain
 * @qtype: Query type
 * @response_code: DNS response code
 * @flags: Query flags
 * @latency_us: Query latency in microseconds
 */
struct dns_query_log {
	struct list_head list;
	ktime_t timestamp;
	char domain[DNS_MAX_NAME_LEN];
	u16 qtype;
	u8 response_code;
	u32 flags;
	u32 latency_us;
};

/**
 * struct dns_config - Per-fd DNS configuration
 * @servers: List of DNS servers
 * @bypass_rules: List of bypass rules
 * @cache: DNS cache
 * @leak_prevention: Enable DNS leak prevention
 * @proxy_dns: Use DNS over proxy (SOCKS DNS)
 * @validate_responses: Validate DNS responses
 * @log_queries: Log DNS queries
 * @default_transport: Default transport type
 * @custom_server_set: Custom DNS servers configured
 * @lock: Configuration lock
 */
struct dns_config {
	struct list_head servers;
	struct list_head bypass_rules;
	struct dns_cache cache;
	bool leak_prevention;
	bool proxy_dns;
	bool validate_responses;
	bool log_queries;
	u8 default_transport;
	bool custom_server_set;
	spinlock_t lock;
};

/**
 * struct dns_statistics - DNS statistics
 * @queries_total: Total queries processed
 * @queries_cached: Queries served from cache
 * @queries_proxied: Queries sent through proxy
 * @queries_leaked: Queries that leaked (bypassed proxy)
 * @queries_blocked: Queries blocked by rules
 * @queries_failed: Failed queries
 * @cache_hits: Cache hits
 * @cache_misses: Cache misses
 * @avg_latency_us: Average query latency
 * @doh_queries: DNS-over-HTTPS queries
 * @dot_queries: DNS-over-TLS queries
 * @socks_dns_queries: SOCKS DNS queries
 */
struct dns_statistics {
	atomic64_t queries_total;
	atomic64_t queries_cached;
	atomic64_t queries_proxied;
	atomic64_t queries_leaked;
	atomic64_t queries_blocked;
	atomic64_t queries_failed;
	atomic64_t cache_hits;
	atomic64_t cache_misses;
	atomic64_t avg_latency_us;
	atomic64_t doh_queries;
	atomic64_t dot_queries;
	atomic64_t socks_dns_queries;
};

/**
 * struct dns_context - DNS handling context
 * @config: DNS configuration
 * @query_log: List of query logs
 * @log_lock: Log lock
 * @log_size: Current log size
 * @max_log_size: Maximum log size
 * @stats: DNS statistics
 */
struct dns_context {
	struct dns_config config;
	struct list_head query_log;
	spinlock_t log_lock;
	atomic_t log_size;
	u32 max_log_size;
	struct dns_statistics stats;
};

/* DNS Cache Operations */
int dns_cache_init(struct dns_cache *cache, u32 max_size);
void dns_cache_destroy(struct dns_cache *cache);
struct dns_cache_entry *dns_cache_lookup(struct dns_cache *cache,
					  const char *domain, u16 qtype);
int dns_cache_insert(struct dns_cache *cache, const char *domain,
		     u16 qtype, const void *addresses, u8 addr_count,
		     u32 ttl, bool is_ipv6);
void dns_cache_evict_lru(struct dns_cache *cache);
void dns_cache_clear(struct dns_cache *cache);
void dns_cache_cleanup_expired(struct dns_cache *cache);

/* DNS Configuration Operations */
int dns_config_init(struct dns_config *config);
void dns_config_destroy(struct dns_config *config);
int dns_config_add_server(struct dns_config *config,
			   const void *addr, bool is_ipv6,
			   u16 port, u8 transport, u8 priority);
int dns_config_remove_server(struct dns_config *config,
			      const void *addr, bool is_ipv6);
int dns_config_add_bypass_rule(struct dns_config *config,
				const char *domain, u8 action);
int dns_config_remove_bypass_rule(struct dns_config *config,
				   const char *domain);
bool dns_config_check_bypass(struct dns_config *config,
			      const char *domain);

/* DNS Context Operations */
int dns_context_init(struct dns_context *ctx);
void dns_context_destroy(struct dns_context *ctx);

/* DNS Packet Processing */
int dns_parse_query(const u8 *data, size_t len, char *domain,
		    size_t domain_size, u16 *qtype);
int dns_build_query(u8 *buffer, size_t buffer_size,
		    const char *domain, u16 qtype, u16 txid);
int dns_parse_response(const u8 *data, size_t len,
		       void *addresses, u8 *addr_count,
		       u32 *ttl, bool *is_ipv6);
int dns_validate_response(const u8 *data, size_t len);

/* DNS Interception */
int dns_intercept_query(struct sk_buff *skb, struct dns_context *ctx);
int dns_intercept_response(struct sk_buff *skb, struct dns_context *ctx);

/* DNS Proxying */
int dns_proxy_query(struct dns_context *ctx, const char *domain,
		    u16 qtype, void *result, u8 *result_count,
		    bool *is_ipv6);
int dns_socks_query(struct dns_context *ctx, const char *domain,
		    u16 qtype, void *result, u8 *result_count,
		    bool *is_ipv6);

/* DNS Leak Prevention */
bool dns_check_leak(struct sk_buff *skb, struct dns_context *ctx);
int dns_block_leaked_query(struct sk_buff *skb);

/* DNS Query Logging */
int dns_log_query(struct dns_context *ctx, const char *domain,
		  u16 qtype, u8 response_code, u32 flags, u32 latency_us);
int dns_get_query_log(struct dns_context *ctx, char *buffer,
		      size_t buffer_size, u32 max_entries);

/* DNS Statistics */
void dns_stats_update_query(struct dns_statistics *stats, u32 flags,
			    u32 latency_us);
int dns_get_statistics(struct dns_context *ctx,
		       struct dns_statistics *stats);

/* DNS Helper Functions */
bool dns_is_valid_domain(const char *domain);
int dns_domain_match_pattern(const char *domain, const char *pattern);
u32 dns_hash_domain(const char *domain);
int dns_decode_name(const u8 *packet, size_t packet_len,
		    size_t offset, char *name, size_t name_size);
int dns_encode_name(const char *name, u8 *buffer, size_t buffer_size);

/* DNS Transport Selection */
struct dns_server *dns_select_server(struct dns_config *config);
int dns_send_query(struct dns_server *server, const u8 *query,
		   size_t query_len, u8 *response, size_t *response_len);

#endif /* _MUTEX_DNS_H */
