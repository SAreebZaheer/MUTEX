// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX DNS Handling Module - Implementation
 *
 * Provides intelligent DNS interception, caching, proxying, and leak prevention.
 *
 * Copyright (C) 2025 MUTEX Team
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/sock.h>

#include "mutex_dns.h"

/* ============================================================================
 * DNS Cache Operations
 * ============================================================================ */

/**
 * dns_cache_init - Initialize DNS cache
 * @cache: Cache structure to initialize
 * @max_size: Maximum number of cache entries
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_cache_init(struct dns_cache *cache, u32 max_size)
{
	int i;

	if (!cache || max_size == 0)
		return -EINVAL;

	/* Initialize hash table buckets */
	for (i = 0; i < DNS_CACHE_BUCKETS; i++)
		INIT_HLIST_HEAD(&cache->buckets[i]);

	/* Initialize LRU list */
	INIT_LIST_HEAD(&cache->lru_list);

	spin_lock_init(&cache->lock);
	atomic_set(&cache->size, 0);
	cache->max_size = max_size;
	atomic64_set(&cache->hits, 0);
	atomic64_set(&cache->misses, 0);
	atomic64_set(&cache->evictions, 0);

	pr_info("DNS cache initialized: max_size=%u\n", max_size);
	return 0;
}

/**
 * dns_cache_destroy - Destroy DNS cache
 * @cache: Cache structure to destroy
 */
void dns_cache_destroy(struct dns_cache *cache)
{
	struct dns_cache_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!cache)
		return;

	spin_lock(&cache->lock);

	/* Free all cache entries */
	for (i = 0; i < DNS_CACHE_BUCKETS; i++) {
		hlist_for_each_entry_safe(entry, tmp, &cache->buckets[i], hlist) {
			hlist_del(&entry->hlist);
			list_del(&entry->lru);
			kfree(entry);
		}
	}

	atomic_set(&cache->size, 0);
	spin_unlock(&cache->lock);

	pr_info("DNS cache destroyed\n");
}

/**
 * dns_hash_domain - Hash domain name for cache lookup
 * @domain: Domain name to hash
 *
 * Return: Hash value
 */
u32 dns_hash_domain(const char *domain)
{
	return jhash(domain, strlen(domain), 0) % DNS_CACHE_BUCKETS;
}

/**
 * dns_cache_lookup - Lookup domain in cache
 * @cache: Cache structure
 * @domain: Domain name to lookup
 * @qtype: Query type
 *
 * Return: Cache entry if found, NULL otherwise
 */
struct dns_cache_entry *dns_cache_lookup(struct dns_cache *cache,
					  const char *domain, u16 qtype)
{
	struct dns_cache_entry *entry;
	u32 hash;
	unsigned long now = jiffies;

	if (!cache || !domain)
		return NULL;

	hash = dns_hash_domain(domain);

	spin_lock(&cache->lock);

	hlist_for_each_entry(entry, &cache->buckets[hash], hlist) {
		/* Check if entry matches and is not expired */
		if (entry->qtype == qtype &&
		    strcmp(entry->domain, domain) == 0) {
			/* Check TTL */
			if (time_after(now, entry->timestamp + entry->ttl * HZ)) {
				/* Entry expired, remove it */
				hlist_del(&entry->hlist);
				list_del(&entry->lru);
				kfree(entry);
				atomic_dec(&cache->size);
				spin_unlock(&cache->lock);
				atomic64_inc(&cache->misses);
				return NULL;
			}

			/* Move to head of LRU list */
			list_move(&entry->lru, &cache->lru_list);
			atomic_inc(&entry->hits);
			atomic64_inc(&cache->hits);
			spin_unlock(&cache->lock);
			return entry;
		}
	}

	spin_unlock(&cache->lock);
	atomic64_inc(&cache->misses);
	return NULL;
}

/**
 * dns_cache_insert - Insert entry into cache
 * @cache: Cache structure
 * @domain: Domain name
 * @qtype: Query type
 * @addresses: Array of addresses
 * @addr_count: Number of addresses
 * @ttl: Time to live in seconds
 * @is_ipv6: IPv6 flag
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_cache_insert(struct dns_cache *cache, const char *domain,
		     u16 qtype, const void *addresses, u8 addr_count,
		     u32 ttl, bool is_ipv6)
{
	struct dns_cache_entry *entry;
	u32 hash;
	size_t addr_size;

	if (!cache || !domain || !addresses || addr_count == 0)
		return -EINVAL;

	/* Clamp TTL */
	if (ttl < DNS_CACHE_MIN_TTL)
		ttl = DNS_CACHE_MIN_TTL;
	else if (ttl > DNS_CACHE_MAX_TTL)
		ttl = DNS_CACHE_MAX_TTL;

	/* Allocate new entry */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	/* Initialize entry */
	strncpy(entry->domain, domain, DNS_MAX_NAME_LEN - 1);
	entry->domain[DNS_MAX_NAME_LEN - 1] = '\0';
	entry->qtype = qtype;
	entry->addr_count = min_t(u8, addr_count, 8);
	entry->ttl = ttl;
	entry->timestamp = jiffies;
	atomic_set(&entry->hits, 0);
	entry->flags = 0;

	/* Copy addresses */
	addr_size = is_ipv6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	memcpy(&entry->addresses, addresses, addr_size * entry->addr_count);

	hash = dns_hash_domain(domain);

	spin_lock(&cache->lock);

	/* Evict if cache is full */
	while (atomic_read(&cache->size) >= cache->max_size)
		dns_cache_evict_lru(cache);

	/* Insert into hash table and LRU list */
	hlist_add_head(&entry->hlist, &cache->buckets[hash]);
	list_add(&entry->lru, &cache->lru_list);
	atomic_inc(&cache->size);

	spin_unlock(&cache->lock);

	pr_debug("DNS cache insert: domain=%s qtype=%u addr_count=%u ttl=%u\n",
		 domain, qtype, addr_count, ttl);
	return 0;
}

/**
 * dns_cache_evict_lru - Evict least recently used entry
 * @cache: Cache structure
 */
void dns_cache_evict_lru(struct dns_cache *cache)
{
	struct dns_cache_entry *entry;

	if (!cache || list_empty(&cache->lru_list))
		return;

	/* Get LRU entry (tail of list) */
	entry = list_last_entry(&cache->lru_list, struct dns_cache_entry, lru);

	/* Remove from hash table and LRU list */
	hlist_del(&entry->hlist);
	list_del(&entry->lru);
	atomic_dec(&cache->size);
	atomic64_inc(&cache->evictions);

	kfree(entry);
}

/**
 * dns_cache_clear - Clear all cache entries
 * @cache: Cache structure
 */
void dns_cache_clear(struct dns_cache *cache)
{
	struct dns_cache_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!cache)
		return;

	spin_lock(&cache->lock);

	for (i = 0; i < DNS_CACHE_BUCKETS; i++) {
		hlist_for_each_entry_safe(entry, tmp, &cache->buckets[i], hlist) {
			hlist_del(&entry->hlist);
			list_del(&entry->lru);
			kfree(entry);
		}
	}

	atomic_set(&cache->size, 0);
	spin_unlock(&cache->lock);
}

/**
 * dns_cache_cleanup_expired - Remove expired entries from cache
 * @cache: Cache structure
 */
void dns_cache_cleanup_expired(struct dns_cache *cache)
{
	struct dns_cache_entry *entry;
	struct hlist_node *tmp;
	unsigned long now = jiffies;
	int i;

	if (!cache)
		return;

	spin_lock(&cache->lock);

	for (i = 0; i < DNS_CACHE_BUCKETS; i++) {
		hlist_for_each_entry_safe(entry, tmp, &cache->buckets[i], hlist) {
			if (time_after(now, entry->timestamp + entry->ttl * HZ)) {
				hlist_del(&entry->hlist);
				list_del(&entry->lru);
				kfree(entry);
				atomic_dec(&cache->size);
			}
		}
	}

	spin_unlock(&cache->lock);
}

/* ============================================================================
 * DNS Configuration Operations
 * ============================================================================ */

/**
 * dns_config_init - Initialize DNS configuration
 * @config: Configuration structure to initialize
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_config_init(struct dns_config *config)
{
	int ret;

	if (!config)
		return -EINVAL;

	INIT_LIST_HEAD(&config->servers);
	INIT_LIST_HEAD(&config->bypass_rules);

	ret = dns_cache_init(&config->cache, DNS_CACHE_SIZE);
	if (ret < 0)
		return ret;

	config->leak_prevention = true;
	config->proxy_dns = false;
	config->validate_responses = true;
	config->log_queries = false;
	config->default_transport = DNS_TRANSPORT_UDP;
	config->custom_server_set = false;

	spin_lock_init(&config->lock);

	pr_info("DNS config initialized\n");
	return 0;
}

/**
 * dns_config_destroy - Destroy DNS configuration
 * @config: Configuration structure to destroy
 */
void dns_config_destroy(struct dns_config *config)
{
	struct dns_server *server, *tmp_server;
	struct dns_bypass_rule *rule, *tmp_rule;

	if (!config)
		return;

	spin_lock(&config->lock);

	/* Free server list */
	list_for_each_entry_safe(server, tmp_server, &config->servers, list) {
		list_del(&server->list);
		kfree(server);
	}

	/* Free bypass rules */
	list_for_each_entry_safe(rule, tmp_rule, &config->bypass_rules, list) {
		list_del(&rule->list);
		kfree(rule);
	}

	spin_unlock(&config->lock);

	/* Destroy cache */
	dns_cache_destroy(&config->cache);

	pr_info("DNS config destroyed\n");
}

/**
 * dns_config_add_server - Add DNS server to configuration
 * @config: Configuration structure
 * @addr: Server address
 * @is_ipv6: IPv6 flag
 * @port: Server port
 * @transport: Transport type
 * @priority: Server priority
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_config_add_server(struct dns_config *config,
			   const void *addr, bool is_ipv6,
			   u16 port, u8 transport, u8 priority)
{
	struct dns_server *server;

	if (!config || !addr)
		return -EINVAL;

	server = kzalloc(sizeof(*server), GFP_KERNEL);
	if (!server)
		return -ENOMEM;

	if (is_ipv6)
		memcpy(&server->addr.ipv6, addr, sizeof(struct in6_addr));
	else
		memcpy(&server->addr.ipv4, addr, sizeof(struct in_addr));

	server->port = port ? port : DNS_PORT;
	server->transport = transport;
	server->priority = priority;
	server->is_ipv6 = is_ipv6;
	atomic_set(&server->failures, 0);
	server->last_failure = 0;

	spin_lock(&config->lock);
	list_add_tail(&server->list, &config->servers);
	config->custom_server_set = true;
	spin_unlock(&config->lock);

	pr_info("DNS server added: port=%u transport=%u priority=%u\n",
		port, transport, priority);
	return 0;
}

/**
 * dns_config_remove_server - Remove DNS server from configuration
 * @config: Configuration structure
 * @addr: Server address
 * @is_ipv6: IPv6 flag
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_config_remove_server(struct dns_config *config,
			      const void *addr, bool is_ipv6)
{
	struct dns_server *server, *tmp;
	int found = 0;

	if (!config || !addr)
		return -EINVAL;

	spin_lock(&config->lock);

	list_for_each_entry_safe(server, tmp, &config->servers, list) {
		if (server->is_ipv6 == is_ipv6) {
			if (is_ipv6 && memcmp(&server->addr.ipv6, addr,
					      sizeof(struct in6_addr)) == 0) {
				list_del(&server->list);
				kfree(server);
				found = 1;
				break;
			} else if (!is_ipv6 && memcmp(&server->addr.ipv4, addr,
						       sizeof(struct in_addr)) == 0) {
				list_del(&server->list);
				kfree(server);
				found = 1;
				break;
			}
		}
	}

	if (list_empty(&config->servers))
		config->custom_server_set = false;

	spin_unlock(&config->lock);

	return found ? 0 : -ENOENT;
}

/**
 * dns_config_add_bypass_rule - Add domain bypass rule
 * @config: Configuration structure
 * @domain: Domain pattern (supports wildcards)
 * @action: ALLOW or BLOCK
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_config_add_bypass_rule(struct dns_config *config,
				const char *domain, u8 action)
{
	struct dns_bypass_rule *rule;

	if (!config || !domain)
		return -EINVAL;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	strncpy(rule->domain, domain, DNS_MAX_NAME_LEN - 1);
	rule->domain[DNS_MAX_NAME_LEN - 1] = '\0';
	rule->action = action;
	atomic_set(&rule->hits, 0);

	spin_lock(&config->lock);
	list_add_tail(&rule->list, &config->bypass_rules);
	spin_unlock(&config->lock);

	pr_info("DNS bypass rule added: domain=%s action=%u\n", domain, action);
	return 0;
}

/**
 * dns_config_remove_bypass_rule - Remove domain bypass rule
 * @config: Configuration structure
 * @domain: Domain pattern
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_config_remove_bypass_rule(struct dns_config *config,
				   const char *domain)
{
	struct dns_bypass_rule *rule, *tmp;
	int found = 0;

	if (!config || !domain)
		return -EINVAL;

	spin_lock(&config->lock);

	list_for_each_entry_safe(rule, tmp, &config->bypass_rules, list) {
		if (strcmp(rule->domain, domain) == 0) {
			list_del(&rule->list);
			kfree(rule);
			found = 1;
			break;
		}
	}

	spin_unlock(&config->lock);

	return found ? 0 : -ENOENT;
}

/**
 * dns_domain_match_pattern - Match domain against pattern with wildcards
 * @domain: Domain name to match
 * @pattern: Pattern (supports * wildcard)
 *
 * Return: 1 if matches, 0 otherwise
 */
int dns_domain_match_pattern(const char *domain, const char *pattern)
{
	if (!domain || !pattern)
		return 0;

	/* Exact match */
	if (strcmp(domain, pattern) == 0)
		return 1;

	/* Wildcard match: *.example.com matches subdomain.example.com */
	if (pattern[0] == '*' && pattern[1] == '.') {
		const char *suffix = pattern + 2;
		size_t suffix_len = strlen(suffix);
		size_t domain_len = strlen(domain);

		/* Domain must be longer than suffix to have a subdomain */
		if (domain_len > suffix_len &&
		    strcmp(domain + domain_len - suffix_len, suffix) == 0) {
			/* Check that there's a dot before the suffix */
			if (domain[domain_len - suffix_len - 1] == '.')
				return 1;
		}
	}

	return 0;
}

/**
 * dns_config_check_bypass - Check if domain should bypass proxy
 * @config: Configuration structure
 * @domain: Domain name
 *
 * Return: true if should bypass, false otherwise
 */
bool dns_config_check_bypass(struct dns_config *config, const char *domain)
{
	struct dns_bypass_rule *rule;
	bool bypass = false;

	if (!config || !domain)
		return false;

	spin_lock(&config->lock);

	list_for_each_entry(rule, &config->bypass_rules, list) {
		if (dns_domain_match_pattern(domain, rule->domain)) {
			atomic_inc(&rule->hits);
			bypass = (rule->action == DNS_BYPASS_ACTION_ALLOW);
			break;
		}
	}

	spin_unlock(&config->lock);

	return bypass;
}

/* ============================================================================
 * DNS Context Operations
 * ============================================================================ */

/**
 * dns_context_init - Initialize DNS context
 * @ctx: Context structure to initialize
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_context_init(struct dns_context *ctx)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = dns_config_init(&ctx->config);
	if (ret < 0)
		return ret;

	INIT_LIST_HEAD(&ctx->query_log);
	spin_lock_init(&ctx->log_lock);
	atomic_set(&ctx->log_size, 0);
	ctx->max_log_size = 1000;

	/* Initialize statistics */
	atomic64_set(&ctx->stats.queries_total, 0);
	atomic64_set(&ctx->stats.queries_cached, 0);
	atomic64_set(&ctx->stats.queries_proxied, 0);
	atomic64_set(&ctx->stats.queries_leaked, 0);
	atomic64_set(&ctx->stats.queries_blocked, 0);
	atomic64_set(&ctx->stats.queries_failed, 0);
	atomic64_set(&ctx->stats.cache_hits, 0);
	atomic64_set(&ctx->stats.cache_misses, 0);
	atomic64_set(&ctx->stats.avg_latency_us, 0);
	atomic64_set(&ctx->stats.doh_queries, 0);
	atomic64_set(&ctx->stats.dot_queries, 0);
	atomic64_set(&ctx->stats.socks_dns_queries, 0);

	pr_info("DNS context initialized\n");
	return 0;
}

/**
 * dns_context_destroy - Destroy DNS context
 * @ctx: Context structure to destroy
 */
void dns_context_destroy(struct dns_context *ctx)
{
	struct dns_query_log *log, *tmp;

	if (!ctx)
		return;

	/* Free query log */
	spin_lock(&ctx->log_lock);
	list_for_each_entry_safe(log, tmp, &ctx->query_log, list) {
		list_del(&log->list);
		kfree(log);
	}
	spin_unlock(&ctx->log_lock);

	/* Destroy configuration */
	dns_config_destroy(&ctx->config);

	pr_info("DNS context destroyed\n");
}

/* ============================================================================
 * DNS Packet Processing
 * ============================================================================ */

/**
 * dns_is_valid_domain - Validate domain name
 * @domain: Domain name to validate
 *
 * Return: true if valid, false otherwise
 */
bool dns_is_valid_domain(const char *domain)
{
	size_t len;
	int label_len = 0;
	bool in_label = false;

	if (!domain)
		return false;

	len = strlen(domain);
	if (len == 0 || len > DNS_MAX_NAME_LEN)
		return false;

	/* Check each character */
	for (size_t i = 0; i < len; i++) {
		char c = domain[i];

		if (c == '.') {
			if (label_len == 0 || label_len > DNS_MAX_LABEL_LEN)
				return false;
			label_len = 0;
			in_label = false;
		} else if ((c >= 'a' && c <= 'z') ||
			   (c >= 'A' && c <= 'Z') ||
			   (c >= '0' && c <= '9') ||
			   c == '-' || c == '_') {
			label_len++;
			in_label = true;

			/* Label can't start or end with hyphen */
			if (c == '-' && (label_len == 1 || i + 1 >= len || domain[i + 1] == '.'))
				return false;
		} else {
			return false;
		}
	}

	/* Check last label */
	if (label_len == 0 || label_len > DNS_MAX_LABEL_LEN)
		return false;

	return true;
}

/**
 * dns_decode_name - Decode DNS name from packet
 * @packet: DNS packet
 * @packet_len: Packet length
 * @offset: Offset to name in packet
 * @name: Buffer to store decoded name
 * @name_size: Size of name buffer
 *
 * Return: Number of bytes read, or negative error code
 */
int dns_decode_name(const u8 *packet, size_t packet_len,
		    size_t offset, char *name, size_t name_size)
{
	size_t pos = offset;
	size_t name_pos = 0;
	int jumps = 0;
	size_t original_pos = 0;

	if (!packet || !name || packet_len < DNS_HEADER_SIZE)
		return -EINVAL;

	while (pos < packet_len && jumps < 10) {
		u8 len = packet[pos];

		/* End of name */
		if (len == 0) {
			if (name_pos > 0 && name_pos < name_size)
				name[name_pos - 1] = '\0'; /* Remove trailing dot */
			else if (name_pos < name_size)
				name[0] = '\0';

			return original_pos ? original_pos - offset + 1 : pos - offset + 1;
		}

		/* Compression pointer */
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= packet_len)
				return -EINVAL;

			if (original_pos == 0)
				original_pos = pos + 2;

			pos = ((len & 0x3F) << 8) | packet[pos + 1];
			jumps++;
			continue;
		}

		/* Regular label */
		if (len > DNS_MAX_LABEL_LEN || pos + len + 1 > packet_len)
			return -EINVAL;

		if (name_pos + len + 1 >= name_size)
			return -ENOMEM;

		pos++;
		memcpy(name + name_pos, packet + pos, len);
		name_pos += len;
		name[name_pos++] = '.';
		pos += len;
	}

	return -EINVAL;
}

/**
 * dns_encode_name - Encode domain name for DNS packet
 * @name: Domain name to encode
 * @buffer: Buffer to store encoded name
 * @buffer_size: Size of buffer
 *
 * Return: Number of bytes written, or negative error code
 */
int dns_encode_name(const char *name, u8 *buffer, size_t buffer_size)
{
	size_t pos = 0;
	size_t label_start = 0;
	size_t i = 0;
	size_t name_len;

	if (!name || !buffer || buffer_size == 0)
		return -EINVAL;

	name_len = strlen(name);
	if (name_len == 0 || name_len > DNS_MAX_NAME_LEN)
		return -EINVAL;

	while (i <= name_len) {
		if (name[i] == '.' || name[i] == '\0') {
			size_t label_len = i - label_start;

			if (label_len == 0) {
				if (name[i] == '\0')
					break;
				label_start = i + 1;
				i++;
				continue;
			}

			if (label_len > DNS_MAX_LABEL_LEN)
				return -EINVAL;

			if (pos + label_len + 1 >= buffer_size)
				return -ENOMEM;

			buffer[pos++] = label_len;
			memcpy(buffer + pos, name + label_start, label_len);
			pos += label_len;
			label_start = i + 1;
		}
		i++;
	}

	if (pos >= buffer_size)
		return -ENOMEM;

	buffer[pos++] = 0; /* Null terminator */
	return pos;
}

/**
 * dns_parse_query - Parse DNS query packet
 * @data: DNS packet data
 * @len: Packet length
 * @domain: Buffer to store domain name
 * @domain_size: Size of domain buffer
 * @qtype: Pointer to store query type
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_parse_query(const u8 *data, size_t len, char *domain,
		    size_t domain_size, u16 *qtype)
{
	struct dns_header *header;
	int name_len;

	if (!data || len < DNS_HEADER_SIZE || !domain || !qtype)
		return -EINVAL;

	header = (struct dns_header *)data;

	/* Check if this is a query */
	if (ntohs(header->flags) & DNS_FLAG_QR)
		return -EINVAL;

	/* Must have at least one question */
	if (ntohs(header->qdcount) == 0)
		return -EINVAL;

	/* Decode domain name */
	name_len = dns_decode_name(data, len, DNS_HEADER_SIZE,
				    domain, domain_size);
	if (name_len < 0)
		return name_len;

	/* Parse question */
	if (DNS_HEADER_SIZE + name_len + 4 > len)
		return -EINVAL;

	*qtype = ntohs(*(u16 *)(data + DNS_HEADER_SIZE + name_len));

	return 0;
}

/**
 * dns_build_query - Build DNS query packet
 * @buffer: Buffer to store query
 * @buffer_size: Size of buffer
 * @domain: Domain name to query
 * @qtype: Query type
 * @txid: Transaction ID
 *
 * Return: Query length on success, negative error code on failure
 */
int dns_build_query(u8 *buffer, size_t buffer_size,
		    const char *domain, u16 qtype, u16 txid)
{
	struct dns_header *header;
	int name_len;
	struct dns_question *question;
	size_t total_len;

	if (!buffer || !domain || buffer_size < DNS_MAX_PACKET_SIZE)
		return -EINVAL;

	/* Build header */
	header = (struct dns_header *)buffer;
	header->id = htons(txid);
	header->flags = htons(DNS_FLAG_RD); /* Recursion desired */
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	/* Encode domain name */
	name_len = dns_encode_name(domain, buffer + DNS_HEADER_SIZE,
				    buffer_size - DNS_HEADER_SIZE);
	if (name_len < 0)
		return name_len;

	/* Add question section */
	question = (struct dns_question *)(buffer + DNS_HEADER_SIZE + name_len);
	question->qtype = htons(qtype);
	question->qclass = htons(DNS_CLASS_IN);

	total_len = DNS_HEADER_SIZE + name_len + sizeof(struct dns_question);
	return total_len;
}

/**
 * dns_parse_response - Parse DNS response packet
 * @data: DNS packet data
 * @len: Packet length
 * @addresses: Buffer to store addresses
 * @addr_count: Pointer to store address count
 * @ttl: Pointer to store TTL
 * @is_ipv6: Pointer to store IPv6 flag
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_parse_response(const u8 *data, size_t len,
		       void *addresses, u8 *addr_count,
		       u32 *ttl, bool *is_ipv6)
{
	struct dns_header *header;
	u16 ancount;
	size_t pos;
	int name_len;
	char domain[DNS_MAX_NAME_LEN];
	u8 count = 0;
	u32 min_ttl = DNS_CACHE_MAX_TTL;

	if (!data || len < DNS_HEADER_SIZE || !addresses || !addr_count)
		return -EINVAL;

	header = (struct dns_header *)data;

	/* Check if this is a response */
	if (!(ntohs(header->flags) & DNS_FLAG_QR))
		return -EINVAL;

	/* Check response code */
	if ((ntohs(header->flags) & 0x0F) != DNS_RCODE_NOERROR)
		return -ENOENT;

	ancount = ntohs(header->ancount);
	if (ancount == 0)
		return -ENOENT;

	/* Skip question section */
	name_len = dns_decode_name(data, len, DNS_HEADER_SIZE,
				    domain, sizeof(domain));
	if (name_len < 0)
		return name_len;

	pos = DNS_HEADER_SIZE + name_len + 4; /* +4 for qtype and qclass */

	/* Parse answer section */
	for (u16 i = 0; i < ancount && count < 8; i++) {
		struct dns_rr *rr;
		u16 rr_type;
		u32 rr_ttl;
		u16 rdlength;

		/* Skip name */
		name_len = dns_decode_name(data, len, pos, domain, sizeof(domain));
		if (name_len < 0)
			break;

		pos += name_len;

		if (pos + sizeof(struct dns_rr) > len)
			break;

		rr = (struct dns_rr *)(data + pos);
		rr_type = ntohs(rr->type);
		rr_ttl = ntohl(rr->ttl);
		rdlength = ntohs(rr->rdlength);

		pos += sizeof(struct dns_rr);

		if (pos + rdlength > len)
			break;

		/* Extract IPv4 or IPv6 address */
		if (rr_type == DNS_TYPE_A && rdlength == 4) {
			struct in_addr *ipv4 = (struct in_addr *)addresses;
			memcpy(&ipv4[count], data + pos, 4);
			count++;
			if (is_ipv6)
				*is_ipv6 = false;
			if (rr_ttl < min_ttl)
				min_ttl = rr_ttl;
		} else if (rr_type == DNS_TYPE_AAAA && rdlength == 16) {
			struct in6_addr *ipv6 = (struct in6_addr *)addresses;
			memcpy(&ipv6[count], data + pos, 16);
			count++;
			if (is_ipv6)
				*is_ipv6 = true;
			if (rr_ttl < min_ttl)
				min_ttl = rr_ttl;
		}

		pos += rdlength;
	}

	*addr_count = count;
	if (ttl)
		*ttl = min_ttl;

	return count > 0 ? 0 : -ENOENT;
}

/**
 * dns_validate_response - Validate DNS response packet
 * @data: DNS packet data
 * @len: Packet length
 *
 * Return: 0 if valid, negative error code otherwise
 */
int dns_validate_response(const u8 *data, size_t len)
{
	struct dns_header *header;

	if (!data || len < DNS_HEADER_SIZE)
		return -EINVAL;

	header = (struct dns_header *)data;

	/* Must be a response */
	if (!(ntohs(header->flags) & DNS_FLAG_QR))
		return -EINVAL;

	/* Check for valid response code */
	u8 rcode = ntohs(header->flags) & 0x0F;
	if (rcode > DNS_RCODE_REFUSED)
		return -EINVAL;

	return 0;
}

/* ============================================================================
 * DNS Query Logging
 * ============================================================================ */

/**
 * dns_log_query - Log DNS query
 * @ctx: DNS context
 * @domain: Queried domain
 * @qtype: Query type
 * @response_code: DNS response code
 * @flags: Query flags
 * @latency_us: Query latency in microseconds
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_log_query(struct dns_context *ctx, const char *domain,
		  u16 qtype, u8 response_code, u32 flags, u32 latency_us)
{
	struct dns_query_log *log;

	if (!ctx || !domain || !ctx->config.log_queries)
		return 0;

	log = kzalloc(sizeof(*log), GFP_ATOMIC);
	if (!log)
		return -ENOMEM;

	log->timestamp = ktime_get();
	strncpy(log->domain, domain, DNS_MAX_NAME_LEN - 1);
	log->domain[DNS_MAX_NAME_LEN - 1] = '\0';
	log->qtype = qtype;
	log->response_code = response_code;
	log->flags = flags;
	log->latency_us = latency_us;

	spin_lock(&ctx->log_lock);

	/* Evict oldest entry if log is full */
	while (atomic_read(&ctx->log_size) >= ctx->max_log_size) {
		struct dns_query_log *old = list_first_entry(&ctx->query_log,
							      struct dns_query_log,
							      list);
		list_del(&old->list);
		kfree(old);
		atomic_dec(&ctx->log_size);
	}

	list_add_tail(&log->list, &ctx->query_log);
	atomic_inc(&ctx->log_size);

	spin_unlock(&ctx->log_lock);

	return 0;
}

/**
 * dns_get_query_log - Get DNS query log
 * @ctx: DNS context
 * @buffer: Buffer to store log
 * @buffer_size: Size of buffer
 * @max_entries: Maximum number of entries to return
 *
 * Return: Number of bytes written, or negative error code
 */
int dns_get_query_log(struct dns_context *ctx, char *buffer,
		      size_t buffer_size, u32 max_entries)
{
	struct dns_query_log *log;
	size_t pos = 0;
	u32 count = 0;

	if (!ctx || !buffer)
		return -EINVAL;

	spin_lock(&ctx->log_lock);

	list_for_each_entry(log, &ctx->query_log, list) {
		int written;

		if (count >= max_entries)
			break;

		written = snprintf(buffer + pos, buffer_size - pos,
				   "%lld,%s,%u,%u,%u,%u\n",
				   ktime_to_ms(log->timestamp),
				   log->domain, log->qtype,
				   log->response_code, log->flags,
				   log->latency_us);

		if (written < 0 || pos + written >= buffer_size)
			break;

		pos += written;
		count++;
	}

	spin_unlock(&ctx->log_lock);

	return pos;
}

/* ============================================================================
 * DNS Statistics
 * ============================================================================ */

/**
 * dns_stats_update_query - Update DNS statistics
 * @stats: Statistics structure
 * @flags: Query flags
 * @latency_us: Query latency in microseconds
 */
void dns_stats_update_query(struct dns_statistics *stats, u32 flags,
			    u32 latency_us)
{
	if (!stats)
		return;

	atomic64_inc(&stats->queries_total);

	if (flags & DNS_QUERY_FLAG_CACHED)
		atomic64_inc(&stats->queries_cached);
	if (flags & DNS_QUERY_FLAG_PROXIED)
		atomic64_inc(&stats->queries_proxied);
	if (flags & DNS_QUERY_FLAG_LEAKED)
		atomic64_inc(&stats->queries_leaked);

	/* Update average latency */
	atomic64_set(&stats->avg_latency_us, latency_us);
}

/**
 * dns_get_statistics - Get DNS statistics
 * @ctx: DNS context
 * @stats: Buffer to store statistics
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_get_statistics(struct dns_context *ctx,
		       struct dns_statistics *stats)
{
	if (!ctx || !stats)
		return -EINVAL;

	memcpy(stats, &ctx->stats, sizeof(*stats));
	return 0;
}

/* ============================================================================
 * DNS Interception (Stub implementations)
 * ============================================================================ */

/**
 * dns_intercept_query - Intercept DNS query
 * @skb: Socket buffer
 * @ctx: DNS context
 *
 * Return: 0 to allow packet, negative to drop
 */
int dns_intercept_query(struct sk_buff *skb, struct dns_context *ctx)
{
	/* Stub implementation - would integrate with netfilter hooks */
	return 0;
}

/**
 * dns_intercept_response - Intercept DNS response
 * @skb: Socket buffer
 * @ctx: DNS context
 *
 * Return: 0 to allow packet, negative to drop
 */
int dns_intercept_response(struct sk_buff *skb, struct dns_context *ctx)
{
	/* Stub implementation - would integrate with netfilter hooks */
	return 0;
}

/* ============================================================================
 * DNS Proxying (Stub implementations)
 * ============================================================================ */

/**
 * dns_proxy_query - Proxy DNS query through configured servers
 * @ctx: DNS context
 * @domain: Domain to query
 * @qtype: Query type
 * @result: Buffer to store result
 * @result_count: Pointer to store result count
 * @is_ipv6: Pointer to store IPv6 flag
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_proxy_query(struct dns_context *ctx, const char *domain,
		    u16 qtype, void *result, u8 *result_count,
		    bool *is_ipv6)
{
	/* Stub implementation - would send query to DNS servers */
	return -ENOSYS;
}

/**
 * dns_socks_query - Query DNS through SOCKS proxy
 * @ctx: DNS context
 * @domain: Domain to query
 * @qtype: Query type
 * @result: Buffer to store result
 * @result_count: Pointer to store result count
 * @is_ipv6: Pointer to store IPv6 flag
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_socks_query(struct dns_context *ctx, const char *domain,
		    u16 qtype, void *result, u8 *result_count,
		    bool *is_ipv6)
{
	/* Stub implementation - would send query through SOCKS proxy */
	if (ctx && ctx->config.proxy_dns) {
		atomic64_inc(&ctx->stats.socks_dns_queries);
	}
	return -ENOSYS;
}

/* ============================================================================
 * DNS Leak Prevention (Stub implementations)
 * ============================================================================ */

/**
 * dns_check_leak - Check if DNS query is leaking
 * @skb: Socket buffer
 * @ctx: DNS context
 *
 * Return: true if leaking, false otherwise
 */
bool dns_check_leak(struct sk_buff *skb, struct dns_context *ctx)
{
	/* Stub implementation - would check if query bypasses proxy */
	return false;
}

/**
 * dns_block_leaked_query - Block leaked DNS query
 * @skb: Socket buffer
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_block_leaked_query(struct sk_buff *skb)
{
	/* Stub implementation - would drop the packet */
	return 0;
}

/* ============================================================================
 * DNS Transport Selection
 * ============================================================================ */

/**
 * dns_select_server - Select DNS server from configuration
 * @config: DNS configuration
 *
 * Return: Selected server, or NULL if none available
 */
struct dns_server *dns_select_server(struct dns_config *config)
{
	struct dns_server *server, *best = NULL;
	u8 best_priority = 255;

	if (!config)
		return NULL;

	spin_lock(&config->lock);

	/* Select server with lowest priority and fewest failures */
	list_for_each_entry(server, &config->servers, list) {
		if (server->priority < best_priority ||
		    (server->priority == best_priority &&
		     (!best || atomic_read(&server->failures) <
		      atomic_read(&best->failures)))) {
			best = server;
			best_priority = server->priority;
		}
	}

	spin_unlock(&config->lock);

	return best;
}

/**
 * dns_send_query - Send DNS query to server
 * @server: DNS server
 * @query: Query packet
 * @query_len: Query length
 * @response: Buffer for response
 * @response_len: Pointer to response length
 *
 * Return: 0 on success, negative error code on failure
 */
int dns_send_query(struct dns_server *server, const u8 *query,
		   size_t query_len, u8 *response, size_t *response_len)
{
	/* Stub implementation - would send query via network */
	return -ENOSYS;
}
