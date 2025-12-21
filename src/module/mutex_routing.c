// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_routing.c - MUTEX advanced routing implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements advanced routing and policy-based routing for
 * the MUTEX proxy system.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "mutex_routing.h"

/* Global routing tables list */
static LIST_HEAD(routing_tables);
static DEFINE_SPINLOCK(routing_tables_lock);

/* Global server groups list */
static LIST_HEAD(routing_groups);
static DEFINE_SPINLOCK(routing_groups_lock);

/* Global policy rules list (sorted by priority) */
static LIST_HEAD(routing_rules);
static DEFINE_SPINLOCK(routing_rules_lock);

/* Routing cache */
static struct hlist_head *routing_cache;
static DEFINE_SPINLOCK(routing_cache_lock);

/* Global statistics */
static struct routing_statistics routing_stats;

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * routing_addr_match - Check if address matches prefix
 * @addr: Address to check
 * @prefix: Prefix to match against
 *
 * Return: true if match, false otherwise
 */
static bool routing_addr_match(const union routing_addr *addr,
				const struct routing_prefix *prefix)
{
	if (!addr || !prefix)
		return false;

	if (prefix->is_ipv6) {
		/* IPv6 matching */
		int bytes = prefix->prefix_len / 8;
		int bits = prefix->prefix_len % 8;
		int i;

		for (i = 0; i < bytes; i++) {
			if (addr->v6.s6_addr[i] != prefix->addr.v6.s6_addr[i])
				return false;
		}

		if (bits) {
			__u8 mask = (0xFF << (8 - bits)) & 0xFF;
			if ((addr->v6.s6_addr[bytes] & mask) !=
			    (prefix->addr.v6.s6_addr[bytes] & mask))
				return false;
		}
	} else {
		/* IPv4 matching */
		__u32 mask = prefix->prefix_len == 0 ? 0 :
			     htonl(~0UL << (32 - prefix->prefix_len));
		if ((addr->v4 & mask) != (prefix->addr.v4 & mask))
			return false;
	}

	return true;
}

/**
 * routing_hash_context - Calculate hash for routing context
 * @ctx: Routing context
 *
 * Return: Hash value
 */
static __u32 routing_hash_context(const struct routing_context *ctx)
{
	__u32 hash = 0;

	if (ctx->is_ipv6) {
		hash = jhash2((__u32 *)&ctx->src_addr.v6, 4, hash);
		hash = jhash2((__u32 *)&ctx->dst_addr.v6, 4, hash);
	} else {
		hash = jhash_2words(ctx->src_addr.v4, ctx->dst_addr.v4, hash);
	}

	hash = jhash_2words(ctx->src_port, ctx->dst_port, hash);
	hash = jhash_1word(ctx->protocol, hash);

	return hash;
}

/* ========================================================================
 * Routing Table Management
 * ======================================================================== */

/**
 * routing_table_create - Create new routing table
 * @id: Table identifier
 * @name: Table name
 *
 * Return: Pointer to routing table or NULL on error
 */
struct routing_table *routing_table_create(__u32 id, const char *name)
{
	struct routing_table *table;

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->id = id;
	if (name)
		strncpy(table->name, name, sizeof(table->name) - 1);
	table->entries = RB_ROOT;
	atomic_set(&table->num_entries, 0);
	rwlock_init(&table->lock);
	INIT_LIST_HEAD(&table->list);

	spin_lock(&routing_tables_lock);
	list_add_tail(&table->list, &routing_tables);
	spin_unlock(&routing_tables_lock);

	pr_info("Routing: Created table %u (%s)\n", id, name ? name : "unnamed");
	return table;
}
EXPORT_SYMBOL(routing_table_create);

/**
 * routing_table_destroy - Destroy routing table
 * @table: Routing table to destroy
 */
void routing_table_destroy(struct routing_table *table)
{
	struct rb_node *node;
	struct routing_table_entry *entry;

	if (!table)
		return;

	spin_lock(&routing_tables_lock);
	list_del(&table->list);
	spin_unlock(&routing_tables_lock);

	/* Free all entries */
	write_lock(&table->lock);
	while ((node = rb_first(&table->entries))) {
		entry = rb_entry(node, struct routing_table_entry, node);
		rb_erase(node, &table->entries);
		kfree(entry);
	}
	write_unlock(&table->lock);

	kfree(table);
	pr_info("Routing: Destroyed table %u\n", table->id);
}
EXPORT_SYMBOL(routing_table_destroy);

/**
 * routing_table_add_entry - Add entry to routing table
 * @table: Routing table
 * @prefix: Destination prefix
 * @group: Target server group
 * @metric: Route metric
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_table_add_entry(struct routing_table *table,
			     const struct routing_prefix *prefix,
			     struct routing_server_group *group,
			     __u32 metric)
{
	struct routing_table_entry *entry;

	if (!table || !prefix || !group)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->dst_prefix, prefix, sizeof(*prefix));
	entry->server_group = group;
	entry->metric = metric;
	atomic64_set(&entry->packets, 0);
	atomic64_set(&entry->bytes, 0);

	write_lock(&table->lock);
	/* Insert into red-black tree (simple insertion for now) */
	/* TODO: Implement proper longest prefix match tree */
	write_unlock(&table->lock);

	atomic_inc(&table->num_entries);
	return 0;
}
EXPORT_SYMBOL(routing_table_add_entry);

/* ========================================================================
 * Server Group Management
 * ======================================================================== */

/**
 * routing_group_create - Create server group
 * @name: Group name
 * @lb_algo: Load balancing algorithm
 *
 * Return: Pointer to server group or NULL on error
 */
struct routing_server_group *routing_group_create(const char *name,
						   enum routing_lb_algorithm lb_algo)
{
	struct routing_server_group *group;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	if (name)
		strncpy(group->name, name, sizeof(group->name) - 1);
	group->lb_algorithm = lb_algo;
	group->failover_strategy = ROUTING_FAILOVER_PASSIVE;
	atomic_set(&group->num_servers, 0);
	atomic_set(&group->next_rr_index, 0);
	INIT_LIST_HEAD(&group->servers);
	spin_lock_init(&group->lock);
	INIT_LIST_HEAD(&group->list);

	spin_lock(&routing_groups_lock);
	list_add_tail(&group->list, &routing_groups);
	spin_unlock(&routing_groups_lock);

	pr_info("Routing: Created server group '%s' with LB algo %d\n",
		name ? name : "unnamed", lb_algo);
	return group;
}
EXPORT_SYMBOL(routing_group_create);

/**
 * routing_group_destroy - Destroy server group
 * @group: Server group to destroy
 */
void routing_group_destroy(struct routing_server_group *group)
{
	struct routing_server *server, *tmp;

	if (!group)
		return;

	spin_lock(&routing_groups_lock);
	list_del(&group->list);
	spin_unlock(&routing_groups_lock);

	spin_lock(&group->lock);
	list_for_each_entry_safe(server, tmp, &group->servers, list) {
		list_del(&server->list);
		kfree(server);
	}
	spin_unlock(&group->lock);

	kfree(group);
	pr_info("Routing: Destroyed server group '%s'\n", group->name);
}
EXPORT_SYMBOL(routing_group_destroy);

/**
 * routing_group_add_server - Add server to group
 * @group: Server group
 * @addr: Server address
 * @port: Server port
 * @weight: Server weight
 * @is_ipv6: IPv6 address
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_group_add_server(struct routing_server_group *group,
			      const union routing_addr *addr,
			      __be16 port,
			      __u32 weight,
			      bool is_ipv6)
{
	struct routing_server *server;
	static atomic_t next_id = ATOMIC_INIT(1);

	if (!group || !addr)
		return -EINVAL;

	if (atomic_read(&group->num_servers) >= ROUTING_MAX_SERVERS)
		return -ENOSPC;

	server = kzalloc(sizeof(*server), GFP_KERNEL);
	if (!server)
		return -ENOMEM;

	server->id = atomic_inc_return(&next_id);
	memcpy(&server->addr, addr, sizeof(*addr));
	server->port = port;
	server->weight = weight ? weight : 1;
	server->priority = 0;
	server->max_connections = 0;  /* Unlimited */
	atomic_set(&server->current_connections, 0);
	atomic64_set(&server->total_connections, 0);
	atomic_set(&server->failures, 0);
	server->avg_latency_ms = 0;
	server->is_active = true;
	server->is_backup = false;
	server->is_ipv6 = is_ipv6;
	spin_lock_init(&server->lock);
	INIT_LIST_HEAD(&server->list);

	spin_lock(&group->lock);
	list_add_tail(&server->list, &group->servers);
	spin_unlock(&group->lock);

	atomic_inc(&group->num_servers);

	pr_info("Routing: Added server %u to group '%s'\n",
		server->id, group->name);
	return 0;
}
EXPORT_SYMBOL(routing_group_add_server);

/**
 * routing_group_select_server - Select server from group
 * @group: Server group
 * @ctx: Routing context
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_group_select_server(struct routing_server_group *group,
						    const struct routing_context *ctx)
{
	struct routing_server *server = NULL;

	if (!group)
		return NULL;

	atomic64_inc(&routing_stats.lb_selections);

	switch (group->lb_algorithm) {
	case ROUTING_LB_ROUND_ROBIN:
		server = routing_lb_round_robin(group);
		break;
	case ROUTING_LB_LEAST_CONN:
		server = routing_lb_least_conn(group);
		break;
	case ROUTING_LB_WEIGHTED:
		server = routing_lb_weighted(group);
		break;
	case ROUTING_LB_RANDOM:
		server = routing_lb_random(group);
		break;
	case ROUTING_LB_HASH:
		server = routing_lb_hash(group, ctx);
		break;
	case ROUTING_LB_LEAST_LATENCY:
		server = routing_lb_least_latency(group);
		break;
	default:
		server = routing_lb_round_robin(group);
		break;
	}

	if (server)
		atomic_inc(&server->current_connections);

	return server;
}
EXPORT_SYMBOL(routing_group_select_server);

/* ========================================================================
 * Load Balancing Algorithms
 * ======================================================================== */

/**
 * routing_lb_round_robin - Round-robin load balancing
 * @group: Server group
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_round_robin(struct routing_server_group *group)
{
	struct routing_server *server;
	int count = 0;
	int target_index;

	if (!group || list_empty(&group->servers))
		return NULL;

	target_index = atomic_inc_return(&group->next_rr_index) %
		       atomic_read(&group->num_servers);

	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup) {
			if (count == target_index) {
				spin_unlock(&group->lock);
				return server;
			}
			count++;
		}
	}
	spin_unlock(&group->lock);

	return NULL;
}
EXPORT_SYMBOL(routing_lb_round_robin);

/**
 * routing_lb_least_conn - Least connections load balancing
 * @group: Server group
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_least_conn(struct routing_server_group *group)
{
	struct routing_server *server, *best = NULL;
	int min_conn = INT_MAX;
	int conn;

	if (!group || list_empty(&group->servers))
		return NULL;

	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (!server->is_active || server->is_backup)
			continue;

		conn = atomic_read(&server->current_connections);
		if (conn < min_conn) {
			min_conn = conn;
			best = server;
		}
	}
	spin_unlock(&group->lock);

	return best;
}
EXPORT_SYMBOL(routing_lb_least_conn);

/**
 * routing_lb_weighted - Weighted load balancing
 * @group: Server group
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_weighted(struct routing_server_group *group)
{
	struct routing_server *server;
	__u32 total_weight = 0;
	__u32 random_weight;
	__u32 current_weight = 0;

	if (!group || list_empty(&group->servers))
		return NULL;

	/* Calculate total weight */
	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup)
			total_weight += server->weight;
	}

	if (total_weight == 0) {
		spin_unlock(&group->lock);
		return NULL;
	}

	/* Select based on random weight */
	random_weight = get_random_u32() % total_weight;

	list_for_each_entry(server, &group->servers, list) {
		if (!server->is_active || server->is_backup)
			continue;

		current_weight += server->weight;
		if (current_weight > random_weight) {
			spin_unlock(&group->lock);
			return server;
		}
	}
	spin_unlock(&group->lock);

	return NULL;
}
EXPORT_SYMBOL(routing_lb_weighted);

/**
 * routing_lb_random - Random load balancing
 * @group: Server group
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_random(struct routing_server_group *group)
{
	struct routing_server *server;
	int count = 0, target, i = 0;

	if (!group || list_empty(&group->servers))
		return NULL;

	/* Count active servers */
	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup)
			count++;
	}

	if (count == 0) {
		spin_unlock(&group->lock);
		return NULL;
	}

	target = get_random_u32() % count;

	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup) {
			if (i == target) {
				spin_unlock(&group->lock);
				return server;
			}
			i++;
		}
	}
	spin_unlock(&group->lock);

	return NULL;
}
EXPORT_SYMBOL(routing_lb_random);

/**
 * routing_lb_hash - Hash-based load balancing
 * @group: Server group
 * @ctx: Routing context
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_hash(struct routing_server_group *group,
					const struct routing_context *ctx)
{
	struct routing_server *server;
	__u32 hash;
	int count = 0, target, i = 0;

	if (!group || !ctx || list_empty(&group->servers))
		return NULL;

	/* Count active servers */
	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup)
			count++;
	}

	if (count == 0) {
		spin_unlock(&group->lock);
		return NULL;
	}

	hash = routing_hash_context(ctx);
	target = hash % count;

	list_for_each_entry(server, &group->servers, list) {
		if (server->is_active && !server->is_backup) {
			if (i == target) {
				spin_unlock(&group->lock);
				return server;
			}
			i++;
		}
	}
	spin_unlock(&group->lock);

	return NULL;
}
EXPORT_SYMBOL(routing_lb_hash);

/**
 * routing_lb_least_latency - Least latency load balancing
 * @group: Server group
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lb_least_latency(struct routing_server_group *group)
{
	struct routing_server *server, *best = NULL;
	__u32 min_latency = UINT_MAX;

	if (!group || list_empty(&group->servers))
		return NULL;

	spin_lock(&group->lock);
	list_for_each_entry(server, &group->servers, list) {
		if (!server->is_active || server->is_backup)
			continue;

		if (server->avg_latency_ms < min_latency) {
			min_latency = server->avg_latency_ms;
			best = server;
		}
	}
	spin_unlock(&group->lock);

	return best;
}
EXPORT_SYMBOL(routing_lb_least_latency);

/* ========================================================================
 * Policy Rules
 * ======================================================================== */

/**
 * routing_rule_match - Find matching policy rule
 * @ctx: Routing context
 *
 * Return: Matching rule or NULL
 */
struct routing_policy_rule *routing_rule_match(const struct routing_context *ctx)
{
	struct routing_policy_rule *rule;

	if (!ctx)
		return NULL;

	spin_lock(&routing_rules_lock);
	list_for_each_entry(rule, &routing_rules, list) {
		if (!rule->enabled)
			continue;

		/* Check source address */
		if (rule->match_flags & ROUTING_MATCH_SRC_ADDR) {
			if (!routing_addr_match(&ctx->src_addr, &rule->src_prefix))
				continue;
		}

		/* Check destination address */
		if (rule->match_flags & ROUTING_MATCH_DST_ADDR) {
			if (!routing_addr_match(&ctx->dst_addr, &rule->dst_prefix))
				continue;
		}

		/* Check source port */
		if (rule->match_flags & ROUTING_MATCH_SRC_PORT) {
			if (ctx->src_port < rule->src_port_min ||
			    ctx->src_port > rule->src_port_max)
				continue;
		}

		/* Check destination port */
		if (rule->match_flags & ROUTING_MATCH_DST_PORT) {
			if (ctx->dst_port < rule->dst_port_min ||
			    ctx->dst_port > rule->dst_port_max)
				continue;
		}

		/* Check protocol */
		if (rule->match_flags & ROUTING_MATCH_PROTOCOL) {
			if (ctx->protocol != rule->protocol)
				continue;
		}

		/* Rule matched */
		atomic64_inc(&rule->packets_matched);
		atomic64_inc(&routing_stats.policy_matches);
		rule->last_match = jiffies;
		spin_unlock(&routing_rules_lock);
		return rule;
	}
	spin_unlock(&routing_rules_lock);

	return NULL;
}
EXPORT_SYMBOL(routing_rule_match);

/* ========================================================================
 * Routing Cache
 * ======================================================================== */

/**
 * routing_cache_init - Initialize routing cache
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_cache_init(void)
{
	int i;

	routing_cache = kmalloc_array(ROUTING_CACHE_SIZE,
				      sizeof(struct hlist_head),
				      GFP_KERNEL);
	if (!routing_cache)
		return -ENOMEM;

	for (i = 0; i < ROUTING_CACHE_SIZE; i++)
		INIT_HLIST_HEAD(&routing_cache[i]);

	pr_info("Routing: Cache initialized with %d buckets\n",
		ROUTING_CACHE_SIZE);
	return 0;
}
EXPORT_SYMBOL(routing_cache_init);

/**
 * routing_cache_destroy - Destroy routing cache
 */
void routing_cache_destroy(void)
{
	struct routing_cache_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!routing_cache)
		return;

	spin_lock(&routing_cache_lock);
	for (i = 0; i < ROUTING_CACHE_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp, &routing_cache[i], hlist) {
			hlist_del(&entry->hlist);
			kfree(entry);
		}
	}
	spin_unlock(&routing_cache_lock);

	kfree(routing_cache);
	routing_cache = NULL;
	pr_info("Routing: Cache destroyed\n");
}
EXPORT_SYMBOL(routing_cache_destroy);

/**
 * routing_cache_lookup - Lookup in routing cache
 * @ctx: Routing context
 *
 * Return: Cached server or NULL
 */
struct routing_server *routing_cache_lookup(const struct routing_context *ctx)
{
	struct routing_cache_entry *entry;
	__u32 hash;
	unsigned long now = jiffies;
	struct routing_server *server = NULL;

	if (!routing_cache || !ctx)
		return NULL;

	hash = routing_hash_context(ctx);

	spin_lock(&routing_cache_lock);
	hlist_for_each_entry(entry, &routing_cache[hash % ROUTING_CACHE_SIZE], hlist) {
		if (entry->key_hash == hash) {
			/* Check if entry is still valid */
			if (time_after(now, entry->timestamp +
				       msecs_to_jiffies(ROUTING_CACHE_TIMEOUT_MS))) {
				/* Entry expired */
				hlist_del(&entry->hlist);
				kfree(entry);
				atomic64_inc(&routing_stats.cache_misses);
				break;
			}

			atomic_inc(&entry->hits);
			atomic64_inc(&routing_stats.cache_hits);
			server = entry->server;
			break;
		}
	}
	spin_unlock(&routing_cache_lock);

	if (!server)
		atomic64_inc(&routing_stats.cache_misses);

	return server;
}
EXPORT_SYMBOL(routing_cache_lookup);

/**
 * routing_cache_insert - Insert into routing cache
 * @ctx: Routing context
 * @server: Server to cache
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_cache_insert(const struct routing_context *ctx,
			  struct routing_server *server)
{
	struct routing_cache_entry *entry;
	__u32 hash;

	if (!routing_cache || !ctx || !server)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	hash = routing_hash_context(ctx);
	entry->key_hash = hash;
	entry->server = server;
	entry->timestamp = jiffies;
	atomic_set(&entry->hits, 0);
	INIT_HLIST_NODE(&entry->hlist);

	spin_lock(&routing_cache_lock);
	hlist_add_head(&entry->hlist, &routing_cache[hash % ROUTING_CACHE_SIZE]);
	spin_unlock(&routing_cache_lock);

	return 0;
}
EXPORT_SYMBOL(routing_cache_insert);

/**
 * routing_cache_invalidate - Invalidate routing cache
 */
void routing_cache_invalidate(void)
{
	struct routing_cache_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!routing_cache)
		return;

	spin_lock(&routing_cache_lock);
	for (i = 0; i < ROUTING_CACHE_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp, &routing_cache[i], hlist) {
			hlist_del(&entry->hlist);
			kfree(entry);
		}
	}
	spin_unlock(&routing_cache_lock);

	pr_info("Routing: Cache invalidated\n");
}
EXPORT_SYMBOL(routing_cache_invalidate);

/* ========================================================================
 * Routing Decision
 * ======================================================================== */

/**
 * routing_context_init - Initialize routing context from packet
 * @ctx: Routing context to initialize
 * @skb: Socket buffer
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_context_init(struct routing_context *ctx, struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct udphdr *udph;

	if (!ctx || !skb)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->skb = skb;

	/* Determine IP version */
	if (skb->protocol == htons(ETH_P_IP)) {
		ctx->is_ipv6 = false;
		iph = ip_hdr(skb);
		ctx->src_addr.v4 = iph->saddr;
		ctx->dst_addr.v4 = iph->daddr;
		ctx->protocol = iph->protocol;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ctx->is_ipv6 = true;
		ipv6h = ipv6_hdr(skb);
		memcpy(&ctx->src_addr.v6, &ipv6h->saddr, sizeof(struct in6_addr));
		memcpy(&ctx->dst_addr.v6, &ipv6h->daddr, sizeof(struct in6_addr));
		ctx->protocol = ipv6h->nexthdr;
	} else {
		return -EINVAL;
	}

	/* Extract ports for TCP/UDP */
	if (ctx->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		ctx->src_port = tcph->source;
		ctx->dst_port = tcph->dest;
	} else if (ctx->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		ctx->src_port = udph->source;
		ctx->dst_port = udph->dest;
	}

	ctx->mark = skb->mark;
	ctx->iface = skb->dev;

	return 0;
}
EXPORT_SYMBOL(routing_context_init);

/**
 * routing_lookup - Perform routing lookup
 * @ctx: Routing context
 *
 * Return: Selected server or NULL
 */
struct routing_server *routing_lookup(const struct routing_context *ctx)
{
	struct routing_policy_rule *rule;
	struct routing_server *server;

	if (!ctx)
		return NULL;

	atomic64_inc(&routing_stats.packets_routed);

	/* Check cache first */
	server = routing_cache_lookup(ctx);
	if (server)
		return server;

	/* Check policy rules */
	rule = routing_rule_match(ctx);
	if (rule && rule->target_group) {
		server = routing_group_select_server(rule->target_group, ctx);
		if (server) {
			routing_cache_insert(ctx, server);
			return server;
		}
	}

	/* Fallback: use default routing */
	/* TODO: Implement routing table lookup */

	return NULL;
}
EXPORT_SYMBOL(routing_lookup);

/* ========================================================================
 * Statistics
 * ======================================================================== */

/**
 * routing_get_statistics - Get routing statistics
 * @stats: Output statistics structure
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_get_statistics(struct routing_statistics *stats)
{
	if (!stats)
		return -EINVAL;

	atomic64_set(&stats->packets_routed, atomic64_read(&routing_stats.packets_routed));
	atomic64_set(&stats->bytes_routed, atomic64_read(&routing_stats.bytes_routed));
	atomic64_set(&stats->cache_hits, atomic64_read(&routing_stats.cache_hits));
	atomic64_set(&stats->cache_misses, atomic64_read(&routing_stats.cache_misses));
	atomic64_set(&stats->policy_matches, atomic64_read(&routing_stats.policy_matches));
	atomic64_set(&stats->table_lookups, atomic64_read(&routing_stats.table_lookups));
	atomic64_set(&stats->lb_selections, atomic64_read(&routing_stats.lb_selections));
	atomic64_set(&stats->failovers, atomic64_read(&routing_stats.failovers));
	atomic64_set(&stats->health_checks, atomic64_read(&routing_stats.health_checks));

	return 0;
}
EXPORT_SYMBOL(routing_get_statistics);

/**
 * routing_reset_statistics - Reset routing statistics
 */
void routing_reset_statistics(void)
{
	atomic64_set(&routing_stats.packets_routed, 0);
	atomic64_set(&routing_stats.bytes_routed, 0);
	atomic64_set(&routing_stats.cache_hits, 0);
	atomic64_set(&routing_stats.cache_misses, 0);
	atomic64_set(&routing_stats.policy_matches, 0);
	atomic64_set(&routing_stats.table_lookups, 0);
	atomic64_set(&routing_stats.lb_selections, 0);
	atomic64_set(&routing_stats.failovers, 0);
	atomic64_set(&routing_stats.health_checks, 0);

	pr_info("Routing: Statistics reset\n");
}
EXPORT_SYMBOL(routing_reset_statistics);

/* ========================================================================
 * Module Initialization
 * ======================================================================== */

/**
 * routing_init - Initialize routing module
 *
 * Return: 0 on success, negative error code otherwise
 */
int routing_init(void)
{
	int ret;

	/* Initialize routing cache */
	ret = routing_cache_init();
	if (ret < 0) {
		pr_err("Routing: Failed to initialize cache: %d\n", ret);
		return ret;
	}

	/* Reset statistics */
	routing_reset_statistics();

	pr_info("MUTEX Advanced Routing module initialized\n");
	return 0;
}
EXPORT_SYMBOL(routing_init);

/**
 * routing_exit - Cleanup routing module
 */
void routing_exit(void)
{
	struct routing_table *table, *table_tmp;
	struct routing_server_group *group, *group_tmp;

	/* Destroy all tables */
	list_for_each_entry_safe(table, table_tmp, &routing_tables, list) {
		routing_table_destroy(table);
	}

	/* Destroy all server groups */
	list_for_each_entry_safe(group, group_tmp, &routing_groups, list) {
		routing_group_destroy(group);
	}

	/* Destroy cache */
	routing_cache_destroy();

	pr_info("MUTEX Advanced Routing module exiting\n");
	pr_info("  Packets routed: %lld\n",
		atomic64_read(&routing_stats.packets_routed));
	pr_info("  Cache hits: %lld\n",
		atomic64_read(&routing_stats.cache_hits));
	pr_info("  Cache misses: %lld\n",
		atomic64_read(&routing_stats.cache_misses));
	pr_info("  LB selections: %lld\n",
		atomic64_read(&routing_stats.lb_selections));
}
EXPORT_SYMBOL(routing_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Team");
MODULE_DESCRIPTION("MUTEX Advanced Routing Module");
MODULE_VERSION("1.0");
