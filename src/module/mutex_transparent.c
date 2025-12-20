// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Transparent Proxying Implementation
 *
 * This file implements transparent proxy interception without requiring
 * application modification. Connections are automatically redirected through
 * configured proxies (SOCKS or HTTP) based on destination address, bypass
 * rules, and process filtering.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/ip.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "mutex_transparent.h"
#include "mutex_conn_track.h"
#include "mutex_packet_rewrite.h"
#include "mutex_socks.h"
#include "mutex_http_proxy.h"

/* ========== Global Statistics ========== */

struct transparent_statistics transparent_stats;

/* ========== Private Network Definitions (RFC 1918) ========== */

#define PRIV_NET_10_START    0x0A000000  /* 10.0.0.0 */
#define PRIV_NET_10_END      0x0AFFFFFF  /* 10.255.255.255 */
#define PRIV_NET_172_START   0xAC100000  /* 172.16.0.0 */
#define PRIV_NET_172_END     0xAC1FFFFF  /* 172.31.255.255 */
#define PRIV_NET_192_START   0xC0A80000  /* 192.168.0.0 */
#define PRIV_NET_192_END     0xC0A8FFFF  /* 192.168.255.255 */
#define LOOPBACK_NET_START   0x7F000000  /* 127.0.0.0 */
#define LOOPBACK_NET_END     0x7FFFFFFF  /* 127.255.255.255 */
#define LINK_LOCAL_START     0xA9FE0000  /* 169.254.0.0 */
#define LINK_LOCAL_END       0xA9FEFFFF  /* 169.254.255.255 */

/* ========== Context Management ========== */

/**
 * transparent_context_alloc() - Allocate transparent proxy context
 *
 * Creates a new transparent proxy context with default configuration.
 *
 * Returns: Pointer to allocated context or NULL on failure
 */
struct transparent_context *transparent_context_alloc(void)
{
	struct transparent_context *ctx;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	/* Initialize NAT table */
	ctx->nat = kzalloc(sizeof(*ctx->nat), GFP_KERNEL);
	if (!ctx->nat) {
		kfree(ctx);
		return NULL;
	}

	for (i = 0; i < 1024; i++) {
		INIT_HLIST_HEAD(&ctx->nat->buckets[i]);
		spin_lock_init(&ctx->nat->locks[i]);
	}
	atomic_set(&ctx->nat->entry_count, 0);

	/* Default configuration */
	ctx->config.mode = TRANSPARENT_MODE_DISABLED;
	ctx->config.protocol = PROXY_PROTOCOL_AUTO;
	ctx->config.target_pid = 0;
	ctx->config.inherit_children = true;
	ctx->config.bypass.bypass_local = true;
	ctx->config.bypass.bypass_private = false;
	ctx->config.bypass.bypass_multicast = true;
	ctx->config.dns.intercept_dns = false;
	ctx->config.dns.proxy_dns = false;
	ctx->config.dns.leak_prevention = true;
	ctx->config.auto_select_proxy = true;
	ctx->config.prefer_socks5 = true;
	ctx->config.preserve_source_port = false;
	ctx->config.connect_timeout = 30000; /* 30 seconds */
	ctx->config.idle_timeout = 300; /* 5 minutes */
	ctx->config.collect_stats = true;
	ctx->config.verbose_logging = false;

	spin_lock_init(&ctx->config.bypass.lock);

	/* Initialize statistics */
	atomic64_set(&ctx->connections_intercepted, 0);
	atomic64_set(&ctx->connections_proxied, 0);
	atomic64_set(&ctx->connections_bypassed, 0);
	atomic64_set(&ctx->connections_direct, 0);
	atomic64_set(&ctx->dns_queries_intercepted, 0);
	atomic64_set(&ctx->dns_queries_proxied, 0);
	atomic64_set(&ctx->nat_entries_created, 0);
	atomic64_set(&ctx->nat_lookups, 0);
	atomic64_set(&ctx->bytes_proxied, 0);
	atomic64_set(&ctx->errors, 0);

	ctx->created = jiffies;
	ctx->last_activity = jiffies;

	refcount_set(&ctx->refcount, 1);

	pr_info("mutex: Allocated transparent proxy context\n");
	return ctx;
}

/**
 * transparent_context_free() - Free transparent proxy context
 * @ctx: Context to free
 */
void transparent_context_free(struct transparent_context *ctx)
{
	if (!ctx)
		return;

	transparent_nat_cleanup(ctx);
	kfree(ctx->nat);

	/* Free proxy connections */
	if (ctx->active_protocol == PROXY_PROTOCOL_SOCKS4 ||
	    ctx->active_protocol == PROXY_PROTOCOL_SOCKS5) {
		if (ctx->proxy.socks)
			socks_connection_free(ctx->proxy.socks);
	} else if (ctx->active_protocol == PROXY_PROTOCOL_HTTP) {
		if (ctx->proxy.http)
			http_connection_free(ctx->proxy.http);
	}

	kfree(ctx);
	pr_info("mutex: Freed transparent proxy context\n");
}

void transparent_context_get(struct transparent_context *ctx)
{
	if (ctx)
		refcount_inc(&ctx->refcount);
}

void transparent_context_put(struct transparent_context *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->refcount))
		transparent_context_free(ctx);
}

/* ========== Configuration ========== */

int transparent_set_config(struct transparent_context *ctx,
			   const struct transparent_config *config)
{
	if (!ctx || !config)
		return -EINVAL;

	memcpy(&ctx->config, config, sizeof(*config));
	return 0;
}

int transparent_get_config(struct transparent_context *ctx,
			   struct transparent_config *config)
{
	if (!ctx || !config)
		return -EINVAL;

	memcpy(config, &ctx->config, sizeof(*config));
	return 0;
}

int transparent_set_mode(struct transparent_context *ctx,
			 enum transparent_mode mode)
{
	if (!ctx)
		return -EINVAL;

	if (mode < TRANSPARENT_MODE_DISABLED || mode > TRANSPARENT_MODE_CGROUP)
		return -EINVAL;

	ctx->config.mode = mode;
	pr_info("mutex: Set transparent mode to %s\n",
		transparent_mode_name(mode));
	return 0;
}

/* ========== Bypass Rules ========== */

int transparent_add_bypass_rule(struct transparent_context *ctx,
				const struct bypass_rule *rule)
{
	unsigned long flags;

	if (!ctx || !rule)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.bypass.lock, flags);

	if (ctx->config.bypass.count >= BYPASS_RULE_MAX) {
		spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);
		return -ENOSPC;
	}

	memcpy(&ctx->config.bypass.rules[ctx->config.bypass.count],
	       rule, sizeof(*rule));
	ctx->config.bypass.count++;

	spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);

	pr_debug("mutex: Added bypass rule (count: %d)\n",
		 ctx->config.bypass.count);
	return 0;
}

int transparent_remove_bypass_rule(struct transparent_context *ctx, int index)
{
	unsigned long flags;
	int i;

	if (!ctx || index < 0)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.bypass.lock, flags);

	if (index >= ctx->config.bypass.count) {
		spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);
		return -EINVAL;
	}

	/* Shift remaining rules down */
	for (i = index; i < ctx->config.bypass.count - 1; i++) {
		memcpy(&ctx->config.bypass.rules[i],
		       &ctx->config.bypass.rules[i + 1],
		       sizeof(struct bypass_rule));
	}
	ctx->config.bypass.count--;

	spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);
	return 0;
}

int transparent_clear_bypass_rules(struct transparent_context *ctx)
{
	unsigned long flags;

	if (!ctx)
		return -EINVAL;

	spin_lock_irqsave(&ctx->config.bypass.lock, flags);
	ctx->config.bypass.count = 0;
	spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);

	pr_debug("mutex: Cleared all bypass rules\n");
	return 0;
}

/**
 * transparent_should_bypass() - Check if connection should bypass proxy
 * @ctx: Transparent proxy context
 * @skb: Packet to check
 *
 * Returns: true if connection should bypass proxy, false otherwise
 */
bool transparent_should_bypass(struct transparent_context *ctx,
			       struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__be32 daddr;
	__be16 dport;
	enum addr_class class;
	unsigned long flags;
	int i;

	if (!ctx || !skb)
		return true;

	iph = ip_hdr(skb);
	if (!iph)
		return true;

	daddr = iph->daddr;

	/* Get destination port */
	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return true;
		dport = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return true;
		dport = udph->dest;
	} else {
		return true; /* Bypass non-TCP/UDP */
	}

	/* Quick checks for common bypasses */
	class = transparent_classify_ipv4(ctx, daddr);

	if (class == ADDR_CLASS_LOCAL && ctx->config.bypass.bypass_local)
		return true;

	if (class == ADDR_CLASS_PRIVATE && ctx->config.bypass.bypass_private)
		return true;

	if (class == ADDR_CLASS_MULTICAST && ctx->config.bypass.bypass_multicast)
		return true;

	/* Check custom bypass rules */
	spin_lock_irqsave(&ctx->config.bypass.lock, flags);

	for (i = 0; i < ctx->config.bypass.count; i++) {
		struct bypass_rule *rule = &ctx->config.bypass.rules[i];

		if (!rule->enabled)
			continue;

		switch (rule->type) {
		case BYPASS_MATCH_ADDR:
			if (daddr == rule->match.ipv4.addr) {
				spin_unlock_irqrestore(&ctx->config.bypass.lock,
						       flags);
				return true;
			}
			break;

		case BYPASS_MATCH_NETWORK:
			if ((daddr & rule->match.ipv4.mask) ==
			    (rule->match.ipv4.addr & rule->match.ipv4.mask)) {
				spin_unlock_irqrestore(&ctx->config.bypass.lock,
						       flags);
				return true;
			}
			break;

		case BYPASS_MATCH_PORT:
			if (ntohs(dport) >= rule->match.port.port_start &&
			    ntohs(dport) <= rule->match.port.port_end) {
				spin_unlock_irqrestore(&ctx->config.bypass.lock,
						       flags);
				return true;
			}
			break;

		case BYPASS_MATCH_PROTOCOL:
			if (iph->protocol == rule->match.proto.protocol) {
				spin_unlock_irqrestore(&ctx->config.bypass.lock,
						       flags);
				return true;
			}
			break;

		case BYPASS_MATCH_PROCESS:
			/* Process matching requires additional context */
			break;

		default:
			break;
		}
	}

	spin_unlock_irqrestore(&ctx->config.bypass.lock, flags);
	return false;
}

/* ========== Address Classification ========== */

enum addr_class transparent_classify_ipv4(struct transparent_context *ctx,
					  __be32 addr)
{
	__u32 addr_host = ntohl(addr);

	/* Loopback */
	if (addr_host >= LOOPBACK_NET_START && addr_host <= LOOPBACK_NET_END)
		return ADDR_CLASS_LOCAL;

	/* Link-local */
	if (addr_host >= LINK_LOCAL_START && addr_host <= LINK_LOCAL_END)
		return ADDR_CLASS_LINK_LOCAL;

	/* Multicast (224.0.0.0/4) */
	if ((addr_host & 0xF0000000) == 0xE0000000)
		return ADDR_CLASS_MULTICAST;

	/* Private networks (RFC 1918) */
	if ((addr_host >= PRIV_NET_10_START && addr_host <= PRIV_NET_10_END) ||
	    (addr_host >= PRIV_NET_172_START && addr_host <= PRIV_NET_172_END) ||
	    (addr_host >= PRIV_NET_192_START && addr_host <= PRIV_NET_192_END))
		return ADDR_CLASS_PRIVATE;

	/* Public internet */
	return ADDR_CLASS_PUBLIC;
}

enum addr_class transparent_classify_ipv6(struct transparent_context *ctx,
					  const struct in6_addr *addr)
{
	/* Loopback (::1) */
	if (ipv6_addr_loopback(addr))
		return ADDR_CLASS_LOCAL;

	/* Link-local (fe80::/10) */
	if (ipv6_addr_is_linklocal(addr))
		return ADDR_CLASS_LINK_LOCAL;

	/* Multicast (ff00::/8) */
	if (ipv6_addr_is_multicast(addr))
		return ADDR_CLASS_MULTICAST;

	/* Private/ULA (fc00::/7) */
	if ((addr->s6_addr[0] & 0xfe) == 0xfc)
		return ADDR_CLASS_PRIVATE;

	/* Public internet */
	return ADDR_CLASS_PUBLIC;
}

bool transparent_is_local_address(__be32 addr)
{
	__u32 addr_host = ntohl(addr);
	return (addr_host >= LOOPBACK_NET_START &&
		addr_host <= LOOPBACK_NET_END);
}

bool transparent_is_private_address(__be32 addr)
{
	__u32 addr_host = ntohl(addr);
	return ((addr_host >= PRIV_NET_10_START &&
		 addr_host <= PRIV_NET_10_END) ||
		(addr_host >= PRIV_NET_172_START &&
		 addr_host <= PRIV_NET_172_END) ||
		(addr_host >= PRIV_NET_192_START &&
		 addr_host <= PRIV_NET_192_END));
}

/* ========== Connection Interception ========== */

/**
 * transparent_intercept_outbound() - Intercept outbound connection
 * @ctx: Transparent proxy context
 * @skb: Outbound packet
 * @conn: Connection tracking entry
 *
 * Intercepts outbound connections and redirects them through configured proxy.
 *
 * Returns: 0 on success, negative error code on failure
 */
int transparent_intercept_outbound(struct transparent_context *ctx,
				   struct sk_buff *skb,
				   struct mutex_conn_entry *conn)
{
	struct iphdr *iph;
	enum proxy_protocol_type protocol;
	struct nat_entry *nat;
	__be32 proxy_addr;
	__be16 proxy_port;
	int ret;

	if (!ctx || !skb || !conn)
		return -EINVAL;

	/* Check if disabled */
	if (ctx->config.mode == TRANSPARENT_MODE_DISABLED)
		return -ENOENT;

	/* Check bypass rules */
	if (transparent_should_bypass(ctx, skb)) {
		atomic64_inc(&ctx->connections_bypassed);
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.total_bypassed);
		return -ENOENT; /* Don't intercept */
	}

	atomic64_inc(&ctx->connections_intercepted);
	if (ctx->config.collect_stats)
		atomic64_inc(&transparent_stats.total_intercepted);

	/* Select proxy protocol */
	protocol = transparent_select_protocol(ctx, skb);
	if (protocol == PROXY_PROTOCOL_DIRECT) {
		atomic64_inc(&ctx->connections_direct);
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.total_direct);
		return -ENOENT;
	}

	/* Get proxy address from connection config */
	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	/* For now, use placeholder proxy address - should come from config */
	proxy_addr = conn->proxy_addr;
	proxy_port = conn->proxy_port;

	if (!proxy_addr || !proxy_port) {
		pr_debug("mutex: No proxy configured for connection\n");
		return -ENOENT;
	}

	/* Create NAT entry */
	nat = transparent_nat_create(ctx, skb, proxy_addr, proxy_port);
	if (!nat) {
		pr_err("mutex: Failed to create NAT entry\n");
		atomic64_inc(&ctx->errors);
		return -ENOMEM;
	}

	/* Establish proxy connection */
	ret = transparent_establish_proxy_connection(ctx, conn, protocol);
	if (ret < 0) {
		pr_err("mutex: Failed to establish proxy connection: %d\n", ret);
		transparent_nat_delete(ctx, nat);
		atomic64_inc(&ctx->errors);
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.connection_errors);
		return ret;
	}

	/* Rewrite packet to proxy */
	ret = transparent_rewrite_outbound(ctx, skb, nat);
	if (ret < 0) {
		pr_err("mutex: Failed to rewrite outbound packet: %d\n", ret);
		transparent_nat_delete(ctx, nat);
		atomic64_inc(&ctx->errors);
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.rewrite_errors);
		return ret;
	}

	atomic64_inc(&ctx->connections_proxied);
	if (ctx->config.collect_stats)
		atomic64_inc(&transparent_stats.total_proxied);

	ctx->last_activity = jiffies;
	return 0;
}

/**
 * transparent_intercept_inbound() - Handle inbound proxy response
 * @ctx: Transparent proxy context
 * @skb: Inbound packet
 * @conn: Connection tracking entry
 *
 * Handles return traffic from proxy, performing reverse NAT translation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int transparent_intercept_inbound(struct transparent_context *ctx,
				  struct sk_buff *skb,
				  struct mutex_conn_entry *conn)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct nat_entry *nat;
	__be32 saddr, daddr;
	__be16 sport, dport;
	__u8 protocol;
	int ret;

	if (!ctx || !skb || !conn)
		return -EINVAL;

	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	saddr = iph->saddr;
	daddr = iph->daddr;
	protocol = iph->protocol;

	/* Get ports */
	if (protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return -EINVAL;
		sport = tcph->source;
		dport = tcph->dest;
	} else if (protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return -EINVAL;
		sport = udph->source;
		dport = udph->dest;
	} else {
		return -EINVAL;
	}

	/* Lookup NAT entry for reverse translation */
	nat = transparent_nat_lookup_inbound(ctx, saddr, sport, daddr, dport,
					     protocol);
	if (!nat) {
		pr_debug("mutex: No NAT entry found for inbound packet\n");
		return -ENOENT;
	}

	atomic64_inc(&ctx->nat_lookups);

	/* Update last seen */
	nat->last_seen = jiffies;

	/* Rewrite packet back to original destination */
	ret = transparent_rewrite_inbound(ctx, skb, nat);
	if (ret < 0) {
		pr_err("mutex: Failed to rewrite inbound packet: %d\n", ret);
		atomic64_inc(&ctx->errors);
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.rewrite_errors);
		return ret;
	}

	/* Update statistics */
	atomic64_add(skb->len, &ctx->bytes_proxied);
	ctx->last_activity = jiffies;

	return 0;
}

/* ========== Proxy Protocol Selection ========== */

enum proxy_protocol_type transparent_select_protocol(
	struct transparent_context *ctx,
	struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be16 dport;

	if (!ctx || !skb)
		return PROXY_PROTOCOL_DIRECT;

	/* If protocol is explicitly set, use it */
	if (ctx->config.protocol != PROXY_PROTOCOL_AUTO)
		return ctx->config.protocol;

	/* Auto-detect based on destination port */
	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_TCP)
		return PROXY_PROTOCOL_DIRECT;

	tcph = tcp_hdr(skb);
	if (!tcph)
		return PROXY_PROTOCOL_DIRECT;

	dport = ntohs(tcph->dest);

	/* HTTPS traffic (443) - prefer based on config */
	if (dport == 443) {
		if (ctx->config.prefer_socks5)
			return PROXY_PROTOCOL_SOCKS5;
		return PROXY_PROTOCOL_HTTP;
	}

	/* HTTP traffic (80) - use HTTP proxy */
	if (dport == 80)
		return PROXY_PROTOCOL_HTTP;

	/* Default to SOCKS5 for other TCP traffic */
	if (ctx->config.prefer_socks5)
		return PROXY_PROTOCOL_SOCKS5;

	return PROXY_PROTOCOL_HTTP;
}

int transparent_establish_proxy_connection(struct transparent_context *ctx,
					   struct mutex_conn_entry *conn,
					   enum proxy_protocol_type protocol)
{
	int ret = 0;

	if (!ctx || !conn)
		return -EINVAL;

	ctx->active_protocol = protocol;

	switch (protocol) {
	case PROXY_PROTOCOL_SOCKS4:
		/* Allocate SOCKS4 connection if not exists */
		if (!ctx->proxy.socks) {
			ctx->proxy.socks = socks_connection_alloc();
			if (!ctx->proxy.socks)
				return -ENOMEM;
		}
		ctx->proxy.socks->version = SOCKS_VERSION_4;
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.socks4_used);
		break;

	case PROXY_PROTOCOL_SOCKS5:
		/* Allocate SOCKS5 connection if not exists */
		if (!ctx->proxy.socks) {
			ctx->proxy.socks = socks_connection_alloc();
			if (!ctx->proxy.socks)
				return -ENOMEM;
		}
		ctx->proxy.socks->version = SOCKS_VERSION_5;
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.socks5_used);
		break;

	case PROXY_PROTOCOL_HTTP:
		/* Allocate HTTP connection if not exists */
		if (!ctx->proxy.http) {
			ctx->proxy.http = http_connection_alloc();
			if (!ctx->proxy.http)
				return -ENOMEM;
		}
		if (ctx->config.collect_stats)
			atomic64_inc(&transparent_stats.http_used);
		break;

	case PROXY_PROTOCOL_DIRECT:
		/* No proxy needed */
		break;

	default:
		return -EINVAL;
	}

	return ret;
}

/* ========== DNS Handling ========== */

#define DNS_PORT 53

int transparent_intercept_dns(struct transparent_context *ctx,
			      struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph;

	if (!ctx || !skb)
		return -EINVAL;

	if (!ctx->config.dns.intercept_dns)
		return -ENOENT;

	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_UDP)
		return -EINVAL;

	udph = udp_hdr(skb);
	if (!udph)
		return -EINVAL;

	/* Check if DNS query (port 53) */
	if (ntohs(udph->dest) != DNS_PORT)
		return -ENOENT;

	atomic64_inc(&ctx->dns_queries_intercepted);
	if (ctx->config.collect_stats)
		atomic64_inc(&transparent_stats.dns_intercepted);

	if (ctx->config.dns.proxy_dns)
		return transparent_proxy_dns_query(ctx, skb);

	return 0;
}

int transparent_proxy_dns_query(struct transparent_context *ctx,
				struct sk_buff *skb)
{
	if (!ctx || !skb)
		return -EINVAL;

	/* TODO: Implement DNS proxying through SOCKS5 or HTTP */
	/* This would involve:
	 * 1. Parse DNS query from packet
	 * 2. Send through proxy connection
	 * 3. Wait for response
	 * 4. Create response packet
	 * 5. Inject back into network stack
	 */

	atomic64_inc(&ctx->dns_queries_proxied);
	if (ctx->config.collect_stats)
		atomic64_inc(&transparent_stats.dns_proxied);

	return -ENOSYS; /* Not yet implemented */
}

int transparent_handle_dns_response(struct transparent_context *ctx,
				    struct sk_buff *skb)
{
	if (!ctx || !skb)
		return -EINVAL;

	/* TODO: Handle DNS response from proxy */
	return -ENOSYS;
}

/* ========== NAT Translation ========== */

static inline unsigned int nat_hash(__be32 saddr, __be16 sport,
				    __be32 daddr, __be16 dport, __u8 protocol)
{
	return jhash_3words((__force u32)saddr,
			    ((__force u32)daddr) ^ ((u32)sport << 16 | dport),
			    protocol, 0) & 1023;
}

struct nat_entry *transparent_nat_create(struct transparent_context *ctx,
					 struct sk_buff *skb,
					 __be32 proxy_addr,
					 __be16 proxy_port)
{
	struct nat_entry *nat;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	unsigned int hash;
	unsigned long flags;

	if (!ctx || !skb)
		return NULL;

	iph = ip_hdr(skb);
	if (!iph)
		return NULL;

	nat = kzalloc(sizeof(*nat), GFP_ATOMIC);
	if (!nat)
		return NULL;

	/* Store original addresses */
	nat->orig_saddr = iph->saddr;
	nat->orig_daddr = iph->daddr;
	nat->protocol = iph->protocol;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph) {
			kfree(nat);
			return NULL;
		}
		nat->orig_sport = tcph->source;
		nat->orig_dport = tcph->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph) {
			kfree(nat);
			return NULL;
		}
		nat->orig_sport = udph->source;
		nat->orig_dport = udph->dest;
	} else {
		kfree(nat);
		return NULL;
	}

	/* Store proxy addresses */
	nat->trans_daddr = proxy_addr;
	nat->trans_dport = proxy_port;
	nat->proxy_reply_addr = proxy_addr;
	nat->proxy_reply_port = proxy_port;

	nat->created = jiffies;
	nat->last_seen = jiffies;

	/* Add to hash table */
	hash = nat_hash(nat->orig_saddr, nat->orig_sport,
			nat->orig_daddr, nat->orig_dport, nat->protocol);

	spin_lock_irqsave(&ctx->nat->locks[hash], flags);
	hlist_add_head_rcu(&nat->hnode, &ctx->nat->buckets[hash]);
	spin_unlock_irqrestore(&ctx->nat->locks[hash], flags);

	atomic_inc(&ctx->nat->entry_count);
	atomic64_inc(&ctx->nat_entries_created);
	if (ctx->config.collect_stats)
		atomic64_inc(&transparent_stats.nat_created);

	pr_debug("mutex: Created NAT entry %pI4:%u -> %pI4:%u via %pI4:%u\n",
		 &nat->orig_saddr, ntohs(nat->orig_sport),
		 &nat->orig_daddr, ntohs(nat->orig_dport),
		 &nat->trans_daddr, ntohs(nat->trans_dport));

	return nat;
}

struct nat_entry *transparent_nat_lookup_outbound(struct transparent_context *ctx,
						  __be32 saddr, __be16 sport,
						  __be32 daddr, __be16 dport,
						  __u8 protocol)
{
	struct nat_entry *nat;
	unsigned int hash;
	unsigned long flags;

	if (!ctx)
		return NULL;

	hash = nat_hash(saddr, sport, daddr, dport, protocol);

	spin_lock_irqsave(&ctx->nat->locks[hash], flags);
	hlist_for_each_entry_rcu(nat, &ctx->nat->buckets[hash], hnode) {
		if (nat->orig_saddr == saddr &&
		    nat->orig_sport == sport &&
		    nat->orig_daddr == daddr &&
		    nat->orig_dport == dport &&
		    nat->protocol == protocol) {
			spin_unlock_irqrestore(&ctx->nat->locks[hash], flags);
			return nat;
		}
	}
	spin_unlock_irqrestore(&ctx->nat->locks[hash], flags);

	return NULL;
}

struct nat_entry *transparent_nat_lookup_inbound(struct transparent_context *ctx,
						 __be32 saddr, __be16 sport,
						 __be32 daddr, __be16 dport,
						 __u8 protocol)
{
	struct nat_entry *nat;
	int i;
	unsigned long flags;

	if (!ctx)
		return NULL;

	/* Inbound lookup requires full table scan since we're matching
	 * on different tuple (proxy addr/port -> original client)
	 */
	for (i = 0; i < 1024; i++) {
		spin_lock_irqsave(&ctx->nat->locks[i], flags);
		hlist_for_each_entry_rcu(nat, &ctx->nat->buckets[i], hnode) {
			if (nat->proxy_reply_addr == saddr &&
			    nat->proxy_reply_port == sport &&
			    nat->protocol == protocol) {
				spin_unlock_irqrestore(&ctx->nat->locks[i],
						       flags);
				return nat;
			}
		}
		spin_unlock_irqrestore(&ctx->nat->locks[i], flags);
	}

	return NULL;
}

void transparent_nat_delete(struct transparent_context *ctx,
			    struct nat_entry *entry)
{
	unsigned int hash;
	unsigned long flags;

	if (!ctx || !entry)
		return;

	hash = nat_hash(entry->orig_saddr, entry->orig_sport,
			entry->orig_daddr, entry->orig_dport, entry->protocol);

	spin_lock_irqsave(&ctx->nat->locks[hash], flags);
	hlist_del_rcu(&entry->hnode);
	spin_unlock_irqrestore(&ctx->nat->locks[hash], flags);

	kfree_rcu(entry, rcu);
	atomic_dec(&ctx->nat->entry_count);

	pr_debug("mutex: Deleted NAT entry\n");
}

void transparent_nat_cleanup(struct transparent_context *ctx)
{
	struct nat_entry *nat;
	struct hlist_node *tmp;
	unsigned long flags;
	int i;
	int deleted = 0;

	if (!ctx || !ctx->nat)
		return;

	for (i = 0; i < 1024; i++) {
		spin_lock_irqsave(&ctx->nat->locks[i], flags);
		hlist_for_each_entry_safe(nat, tmp, &ctx->nat->buckets[i],
					   hnode) {
			hlist_del_rcu(&nat->hnode);
			kfree_rcu(nat, rcu);
			deleted++;
		}
		spin_unlock_irqrestore(&ctx->nat->locks[i], flags);
	}

	atomic_set(&ctx->nat->entry_count, 0);
	pr_info("mutex: Cleaned up %d NAT entries\n", deleted);
}

/* ========== Packet Rewriting ========== */

int transparent_rewrite_outbound(struct transparent_context *ctx,
				 struct sk_buff *skb,
				 struct nat_entry *nat)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int ret;

	if (!ctx || !skb || !nat)
		return -EINVAL;

	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	/* Rewrite destination to proxy */
	ret = rewrite_ip_dest(skb, nat->trans_daddr);
	if (ret < 0)
		return ret;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return -EINVAL;
		ret = rewrite_tcp_dest(skb, nat->trans_dport);
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return -EINVAL;
		ret = rewrite_udp_dest(skb, nat->trans_dport);
	} else {
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	pr_debug("mutex: Rewrote outbound packet to proxy\n");
	return 0;
}

int transparent_rewrite_inbound(struct transparent_context *ctx,
				struct sk_buff *skb,
				struct nat_entry *nat)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int ret;

	if (!ctx || !skb || !nat)
		return -EINVAL;

	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	/* Rewrite source back to original destination */
	ret = rewrite_ip_source(skb, nat->orig_daddr);
	if (ret < 0)
		return ret;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return -EINVAL;
		ret = rewrite_tcp_source(skb, nat->orig_dport);
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return -EINVAL;
		ret = rewrite_udp_source(skb, nat->orig_dport);
	} else {
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	pr_debug("mutex: Rewrote inbound packet from proxy\n");
	return 0;
}

/* ========== Process Filtering ========== */

bool transparent_should_intercept_process(struct transparent_context *ctx,
					  struct sk_buff *skb)
{
	pid_t current_pid;

	if (!ctx || !skb)
		return false;

	/* Global mode intercepts all processes */
	if (ctx->config.mode == TRANSPARENT_MODE_GLOBAL)
		return true;

	/* If no target PID, intercept all */
	if (ctx->config.target_pid == 0)
		return true;

	/* Get current process PID */
	current_pid = task_pid_nr(current);

	/* Check if current process matches target */
	if (current_pid == ctx->config.target_pid)
		return true;

	/* Check if child process should be intercepted */
	if (ctx->config.inherit_children &&
	    transparent_is_child_process(ctx->config.target_pid, current_pid))
		return true;

	return false;
}

bool transparent_is_target_process(struct transparent_context *ctx, pid_t pid)
{
	if (!ctx)
		return false;

	if (ctx->config.target_pid == 0)
		return true;

	if (pid == ctx->config.target_pid)
		return true;

	if (ctx->config.inherit_children &&
	    transparent_is_child_process(ctx->config.target_pid, pid))
		return true;

	return false;
}

bool transparent_is_child_process(pid_t parent, pid_t child)
{
	struct task_struct *task;
	struct pid *pid_struct;
	pid_t current_ppid;

	/* Get task struct for child */
	pid_struct = find_get_pid(child);
	if (!pid_struct)
		return false;

	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task) {
		put_pid(pid_struct);
		return false;
	}

	/* Walk up parent chain */
	rcu_read_lock();
	while (task && task->pid != 0) {
		current_ppid = task_ppid_nr(task);
		if (current_ppid == parent) {
			rcu_read_unlock();
			put_pid(pid_struct);
			return true;
		}
		task = pid_task(find_get_pid(current_ppid), PIDTYPE_PID);
	}
	rcu_read_unlock();

	put_pid(pid_struct);
	return false;
}

/* ========== Integration Functions ========== */

int transparent_attach_to_connection(struct mutex_conn_entry *conn,
				     struct transparent_context *ctx)
{
	if (!conn || !ctx)
		return -EINVAL;

	transparent_context_get(ctx);
	conn->transparent_ctx = ctx;
	return 0;
}

struct transparent_context *transparent_get_from_connection(
	struct mutex_conn_entry *conn)
{
	if (!conn)
		return NULL;

	return conn->transparent_ctx;
}

/* ========== Netfilter Hook Integration ========== */

unsigned int transparent_nf_hook_in(void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct transparent_context *ctx = priv;
	struct mutex_conn_entry *conn;
	int ret;

	if (!ctx || !skb)
		return NF_ACCEPT;

	/* Lookup connection */
	conn = mutex_conn_lookup_by_skb(skb);
	if (!conn)
		return NF_ACCEPT;

	/* Handle inbound traffic from proxy */
	ret = transparent_intercept_inbound(ctx, skb, conn);
	if (ret < 0)
		return NF_ACCEPT;

	return NF_ACCEPT;
}

unsigned int transparent_nf_hook_out(void *priv,
				     struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct transparent_context *ctx = priv;
	struct mutex_conn_entry *conn;
	int ret;

	if (!ctx || !skb)
		return NF_ACCEPT;

	/* Check if should intercept this process */
	if (!transparent_should_intercept_process(ctx, skb))
		return NF_ACCEPT;

	/* Lookup or create connection */
	conn = mutex_conn_lookup_by_skb(skb);
	if (!conn) {
		conn = mutex_conn_alloc_from_skb(skb);
		if (!conn)
			return NF_ACCEPT;
	}

	/* Attach transparent context if not already attached */
	if (!conn->transparent_ctx)
		transparent_attach_to_connection(conn, ctx);

	/* Intercept DNS if configured */
	if (ctx->config.dns.intercept_dns) {
		ret = transparent_intercept_dns(ctx, skb);
		if (ret == 0)
			return NF_STOLEN; /* DNS handled */
	}

	/* Intercept outbound connection */
	ret = transparent_intercept_outbound(ctx, skb, conn);
	if (ret < 0)
		return NF_ACCEPT;

	return NF_ACCEPT;
}

unsigned int transparent_nf_hook_forward(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	/* Forward hook not needed for transparent proxy */
	return NF_ACCEPT;
}

/* ========== Statistics and Monitoring ========== */

void transparent_stats_init(void)
{
	atomic64_set(&transparent_stats.total_intercepted, 0);
	atomic64_set(&transparent_stats.total_proxied, 0);
	atomic64_set(&transparent_stats.total_bypassed, 0);
	atomic64_set(&transparent_stats.total_direct, 0);
	atomic64_set(&transparent_stats.socks4_used, 0);
	atomic64_set(&transparent_stats.socks5_used, 0);
	atomic64_set(&transparent_stats.http_used, 0);
	atomic64_set(&transparent_stats.dns_intercepted, 0);
	atomic64_set(&transparent_stats.dns_proxied, 0);
	atomic64_set(&transparent_stats.nat_created, 0);
	atomic64_set(&transparent_stats.nat_expired, 0);
	atomic64_set(&transparent_stats.rewrite_errors, 0);
	atomic64_set(&transparent_stats.connection_errors, 0);
}

void transparent_stats_print(void)
{
	pr_info("mutex: Transparent Proxy Statistics:\n");
	pr_info("  Intercepted: %llu\n",
		atomic64_read(&transparent_stats.total_intercepted));
	pr_info("  Proxied:     %llu\n",
		atomic64_read(&transparent_stats.total_proxied));
	pr_info("  Bypassed:    %llu\n",
		atomic64_read(&transparent_stats.total_bypassed));
	pr_info("  Direct:      %llu\n",
		atomic64_read(&transparent_stats.total_direct));
	pr_info("  SOCKS4:      %llu\n",
		atomic64_read(&transparent_stats.socks4_used));
	pr_info("  SOCKS5:      %llu\n",
		atomic64_read(&transparent_stats.socks5_used));
	pr_info("  HTTP:        %llu\n",
		atomic64_read(&transparent_stats.http_used));
	pr_info("  DNS Int:     %llu\n",
		atomic64_read(&transparent_stats.dns_intercepted));
	pr_info("  DNS Proxy:   %llu\n",
		atomic64_read(&transparent_stats.dns_proxied));
	pr_info("  NAT Created: %llu\n",
		atomic64_read(&transparent_stats.nat_created));
	pr_info("  NAT Expired: %llu\n",
		atomic64_read(&transparent_stats.nat_expired));
	pr_info("  Errors (RW): %llu\n",
		atomic64_read(&transparent_stats.rewrite_errors));
	pr_info("  Errors (CN): %llu\n",
		atomic64_read(&transparent_stats.connection_errors));
}

void transparent_stats_update(struct transparent_context *ctx)
{
	if (!ctx || !ctx->config.collect_stats)
		return;

	/* Statistics are updated in real-time by individual functions */
}

/* ========== Utility Functions ========== */

const char *transparent_mode_name(enum transparent_mode mode)
{
	switch (mode) {
	case TRANSPARENT_MODE_DISABLED:
		return "Disabled";
	case TRANSPARENT_MODE_PROCESS:
		return "Process";
	case TRANSPARENT_MODE_GLOBAL:
		return "Global";
	case TRANSPARENT_MODE_CGROUP:
		return "Cgroup";
	default:
		return "Unknown";
	}
}

const char *proxy_protocol_name(enum proxy_protocol_type protocol)
{
	switch (protocol) {
	case PROXY_PROTOCOL_AUTO:
		return "Auto";
	case PROXY_PROTOCOL_SOCKS4:
		return "SOCKS4";
	case PROXY_PROTOCOL_SOCKS5:
		return "SOCKS5";
	case PROXY_PROTOCOL_HTTP:
		return "HTTP";
	case PROXY_PROTOCOL_DIRECT:
		return "Direct";
	default:
		return "Unknown";
	}
}

const char *addr_class_name(enum addr_class class)
{
	switch (class) {
	case ADDR_CLASS_LOCAL:
		return "Local";
	case ADDR_CLASS_PRIVATE:
		return "Private";
	case ADDR_CLASS_PUBLIC:
		return "Public";
	case ADDR_CLASS_MULTICAST:
		return "Multicast";
	case ADDR_CLASS_LINK_LOCAL:
		return "Link-local";
	case ADDR_CLASS_UNKNOWN:
		return "Unknown";
	default:
		return "Invalid";
	}
}

bool ipv4_addr_in_network(__be32 addr, __be32 network, __be32 mask)
{
	return (addr & mask) == (network & mask);
}

bool ipv6_addr_in_network(const struct in6_addr *addr,
			  const struct in6_addr *network,
			  const struct in6_addr *mask)
{
	int i;

	for (i = 0; i < 4; i++) {
		if ((addr->s6_addr32[i] & mask->s6_addr32[i]) !=
		    (network->s6_addr32[i] & mask->s6_addr32[i]))
			return false;
	}
	return true;
}

/* ========== Module Initialization ========== */

int mutex_transparent_init(void)
{
	transparent_stats_init();
	pr_info("mutex: Transparent proxy module initialized\n");
	return 0;
}

void mutex_transparent_exit(void)
{
	transparent_stats_print();
	pr_info("mutex: Transparent proxy module exited\n");
}
