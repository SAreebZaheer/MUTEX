// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_ipv6.c - MUTEX IPv6 support implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements comprehensive IPv6 support for the MUTEX proxy system.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ndisc.h>

#include "mutex_ipv6.h"

/* Module statistics */
static struct ipv6_stats g_ipv6_stats = {0};
static DEFINE_SPINLOCK(stats_lock);

/* ========================================================================
 * IPv6 Header Parsing
 * ======================================================================== */

/**
 * ipv6_parse_headers - Parse IPv6 headers and extension headers
 * @skb: Socket buffer containing IPv6 packet
 * @info: Output structure for parsed header information
 *
 * Parses the IPv6 main header and all extension headers, extracting
 * information needed for packet processing.
 *
 * Return: IPV6_PARSE_OK on success, error code otherwise
 */
enum ipv6_parse_result ipv6_parse_headers(struct sk_buff *skb,
					   struct ipv6_header_info *info)
{
	struct ipv6hdr *ipv6h;
	__u8 next_header;
	__u16 offset;
	int i;

	if (!skb || !info)
		return IPV6_PARSE_INVALID;

	memset(info, 0, sizeof(*info));

	/* Get IPv6 header */
	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return IPV6_PARSE_INVALID;

	info->ipv6h = ipv6h;
	next_header = ipv6h->nexthdr;
	offset = sizeof(struct ipv6hdr);

	/* Parse extension headers */
	for (i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
		if (!ipv6_is_extension_header(next_header))
			break;

		if (info->num_ext_headers >= IPV6_MAX_EXT_HEADERS) {
			pr_warn("IPv6: Too many extension headers\n");
			spin_lock(&stats_lock);
			g_ipv6_stats.parse_errors++;
			spin_unlock(&stats_lock);
			return IPV6_PARSE_TOO_MANY_EXT;
		}

		/* Parse this extension header */
		struct ipv6_ext_header *ext = &info->ext_headers[info->num_ext_headers];

		if (ipv6_parse_extension_header(skb, offset, ext) < 0) {
			pr_warn("IPv6: Failed to parse extension header\n");
			spin_lock(&stats_lock);
			g_ipv6_stats.parse_errors++;
			spin_unlock(&stats_lock);
			return IPV6_PARSE_INVALID;
		}

		/* Check for fragment header */
		if (next_header == IPPROTO_FRAGMENT) {
			struct frag_hdr *fh;

			if (offset + sizeof(struct frag_hdr) > skb->len)
				return IPV6_PARSE_TRUNCATED;

			fh = (struct frag_hdr *)(skb->data + offset);
			info->has_fragment = true;
			info->fragment_offset = ntohs(fh->frag_off) & IPV6_FRAG_OFFSET_MASK;
			info->is_first_fragment = (info->fragment_offset == 0);
			info->is_last_fragment = !(ntohs(fh->frag_off) & IPV6_FRAG_MORE_FLAG);
			info->fragment_id = ntohl(fh->identification);
		}

		next_header = ext->next_header;
		offset += ext->length;
		info->num_ext_headers++;
	}

	info->upper_protocol = next_header;
	info->payload_offset = offset;

	spin_lock(&stats_lock);
	g_ipv6_stats.extension_headers_processed += info->num_ext_headers;
	if (info->has_fragment)
		g_ipv6_stats.fragments_processed++;
	spin_unlock(&stats_lock);

	return IPV6_PARSE_OK;
}
EXPORT_SYMBOL(ipv6_parse_headers);

/**
 * ipv6_validate_packet - Validate IPv6 packet structure
 * @skb: Socket buffer to validate
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_validate_packet(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h;

	if (!skb || skb->len < sizeof(struct ipv6hdr))
		return -EINVAL;

	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return -EINVAL;

	/* Check version field */
	if ((ipv6h->version) != 6)
		return -EINVAL;

	/* Validate payload length */
	if (ntohs(ipv6h->payload_len) + sizeof(struct ipv6hdr) > skb->len)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(ipv6_validate_packet);

/**
 * ipv6_has_extension_headers - Check if packet has extension headers
 * @skb: Socket buffer to check
 *
 * Return: true if extension headers present, false otherwise
 */
bool ipv6_has_extension_headers(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);

	if (!ipv6h)
		return false;

	return ipv6_is_extension_header(ipv6h->nexthdr);
}
EXPORT_SYMBOL(ipv6_has_extension_headers);

/**
 * ipv6_get_upper_protocol - Get upper layer protocol from IPv6 packet
 * @skb: Socket buffer
 *
 * Return: Upper layer protocol number
 */
__u8 ipv6_get_upper_protocol(struct sk_buff *skb)
{
	struct ipv6_header_info info;

	if (ipv6_parse_headers(skb, &info) != IPV6_PARSE_OK)
		return IPPROTO_NONE;

	return info.upper_protocol;
}
EXPORT_SYMBOL(ipv6_get_upper_protocol);

/**
 * ipv6_get_payload_offset - Get offset to upper layer payload
 * @skb: Socket buffer
 *
 * Return: Offset in bytes to payload
 */
__u16 ipv6_get_payload_offset(struct sk_buff *skb)
{
	struct ipv6_header_info info;

	if (ipv6_parse_headers(skb, &info) != IPV6_PARSE_OK)
		return 0;

	return info.payload_offset;
}
EXPORT_SYMBOL(ipv6_get_payload_offset);

/* ========================================================================
 * Extension Header Handling
 * ======================================================================== */

/**
 * ipv6_is_extension_header - Check if next header is an extension header
 * @next_header: Next header value to check
 *
 * Return: true if extension header, false otherwise
 */
bool ipv6_is_extension_header(__u8 next_header)
{
	switch (next_header) {
	case IPPROTO_HOPOPTS:		/* Hop-by-Hop Options */
	case IPPROTO_ROUTING:		/* Routing Header */
	case IPPROTO_FRAGMENT:		/* Fragment Header */
	case IPPROTO_DSTOPTS:		/* Destination Options */
	case IPPROTO_AH:		/* Authentication Header */
	case IPPROTO_ESP:		/* Encapsulating Security Payload */
	case IPPROTO_MH:		/* Mobility Header */
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL(ipv6_is_extension_header);

/**
 * ipv6_parse_extension_header - Parse a single extension header
 * @skb: Socket buffer
 * @offset: Offset where extension header starts
 * @ext_info: Output structure for extension header info
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_parse_extension_header(struct sk_buff *skb, __u16 offset,
				 struct ipv6_ext_header *ext_info)
{
	struct ipv6_opt_hdr *opt_hdr;
	__u8 next_header;
	__u16 length;

	if (!skb || !ext_info || offset >= skb->len)
		return -EINVAL;

	opt_hdr = (struct ipv6_opt_hdr *)(skb->data + offset);
	next_header = opt_hdr->nexthdr;

	/* Fragment header has fixed length */
	if (opt_hdr->nexthdr == IPPROTO_FRAGMENT) {
		length = 8;
	} else {
		/* Most extension headers: length = (hdrlen + 1) * 8 */
		length = (opt_hdr->hdrlen + 1) * 8;
	}

	if (offset + length > skb->len)
		return -EINVAL;

	ext_info->type = next_header;
	ext_info->offset = offset;
	ext_info->length = length;
	ext_info->next_header = next_header;

	return 0;
}
EXPORT_SYMBOL(ipv6_parse_extension_header);

/**
 * ipv6_skip_extension_headers - Skip all extension headers
 * @skb: Socket buffer
 * @offset: Input/output offset (updated to payload start)
 * @next_proto: Output next protocol after extensions
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_skip_extension_headers(struct sk_buff *skb, __u16 *offset,
				 __u8 *next_proto)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	__u8 nexthdr = ipv6h->nexthdr;
	__u16 off = sizeof(struct ipv6hdr);

	while (ipv6_is_extension_header(nexthdr) && off < skb->len) {
		struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)(skb->data + off);

		if (nexthdr == IPPROTO_FRAGMENT) {
			off += 8;
		} else {
			off += (opt->hdrlen + 1) * 8;
		}

		nexthdr = opt->nexthdr;

		if (off > skb->len)
			return -EINVAL;
	}

	*offset = off;
	*next_proto = nexthdr;
	return 0;
}
EXPORT_SYMBOL(ipv6_skip_extension_headers);

/* ========================================================================
 * Checksum Operations
 * ======================================================================== */

/**
 * ipv6_calculate_checksum - Calculate IPv6 upper layer checksum
 * @params: Checksum calculation parameters
 *
 * Return: Calculated checksum value
 */
__sum16 ipv6_calculate_checksum(const struct ipv6_checksum_params *params)
{
	__wsum csum;

	if (!params || !params->saddr || !params->daddr || !params->data)
		return 0;

	/* Calculate pseudo-header checksum */
	csum = csum_ipv6_magic(params->saddr, params->daddr,
			       params->len, params->proto, 0);

	/* Add payload checksum */
	csum = csum_partial(params->data, params->len, csum);

	return csum_fold(csum);
}
EXPORT_SYMBOL(ipv6_calculate_checksum);

/**
 * ipv6_calculate_tcp_checksum - Calculate TCP checksum for IPv6
 * @skb: Socket buffer containing TCP packet
 * @saddr: Source IPv6 address
 * @daddr: Destination IPv6 address
 *
 * Return: Calculated TCP checksum
 */
__sum16 ipv6_calculate_tcp_checksum(struct sk_buff *skb,
				     const struct in6_addr *saddr,
				     const struct in6_addr *daddr)
{
	struct ipv6_checksum_params params;
	__u16 offset = ipv6_get_payload_offset(skb);

	params.saddr = saddr;
	params.daddr = daddr;
	params.len = skb->len - offset;
	params.proto = IPPROTO_TCP;
	params.data = skb->data + offset;

	return ipv6_calculate_checksum(&params);
}
EXPORT_SYMBOL(ipv6_calculate_tcp_checksum);

/**
 * ipv6_calculate_udp_checksum - Calculate UDP checksum for IPv6
 * @skb: Socket buffer containing UDP packet
 * @saddr: Source IPv6 address
 * @daddr: Destination IPv6 address
 *
 * Return: Calculated UDP checksum
 */
__sum16 ipv6_calculate_udp_checksum(struct sk_buff *skb,
				     const struct in6_addr *saddr,
				     const struct in6_addr *daddr)
{
	struct ipv6_checksum_params params;
	__u16 offset = ipv6_get_payload_offset(skb);

	params.saddr = saddr;
	params.daddr = daddr;
	params.len = skb->len - offset;
	params.proto = IPPROTO_UDP;
	params.data = skb->data + offset;

	return ipv6_calculate_checksum(&params);
}
EXPORT_SYMBOL(ipv6_calculate_udp_checksum);

/**
 * ipv6_calculate_icmpv6_checksum - Calculate ICMPv6 checksum
 * @skb: Socket buffer containing ICMPv6 packet
 * @saddr: Source IPv6 address
 * @daddr: Destination IPv6 address
 *
 * Return: Calculated ICMPv6 checksum
 */
__sum16 ipv6_calculate_icmpv6_checksum(struct sk_buff *skb,
					const struct in6_addr *saddr,
					const struct in6_addr *daddr)
{
	struct ipv6_checksum_params params;
	__u16 offset = ipv6_get_payload_offset(skb);

	params.saddr = saddr;
	params.daddr = daddr;
	params.len = skb->len - offset;
	params.proto = IPPROTO_ICMPV6;
	params.data = skb->data + offset;

	return ipv6_calculate_checksum(&params);
}
EXPORT_SYMBOL(ipv6_calculate_icmpv6_checksum);

/**
 * ipv6_update_checksum - Update checksums after packet modification
 * @skb: Socket buffer
 * @info: Parsed header information
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_update_checksum(struct sk_buff *skb, struct ipv6_header_info *info)
{
	struct ipv6hdr *ipv6h;
	__sum16 new_csum;

	if (!skb || !info)
		return -EINVAL;

	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return -EINVAL;

	/* Update upper layer checksum based on protocol */
	switch (info->upper_protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph;

		if (info->payload_offset + sizeof(struct tcphdr) > skb->len)
			return -EINVAL;

		tcph = (struct tcphdr *)(skb->data + info->payload_offset);
		tcph->check = 0;
		new_csum = ipv6_calculate_tcp_checksum(skb, &ipv6h->saddr,
						       &ipv6h->daddr);
		tcph->check = new_csum;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph;

		if (info->payload_offset + sizeof(struct udphdr) > skb->len)
			return -EINVAL;

		udph = (struct udphdr *)(skb->data + info->payload_offset);
		udph->check = 0;
		new_csum = ipv6_calculate_udp_checksum(skb, &ipv6h->saddr,
						       &ipv6h->daddr);
		/* UDP checksum is mandatory in IPv6 */
		udph->check = new_csum ? new_csum : CSUM_MANGLED_0;
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr *icmp6h;

		if (info->payload_offset + sizeof(struct icmp6hdr) > skb->len)
			return -EINVAL;

		icmp6h = (struct icmp6hdr *)(skb->data + info->payload_offset);
		icmp6h->icmp6_cksum = 0;
		new_csum = ipv6_calculate_icmpv6_checksum(skb, &ipv6h->saddr,
							  &ipv6h->daddr);
		icmp6h->icmp6_cksum = new_csum;

		spin_lock(&stats_lock);
		g_ipv6_stats.icmpv6_processed++;
		spin_unlock(&stats_lock);
		break;
	}
	default:
		/* Other protocols may not have checksums */
		break;
	}

	return 0;
}
EXPORT_SYMBOL(ipv6_update_checksum);

/**
 * ipv6_verify_checksum - Verify upper layer checksum
 * @skb: Socket buffer
 * @info: Parsed header information
 *
 * Return: 0 if checksum valid, negative error code otherwise
 */
int ipv6_verify_checksum(struct sk_buff *skb, struct ipv6_header_info *info)
{
	struct ipv6hdr *ipv6h;
	__sum16 expected, actual;

	if (!skb || !info)
		return -EINVAL;

	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return -EINVAL;

	switch (info->upper_protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph;

		if (info->payload_offset + sizeof(struct tcphdr) > skb->len)
			return -EINVAL;

		tcph = (struct tcphdr *)(skb->data + info->payload_offset);
		actual = tcph->check;
		tcph->check = 0;
		expected = ipv6_calculate_tcp_checksum(skb, &ipv6h->saddr,
						       &ipv6h->daddr);
		tcph->check = actual;

		if (actual != expected) {
			spin_lock(&stats_lock);
			g_ipv6_stats.checksum_errors++;
			spin_unlock(&stats_lock);
			return -EINVAL;
		}
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph;

		if (info->payload_offset + sizeof(struct udphdr) > skb->len)
			return -EINVAL;

		udph = (struct udphdr *)(skb->data + info->payload_offset);
		actual = udph->check;

		/* UDP checksum of 0 is not allowed in IPv6 */
		if (actual == 0) {
			spin_lock(&stats_lock);
			g_ipv6_stats.checksum_errors++;
			spin_unlock(&stats_lock);
			return -EINVAL;
		}

		udph->check = 0;
		expected = ipv6_calculate_udp_checksum(skb, &ipv6h->saddr,
						       &ipv6h->daddr);
		udph->check = actual;

		if (actual != expected) {
			spin_lock(&stats_lock);
			g_ipv6_stats.checksum_errors++;
			spin_unlock(&stats_lock);
			return -EINVAL;
		}
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr *icmp6h;

		if (info->payload_offset + sizeof(struct icmp6hdr) > skb->len)
			return -EINVAL;

		icmp6h = (struct icmp6hdr *)(skb->data + info->payload_offset);
		actual = icmp6h->icmp6_cksum;
		icmp6h->icmp6_cksum = 0;
		expected = ipv6_calculate_icmpv6_checksum(skb, &ipv6h->saddr,
							  &ipv6h->daddr);
		icmp6h->icmp6_cksum = actual;

		if (actual != expected) {
			spin_lock(&stats_lock);
			g_ipv6_stats.checksum_errors++;
			spin_unlock(&stats_lock);
			return -EINVAL;
		}
		break;
	}
	default:
		/* Other protocols: assume OK */
		break;
	}

	return 0;
}
EXPORT_SYMBOL(ipv6_verify_checksum);

/* ========================================================================
 * Address Translation
 * ======================================================================== */

/**
 * ipv6_rewrite_addresses - Rewrite IPv6 addresses in packet
 * @skb: Socket buffer
 * @params: Rewrite parameters
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_rewrite_addresses(struct sk_buff *skb,
			    const struct ipv6_rewrite_params *params)
{
	struct ipv6hdr *ipv6h;
	struct ipv6_header_info info;
	int ret;

	if (!skb || !params)
		return -EINVAL;

	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return -EINVAL;

	/* Parse headers first */
	ret = ipv6_parse_headers(skb, &info);
	if (ret != IPV6_PARSE_OK)
		return -EINVAL;

	/* Update source address if requested */
	if (params->new_saddr) {
		memcpy(&ipv6h->saddr, params->new_saddr, sizeof(struct in6_addr));
	}

	/* Update destination address if requested */
	if (params->new_daddr) {
		memcpy(&ipv6h->daddr, params->new_daddr, sizeof(struct in6_addr));
	}

	/* Update checksums if requested */
	if (params->update_checksums) {
		ret = ipv6_update_checksum(skb, &info);
		if (ret < 0)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL(ipv6_rewrite_addresses);

/**
 * ipv6_is_v4_mapped - Check if address is IPv4-mapped IPv6
 * @addr: IPv6 address to check
 *
 * Return: true if IPv4-mapped, false otherwise
 */
bool ipv6_is_v4_mapped(const struct in6_addr *addr)
{
	return ipv6_addr_v4mapped(addr);
}
EXPORT_SYMBOL(ipv6_is_v4_mapped);

/**
 * ipv6_v4_to_v6_mapped - Convert IPv4 address to IPv4-mapped IPv6
 * @v4_addr: IPv4 address
 * @v6_addr: Output IPv6 address (::ffff:x.x.x.x)
 */
void ipv6_v4_to_v6_mapped(const __be32 v4_addr, struct in6_addr *v6_addr)
{
	ipv6_addr_set_v4mapped(v4_addr, v6_addr);
}
EXPORT_SYMBOL(ipv6_v4_to_v6_mapped);

/* ========================================================================
 * Address Classification
 * ======================================================================== */

/**
 * ipv6_classify_address - Classify IPv6 address type
 * @addr: IPv6 address to classify
 *
 * Return: Bitmask of IPV6_ADDR_* flags
 */
__u32 ipv6_classify_address(const struct in6_addr *addr)
{
	__u32 type = 0;

	if (!addr)
		return 0;

	if (ipv6_addr_any(addr))
		type |= IPV6_ADDR_UNSPECIFIED;

	if (ipv6_addr_loopback(addr))
		type |= IPV6_ADDR_LOOPBACK;

	if (ipv6_addr_is_multicast(addr))
		type |= IPV6_ADDR_MULTICAST;

	if (ipv6_addr_type(addr) & IPV6_ADDR_LINKLOCAL)
		type |= IPV6_ADDR_LINKLOCAL;

	if ((addr->s6_addr[0] & 0xfe) == 0xfc)
		type |= IPV6_ADDR_UNIQUELOCAL;

	if (ipv6_addr_v4mapped(addr))
		type |= IPV6_ADDR_V4MAPPED;

	/* If none of the special types, it's likely global unicast */
	if (type == 0)
		type |= IPV6_ADDR_GLOBAL;

	return type;
}
EXPORT_SYMBOL(ipv6_classify_address);

/**
 * ipv6_is_global_unicast - Check if address is global unicast
 * @addr: IPv6 address to check
 *
 * Return: true if global unicast, false otherwise
 */
bool ipv6_is_global_unicast(const struct in6_addr *addr)
{
	__u32 type = ipv6_classify_address(addr);
	return (type & IPV6_ADDR_GLOBAL) != 0;
}
EXPORT_SYMBOL(ipv6_is_global_unicast);

/**
 * ipv6_is_unique_local - Check if address is unique local
 * @addr: IPv6 address to check
 *
 * Return: true if unique local (fc00::/7), false otherwise
 */
bool ipv6_is_unique_local(const struct in6_addr *addr)
{
	return (addr->s6_addr[0] & 0xfe) == 0xfc;
}
EXPORT_SYMBOL(ipv6_is_unique_local);

/* ========================================================================
 * ICMPv6 Handling
 * ======================================================================== */

/**
 * ipv6_is_icmpv6_error - Check if ICMPv6 type is an error message
 * @type: ICMPv6 message type
 *
 * Return: true if error message, false otherwise
 */
bool ipv6_is_icmpv6_error(__u8 type)
{
	return type < 128;
}
EXPORT_SYMBOL(ipv6_is_icmpv6_error);

/**
 * ipv6_process_icmpv6 - Process ICMPv6 packet
 * @skb: Socket buffer
 * @info: Parsed header information
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_process_icmpv6(struct sk_buff *skb, struct ipv6_header_info *info)
{
	struct icmp6hdr *icmp6h;

	if (!skb || !info)
		return -EINVAL;

	if (info->payload_offset + sizeof(struct icmp6hdr) > skb->len)
		return -EINVAL;

	icmp6h = (struct icmp6hdr *)(skb->data + info->payload_offset);

	/* Verify checksum */
	if (ipv6_verify_checksum(skb, info) < 0) {
		pr_warn("IPv6: ICMPv6 checksum verification failed\n");
		return -EINVAL;
	}

	spin_lock(&stats_lock);
	g_ipv6_stats.icmpv6_processed++;
	spin_unlock(&stats_lock);

	return 0;
}
EXPORT_SYMBOL(ipv6_process_icmpv6);

/* ========================================================================
 * Fragmentation Handling
 * ======================================================================== */

/**
 * ipv6_is_fragmented - Check if packet is fragmented
 * @skb: Socket buffer
 *
 * Return: true if fragmented, false otherwise
 */
bool ipv6_is_fragmented(struct sk_buff *skb)
{
	struct ipv6_header_info info;

	if (ipv6_parse_headers(skb, &info) != IPV6_PARSE_OK)
		return false;

	return info.has_fragment;
}
EXPORT_SYMBOL(ipv6_is_fragmented);

/**
 * ipv6_parse_fragment_header - Parse fragment header information
 * @skb: Socket buffer
 * @frag_info: Output fragment information
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_parse_fragment_header(struct sk_buff *skb,
				struct ipv6_fragment_info *frag_info)
{
	struct ipv6_header_info info;
	int ret;

	if (!skb || !frag_info)
		return -EINVAL;

	memset(frag_info, 0, sizeof(*frag_info));

	ret = ipv6_parse_headers(skb, &info);
	if (ret != IPV6_PARSE_OK)
		return -EINVAL;

	if (!info.has_fragment)
		return -ENOENT;

	frag_info->original_id = info.fragment_id;
	frag_info->reassembled = false;

	return 0;
}
EXPORT_SYMBOL(ipv6_parse_fragment_header);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * ipv6_print_address - Format IPv6 address as string
 * @addr: IPv6 address
 * @buf: Output buffer
 * @len: Buffer length
 */
void ipv6_print_address(const struct in6_addr *addr, char *buf, size_t len)
{
	if (!addr || !buf || len == 0)
		return;

	snprintf(buf, len, "%pI6c", addr);
}
EXPORT_SYMBOL(ipv6_print_address);

/**
 * ipv6_compare_addresses - Compare two IPv6 addresses
 * @addr1: First address
 * @addr2: Second address
 *
 * Return: 0 if equal, non-zero otherwise
 */
int ipv6_compare_addresses(const struct in6_addr *addr1,
			    const struct in6_addr *addr2)
{
	if (!addr1 || !addr2)
		return -1;

	return ipv6_addr_cmp(addr1, addr2);
}
EXPORT_SYMBOL(ipv6_compare_addresses);

/**
 * ipv6_copy_address - Copy IPv6 address
 * @dst: Destination
 * @src: Source
 */
void ipv6_copy_address(struct in6_addr *dst, const struct in6_addr *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(struct in6_addr));
}
EXPORT_SYMBOL(ipv6_copy_address);

/* ========================================================================
 * Statistics and Debugging
 * ======================================================================== */

/**
 * ipv6_get_stats - Get IPv6 statistics
 * @stats: Output statistics structure
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_get_stats(struct ipv6_stats *stats)
{
	if (!stats)
		return -EINVAL;

	spin_lock(&stats_lock);
	memcpy(stats, &g_ipv6_stats, sizeof(*stats));
	spin_unlock(&stats_lock);

	return 0;
}
EXPORT_SYMBOL(ipv6_get_stats);

/**
 * ipv6_reset_stats - Reset IPv6 statistics
 */
void ipv6_reset_stats(void)
{
	spin_lock(&stats_lock);
	memset(&g_ipv6_stats, 0, sizeof(g_ipv6_stats));
	spin_unlock(&stats_lock);
}
EXPORT_SYMBOL(ipv6_reset_stats);

/**
 * ipv6_dump_header - Dump IPv6 header information for debugging
 * @skb: Socket buffer
 */
void ipv6_dump_header(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h;
	char saddr[64], daddr[64];

	if (!skb)
		return;

	ipv6h = ipv6_hdr(skb);
	if (!ipv6h)
		return;

	ipv6_print_address(&ipv6h->saddr, saddr, sizeof(saddr));
	ipv6_print_address(&ipv6h->daddr, daddr, sizeof(daddr));

	pr_info("IPv6 Header:\n");
	pr_info("  Version: %u\n", ipv6h->version);
	pr_info("  Traffic Class: 0x%02x\n", (ipv6h->priority << 4) | ((ipv6h->flow_lbl[0] >> 4) & 0x0F));
	pr_info("  Flow Label: 0x%05x\n", ((ipv6h->flow_lbl[0] & 0x0F) << 16) | (ipv6h->flow_lbl[1] << 8) | ipv6h->flow_lbl[2]);
	pr_info("  Payload Length: %u\n", ntohs(ipv6h->payload_len));
	pr_info("  Next Header: %u\n", ipv6h->nexthdr);
	pr_info("  Hop Limit: %u\n", ipv6h->hop_limit);
	pr_info("  Source: %s\n", saddr);
	pr_info("  Destination: %s\n", daddr);
}
EXPORT_SYMBOL(ipv6_dump_header);

/* ========================================================================
 * Dual-Stack Support
 * ======================================================================== */

/**
 * ipv6_dual_stack_init - Initialize dual-stack context
 * @ctx: Dual-stack context
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_dual_stack_init(struct ipv6_dual_stack_context *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->prefer_ipv6 = true;  /* Prefer IPv6 by default (RFC 6724) */
	ctx->allow_v4_mapped = true;

	return 0;
}
EXPORT_SYMBOL(ipv6_dual_stack_init);

/* ========================================================================
 * Module Initialization
 * ======================================================================== */

/**
 * ipv6_support_init - Initialize IPv6 support module
 *
 * Return: 0 on success, negative error code otherwise
 */
int ipv6_support_init(void)
{
	pr_info("MUTEX IPv6 support module initialized\n");
	ipv6_reset_stats();
	return 0;
}
EXPORT_SYMBOL(ipv6_support_init);

/**
 * ipv6_support_exit - Cleanup IPv6 support module
 */
void ipv6_support_exit(void)
{
	pr_info("MUTEX IPv6 support module exiting\n");
	pr_info("  Packets processed: %llu\n", g_ipv6_stats.packets_processed);
	pr_info("  Packets proxied: %llu\n", g_ipv6_stats.packets_proxied);
	pr_info("  Extension headers: %llu\n", g_ipv6_stats.extension_headers_processed);
	pr_info("  Fragments: %llu\n", g_ipv6_stats.fragments_processed);
	pr_info("  ICMPv6 packets: %llu\n", g_ipv6_stats.icmpv6_processed);
	pr_info("  Checksum errors: %llu\n", g_ipv6_stats.checksum_errors);
	pr_info("  Parse errors: %llu\n", g_ipv6_stats.parse_errors);
}
EXPORT_SYMBOL(ipv6_support_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Team");
MODULE_DESCRIPTION("MUTEX IPv6 Support Module");
MODULE_VERSION("1.0");
