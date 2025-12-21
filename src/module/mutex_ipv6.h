/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_ipv6.h - MUTEX IPv6 support header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements full IPv6 support for the MUTEX proxy system,
 * including IPv6 header parsing, extension header handling, checksum
 * calculations, address translation, dual-stack support, fragmentation
 * handling, ICMPv6 support, and IPv6-specific proxy protocols.
 */

#ifndef _MUTEX_IPV6_H
#define _MUTEX_IPV6_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/addrconf.h>

/* IPv6 extension header types */
#define IPV6_EXT_HOP_BY_HOP		0	/* Hop-by-Hop Options */
#define IPV6_EXT_ROUTING		43	/* Routing Header */
#define IPV6_EXT_FRAGMENT		44	/* Fragment Header */
#define IPV6_EXT_DEST_OPTIONS		60	/* Destination Options */
#define IPV6_EXT_AUTH			51	/* Authentication Header */
#define IPV6_EXT_ESP			50	/* Encapsulating Security Payload */
#define IPV6_EXT_MOBILITY		135	/* Mobility Header */

/* IPv6 address types */
#define IPV6_ADDR_UNSPECIFIED		0x0001	/* :: */
#define IPV6_ADDR_LOOPBACK		0x0002	/* ::1 */
#define IPV6_ADDR_MULTICAST		0x0004	/* ffxx::/8 */
#define IPV6_ADDR_LINKLOCAL		0x0008	/* fe80::/10 */
#define IPV6_ADDR_SITELOCAL		0x0010	/* fec0::/10 (deprecated) */
#define IPV6_ADDR_UNIQUELOCAL		0x0020	/* fc00::/7 */
#define IPV6_ADDR_GLOBAL		0x0040	/* Global unicast */
#define IPV6_ADDR_V4MAPPED		0x0080	/* ::ffff:0:0/96 */
#define IPV6_ADDR_V4COMPAT		0x0100	/* ::/96 (deprecated) */

/* IPv6 fragmentation constants */
#define IPV6_FRAG_HDR_LEN		8
#define IPV6_FRAG_OFFSET_MASK		0xFFF8
#define IPV6_FRAG_MORE_FLAG		0x0001

/* Maximum extension headers we'll process */
#define IPV6_MAX_EXT_HEADERS		8

/* ICMPv6 message types we handle */
#define ICMPV6_DEST_UNREACH		1
#define ICMPV6_PKT_TOOBIG		2
#define ICMPV6_TIME_EXCEED		3
#define ICMPV6_PARAMPROB		4
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129
#define ICMPV6_MGM_QUERY		130
#define ICMPV6_MGM_REPORT		131
#define ICMPV6_MGM_REDUCTION		132

/**
 * enum ipv6_parse_result - Result of IPv6 header parsing
 * @IPV6_PARSE_OK: Successfully parsed
 * @IPV6_PARSE_INVALID: Invalid IPv6 packet
 * @IPV6_PARSE_UNSUPPORTED_EXT: Unsupported extension header
 * @IPV6_PARSE_TOO_MANY_EXT: Too many extension headers
 * @IPV6_PARSE_TRUNCATED: Packet truncated
 */
enum ipv6_parse_result {
	IPV6_PARSE_OK = 0,
	IPV6_PARSE_INVALID = -1,
	IPV6_PARSE_UNSUPPORTED_EXT = -2,
	IPV6_PARSE_TOO_MANY_EXT = -3,
	IPV6_PARSE_TRUNCATED = -4,
};

/**
 * struct ipv6_ext_header - IPv6 extension header info
 * @type: Extension header type (next header value)
 * @offset: Offset in packet where this header starts
 * @length: Total length of this extension header
 * @next_header: Next header type after this extension
 *
 * Information about a single IPv6 extension header.
 */
struct ipv6_ext_header {
	__u8 type;
	__u16 offset;
	__u16 length;
	__u8 next_header;
};

/**
 * struct ipv6_header_info - Parsed IPv6 header information
 * @ipv6h: Pointer to IPv6 header
 * @payload_offset: Offset to upper layer protocol data
 * @upper_protocol: Upper layer protocol (TCP, UDP, ICMPv6, etc.)
 * @num_ext_headers: Number of extension headers found
 * @ext_headers: Array of extension header information
 * @has_fragment: True if fragment header present
 * @fragment_offset: Fragment offset (in 8-byte units)
 * @is_first_fragment: True if this is the first fragment
 * @is_last_fragment: True if this is the last fragment
 * @fragment_id: Fragment identification value
 *
 * Complete information about parsed IPv6 headers.
 */
struct ipv6_header_info {
	struct ipv6hdr *ipv6h;
	__u16 payload_offset;
	__u8 upper_protocol;
	__u8 num_ext_headers;
	struct ipv6_ext_header ext_headers[IPV6_MAX_EXT_HEADERS];
	bool has_fragment;
	__u16 fragment_offset;
	bool is_first_fragment;
	bool is_last_fragment;
	__u32 fragment_id;
};

/**
 * struct ipv6_rewrite_params - Parameters for IPv6 packet rewriting
 * @new_saddr: New source IPv6 address (NULL = no change)
 * @new_daddr: New destination IPv6 address (NULL = no change)
 * @update_checksums: If true, recalculate all checksums
 * @preserve_ext_headers: If true, preserve all extension headers
 *
 * Parameters controlling IPv6 packet rewriting operations.
 */
struct ipv6_rewrite_params {
	const struct in6_addr *new_saddr;
	const struct in6_addr *new_daddr;
	bool update_checksums;
	bool preserve_ext_headers;
};

/**
 * struct ipv6_checksum_params - Parameters for IPv6 checksum calculation
 * @saddr: Source IPv6 address
 * @daddr: Destination IPv6 address
 * @len: Length of upper layer protocol data
 * @proto: Upper layer protocol number
 * @data: Pointer to upper layer protocol data
 *
 * Parameters for calculating IPv6 upper layer checksums.
 */
struct ipv6_checksum_params {
	const struct in6_addr *saddr;
	const struct in6_addr *daddr;
	__u32 len;
	__u8 proto;
	const void *data;
};

/**
 * struct ipv6_fragment_info - IPv6 fragmentation context
 * @original_id: Original fragment ID
 * @reassembled: True if this is a reassembled packet
 * @needs_refrag: True if packet needs to be refragmented
 * @max_fragment_size: Maximum fragment size for refragmentation
 *
 * Context for handling IPv6 fragmentation.
 */
struct ipv6_fragment_info {
	__u32 original_id;
	bool reassembled;
	bool needs_refrag;
	__u16 max_fragment_size;
};

/**
 * struct ipv6_dual_stack_context - Dual-stack (IPv4/IPv6) context
 * @prefer_ipv6: Prefer IPv6 when both available
 * @allow_v4_mapped: Allow IPv4-mapped IPv6 addresses
 * @allow_nat64: Allow NAT64 translation
 * @nat64_prefix: NAT64 prefix for translation
 *
 * Configuration for dual-stack IPv4/IPv6 operation.
 */
struct ipv6_dual_stack_context {
	bool prefer_ipv6;
	bool allow_v4_mapped;
	bool allow_nat64;
	struct in6_addr nat64_prefix;
};

/* Function prototypes */

/* IPv6 header parsing */
enum ipv6_parse_result ipv6_parse_headers(struct sk_buff *skb,
					   struct ipv6_header_info *info);
int ipv6_validate_packet(struct sk_buff *skb);
bool ipv6_has_extension_headers(struct sk_buff *skb);
__u8 ipv6_get_upper_protocol(struct sk_buff *skb);
__u16 ipv6_get_payload_offset(struct sk_buff *skb);

/* Extension header handling */
int ipv6_parse_extension_header(struct sk_buff *skb, __u16 offset,
				 struct ipv6_ext_header *ext_info);
int ipv6_skip_extension_headers(struct sk_buff *skb, __u16 *offset,
				 __u8 *next_proto);
bool ipv6_is_extension_header(__u8 next_header);
int ipv6_remove_extension_header(struct sk_buff *skb, __u8 ext_type);
int ipv6_add_extension_header(struct sk_buff *skb, __u8 ext_type,
			       const void *ext_data, __u16 ext_len);

/* Checksum operations */
__sum16 ipv6_calculate_checksum(const struct ipv6_checksum_params *params);
int ipv6_update_checksum(struct sk_buff *skb, struct ipv6_header_info *info);
int ipv6_verify_checksum(struct sk_buff *skb, struct ipv6_header_info *info);
__sum16 ipv6_calculate_tcp_checksum(struct sk_buff *skb,
				     const struct in6_addr *saddr,
				     const struct in6_addr *daddr);
__sum16 ipv6_calculate_udp_checksum(struct sk_buff *skb,
				     const struct in6_addr *saddr,
				     const struct in6_addr *daddr);
__sum16 ipv6_calculate_icmpv6_checksum(struct sk_buff *skb,
					const struct in6_addr *saddr,
					const struct in6_addr *daddr);

/* Address translation */
int ipv6_rewrite_addresses(struct sk_buff *skb,
			    const struct ipv6_rewrite_params *params);
int ipv6_translate_to_v4(struct sk_buff *skb, __be32 *v4_addr);
int ipv6_translate_from_v4(struct sk_buff *skb, const struct in6_addr *v6_addr);
bool ipv6_is_v4_mapped(const struct in6_addr *addr);
bool ipv6_is_v4_compatible(const struct in6_addr *addr);
void ipv6_v4_to_v6_mapped(const __be32 v4_addr, struct in6_addr *v6_addr);
void ipv6_v4_to_v6_compatible(const __be32 v4_addr, struct in6_addr *v6_addr);

/* Address classification */
__u32 ipv6_classify_address(const struct in6_addr *addr);
bool ipv6_is_global_unicast(const struct in6_addr *addr);
bool ipv6_is_unique_local(const struct in6_addr *addr);
bool ipv6_is_multicast(const struct in6_addr *addr);
bool ipv6_is_solicited_node_multicast(const struct in6_addr *addr);

/* Fragmentation handling */
int ipv6_parse_fragment_header(struct sk_buff *skb,
				struct ipv6_fragment_info *frag_info);
bool ipv6_is_fragmented(struct sk_buff *skb);
int ipv6_reassemble_fragments(struct sk_buff *skb);
int ipv6_fragment_packet(struct sk_buff *skb, __u16 mtu,
			  struct sk_buff **fragments, int *num_fragments);
int ipv6_handle_pmtud(struct sk_buff *skb, __u16 mtu);

/* ICMPv6 handling */
int ipv6_process_icmpv6(struct sk_buff *skb, struct ipv6_header_info *info);
int ipv6_send_icmpv6_error(struct sk_buff *orig_skb, __u8 type, __u8 code,
			    __u32 info);
bool ipv6_is_icmpv6_error(__u8 type);
bool ipv6_should_proxy_icmpv6(struct sk_buff *skb);
int ipv6_handle_neighbor_discovery(struct sk_buff *skb);

/* Dual-stack support */
int ipv6_dual_stack_init(struct ipv6_dual_stack_context *ctx);
int ipv6_dual_stack_select_family(struct ipv6_dual_stack_context *ctx,
				   const struct in6_addr *v6_addr,
				   __be32 v4_addr, bool *use_ipv6);
int ipv6_nat64_translate(struct sk_buff *skb, struct ipv6_dual_stack_context *ctx,
			 bool v4_to_v6);

/* Utility functions */
void ipv6_print_address(const struct in6_addr *addr, char *buf, size_t len);
int ipv6_compare_addresses(const struct in6_addr *addr1,
			    const struct in6_addr *addr2);
bool ipv6_is_zero_address(const struct in6_addr *addr);
void ipv6_copy_address(struct in6_addr *dst, const struct in6_addr *src);

/* Statistics and debugging */
struct ipv6_stats {
	__u64 packets_processed;
	__u64 packets_proxied;
	__u64 packets_dropped;
	__u64 extension_headers_processed;
	__u64 fragments_processed;
	__u64 icmpv6_processed;
	__u64 checksum_errors;
	__u64 parse_errors;
	__u64 dual_stack_translations;
};

int ipv6_get_stats(struct ipv6_stats *stats);
void ipv6_reset_stats(void);
void ipv6_dump_header(struct sk_buff *skb);

/* Module initialization/cleanup */
int ipv6_support_init(void);
void ipv6_support_exit(void);

#endif /* _MUTEX_IPV6_H */
