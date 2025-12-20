/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_packet_rewrite.h - MUTEX packet rewriting header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements packet modification for proxy routing, including
 * IP/TCP/UDP header modifications and checksum calculations.
 */

#ifndef _MUTEX_PACKET_REWRITE_H
#define _MUTEX_PACKET_REWRITE_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>

/* Rewrite operation flags */
#define REWRITE_FLAG_SRC_ADDR		(1 << 0)	/* Modify source address */
#define REWRITE_FLAG_DST_ADDR		(1 << 1)	/* Modify dest address */
#define REWRITE_FLAG_SRC_PORT		(1 << 2)	/* Modify source port */
#define REWRITE_FLAG_DST_PORT		(1 << 3)	/* Modify dest port */
#define REWRITE_FLAG_TCP_SEQ		(1 << 4)	/* Modify TCP seq number */
#define REWRITE_FLAG_TCP_ACK		(1 << 5)	/* Modify TCP ack number */
#define REWRITE_FLAG_UPDATE_CSUM	(1 << 6)	/* Recalculate checksums */
#define REWRITE_FLAG_VALIDATE		(1 << 7)	/* Validate after rewrite */

/* Maximum supported MTU for packet handling */
#define MUTEX_MAX_MTU			9000		/* Jumbo frames */
#define MUTEX_MIN_MTU			576		/* IPv4 minimum */

/**
 * enum rewrite_result - Result of packet rewrite operation
 * @REWRITE_OK: Packet successfully rewritten
 * @REWRITE_ERROR: General error occurred
 * @REWRITE_INVALID_PACKET: Packet validation failed
 * @REWRITE_NO_MEMORY: Memory allocation failed
 * @REWRITE_UNSUPPORTED: Unsupported protocol or feature
 * @REWRITE_MTU_EXCEEDED: Packet exceeds MTU after rewrite
 * @REWRITE_CHECKSUM_ERROR: Checksum calculation failed
 */
enum rewrite_result {
	REWRITE_OK = 0,
	REWRITE_ERROR = -1,
	REWRITE_INVALID_PACKET = -2,
	REWRITE_NO_MEMORY = -3,
	REWRITE_UNSUPPORTED = -4,
	REWRITE_MTU_EXCEEDED = -5,
	REWRITE_CHECKSUM_ERROR = -6,
};

/**
 * struct rewrite_params_v4 - IPv4 packet rewrite parameters
 * @flags: Combination of REWRITE_FLAG_* flags
 * @new_saddr: New source IPv4 address
 * @new_daddr: New destination IPv4 address
 * @new_sport: New source port
 * @new_dport: New destination port
 * @tcp_seq_delta: TCP sequence number adjustment
 * @tcp_ack_delta: TCP acknowledgment number adjustment
 *
 * Parameters for rewriting IPv4 packets. Only fields corresponding
 * to set flags will be modified.
 */
struct rewrite_params_v4 {
	__u32 flags;
	__be32 new_saddr;
	__be32 new_daddr;
	__be16 new_sport;
	__be16 new_dport;
	__s32 tcp_seq_delta;
	__s32 tcp_ack_delta;
};

/**
 * struct rewrite_params_v6 - IPv6 packet rewrite parameters
 * @flags: Combination of REWRITE_FLAG_* flags
 * @new_saddr: New source IPv6 address
 * @new_daddr: New destination IPv6 address
 * @new_sport: New source port
 * @new_dport: New destination port
 * @tcp_seq_delta: TCP sequence number adjustment
 * @tcp_ack_delta: TCP acknowledgment number adjustment
 *
 * Parameters for rewriting IPv6 packets. Only fields corresponding
 * to set flags will be modified.
 */
struct rewrite_params_v6 {
	__u32 flags;
	struct in6_addr new_saddr;
	struct in6_addr new_daddr;
	__be16 new_sport;
	__be16 new_dport;
	__s32 tcp_seq_delta;
	__s32 tcp_ack_delta;
};

/**
 * struct packet_info - Packet metadata for rewriting
 * @is_ipv6: True if IPv6, false if IPv4
 * @protocol: IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
 * @iph: Pointer to IPv4 header (NULL if IPv6)
 * @ip6h: Pointer to IPv6 header (NULL if IPv4)
 * @tcph: Pointer to TCP header (NULL if not TCP)
 * @udph: Pointer to UDP header (NULL if not UDP)
 * @data_len: Length of payload data
 * @mtu: Maximum transmission unit for this path
 *
 * Cached packet information extracted during validation.
 * Avoids redundant header parsing during rewrite operations.
 */
struct packet_info {
	bool is_ipv6;
	__u8 protocol;

	/* IPv4/IPv6 headers (one will be NULL) */
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	/* Transport layer headers (one or both may be NULL) */
	struct tcphdr *tcph;
	struct udph *udph;

	/* Payload information */
	__u32 data_len;
	__u32 mtu;
};

/* Packet validation functions */
bool mutex_pkt_validate_ipv4(struct sk_buff *skb, struct packet_info *info);
bool mutex_pkt_validate_ipv6(struct sk_buff *skb, struct packet_info *info);
bool mutex_pkt_validate_tcp(struct sk_buff *skb, struct packet_info *info);
bool mutex_pkt_validate_udp(struct sk_buff *skb, struct packet_info *info);
bool mutex_pkt_validate(struct sk_buff *skb, struct packet_info *info);

/* Checksum calculation functions */
void mutex_pkt_update_ipv4_checksum(struct iphdr *iph);
void mutex_pkt_update_tcp_checksum(struct sk_buff *skb, struct packet_info *info);
void mutex_pkt_update_udp_checksum(struct sk_buff *skb, struct packet_info *info);
int mutex_pkt_update_checksums(struct sk_buff *skb, struct packet_info *info);

/* IPv4 rewrite functions */
int mutex_pkt_rewrite_ipv4_addr(struct sk_buff *skb,
				struct packet_info *info,
				const struct rewrite_params_v4 *params);
int mutex_pkt_rewrite_tcp_port(struct sk_buff *skb,
			       struct packet_info *info,
			       __be16 new_sport,
			       __be16 new_dport);
int mutex_pkt_rewrite_udp_port(struct sk_buff *skb,
			       struct packet_info *info,
			       __be16 new_sport,
			       __be16 new_dport);
int mutex_pkt_rewrite_tcp_seq(struct sk_buff *skb,
			      struct packet_info *info,
			      __s32 seq_delta,
			      __s32 ack_delta);

/* IPv6 rewrite functions */
int mutex_pkt_rewrite_ipv6_addr(struct sk_buff *skb,
				struct packet_info *info,
				const struct rewrite_params_v6 *params);

/* High-level rewrite functions */
int mutex_pkt_rewrite_ipv4(struct sk_buff *skb,
			   const struct rewrite_params_v4 *params);
int mutex_pkt_rewrite_ipv6(struct sk_buff *skb,
			   const struct rewrite_params_v6 *params);

/* Packet cloning and inspection */
struct sk_buff *mutex_pkt_clone(struct sk_buff *skb, gfp_t gfp_mask);
void mutex_pkt_dump(const struct sk_buff *skb, const char *prefix);

/* MTU handling */
int mutex_pkt_check_mtu(struct sk_buff *skb, __u32 mtu);
int mutex_pkt_fragment_if_needed(struct sk_buff **skb, __u32 mtu);

/* Statistics for debugging */
struct rewrite_stats {
	atomic64_t packets_rewritten;
	atomic64_t ipv4_addr_rewrites;
	atomic64_t ipv6_addr_rewrites;
	atomic64_t tcp_port_rewrites;
	atomic64_t udp_port_rewrites;
	atomic64_t tcp_seq_rewrites;
	atomic64_t checksum_updates;
	atomic64_t validation_failures;
	atomic64_t mtu_exceeded;
	atomic64_t errors;
};

extern struct rewrite_stats global_rewrite_stats;

/* Initialization and cleanup */
int mutex_packet_rewrite_init(void);
void mutex_packet_rewrite_exit(void);

#endif /* _MUTEX_PACKET_REWRITE_H */
