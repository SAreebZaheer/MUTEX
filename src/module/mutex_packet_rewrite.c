// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_packet_rewrite.c - MUTEX packet rewriting implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This module implements packet modification for proxy routing, including:
 * - IP header modification (source/destination address changes)
 * - TCP header modifications (ports, sequence numbers)
 * - UDP header modifications (ports)
 * - Checksum calculations (IP, TCP, UDP)
 * - Packet validation before/after modification
 * - MTU handling and fragmented packets
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "mutex_packet_rewrite.h"

/* Global statistics */
struct rewrite_stats global_rewrite_stats = {
	.packets_rewritten = ATOMIC64_INIT(0),
	.ipv4_addr_rewrites = ATOMIC64_INIT(0),
	.ipv6_addr_rewrites = ATOMIC64_INIT(0),
	.tcp_port_rewrites = ATOMIC64_INIT(0),
	.udp_port_rewrites = ATOMIC64_INIT(0),
	.tcp_seq_rewrites = ATOMIC64_INIT(0),
	.checksum_updates = ATOMIC64_INIT(0),
	.validation_failures = ATOMIC64_INIT(0),
	.mtu_exceeded = ATOMIC64_INIT(0),
	.errors = ATOMIC64_INIT(0),
};

/* Debug logging */
static bool debug = false;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable packet rewriting debug logging");

#define PKT_DBG(fmt, ...) \
	do { if (unlikely(debug)) pr_info("mutex_pkt: " fmt, ##__VA_ARGS__); } while (0)

/**
 * mutex_pkt_validate_ipv4 - Validate IPv4 packet structure
 * @skb: Socket buffer to validate
 * @info: Packet information structure to fill
 *
 * Validates that the sk_buff contains a well-formed IPv4 packet and
 * extracts packet information for later use.
 *
 * Return: true if valid, false otherwise
 */
bool mutex_pkt_validate_ipv4(struct sk_buff *skb, struct packet_info *info)
{
	struct iphdr *iph;
	__u32 iph_len;

	/* Ensure we have linear IP header */
	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		PKT_DBG("IPv4 header too short\n");
		return false;
	}

	iph = ip_hdr(skb);

	/* Validate IP version */
	if (iph->version != 4) {
		PKT_DBG("Invalid IP version: %u\n", iph->version);
		return false;
	}

	/* Validate IP header length */
	iph_len = iph->ihl * 4;
	if (iph_len < sizeof(struct iphdr)) {
		PKT_DBG("IPv4 header length too short: %u\n", iph_len);
		return false;
	}

	/* Ensure we have complete IP header */
	if (!pskb_may_pull(skb, iph_len)) {
		PKT_DBG("Cannot pull complete IPv4 header\n");
		return false;
	}

	/* Re-get header pointer after potential reallocation */
	iph = ip_hdr(skb);

	/* Validate total length */
	if (ntohs(iph->tot_len) > skb->len) {
		PKT_DBG("IPv4 total length exceeds skb length\n");
		return false;
	}

	/* Fill packet info */
	info->is_ipv6 = false;
	info->protocol = iph->protocol;
	info->iph = iph;
	info->ip6h = NULL;
	info->tcph = NULL;
	info->udph = NULL;
	info->data_len = ntohs(iph->tot_len) - iph_len;

	PKT_DBG("IPv4 packet valid: proto=%u, len=%u\n",
		info->protocol, info->data_len);

	return true;
}

/**
 * mutex_pkt_validate_ipv6 - Validate IPv6 packet structure
 * @skb: Socket buffer to validate
 * @info: Packet information structure to fill
 *
 * Validates that the sk_buff contains a well-formed IPv6 packet.
 * Note: This is a basic implementation that doesn't handle extension headers.
 *
 * Return: true if valid, false otherwise
 */
bool mutex_pkt_validate_ipv6(struct sk_buff *skb, struct packet_info *info)
{
	struct ipv6hdr *ip6h;

	/* Ensure we have IPv6 header */
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr))) {
		PKT_DBG("IPv6 header too short\n");
		return false;
	}

	ip6h = ipv6_hdr(skb);

	/* Validate IP version */
	if (ip6h->version != 6) {
		PKT_DBG("Invalid IPv6 version: %u\n", ip6h->version);
		return false;
	}

	/* Fill packet info */
	info->is_ipv6 = true;
	info->protocol = ip6h->nexthdr;
	info->iph = NULL;
	info->ip6h = ip6h;
	info->tcph = NULL;
	info->udph = NULL;
	info->data_len = ntohs(ip6h->payload_len);

	PKT_DBG("IPv6 packet valid: proto=%u, len=%u\n",
		info->protocol, info->data_len);

	return true;
}

/**
 * mutex_pkt_validate_tcp - Validate TCP header
 * @skb: Socket buffer to validate
 * @info: Packet information structure (must already have IP info)
 *
 * Validates TCP header and updates packet info structure.
 *
 * Return: true if valid, false otherwise
 */
bool mutex_pkt_validate_tcp(struct sk_buff *skb, struct packet_info *info)
{
	struct tcphdr *tcph;
	__u32 tcp_hdr_len;
	__u32 transport_offset;

	/* Calculate transport layer offset */
	if (info->is_ipv6) {
		transport_offset = sizeof(struct ipv6hdr);
	} else {
		transport_offset = info->iph->ihl * 4;
	}

	/* Ensure we have TCP header */
	if (!pskb_may_pull(skb, transport_offset + sizeof(struct tcphdr))) {
		PKT_DBG("TCP header too short\n");
		return false;
	}

	tcph = (struct tcphdr *)(skb->data + transport_offset);

	/* Validate TCP header length */
	tcp_hdr_len = tcph->doff * 4;
	if (tcp_hdr_len < sizeof(struct tcphdr)) {
		PKT_DBG("TCP header length too short: %u\n", tcp_hdr_len);
		return false;
	}

	/* Ensure we have complete TCP header */
	if (!pskb_may_pull(skb, transport_offset + tcp_hdr_len)) {
		PKT_DBG("Cannot pull complete TCP header\n");
		return false;
	}

	/* Re-get pointers after potential reallocation */
	if (info->is_ipv6) {
		info->ip6h = ipv6_hdr(skb);
	} else {
		info->iph = ip_hdr(skb);
	}
	tcph = (struct tcphdr *)(skb->data + transport_offset);

	info->tcph = tcph;

	PKT_DBG("TCP header valid: sport=%u, dport=%u, seq=%u\n",
		ntohs(tcph->source), ntohs(tcph->dest), ntohl(tcph->seq));

	return true;
}

/**
 * mutex_pkt_validate_udp - Validate UDP header
 * @skb: Socket buffer to validate
 * @info: Packet information structure (must already have IP info)
 *
 * Validates UDP header and updates packet info structure.
 *
 * Return: true if valid, false otherwise
 */
bool mutex_pkt_validate_udp(struct sk_buff *skb, struct packet_info *info)
{
	struct udphdr *udph;
	__u32 transport_offset;

	/* Calculate transport layer offset */
	if (info->is_ipv6) {
		transport_offset = sizeof(struct ipv6hdr);
	} else {
		transport_offset = info->iph->ihl * 4;
	}

	/* Ensure we have UDP header */
	if (!pskb_may_pull(skb, transport_offset + sizeof(struct udphdr))) {
		PKT_DBG("UDP header too short\n");
		return false;
	}

	udph = (struct udphdr *)(skb->data + transport_offset);

	/* Validate UDP length */
	if (ntohs(udph->len) < sizeof(struct udphdr)) {
		PKT_DBG("UDP length too short: %u\n", ntohs(udph->len));
		return false;
	}

	/* Re-get IP header pointer after potential reallocation */
	if (info->is_ipv6) {
		info->ip6h = ipv6_hdr(skb);
	} else {
		info->iph = ip_hdr(skb);
	}

	info->udph = udph;

	PKT_DBG("UDP header valid: sport=%u, dport=%u, len=%u\n",
		ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));

	return true;
}

/**
 * mutex_pkt_validate - Validate complete packet structure
 * @skb: Socket buffer to validate
 * @info: Packet information structure to fill
 *
 * Validates IP header and transport layer header (if TCP/UDP).
 * This is the main validation entry point.
 *
 * Return: true if valid, false otherwise
 */
bool mutex_pkt_validate(struct sk_buff *skb, struct packet_info *info)
{
	if (!skb || !info) {
		PKT_DBG("NULL skb or info\n");
		return false;
	}

	memset(info, 0, sizeof(*info));

	/* Determine IP version and validate */
	if (skb->protocol == htons(ETH_P_IP)) {
		if (!mutex_pkt_validate_ipv4(skb, info)) {
			atomic64_inc(&global_rewrite_stats.validation_failures);
			return false;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (!mutex_pkt_validate_ipv6(skb, info)) {
			atomic64_inc(&global_rewrite_stats.validation_failures);
			return false;
		}
	} else {
		PKT_DBG("Unsupported protocol: 0x%04x\n", ntohs(skb->protocol));
		return false;
	}

	/* Validate transport layer */
	if (info->protocol == IPPROTO_TCP) {
		if (!mutex_pkt_validate_tcp(skb, info)) {
			atomic64_inc(&global_rewrite_stats.validation_failures);
			return false;
		}
	} else if (info->protocol == IPPROTO_UDP) {
		if (!mutex_pkt_validate_udp(skb, info)) {
			atomic64_inc(&global_rewrite_stats.validation_failures);
			return false;
		}
	}

	return true;
}

/**
 * mutex_pkt_update_ipv4_checksum - Update IPv4 header checksum
 * @iph: IPv4 header
 *
 * Recalculates the IPv4 header checksum after modifications.
 */
void mutex_pkt_update_ipv4_checksum(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	PKT_DBG("Updated IPv4 checksum: 0x%04x\n", ntohs(iph->check));
}

/**
 * mutex_pkt_update_tcp_checksum - Update TCP checksum
 * @skb: Socket buffer
 * @info: Packet information
 *
 * Recalculates TCP checksum for both IPv4 and IPv6.
 */
void mutex_pkt_update_tcp_checksum(struct sk_buff *skb, struct packet_info *info)
{
	struct tcphdr *tcph = info->tcph;
	__u32 tcp_len;
	__wsum csum;

	if (!tcph)
		return;

	/* Calculate TCP segment length */
	if (info->is_ipv6) {
		tcp_len = ntohs(info->ip6h->payload_len);
	} else {
		tcp_len = ntohs(info->iph->tot_len) - (info->iph->ihl * 4);
	}

	/* Zero out old checksum */
	tcph->check = 0;

	/* Calculate new checksum */
	if (info->is_ipv6) {
		csum = ~csum_unfold(csum_ipv6_magic(&info->ip6h->saddr,
						    &info->ip6h->daddr,
						    tcp_len, IPPROTO_TCP, 0));
	} else {
		csum = ~csum_unfold(csum_tcpudp_magic(info->iph->saddr,
						       info->iph->daddr,
						       tcp_len, IPPROTO_TCP, 0));
	}

	tcph->check = csum_fold(csum_add(csum,
					 csum_partial((char *)tcph, tcp_len, 0)));

	PKT_DBG("Updated TCP checksum: 0x%04x\n", ntohs(tcph->check));
	atomic64_inc(&global_rewrite_stats.checksum_updates);
}

/**
 * mutex_pkt_update_udp_checksum - Update UDP checksum
 * @skb: Socket buffer
 * @info: Packet information
 *
 * Recalculates UDP checksum for both IPv4 and IPv6.
 * For IPv4, checksum is optional; for IPv6, it's mandatory.
 */
void mutex_pkt_update_udp_checksum(struct sk_buff *skb, struct packet_info *info)
{
	struct udphdr *udph = info->udph;
	__u32 udp_len;
	__wsum csum;

	if (!udph)
		return;

	udp_len = ntohs(udph->len);

	/* Zero out old checksum */
	udph->check = 0;

	/* Calculate new checksum */
	if (info->is_ipv6) {
		/* IPv6: UDP checksum is mandatory */
		csum = ~csum_unfold(csum_ipv6_magic(&info->ip6h->saddr,
						    &info->ip6h->daddr,
						    udp_len, IPPROTO_UDP, 0));
		udph->check = csum_fold(csum_add(csum,
						 csum_partial((char *)udph, udp_len, 0)));

		/* UDP checksum of 0 is invalid in IPv6, use 0xFFFF instead */
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;
	} else {
		/* IPv4: UDP checksum is optional, but we calculate it anyway */
		csum = ~csum_unfold(csum_tcpudp_magic(info->iph->saddr,
						       info->iph->daddr,
						       udp_len, IPPROTO_UDP, 0));
		udph->check = csum_fold(csum_add(csum,
						 csum_partial((char *)udph, udp_len, 0)));
	}

	PKT_DBG("Updated UDP checksum: 0x%04x\n", ntohs(udph->check));
	atomic64_inc(&global_rewrite_stats.checksum_updates);
}

/**
 * mutex_pkt_update_checksums - Update all checksums after packet modification
 * @skb: Socket buffer
 * @info: Packet information
 *
 * Updates IP and transport layer checksums.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_pkt_update_checksums(struct sk_buff *skb, struct packet_info *info)
{
	/* Update IP checksum (IPv4 only) */
	if (!info->is_ipv6 && info->iph) {
		mutex_pkt_update_ipv4_checksum(info->iph);
	}

	/* Update transport layer checksum */
	if (info->protocol == IPPROTO_TCP && info->tcph) {
		mutex_pkt_update_tcp_checksum(skb, info);
	} else if (info->protocol == IPPROTO_UDP && info->udph) {
		mutex_pkt_update_udp_checksum(skb, info);
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_ipv4_addr - Rewrite IPv4 addresses
 * @skb: Socket buffer
 * @info: Packet information
 * @params: Rewrite parameters
 *
 * Modifies source and/or destination IPv4 addresses based on flags.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_ipv4_addr(struct sk_buff *skb,
				struct packet_info *info,
				const struct rewrite_params_v4 *params)
{
	struct iphdr *iph = info->iph;
	bool modified = false;

	if (!iph || info->is_ipv6) {
		PKT_DBG("Not an IPv4 packet\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Make skb writable */
	if (skb_ensure_writable(skb, sizeof(struct iphdr))) {
		PKT_DBG("Cannot make skb writable\n");
		return REWRITE_ERROR;
	}

	/* Re-get header pointer after potential reallocation */
	iph = ip_hdr(skb);
	info->iph = iph;

	/* Modify source address */
	if (params->flags & REWRITE_FLAG_SRC_ADDR) {
		PKT_DBG("Rewriting src addr: %pI4 -> %pI4\n",
			&iph->saddr, &params->new_saddr);
		iph->saddr = params->new_saddr;
		modified = true;
	}

	/* Modify destination address */
	if (params->flags & REWRITE_FLAG_DST_ADDR) {
		PKT_DBG("Rewriting dst addr: %pI4 -> %pI4\n",
			&iph->daddr, &params->new_daddr);
		iph->daddr = params->new_daddr;
		modified = true;
	}

	if (modified) {
		atomic64_inc(&global_rewrite_stats.ipv4_addr_rewrites);
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_tcp_port - Rewrite TCP ports
 * @skb: Socket buffer
 * @info: Packet information
 * @new_sport: New source port (0 = don't change)
 * @new_dport: New destination port (0 = don't change)
 *
 * Modifies TCP source and/or destination ports.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_tcp_port(struct sk_buff *skb,
			       struct packet_info *info,
			       __be16 new_sport,
			       __be16 new_dport)
{
	struct tcphdr *tcph = info->tcph;
	__u32 offset;
	bool modified = false;

	if (!tcph || info->protocol != IPPROTO_TCP) {
		PKT_DBG("Not a TCP packet\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Calculate TCP header offset */
	if (info->is_ipv6) {
		offset = sizeof(struct ipv6hdr);
	} else {
		offset = info->iph->ihl * 4;
	}

	/* Make skb writable */
	if (skb_ensure_writable(skb, offset + sizeof(struct tcphdr))) {
		PKT_DBG("Cannot make TCP header writable\n");
		return REWRITE_ERROR;
	}

	/* Re-get pointers after potential reallocation */
	if (info->is_ipv6) {
		info->ip6h = ipv6_hdr(skb);
	} else {
		info->iph = ip_hdr(skb);
	}
	tcph = (struct tcphdr *)(skb->data + offset);
	info->tcph = tcph;

	/* Modify source port */
	if (new_sport) {
		PKT_DBG("Rewriting TCP src port: %u -> %u\n",
			ntohs(tcph->source), ntohs(new_sport));
		tcph->source = new_sport;
		modified = true;
	}

	/* Modify destination port */
	if (new_dport) {
		PKT_DBG("Rewriting TCP dst port: %u -> %u\n",
			ntohs(tcph->dest), ntohs(new_dport));
		tcph->dest = new_dport;
		modified = true;
	}

	if (modified) {
		atomic64_inc(&global_rewrite_stats.tcp_port_rewrites);
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_udp_port - Rewrite UDP ports
 * @skb: Socket buffer
 * @info: Packet information
 * @new_sport: New source port (0 = don't change)
 * @new_dport: New destination port (0 = don't change)
 *
 * Modifies UDP source and/or destination ports.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_udp_port(struct sk_buff *skb,
			       struct packet_info *info,
			       __be16 new_sport,
			       __be16 new_dport)
{
	struct udphdr *udph = info->udph;
	__u32 offset;
	bool modified = false;

	if (!udph || info->protocol != IPPROTO_UDP) {
		PKT_DBG("Not a UDP packet\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Calculate UDP header offset */
	if (info->is_ipv6) {
		offset = sizeof(struct ipv6hdr);
	} else {
		offset = info->iph->ihl * 4;
	}

	/* Make skb writable */
	if (skb_ensure_writable(skb, offset + sizeof(struct udphdr))) {
		PKT_DBG("Cannot make UDP header writable\n");
		return REWRITE_ERROR;
	}

	/* Re-get pointers after potential reallocation */
	if (info->is_ipv6) {
		info->ip6h = ipv6_hdr(skb);
	} else {
		info->iph = ip_hdr(skb);
	}
	udph = (struct udphdr *)(skb->data + offset);
	info->udph = udph;

	/* Modify source port */
	if (new_sport) {
		PKT_DBG("Rewriting UDP src port: %u -> %u\n",
			ntohs(udph->source), ntohs(new_sport));
		udph->source = new_sport;
		modified = true;
	}

	/* Modify destination port */
	if (new_dport) {
		PKT_DBG("Rewriting UDP dst port: %u -> %u\n",
			ntohs(udph->dest), ntohs(new_dport));
		udph->dest = new_dport;
		modified = true;
	}

	if (modified) {
		atomic64_inc(&global_rewrite_stats.udp_port_rewrites);
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_tcp_seq - Adjust TCP sequence and ack numbers
 * @skb: Socket buffer
 * @info: Packet information
 * @seq_delta: Amount to add to sequence number
 * @ack_delta: Amount to add to acknowledgment number
 *
 * Modifies TCP sequence and acknowledgment numbers for transparent proxying.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_tcp_seq(struct sk_buff *skb,
			      struct packet_info *info,
			      __s32 seq_delta,
			      __s32 ack_delta)
{
	struct tcphdr *tcph = info->tcph;
	__u32 offset;
	__u32 old_seq, old_ack, new_seq, new_ack;

	if (!tcph || info->protocol != IPPROTO_TCP) {
		PKT_DBG("Not a TCP packet\n");
		return REWRITE_INVALID_PACKET;
	}

	if (seq_delta == 0 && ack_delta == 0) {
		return REWRITE_OK;
	}

	/* Calculate TCP header offset */
	if (info->is_ipv6) {
		offset = sizeof(struct ipv6hdr);
	} else {
		offset = info->iph->ihl * 4;
	}

	/* Make skb writable */
	if (skb_ensure_writable(skb, offset + sizeof(struct tcphdr))) {
		PKT_DBG("Cannot make TCP header writable\n");
		return REWRITE_ERROR;
	}

	/* Re-get pointers after potential reallocation */
	if (info->is_ipv6) {
		info->ip6h = ipv6_hdr(skb);
	} else {
		info->iph = ip_hdr(skb);
	}
	tcph = (struct tcphdr *)(skb->data + offset);
	info->tcph = tcph;

	/* Adjust sequence number */
	if (seq_delta) {
		old_seq = ntohl(tcph->seq);
		new_seq = old_seq + seq_delta;
		tcph->seq = htonl(new_seq);
		PKT_DBG("Adjusted TCP seq: %u -> %u (delta=%d)\n",
			old_seq, new_seq, seq_delta);
	}

	/* Adjust acknowledgment number */
	if (ack_delta && tcph->ack) {
		old_ack = ntohl(tcph->ack_seq);
		new_ack = old_ack + ack_delta;
		tcph->ack_seq = htonl(new_ack);
		PKT_DBG("Adjusted TCP ack: %u -> %u (delta=%d)\n",
			old_ack, new_ack, ack_delta);
	}

	atomic64_inc(&global_rewrite_stats.tcp_seq_rewrites);

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_ipv6_addr - Rewrite IPv6 addresses
 * @skb: Socket buffer
 * @info: Packet information
 * @params: Rewrite parameters
 *
 * Modifies source and/or destination IPv6 addresses based on flags.
 * Note: This is a basic implementation.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_ipv6_addr(struct sk_buff *skb,
				struct packet_info *info,
				const struct rewrite_params_v6 *params)
{
	struct ipv6hdr *ip6h = info->ip6h;
	bool modified = false;

	if (!ip6h || !info->is_ipv6) {
		PKT_DBG("Not an IPv6 packet\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Make skb writable */
	if (skb_ensure_writable(skb, sizeof(struct ipv6hdr))) {
		PKT_DBG("Cannot make skb writable\n");
		return REWRITE_ERROR;
	}

	/* Re-get header pointer after potential reallocation */
	ip6h = ipv6_hdr(skb);
	info->ip6h = ip6h;

	/* Modify source address */
	if (params->flags & REWRITE_FLAG_SRC_ADDR) {
		PKT_DBG("Rewriting IPv6 src addr: %pI6c -> %pI6c\n",
			&ip6h->saddr, &params->new_saddr);
		ip6h->saddr = params->new_saddr;
		modified = true;
	}

	/* Modify destination address */
	if (params->flags & REWRITE_FLAG_DST_ADDR) {
		PKT_DBG("Rewriting IPv6 dst addr: %pI6c -> %pI6c\n",
			&ip6h->daddr, &params->new_daddr);
		ip6h->daddr = params->new_daddr;
		modified = true;
	}

	if (modified) {
		atomic64_inc(&global_rewrite_stats.ipv6_addr_rewrites);
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_ipv4 - High-level IPv4 packet rewrite function
 * @skb: Socket buffer
 * @params: Rewrite parameters
 *
 * Performs complete IPv4 packet rewrite including addresses, ports,
 * sequence numbers, and checksum updates.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_ipv4(struct sk_buff *skb,
			   const struct rewrite_params_v4 *params)
{
	struct packet_info info;
	int ret;

	/* Validate packet structure */
	if (!mutex_pkt_validate(skb, &info)) {
		PKT_DBG("Packet validation failed\n");
		atomic64_inc(&global_rewrite_stats.errors);
		return REWRITE_INVALID_PACKET;
	}

	if (info.is_ipv6) {
		PKT_DBG("Expected IPv4, got IPv6\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Rewrite IP addresses */
	if (params->flags & (REWRITE_FLAG_SRC_ADDR | REWRITE_FLAG_DST_ADDR)) {
		ret = mutex_pkt_rewrite_ipv4_addr(skb, &info, params);
		if (ret != REWRITE_OK) {
			atomic64_inc(&global_rewrite_stats.errors);
			return ret;
		}
	}

	/* Rewrite transport layer ports */
	if (info.protocol == IPPROTO_TCP) {
		if (params->flags & (REWRITE_FLAG_SRC_PORT | REWRITE_FLAG_DST_PORT)) {
			ret = mutex_pkt_rewrite_tcp_port(skb, &info,
							 params->new_sport,
							 params->new_dport);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}

		/* Adjust TCP sequence numbers */
		if (params->flags & (REWRITE_FLAG_TCP_SEQ | REWRITE_FLAG_TCP_ACK)) {
			ret = mutex_pkt_rewrite_tcp_seq(skb, &info,
							params->tcp_seq_delta,
							params->tcp_ack_delta);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}
	} else if (info.protocol == IPPROTO_UDP) {
		if (params->flags & (REWRITE_FLAG_SRC_PORT | REWRITE_FLAG_DST_PORT)) {
			ret = mutex_pkt_rewrite_udp_port(skb, &info,
							 params->new_sport,
							 params->new_dport);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}
	}

	/* Update checksums */
	if (params->flags & REWRITE_FLAG_UPDATE_CSUM) {
		ret = mutex_pkt_update_checksums(skb, &info);
		if (ret != REWRITE_OK) {
			atomic64_inc(&global_rewrite_stats.errors);
			return ret;
		}
	}

	/* Validate after rewrite */
	if (params->flags & REWRITE_FLAG_VALIDATE) {
		if (!mutex_pkt_validate(skb, &info)) {
			PKT_DBG("Post-rewrite validation failed\n");
			atomic64_inc(&global_rewrite_stats.errors);
			return REWRITE_INVALID_PACKET;
		}
	}

	atomic64_inc(&global_rewrite_stats.packets_rewritten);
	return REWRITE_OK;
}

/**
 * mutex_pkt_rewrite_ipv6 - High-level IPv6 packet rewrite function
 * @skb: Socket buffer
 * @params: Rewrite parameters
 *
 * Performs complete IPv6 packet rewrite including addresses, ports,
 * sequence numbers, and checksum updates.
 *
 * Return: REWRITE_OK on success, negative error code on failure
 */
int mutex_pkt_rewrite_ipv6(struct sk_buff *skb,
			   const struct rewrite_params_v6 *params)
{
	struct packet_info info;
	int ret;

	/* Validate packet structure */
	if (!mutex_pkt_validate(skb, &info)) {
		PKT_DBG("Packet validation failed\n");
		atomic64_inc(&global_rewrite_stats.errors);
		return REWRITE_INVALID_PACKET;
	}

	if (!info.is_ipv6) {
		PKT_DBG("Expected IPv6, got IPv4\n");
		return REWRITE_INVALID_PACKET;
	}

	/* Rewrite IP addresses */
	if (params->flags & (REWRITE_FLAG_SRC_ADDR | REWRITE_FLAG_DST_ADDR)) {
		ret = mutex_pkt_rewrite_ipv6_addr(skb, &info, params);
		if (ret != REWRITE_OK) {
			atomic64_inc(&global_rewrite_stats.errors);
			return ret;
		}
	}

	/* Rewrite transport layer ports (same as IPv4) */
	if (info.protocol == IPPROTO_TCP) {
		if (params->flags & (REWRITE_FLAG_SRC_PORT | REWRITE_FLAG_DST_PORT)) {
			ret = mutex_pkt_rewrite_tcp_port(skb, &info,
							 params->new_sport,
							 params->new_dport);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}

		/* Adjust TCP sequence numbers */
		if (params->flags & (REWRITE_FLAG_TCP_SEQ | REWRITE_FLAG_TCP_ACK)) {
			ret = mutex_pkt_rewrite_tcp_seq(skb, &info,
							params->tcp_seq_delta,
							params->tcp_ack_delta);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}
	} else if (info.protocol == IPPROTO_UDP) {
		if (params->flags & (REWRITE_FLAG_SRC_PORT | REWRITE_FLAG_DST_PORT)) {
			ret = mutex_pkt_rewrite_udp_port(skb, &info,
							 params->new_sport,
							 params->new_dport);
			if (ret != REWRITE_OK) {
				atomic64_inc(&global_rewrite_stats.errors);
				return ret;
			}
		}
	}

	/* Update checksums */
	if (params->flags & REWRITE_FLAG_UPDATE_CSUM) {
		ret = mutex_pkt_update_checksums(skb, &info);
		if (ret != REWRITE_OK) {
			atomic64_inc(&global_rewrite_stats.errors);
			return ret;
		}
	}

	/* Validate after rewrite */
	if (params->flags & REWRITE_FLAG_VALIDATE) {
		if (!mutex_pkt_validate(skb, &info)) {
			PKT_DBG("Post-rewrite validation failed\n");
			atomic64_inc(&global_rewrite_stats.errors);
			return REWRITE_INVALID_PACKET;
		}
	}

	atomic64_inc(&global_rewrite_stats.packets_rewritten);
	return REWRITE_OK;
}

/**
 * mutex_pkt_clone - Clone a packet for inspection
 * @skb: Socket buffer to clone
 * @gfp_mask: GFP allocation flags
 *
 * Creates a copy of the packet for inspection without modifying original.
 *
 * Return: Cloned sk_buff on success, NULL on failure
 */
struct sk_buff *mutex_pkt_clone(struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff *nskb;

	nskb = skb_clone(skb, gfp_mask);
	if (!nskb) {
		PKT_DBG("Failed to clone packet\n");
		return NULL;
	}

	PKT_DBG("Packet cloned successfully\n");
	return nskb;
}

/**
 * mutex_pkt_dump - Dump packet information for debugging
 * @skb: Socket buffer
 * @prefix: Prefix string for log messages
 *
 * Prints detailed packet information to kernel log (if debug enabled).
 */
void mutex_pkt_dump(const struct sk_buff *skb, const char *prefix)
{
	if (!debug)
		return;

	pr_info("%s: skb=%p len=%u data_len=%u protocol=0x%04x\n",
		prefix, skb, skb->len, skb->data_len, ntohs(skb->protocol));

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		pr_info("  IPv4: %pI4 -> %pI4, proto=%u, len=%u\n",
			&iph->saddr, &iph->daddr, iph->protocol,
			ntohs(iph->tot_len));

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = (struct tcphdr *)
				((char *)iph + (iph->ihl * 4));
			pr_info("  TCP: %u -> %u, seq=%u, ack=%u\n",
				ntohs(tcph->source), ntohs(tcph->dest),
				ntohl(tcph->seq), ntohl(tcph->ack_seq));
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = (struct udphdr *)
				((char *)iph + (iph->ihl * 4));
			pr_info("  UDP: %u -> %u, len=%u\n",
				ntohs(udph->source), ntohs(udph->dest),
				ntohs(udph->len));
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		pr_info("  IPv6: %pI6c -> %pI6c, proto=%u, len=%u\n",
			&ip6h->saddr, &ip6h->daddr, ip6h->nexthdr,
			ntohs(ip6h->payload_len));
	}
}

/**
 * mutex_pkt_check_mtu - Check if packet exceeds MTU
 * @skb: Socket buffer
 * @mtu: Maximum transmission unit
 *
 * Checks if the packet size exceeds the specified MTU.
 *
 * Return: 0 if within MTU, negative error code if exceeds
 */
int mutex_pkt_check_mtu(struct sk_buff *skb, __u32 mtu)
{
	if (skb->len > mtu) {
		PKT_DBG("Packet size %u exceeds MTU %u\n", skb->len, mtu);
		atomic64_inc(&global_rewrite_stats.mtu_exceeded);
		return REWRITE_MTU_EXCEEDED;
	}

	return REWRITE_OK;
}

/**
 * mutex_pkt_fragment_if_needed - Fragment packet if it exceeds MTU
 * @skb: Pointer to socket buffer (may be replaced)
 * @mtu: Maximum transmission unit
 *
 * Fragments the packet if necessary to fit within MTU.
 * Note: This is a stub implementation. Full fragmentation is complex
 * and should be handled by the network stack.
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_pkt_fragment_if_needed(struct sk_buff **skb, __u32 mtu)
{
	if ((*skb)->len <= mtu) {
		return REWRITE_OK;
	}

	PKT_DBG("Packet fragmentation needed (len=%u, mtu=%u)\n",
		(*skb)->len, mtu);

	/* Let the network stack handle fragmentation */
	return REWRITE_UNSUPPORTED;
}

/**
 * mutex_packet_rewrite_init - Initialize packet rewriting module
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_packet_rewrite_init(void)
{
	pr_info("mutex_packet_rewrite: Initializing packet rewriting module\n");

	/* Initialize statistics */
	atomic64_set(&global_rewrite_stats.packets_rewritten, 0);
	atomic64_set(&global_rewrite_stats.ipv4_addr_rewrites, 0);
	atomic64_set(&global_rewrite_stats.ipv6_addr_rewrites, 0);
	atomic64_set(&global_rewrite_stats.tcp_port_rewrites, 0);
	atomic64_set(&global_rewrite_stats.udp_port_rewrites, 0);
	atomic64_set(&global_rewrite_stats.tcp_seq_rewrites, 0);
	atomic64_set(&global_rewrite_stats.checksum_updates, 0);
	atomic64_set(&global_rewrite_stats.validation_failures, 0);
	atomic64_set(&global_rewrite_stats.mtu_exceeded, 0);
	atomic64_set(&global_rewrite_stats.errors, 0);

	pr_info("mutex_packet_rewrite: Module initialized successfully\n");
	return 0;
}

/**
 * mutex_packet_rewrite_exit - Clean up packet rewriting module
 */
void mutex_packet_rewrite_exit(void)
{
	pr_info("mutex_packet_rewrite: Shutting down (rewrote %lld packets)\n",
		atomic64_read(&global_rewrite_stats.packets_rewritten));

	/* Print final statistics */
	pr_info("  IPv4 addr rewrites: %lld\n",
		atomic64_read(&global_rewrite_stats.ipv4_addr_rewrites));
	pr_info("  IPv6 addr rewrites: %lld\n",
		atomic64_read(&global_rewrite_stats.ipv6_addr_rewrites));
	pr_info("  TCP port rewrites: %lld\n",
		atomic64_read(&global_rewrite_stats.tcp_port_rewrites));
	pr_info("  UDP port rewrites: %lld\n",
		atomic64_read(&global_rewrite_stats.udp_port_rewrites));
	pr_info("  TCP seq rewrites: %lld\n",
		atomic64_read(&global_rewrite_stats.tcp_seq_rewrites));
	pr_info("  Checksum updates: %lld\n",
		atomic64_read(&global_rewrite_stats.checksum_updates));
	pr_info("  Validation failures: %lld\n",
		atomic64_read(&global_rewrite_stats.validation_failures));
	pr_info("  MTU exceeded: %lld\n",
		atomic64_read(&global_rewrite_stats.mtu_exceeded));
	pr_info("  Errors: %lld\n",
		atomic64_read(&global_rewrite_stats.errors));
}

EXPORT_SYMBOL_GPL(mutex_pkt_validate);
EXPORT_SYMBOL_GPL(mutex_pkt_update_checksums);
EXPORT_SYMBOL_GPL(mutex_pkt_rewrite_ipv4);
EXPORT_SYMBOL_GPL(mutex_pkt_rewrite_ipv6);
EXPORT_SYMBOL_GPL(mutex_pkt_clone);
EXPORT_SYMBOL_GPL(global_rewrite_stats);
