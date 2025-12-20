// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MUTEX Protocol Detection Implementation
 *
 * Deep packet inspection, heuristic analysis, and intelligent protocol
 * detection for kernel-level proxy routing.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <net/ip.h>

#include "mutex_protocol_detect.h"

/* Default configuration values */
#define DEFAULT_INSPECTION_DEPTH 1024
#define DEFAULT_CONN_TIMEOUT 300  /* 5 minutes */
#define DEFAULT_MIN_CONFIDENCE CONFIDENCE_MEDIUM

/* Protocol name lookup table */
static const char * const protocol_names[] = {
	[PROTO_UNKNOWN] = "unknown",
	[PROTO_HTTP] = "http",
	[PROTO_HTTPS] = "https",
	[PROTO_DNS] = "dns",
	[PROTO_SSH] = "ssh",
	[PROTO_FTP] = "ftp",
	[PROTO_SMTP] = "smtp",
	[PROTO_POP3] = "pop3",
	[PROTO_IMAP] = "imap",
	[PROTO_TELNET] = "telnet",
	[PROTO_RDP] = "rdp",
	[PROTO_VNC] = "vnc",
	[PROTO_SOCKS4] = "socks4",
	[PROTO_SOCKS5] = "socks5",
	[PROTO_BITTORRENT] = "bittorrent",
	[PROTO_QUIC] = "quic",
	[PROTO_RTSP] = "rtsp",
	[PROTO_SIP] = "sip",
	[PROTO_IRC] = "irc",
	[PROTO_XMPP] = "xmpp",
	[PROTO_OPENVPN] = "openvpn",
	[PROTO_WIREGUARD] = "wireguard",
	[PROTO_TLS_GENERIC] = "tls",
	[PROTO_DTLS] = "dtls",
};

const char *protocol_name(enum protocol_type protocol)
{
	if (protocol < PROTO_MAX)
		return protocol_names[protocol];
	return "invalid";
}

const char *protocol_confidence_name(enum detection_confidence confidence)
{
	switch (confidence) {
	case CONFIDENCE_NONE:    return "none";
	case CONFIDENCE_LOW:     return "low";
	case CONFIDENCE_MEDIUM:  return "medium";
	case CONFIDENCE_HIGH:    return "high";
	case CONFIDENCE_CERTAIN: return "certain";
	default:                 return "invalid";
	}
}

const char *protocol_action_name(enum routing_action action)
{
	switch (action) {
	case ACTION_PROXY:   return "proxy";
	case ACTION_DIRECT:  return "direct";
	case ACTION_BLOCK:   return "block";
	case ACTION_INSPECT: return "inspect";
	case ACTION_DEFAULT: return "default";
	default:             return "invalid";
	}
}

/* Helper: Hash function for connection tracking */
static u32 conn_hash(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto)
{
	u32 hash;

	hash = jhash_3words(src_ip, dst_ip,
			    (proto << 16) | src_port << 8 | dst_port,
			    0);
	return hash;
}

/* Helper: Find existing connection state */
static struct protocol_conn_state *find_conn_state(
	struct protocol_detect_context *ctx,
	u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto)
{
	struct protocol_conn_state *state;
	u32 hash;

	hash = conn_hash(src_ip, dst_ip, src_port, dst_port, proto);

	hash_for_each_possible_rcu(ctx->connections, state, hash_node, hash) {
		if (state->src_ip == src_ip &&
		    state->dst_ip == dst_ip &&
		    state->src_port == src_port &&
		    state->dst_port == dst_port &&
		    state->protocol == proto) {
			return state;
		}
	}

	return NULL;
}

/* Helper: Create new connection state */
static struct protocol_conn_state *create_conn_state(
	struct protocol_detect_context *ctx,
	u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 proto)
{
	struct protocol_conn_state *state;
	u32 hash;

	state = kzalloc(sizeof(*state), GFP_ATOMIC);
	if (!state)
		return NULL;

	state->src_ip = src_ip;
	state->dst_ip = dst_ip;
	state->src_port = src_port;
	state->dst_port = dst_port;
	state->protocol = proto;

	state->result.protocol = PROTO_UNKNOWN;
	state->result.confidence = CONFIDENCE_NONE;
	state->result.action = ACTION_INSPECT;
	state->result.first_seen = ktime_get_ns();

	hash = conn_hash(src_ip, dst_ip, src_port, dst_port, proto);

	spin_lock_bh(&ctx->conn_lock);
	hash_add_rcu(ctx->connections, &state->hash_node, hash);
	spin_unlock_bh(&ctx->conn_lock);

	return state;
}

/* Helper: Pattern matching with wildcard support */
static bool pattern_match(const u8 *data, size_t data_len,
			  const struct protocol_pattern *pattern)
{
	size_t i;

	if (pattern->offset + pattern->len > data_len)
		return false;

	data += pattern->offset;

	for (i = 0; i < pattern->len; i++) {
		/* Check if this byte should be matched (bit set in mask) */
		if (pattern->match_mask & (1U << (i % 32))) {
			if (data[i] != pattern->data[i])
				return false;
		}
	}

	return true;
}

/* Port-based protocol detection */
static enum protocol_type detect_by_port(u16 port, u8 transport)
{
	if (transport == IPPROTO_TCP) {
		switch (port) {
		case 80:   return PROTO_HTTP;
		case 443:  return PROTO_HTTPS;
		case 22:   return PROTO_SSH;
		case 21:   return PROTO_FTP;
		case 25:   return PROTO_SMTP;
		case 110:  return PROTO_POP3;
		case 143:  return PROTO_IMAP;
		case 23:   return PROTO_TELNET;
		case 3389: return PROTO_RDP;
		case 5900: return PROTO_VNC;
		case 1080: return PROTO_SOCKS5;
		case 554:  return PROTO_RTSP;
		case 5060: return PROTO_SIP;
		case 6667: case 6668: case 6669: return PROTO_IRC;
		case 5222: case 5269: return PROTO_XMPP;
		case 1194: return PROTO_OPENVPN;
		case 51820: return PROTO_WIREGUARD;
		default:   return PROTO_UNKNOWN;
		}
	} else if (transport == IPPROTO_UDP) {
		switch (port) {
		case 53:   return PROTO_DNS;
		case 443:  return PROTO_QUIC;
		case 5060: return PROTO_SIP;
		case 1194: return PROTO_OPENVPN;
		case 51820: return PROTO_WIREGUARD;
		default:   return PROTO_UNKNOWN;
		}
	}

	return PROTO_UNKNOWN;
}

/* TLS handshake detection and SNI extraction */
int protocol_detect_sni(const u8 *data, size_t len, struct sni_info *sni)
{
	const u8 *p = data;
	u16 tls_version, handshake_len;
	u8 content_type, handshake_type;
	size_t remaining = len;

	memset(sni, 0, sizeof(*sni));

	/* Minimum TLS ClientHello size */
	if (len < 43)
		return -EINVAL;

	/* Check TLS content type (0x16 = Handshake) */
	content_type = p[0];
	if (content_type != 0x16)
		return -EINVAL;

	/* TLS version */
	tls_version = (p[1] << 8) | p[2];
	sni->tls_version = tls_version;

	/* TLS record length */
	handshake_len = (p[3] << 8) | p[4];
	if (handshake_len + 5 > len)
		return -EINVAL;

	p += 5;
	remaining -= 5;

	/* Handshake type (0x01 = ClientHello) */
	handshake_type = p[0];
	if (handshake_type != 0x01)
		return -EINVAL;

	/* Skip handshake header (type + length) */
	p += 4;
	remaining -= 4;

	/* Skip client version (2 bytes) */
	if (remaining < 2)
		return -EINVAL;
	p += 2;
	remaining -= 2;

	/* Skip random (32 bytes) */
	if (remaining < 32)
		return -EINVAL;
	p += 32;
	remaining -= 32;

	/* Skip session ID */
	if (remaining < 1)
		return -EINVAL;
	u8 session_id_len = p[0];
	p += 1 + session_id_len;
	remaining -= 1 + session_id_len;

	/* Skip cipher suites */
	if (remaining < 2)
		return -EINVAL;
	u16 cipher_len = (p[0] << 8) | p[1];
	p += 2 + cipher_len;
	remaining -= 2 + cipher_len;

	/* Skip compression methods */
	if (remaining < 1)
		return -EINVAL;
	u8 comp_len = p[0];
	p += 1 + comp_len;
	remaining -= 1 + comp_len;

	/* Extensions */
	if (remaining < 2)
		return -EINVAL;
	u16 ext_len = (p[0] << 8) | p[1];
	p += 2;
	remaining -= 2;

	if (ext_len > remaining)
		return -EINVAL;

	/* Parse extensions looking for SNI (type 0x00) */
	while (remaining >= 4) {
		u16 ext_type = (p[0] << 8) | p[1];
		u16 ext_data_len = (p[2] << 8) | p[3];

		p += 4;
		remaining -= 4;

		if (ext_data_len > remaining)
			break;

		if (ext_type == 0x00) {  /* SNI extension */
			/* SNI list length */
			if (ext_data_len < 2)
				break;
			u16 sni_list_len = (p[0] << 8) | p[1];

			if (sni_list_len + 2 > ext_data_len)
				break;

			p += 2;

			/* SNI type (0x00 = hostname) */
			if (p[0] == 0x00) {
				u16 hostname_len = (p[1] << 8) | p[2];

				if (hostname_len > 0 && hostname_len < MAX_SNI_SIZE) {
					size_t copy_len = min_t(size_t, hostname_len,
								MAX_SNI_SIZE - 1);
					memcpy(sni->server_name, p + 3, copy_len);
					sni->server_name[copy_len] = '\0';
					sni->valid = true;
					return 0;
				}
			}
			break;
		}

		p += ext_data_len;
		remaining -= ext_data_len;
	}

	return -ENOENT;
}

/* HTTP Host header extraction */
int protocol_detect_http_host(const u8 *data, size_t len, char *host)
{
	const u8 *p = data;
	const u8 *end = data + len;
	const u8 *line_start;
	size_t line_len;

	/* Look for "Host: " header */
	while (p < end) {
		line_start = p;

		/* Find end of line */
		while (p < end && *p != '\r' && *p != '\n')
			p++;

		line_len = p - line_start;

		/* Check if this is the Host header */
		if (line_len > 6 &&
		    (line_start[0] == 'H' || line_start[0] == 'h') &&
		    (line_start[1] == 'o' || line_start[1] == 'O') &&
		    (line_start[2] == 's' || line_start[2] == 'S') &&
		    (line_start[3] == 't' || line_start[3] == 'T') &&
		    line_start[4] == ':') {

			/* Skip "Host: " and whitespace */
			const u8 *host_start = line_start + 5;
			while (host_start < p && (*host_start == ' ' || *host_start == '\t'))
				host_start++;

			size_t host_len = p - host_start;
			if (host_len > 0 && host_len < MAX_HOST_SIZE) {
				memcpy(host, host_start, host_len);
				host[host_len] = '\0';
				return 0;
			}
		}

		/* Skip CR/LF */
		while (p < end && (*p == '\r' || *p == '\n'))
			p++;
	}

	return -ENOENT;
}

/* HTTP protocol detection */
static bool detect_http(const u8 *data, size_t len)
{
	/* Check for HTTP methods */
	if (len < 4)
		return false;

	if (memcmp(data, "GET ", 4) == 0 ||
	    memcmp(data, "POST", 4) == 0 ||
	    memcmp(data, "PUT ", 4) == 0 ||
	    memcmp(data, "HEAD", 4) == 0 ||
	    memcmp(data, "DELE", 4) == 0 ||
	    memcmp(data, "OPTI", 4) == 0 ||
	    memcmp(data, "TRAC", 4) == 0 ||
	    memcmp(data, "CONN", 4) == 0 ||
	    memcmp(data, "PATC", 4) == 0) {
		return true;
	}

	/* Check for HTTP response */
	if (len >= 8 && memcmp(data, "HTTP/1.", 7) == 0)
		return true;

	return false;
}

/* SSH protocol detection */
static bool detect_ssh(const u8 *data, size_t len)
{
	if (len < 4)
		return false;

	return (memcmp(data, "SSH-", 4) == 0);
}

/* DNS protocol detection */
static bool detect_dns(const u8 *data, size_t len)
{
	u16 flags;

	if (len < 12)
		return false;

	/* DNS header validation */
	flags = (data[2] << 8) | data[3];

	/* Check QR bit (query/response), opcode, and other flags */
	/* Basic validation: opcode should be 0 (standard query) for most DNS */
	u8 opcode = (flags >> 11) & 0x0F;

	return (opcode <= 5);  /* Standard query/update/notify */
}

/* SOCKS5 protocol detection */
static bool detect_socks5(const u8 *data, size_t len)
{
	if (len < 3)
		return false;

	/* SOCKS5 greeting: version=5, nmethods, methods... */
	if (data[0] == 0x05 && data[1] > 0 && data[1] < 10)
		return true;

	return false;
}

/* SOCKS4 protocol detection */
static bool detect_socks4(const u8 *data, size_t len)
{
	if (len < 8)
		return false;

	/* SOCKS4 request: version=4, command, port, ip */
	if (data[0] == 0x04 && (data[1] == 0x01 || data[1] == 0x02))
		return true;

	return false;
}

/* QUIC protocol detection */
static bool detect_quic(const u8 *data, size_t len)
{
	if (len < 5)
		return false;

	/* QUIC long header */
	if ((data[0] & 0x80) != 0) {
		/* Check version negotiation or initial packet */
		return true;
	}

	return false;
}

/* BitTorrent protocol detection */
static bool detect_bittorrent(const u8 *data, size_t len)
{
	if (len < 20)
		return false;

	/* BitTorrent handshake */
	if (data[0] == 0x13 && memcmp(data + 1, "BitTorrent protocol", 19) == 0)
		return true;

	return false;
}

/* RDP protocol detection */
static bool detect_rdp(const u8 *data, size_t len)
{
	if (len < 11)
		return false;

	/* RDP Connection Request (X.224) */
	if (data[0] == 0x03 && data[1] == 0x00 && data[5] == 0xe0)
		return true;

	return false;
}

/* VNC protocol detection */
static bool detect_vnc(const u8 *data, size_t len)
{
	if (len < 12)
		return false;

	/* RFB protocol version string */
	if (memcmp(data, "RFB ", 4) == 0)
		return true;

	return false;
}

/* Deep packet inspection with heuristics */
static int inspect_packet_payload(const u8 *data, size_t len,
				  struct protocol_detection_result *result)
{
	struct sni_info sni;
	char http_host[MAX_HOST_SIZE];

	/* Try TLS/HTTPS detection first */
	if (protocol_detect_sni(data, len, &sni) == 0) {
		result->protocol = PROTO_HTTPS;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_SNI;
		memcpy(&result->info.sni, &sni, sizeof(sni));
		return 0;
	}

	/* Check for generic TLS without SNI */
	if (len >= 3 && data[0] == 0x16 && data[1] == 0x03) {
		result->protocol = PROTO_TLS_GENERIC;
		result->confidence = CONFIDENCE_MEDIUM;
		result->detection_methods |= METHOD_DPI;
		return 0;
	}

	/* HTTP detection */
	if (detect_http(data, len)) {
		result->protocol = PROTO_HTTP;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_PATTERN;

		/* Try to extract Host header */
		if (protocol_detect_http_host(data, len, http_host) == 0) {
			strncpy(result->info.http_host, http_host, MAX_HOST_SIZE - 1);
			result->info.http_host[MAX_HOST_SIZE - 1] = '\0';
		}
		return 0;
	}

	/* SSH detection */
	if (detect_ssh(data, len)) {
		result->protocol = PROTO_SSH;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_PATTERN;
		return 0;
	}

	/* DNS detection */
	if (detect_dns(data, len)) {
		result->protocol = PROTO_DNS;
		result->confidence = CONFIDENCE_MEDIUM;
		result->detection_methods |= METHOD_HEURISTIC;
		return 0;
	}

	/* SOCKS detection */
	if (detect_socks5(data, len)) {
		result->protocol = PROTO_SOCKS5;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_PATTERN;
		return 0;
	}

	if (detect_socks4(data, len)) {
		result->protocol = PROTO_SOCKS4;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_PATTERN;
		return 0;
	}

	/* QUIC detection */
	if (detect_quic(data, len)) {
		result->protocol = PROTO_QUIC;
		result->confidence = CONFIDENCE_MEDIUM;
		result->detection_methods |= METHOD_DPI;
		return 0;
	}

	/* BitTorrent detection */
	if (detect_bittorrent(data, len)) {
		result->protocol = PROTO_BITTORRENT;
		result->confidence = CONFIDENCE_CERTAIN;
		result->detection_methods |= METHOD_PATTERN;
		return 0;
	}

	/* RDP detection */
	if (detect_rdp(data, len)) {
		result->protocol = PROTO_RDP;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_DPI;
		return 0;
	}

	/* VNC detection */
	if (detect_vnc(data, len)) {
		result->protocol = PROTO_VNC;
		result->confidence = CONFIDENCE_HIGH;
		result->detection_methods |= METHOD_PATTERN;
		return 0;
	}

	return -ENOENT;
}

/**
 * protocol_detect_packet() - Main protocol detection function
 */
int protocol_detect_packet(struct protocol_detect_context *ctx,
			   struct sk_buff *skb,
			   struct protocol_detection_result *result)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct protocol_conn_state *conn_state;
	const u8 *payload;
	size_t payload_len;
	u32 src_ip, dst_ip;
	u16 src_port, dst_port;
	u8 transport;
	enum protocol_type port_proto;
	int ret;

	if (!ctx || !ctx->enabled || !skb || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->first_seen = ktime_get_ns();

	atomic64_inc(&ctx->stats.total_packets);

	/* Extract IP header */
	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	src_ip = ntohl(iph->saddr);
	dst_ip = ntohl(iph->daddr);
	transport = iph->protocol;

	/* Extract transport header and payload */
	if (transport == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return -EINVAL;

		src_port = ntohs(tcph->source);
		dst_port = ntohs(tcph->dest);

		payload = (u8 *)tcph + (tcph->doff * 4);
		payload_len = skb->len - ((u8 *)payload - (u8 *)iph);

	} else if (transport == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return -EINVAL;

		src_port = ntohs(udph->source);
		dst_port = ntohs(udph->dest);

		payload = (u8 *)udph + sizeof(struct udphdr);
		payload_len = skb->len - ((u8 *)payload - (u8 *)iph);

	} else {
		/* Non-TCP/UDP protocols */
		result->protocol = PROTO_UNKNOWN;
		result->confidence = CONFIDENCE_NONE;
		return 0;
	}

	/* Check cache first */
	rcu_read_lock();
	conn_state = find_conn_state(ctx, src_ip, dst_ip, src_port, dst_port, transport);
	if (conn_state && conn_state->detection_complete) {
		memcpy(result, &conn_state->result, sizeof(*result));
		conn_state->packets_seen++;
		conn_state->bytes_seen += skb->len;
		atomic64_inc(&ctx->stats.cache_hits);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	atomic64_inc(&ctx->stats.cache_misses);
	atomic64_inc(&ctx->stats.total_inspections);

	/* Port-based detection (low confidence) */
	port_proto = detect_by_port(dst_port, transport);
	if (port_proto != PROTO_UNKNOWN) {
		result->protocol = port_proto;
		result->confidence = CONFIDENCE_LOW;
		result->detection_methods |= METHOD_PORT;
		atomic64_inc(&ctx->stats.method_port_hits);
	}

	/* Deep packet inspection if we have payload */
	if (payload_len > 0) {
		size_t inspect_len = min_t(size_t, payload_len, ctx->inspection_depth);

		ret = inspect_packet_payload(payload, inspect_len, result);
		if (ret == 0) {
			/* DPI succeeded, update statistics */
			if (result->detection_methods & METHOD_SNI)
				atomic64_inc(&ctx->stats.method_sni_hits);
			if (result->detection_methods & METHOD_DPI)
				atomic64_inc(&ctx->stats.method_dpi_hits);
			if (result->detection_methods & METHOD_PATTERN)
				atomic64_inc(&ctx->stats.method_pattern_hits);
			if (result->detection_methods & METHOD_HEURISTIC)
				atomic64_inc(&ctx->stats.method_heuristic_hits);
		}
	}

	/* Update or create connection state */
	if (!conn_state) {
		conn_state = create_conn_state(ctx, src_ip, dst_ip,
					       src_port, dst_port, transport);
	}

	if (conn_state) {
		memcpy(&conn_state->result, result, sizeof(*result));
		conn_state->packets_seen++;
		conn_state->bytes_seen += skb->len;

		/* Mark detection complete if confidence is high enough */
		if (result->confidence >= ctx->min_confidence)
			conn_state->detection_complete = true;
	}

	/* Update protocol detection statistics */
	if (result->protocol < PROTO_MAX)
		atomic64_inc(&ctx->stats.proto_detected[result->protocol]);

	result->last_updated = ktime_get_ns();

	return 0;
}

/**
 * protocol_get_routing_action() - Determine routing action for detected protocol
 */
enum routing_action protocol_get_routing_action(
	struct protocol_detect_context *ctx,
	const struct protocol_detection_result *result)
{
	struct protocol_routing_rule *rule;
	enum routing_action action = ctx->default_action;
	u32 highest_priority = 0;

	if (!ctx || !result)
		return ACTION_DEFAULT;

	/* If detection confidence is too low, continue inspecting */
	if (result->confidence < ctx->min_confidence)
		return ACTION_INSPECT;

	spin_lock_bh(&ctx->routing_lock);

	/* Find matching routing rule with highest priority */
	list_for_each_entry(rule, &ctx->routing_rules, list) {
		if (rule->protocol != result->protocol &&
		    rule->protocol != PROTO_UNKNOWN)
			continue;

		/* Check host pattern if specified */
		if (rule->has_host_pattern) {
			const char *host = NULL;

			if (result->protocol == PROTO_HTTPS && result->info.sni.valid)
				host = result->info.sni.server_name;
			else if (result->protocol == PROTO_HTTP)
				host = result->info.http_host;

			if (!host || strstr(host, rule->host_pattern) == NULL)
				continue;
		}

		/* Use highest priority rule */
		if (rule->priority > highest_priority) {
			highest_priority = rule->priority;
			action = rule->action;
			atomic64_inc(&rule->match_count);
		}
	}

	spin_unlock_bh(&ctx->routing_lock);

	/* Update routing statistics */
	switch (action) {
	case ACTION_PROXY:
		atomic64_inc(&ctx->stats.routed_proxy);
		break;
	case ACTION_DIRECT:
		atomic64_inc(&ctx->stats.routed_direct);
		break;
	case ACTION_BLOCK:
		atomic64_inc(&ctx->stats.routed_blocked);
		break;
	default:
		break;
	}

	return action;
}

/**
 * protocol_add_rule() - Add a protocol detection rule
 */
int protocol_add_rule(struct protocol_detect_context *ctx,
		      const struct protocol_rule *rule)
{
	struct protocol_rule *new_rule;

	if (!ctx || !rule)
		return -EINVAL;

	if (rule->protocol >= PROTO_MAX)
		return -EINVAL;

	new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return -ENOMEM;

	memcpy(new_rule, rule, sizeof(*new_rule));

	spin_lock_bh(&ctx->rules_lock);
	list_add_tail(&new_rule->list, &ctx->rules);
	spin_unlock_bh(&ctx->rules_lock);

	return 0;
}

/**
 * protocol_del_rule() - Remove a protocol detection rule
 */
int protocol_del_rule(struct protocol_detect_context *ctx,
		      enum protocol_type protocol)
{
	struct protocol_rule *rule, *tmp;
	int removed = 0;

	if (!ctx)
		return -EINVAL;

	spin_lock_bh(&ctx->rules_lock);
	list_for_each_entry_safe(rule, tmp, &ctx->rules, list) {
		if (rule->protocol == protocol) {
			list_del(&rule->list);
			kfree(rule);
			removed++;
		}
	}
	spin_unlock_bh(&ctx->rules_lock);

	return removed > 0 ? 0 : -ENOENT;
}

/**
 * protocol_add_routing_rule() - Add a protocol routing rule
 */
int protocol_add_routing_rule(struct protocol_detect_context *ctx,
			      const struct protocol_routing_rule *rule)
{
	struct protocol_routing_rule *new_rule;

	if (!ctx || !rule)
		return -EINVAL;

	if (rule->protocol >= PROTO_MAX)
		return -EINVAL;

	new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return -ENOMEM;

	memcpy(new_rule, rule, sizeof(*new_rule));
	atomic64_set(&new_rule->match_count, 0);

	spin_lock_bh(&ctx->routing_lock);
	list_add_tail(&new_rule->list, &ctx->routing_rules);
	spin_unlock_bh(&ctx->routing_lock);

	return 0;
}

/**
 * protocol_del_routing_rule() - Remove a protocol routing rule
 */
int protocol_del_routing_rule(struct protocol_detect_context *ctx, u32 priority)
{
	struct protocol_routing_rule *rule, *tmp;

	if (!ctx)
		return -EINVAL;

	spin_lock_bh(&ctx->routing_lock);
	list_for_each_entry_safe(rule, tmp, &ctx->routing_rules, list) {
		if (rule->priority == priority) {
			list_del(&rule->list);
			kfree(rule);
			spin_unlock_bh(&ctx->routing_lock);
			return 0;
		}
	}
	spin_unlock_bh(&ctx->routing_lock);

	return -ENOENT;
}

/**
 * protocol_detect_get_stats() - Get current statistics
 */
void protocol_detect_get_stats(struct protocol_detect_context *ctx,
			       struct protocol_detection_stats *stats)
{
	int i;

	if (!ctx || !stats)
		return;

	for (i = 0; i < PROTO_MAX; i++) {
		stats->proto_detected[i] = atomic64_read(&ctx->stats.proto_detected[i]);
		stats->proto_errors[i] = atomic64_read(&ctx->stats.proto_errors[i]);
	}

	stats->method_port_hits = atomic64_read(&ctx->stats.method_port_hits);
	stats->method_pattern_hits = atomic64_read(&ctx->stats.method_pattern_hits);
	stats->method_heuristic_hits = atomic64_read(&ctx->stats.method_heuristic_hits);
	stats->method_dpi_hits = atomic64_read(&ctx->stats.method_dpi_hits);
	stats->method_sni_hits = atomic64_read(&ctx->stats.method_sni_hits);
	stats->method_handshake_hits = atomic64_read(&ctx->stats.method_handshake_hits);

	stats->routed_proxy = atomic64_read(&ctx->stats.routed_proxy);
	stats->routed_direct = atomic64_read(&ctx->stats.routed_direct);
	stats->routed_blocked = atomic64_read(&ctx->stats.routed_blocked);

	stats->total_packets = atomic64_read(&ctx->stats.total_packets);
	stats->total_inspections = atomic64_read(&ctx->stats.total_inspections);
	stats->cache_hits = atomic64_read(&ctx->stats.cache_hits);
	stats->cache_misses = atomic64_read(&ctx->stats.cache_misses);
}

/**
 * protocol_detect_reset_stats() - Reset all statistics
 */
void protocol_detect_reset_stats(struct protocol_detect_context *ctx)
{
	int i;

	if (!ctx)
		return;

	for (i = 0; i < PROTO_MAX; i++) {
		atomic64_set(&ctx->stats.proto_detected[i], 0);
		atomic64_set(&ctx->stats.proto_errors[i], 0);
	}

	atomic64_set(&ctx->stats.method_port_hits, 0);
	atomic64_set(&ctx->stats.method_pattern_hits, 0);
	atomic64_set(&ctx->stats.method_heuristic_hits, 0);
	atomic64_set(&ctx->stats.method_dpi_hits, 0);
	atomic64_set(&ctx->stats.method_sni_hits, 0);
	atomic64_set(&ctx->stats.method_handshake_hits, 0);

	atomic64_set(&ctx->stats.routed_proxy, 0);
	atomic64_set(&ctx->stats.routed_direct, 0);
	atomic64_set(&ctx->stats.routed_blocked, 0);

	atomic64_set(&ctx->stats.total_packets, 0);
	atomic64_set(&ctx->stats.total_inspections, 0);
	atomic64_set(&ctx->stats.cache_hits, 0);
	atomic64_set(&ctx->stats.cache_misses, 0);
}

/**
 * protocol_detect_flush_cache() - Flush connection state cache
 */
void protocol_detect_flush_cache(struct protocol_detect_context *ctx)
{
	struct protocol_conn_state *state;
	struct hlist_node *tmp;
	int i;

	if (!ctx)
		return;

	spin_lock_bh(&ctx->conn_lock);
	hash_for_each_safe(ctx->connections, i, tmp, state, hash_node) {
		hash_del_rcu(&state->hash_node);
		kfree_rcu(state, rcu);
	}
	spin_unlock_bh(&ctx->conn_lock);

	synchronize_rcu();
}

/**
 * protocol_detect_init() - Initialize protocol detection context
 */
struct protocol_detect_context *protocol_detect_init(void)
{
	struct protocol_detect_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->enabled = true;
	ctx->inspection_depth = DEFAULT_INSPECTION_DEPTH;
	ctx->connection_timeout = DEFAULT_CONN_TIMEOUT;
	ctx->default_action = ACTION_PROXY;
	ctx->min_confidence = DEFAULT_MIN_CONFIDENCE;

	INIT_LIST_HEAD(&ctx->rules);
	spin_lock_init(&ctx->rules_lock);

	INIT_LIST_HEAD(&ctx->routing_rules);
	spin_lock_init(&ctx->routing_lock);

	hash_init(ctx->connections);
	spin_lock_init(&ctx->conn_lock);

	memset(&ctx->stats, 0, sizeof(ctx->stats));

	pr_info("MUTEX protocol detection initialized\n");

	return ctx;
}

/**
 * protocol_detect_cleanup() - Clean up protocol detection context
 */
void protocol_detect_cleanup(struct protocol_detect_context *ctx)
{
	struct protocol_rule *rule, *rule_tmp;
	struct protocol_routing_rule *rr, *rr_tmp;

	if (!ctx)
		return;

	/* Flush connection cache */
	protocol_detect_flush_cache(ctx);

	/* Free detection rules */
	spin_lock_bh(&ctx->rules_lock);
	list_for_each_entry_safe(rule, rule_tmp, &ctx->rules, list) {
		list_del(&rule->list);
		kfree(rule);
	}
	spin_unlock_bh(&ctx->rules_lock);

	/* Free routing rules */
	spin_lock_bh(&ctx->routing_lock);
	list_for_each_entry_safe(rr, rr_tmp, &ctx->routing_rules, list) {
		list_del(&rr->list);
		kfree(rr);
	}
	spin_unlock_bh(&ctx->routing_lock);

	kfree(ctx);

	pr_info("MUTEX protocol detection cleaned up\n");
}

EXPORT_SYMBOL(protocol_detect_init);
EXPORT_SYMBOL(protocol_detect_cleanup);
EXPORT_SYMBOL(protocol_detect_packet);
EXPORT_SYMBOL(protocol_get_routing_action);
EXPORT_SYMBOL(protocol_add_rule);
EXPORT_SYMBOL(protocol_del_rule);
EXPORT_SYMBOL(protocol_add_routing_rule);
EXPORT_SYMBOL(protocol_del_routing_rule);
EXPORT_SYMBOL(protocol_detect_sni);
EXPORT_SYMBOL(protocol_detect_http_host);
EXPORT_SYMBOL(protocol_name);
EXPORT_SYMBOL(protocol_confidence_name);
EXPORT_SYMBOL(protocol_action_name);
EXPORT_SYMBOL(protocol_detect_get_stats);
EXPORT_SYMBOL(protocol_detect_reset_stats);
EXPORT_SYMBOL(protocol_detect_flush_cache);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Project");
MODULE_DESCRIPTION("Protocol detection for MUTEX kernel proxy");
