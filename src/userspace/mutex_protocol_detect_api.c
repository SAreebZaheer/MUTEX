// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MUTEX Protocol Detection Userspace API Implementation
 *
 * Copyright (C) 2025 MUTEX Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>

#include "mutex_protocol_detect_api.h"

#define PROTO_DETECT_DEVICE "/dev/mutex_proto_detect"

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

/* TLS SNI detection - userspace implementation */
int protocol_detect_sni(const u8 *data, size_t len, struct sni_info *sni)
{
	const u8 *p = data;
	u16 tls_version, handshake_len;
	u8 content_type, handshake_type;
	size_t remaining = len;

	memset(sni, 0, sizeof(*sni));

	if (len < 43)
		return -EINVAL;

	content_type = p[0];
	if (content_type != 0x16)
		return -EINVAL;

	tls_version = (p[1] << 8) | p[2];
	sni->tls_version = tls_version;

	handshake_len = (p[3] << 8) | p[4];
	if (handshake_len + 5 > len)
		return -EINVAL;

	p += 5;
	remaining -= 5;

	handshake_type = p[0];
	if (handshake_type != 0x01)
		return -EINVAL;

	p += 4;
	remaining -= 4;

	if (remaining < 2)
		return -EINVAL;
	p += 2;
	remaining -= 2;

	if (remaining < 32)
		return -EINVAL;
	p += 32;
	remaining -= 32;

	if (remaining < 1)
		return -EINVAL;
	u8 session_id_len = p[0];
	p += 1 + session_id_len;
	remaining -= 1 + session_id_len;

	if (remaining < 2)
		return -EINVAL;
	u16 cipher_len = (p[0] << 8) | p[1];
	p += 2 + cipher_len;
	remaining -= 2 + cipher_len;

	if (remaining < 1)
		return -EINVAL;
	u8 comp_len = p[0];
	p += 1 + comp_len;
	remaining -= 1 + comp_len;

	if (remaining < 2)
		return -EINVAL;
	u16 ext_len = (p[0] << 8) | p[1];
	p += 2;
	remaining -= 2;

	if (ext_len > remaining)
		return -EINVAL;

	while (remaining >= 4) {
		u16 ext_type = (p[0] << 8) | p[1];
		u16 ext_data_len = (p[2] << 8) | p[3];

		p += 4;
		remaining -= 4;

		if (ext_data_len > remaining)
			break;

		if (ext_type == 0x00) {
			if (ext_data_len < 2)
				break;
			u16 sni_list_len = (p[0] << 8) | p[1];

			if (sni_list_len + 2 > ext_data_len)
				break;

			p += 2;

			if (p[0] == 0x00) {
				u16 hostname_len = (p[1] << 8) | p[2];

				if (hostname_len > 0 && hostname_len < MAX_SNI_SIZE) {
					size_t copy_len = (hostname_len < MAX_SNI_SIZE - 1) ?
							  hostname_len : MAX_SNI_SIZE - 1;
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

/* HTTP Host header detection - userspace implementation */
int protocol_detect_http_host(const u8 *data, size_t len, char *host)
{
	const u8 *p = data;
	const u8 *end = data + len;
	const u8 *line_start;
	size_t line_len;

	while (p < end) {
		line_start = p;

		while (p < end && *p != '\r' && *p != '\n')
			p++;

		line_len = p - line_start;

		if (line_len > 6 &&
		    (line_start[0] == 'H' || line_start[0] == 'h') &&
		    (line_start[1] == 'o' || line_start[1] == 'O') &&
		    (line_start[2] == 's' || line_start[2] == 'S') &&
		    (line_start[3] == 't' || line_start[3] == 'T') &&
		    line_start[4] == ':') {

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

		while (p < end && (*p == '\r' || *p == '\n'))
			p++;
	}

	return -ENOENT;
}

int mutex_proto_open(void)
{
	int fd;

	fd = open(PROTO_DETECT_DEVICE, O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			return PROTO_API_NO_DEVICE;
		else if (errno == EACCES || errno == EPERM)
			return PROTO_API_PERMISSION;
		else
			return PROTO_API_ERROR;
	}

	return fd;
}

void mutex_proto_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

int mutex_proto_enable(int fd)
{
	int enable = 1;

	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_ENABLE, &enable) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_disable(int fd)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_DISABLE) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_add_rule(int fd, const struct protocol_rule *rule)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (!rule)
		return PROTO_API_INVALID_ARG;

	if (ioctl(fd, PROTO_DETECT_ADD_RULE, rule) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_del_rule(int fd, enum protocol_type protocol)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_DEL_RULE, &protocol) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_clear_rules(int fd)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_CLEAR_RULES) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_add_route(int fd, const struct protocol_routing_rule *rule)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (!rule)
		return PROTO_API_INVALID_ARG;

	if (ioctl(fd, PROTO_DETECT_ADD_ROUTE, rule) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_del_route(int fd, uint32_t priority)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_DEL_ROUTE, &priority) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_clear_routes(int fd)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_CLEAR_ROUTES) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_set_depth(int fd, uint32_t depth)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_SET_DEPTH, &depth) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_set_timeout(int fd, uint32_t timeout)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_SET_TIMEOUT, &timeout) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_set_default_action(int fd, enum routing_action action)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_SET_DEFAULT, &action) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_get_stats(int fd, struct protocol_detection_stats *stats)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (!stats)
		return PROTO_API_INVALID_ARG;

	if (ioctl(fd, PROTO_DETECT_GET_STATS, stats) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_reset_stats(int fd)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_RESET_STATS) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

int mutex_proto_flush_cache(int fd)
{
	if (fd < 0)
		return PROTO_API_INVALID_FD;

	if (ioctl(fd, PROTO_DETECT_FLUSH_CACHE) < 0)
		return PROTO_API_ERROR;

	return PROTO_API_SUCCESS;
}

void mutex_proto_create_port_rule(enum protocol_type protocol,
				  uint16_t port,
				  uint8_t transport,
				  struct protocol_rule *rule)
{
	if (!rule)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->protocol = protocol;
	rule->port_start = port;
	rule->port_end = port;
	rule->transport = transport;
	rule->methods = METHOD_PORT;
	rule->min_confidence = CONFIDENCE_LOW;
}

void mutex_proto_create_pattern_rule(enum protocol_type protocol,
				     const uint8_t *pattern,
				     size_t pattern_len,
				     size_t offset,
				     struct protocol_rule *rule)
{
	if (!rule || !pattern || pattern_len > MAX_PATTERN_SIZE)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->protocol = protocol;
	rule->methods = METHOD_PATTERN;
	rule->min_confidence = CONFIDENCE_MEDIUM;

	memcpy(rule->patterns[0].data, pattern, pattern_len);
	rule->patterns[0].len = pattern_len;
	rule->patterns[0].offset = offset;
	rule->patterns[0].match_mask = 0xFFFFFFFF;  /* Match all bytes */
	rule->num_patterns = 1;
}

void mutex_proto_create_routing_rule(enum protocol_type protocol,
				     enum routing_action action,
				     uint32_t priority,
				     struct protocol_routing_rule *rule)
{
	if (!rule)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->protocol = protocol;
	rule->action = action;
	rule->priority = priority;
	rule->has_host_pattern = false;
}

void mutex_proto_create_host_routing_rule(enum protocol_type protocol,
					  const char *host_pattern,
					  enum routing_action action,
					  uint32_t priority,
					  struct protocol_routing_rule *rule)
{
	if (!rule || !host_pattern)
		return;

	memset(rule, 0, sizeof(*rule));
	rule->protocol = protocol;
	rule->action = action;
	rule->priority = priority;
	rule->has_host_pattern = true;

	strncpy(rule->host_pattern, host_pattern, MAX_HOST_SIZE - 1);
	rule->host_pattern[MAX_HOST_SIZE - 1] = '\0';
}

void mutex_proto_print_stats(const struct protocol_detection_stats *stats)
{
	int i;
	uint64_t total_detected = 0;

	if (!stats)
		return;

	printf("=== MUTEX Protocol Detection Statistics ===\n\n");

	printf("Protocol Detection:\n");
	for (i = 0; i < PROTO_MAX; i++) {
		uint64_t count = stats->proto_detected[i];
		if (count > 0) {
			printf("  %-20s: %lu\n", protocol_name(i), count);
			total_detected += count;
		}
	}
	printf("  Total Detected      : %lu\n\n", total_detected);

	printf("Detection Methods:\n");
	printf("  Port-based          : %lu\n", stats->method_port_hits);
	printf("  Pattern matching    : %lu\n", stats->method_pattern_hits);
	printf("  Heuristic analysis  : %lu\n", stats->method_heuristic_hits);
	printf("  Deep inspection     : %lu\n", stats->method_dpi_hits);
	printf("  SNI parsing         : %lu\n", stats->method_sni_hits);
	printf("  Handshake analysis  : %lu\n\n", stats->method_handshake_hits);

	printf("Routing Decisions:\n");
	printf("  Routed via proxy    : %lu\n", stats->routed_proxy);
	printf("  Routed directly     : %lu\n", stats->routed_direct);
	printf("  Blocked             : %lu\n\n", stats->routed_blocked);

	printf("Performance:\n");
	printf("  Total packets       : %lu\n", stats->total_packets);
	printf("  Total inspections   : %lu\n", stats->total_inspections);
	printf("  Cache hits          : %lu\n", stats->cache_hits);
	printf("  Cache misses        : %lu\n", stats->cache_misses);

	if (stats->cache_hits + stats->cache_misses > 0) {
		double hit_rate = (double)stats->cache_hits /
				  (stats->cache_hits + stats->cache_misses) * 100.0;
		printf("  Cache hit rate      : %.2f%%\n", hit_rate);
	}

	printf("\n");
}

const char *mutex_proto_get_error_string(int error_code)
{
	switch (error_code) {
	case PROTO_API_SUCCESS:
		return "Success";
	case PROTO_API_ERROR:
		return "Generic error";
	case PROTO_API_INVALID_FD:
		return "Invalid file descriptor";
	case PROTO_API_INVALID_ARG:
		return "Invalid argument";
	case PROTO_API_NO_DEVICE:
		return "Device not found (module not loaded?)";
	case PROTO_API_PERMISSION:
		return "Permission denied (need root/CAP_NET_ADMIN?)";
	default:
		return "Unknown error";
	}
}
