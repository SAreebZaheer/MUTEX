/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MUTEX Protocol Detection Userspace Types
 *
 * Userspace-compatible definitions for protocol detection structures.
 * This file contains only the types needed by userspace applications,
 * without kernel-specific dependencies.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#ifndef MUTEX_PROTOCOL_DETECT_TYPES_H
#define MUTEX_PROTOCOL_DETECT_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
/* Userspace type definitions */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t __be32;
typedef int16_t __be16;
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#endif

/* Protocol types detected by the module */
enum protocol_type {
	PROTO_UNKNOWN = 0,
	PROTO_HTTP,
	PROTO_HTTPS,
	PROTO_DNS,
	PROTO_SSH,
	PROTO_FTP,
	PROTO_SMTP,
	PROTO_POP3,
	PROTO_IMAP,
	PROTO_TELNET,
	PROTO_RDP,
	PROTO_VNC,
	PROTO_SOCKS4,
	PROTO_SOCKS5,
	PROTO_BITTORRENT,
	PROTO_QUIC,
	PROTO_RTSP,
	PROTO_SIP,
	PROTO_IRC,
	PROTO_XMPP,
	PROTO_OPENVPN,
	PROTO_WIREGUARD,
	PROTO_TLS_GENERIC,
	PROTO_DTLS,
	PROTO_MAX
};

/* Detection confidence level */
enum detection_confidence {
	CONFIDENCE_NONE = 0,
	CONFIDENCE_LOW = 1,
	CONFIDENCE_MEDIUM = 2,
	CONFIDENCE_HIGH = 3,
	CONFIDENCE_CERTAIN = 4
};

/* Protocol detection methods */
enum detection_method {
	METHOD_PORT = 0x01,
	METHOD_PATTERN = 0x02,
	METHOD_HEURISTIC = 0x04,
	METHOD_DPI = 0x08,
	METHOD_SNI = 0x10,
	METHOD_HANDSHAKE = 0x20
};

/* Routing action for detected protocol */
enum routing_action {
	ACTION_PROXY = 0,
	ACTION_DIRECT,
	ACTION_BLOCK,
	ACTION_INSPECT,
	ACTION_DEFAULT
};

/* Maximum sizes */
#define MAX_PATTERN_SIZE 64
#define MAX_SNI_SIZE 256
#define MAX_HOST_SIZE 256

/* Detection pattern for DPI */
struct protocol_pattern {
	u8 data[MAX_PATTERN_SIZE];
	size_t len;
	size_t offset;
	u32 match_mask;
} __attribute__((packed));

/* Protocol detection rule */
struct protocol_rule {
	enum protocol_type protocol;
	u16 port_start;
	u16 port_end;
	u8 transport;

	struct protocol_pattern patterns[4];
	u32 num_patterns;
	u32 methods;
	enum detection_confidence min_confidence;
} __attribute__((packed));

/* Routing rule based on protocol */
struct protocol_routing_rule {
	enum protocol_type protocol;
	enum routing_action action;
	char host_pattern[MAX_HOST_SIZE];
	bool has_host_pattern;
	u32 priority;
} __attribute__((packed));

/* SNI information */
struct sni_info {
	char server_name[MAX_SNI_SIZE];
	u16 tls_version;
	bool valid;
} __attribute__((packed));

/* Detection result */
struct protocol_detection_result {
	enum protocol_type protocol;
	enum detection_confidence confidence;
	u32 detection_methods;

	union {
		struct sni_info sni;
		char http_host[MAX_HOST_SIZE];
	} info;

	enum routing_action action;
	u64 first_seen;
	u64 last_updated;
} __attribute__((packed));

/* Protocol detection statistics */
struct protocol_detection_stats {
	/* Per-protocol counters */
	u64 proto_detected[PROTO_MAX];
	u64 proto_errors[PROTO_MAX];

	/* Detection method statistics */
	u64 method_port_hits;
	u64 method_pattern_hits;
	u64 method_heuristic_hits;
	u64 method_dpi_hits;
	u64 method_sni_hits;
	u64 method_handshake_hits;

	/* Routing statistics */
	u64 routed_proxy;
	u64 routed_direct;
	u64 routed_blocked;

	/* Performance metrics */
	u64 total_packets;
	u64 total_inspections;
	u64 cache_hits;
	u64 cache_misses;
} __attribute__((packed));

/* IOCTL command definitions */
#define PROTO_DETECT_IOC_MAGIC 'P'

#define PROTO_DETECT_ENABLE      _IOW(PROTO_DETECT_IOC_MAGIC, 1, int)
#define PROTO_DETECT_DISABLE     _IO(PROTO_DETECT_IOC_MAGIC, 2)
#define PROTO_DETECT_ADD_RULE    _IOW(PROTO_DETECT_IOC_MAGIC, 3, struct protocol_rule)
#define PROTO_DETECT_DEL_RULE    _IOW(PROTO_DETECT_IOC_MAGIC, 4, enum protocol_type)
#define PROTO_DETECT_CLEAR_RULES _IO(PROTO_DETECT_IOC_MAGIC, 5)
#define PROTO_DETECT_ADD_ROUTE   _IOW(PROTO_DETECT_IOC_MAGIC, 6, struct protocol_routing_rule)
#define PROTO_DETECT_DEL_ROUTE   _IOW(PROTO_DETECT_IOC_MAGIC, 7, u32)
#define PROTO_DETECT_CLEAR_ROUTES _IO(PROTO_DETECT_IOC_MAGIC, 8)
#define PROTO_DETECT_SET_DEPTH   _IOW(PROTO_DETECT_IOC_MAGIC, 9, u32)
#define PROTO_DETECT_SET_TIMEOUT _IOW(PROTO_DETECT_IOC_MAGIC, 10, u32)
#define PROTO_DETECT_SET_DEFAULT _IOW(PROTO_DETECT_IOC_MAGIC, 11, enum routing_action)
#define PROTO_DETECT_GET_STATS   _IOR(PROTO_DETECT_IOC_MAGIC, 12, struct protocol_detection_stats)
#define PROTO_DETECT_RESET_STATS _IO(PROTO_DETECT_IOC_MAGIC, 13)
#define PROTO_DETECT_FLUSH_CACHE _IO(PROTO_DETECT_IOC_MAGIC, 14)

/* Function declarations for userspace */
#ifndef __KERNEL__

/**
 * protocol_name() - Get human-readable protocol name
 */
const char *protocol_name(enum protocol_type protocol);

/**
 * protocol_confidence_name() - Get human-readable confidence level name
 */
const char *protocol_confidence_name(enum detection_confidence confidence);

/**
 * protocol_action_name() - Get human-readable action name
 */
const char *protocol_action_name(enum routing_action action);

/**
 * protocol_detect_sni() - Extract SNI from TLS ClientHello
 */
int protocol_detect_sni(const u8 *data, size_t len, struct sni_info *sni);

/**
 * protocol_detect_http_host() - Extract Host header from HTTP request
 */
int protocol_detect_http_host(const u8 *data, size_t len, char *host);

#endif /* !__KERNEL__ */

#endif /* MUTEX_PROTOCOL_DETECT_TYPES_H */
