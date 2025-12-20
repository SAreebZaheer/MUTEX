/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * SOCKS Protocol Support (SOCKS4/SOCKS5)
 *
 * This file defines structures and functions for SOCKS protocol handling
 * in kernel space.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#ifndef _MUTEX_SOCKS_H
#define _MUTEX_SOCKS_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>

/* ========== SOCKS4 Protocol Definitions ========== */

#define SOCKS4_VERSION          0x04
#define SOCKS4_CMD_CONNECT      0x01
#define SOCKS4_CMD_BIND         0x02

/* SOCKS4 Reply Codes */
#define SOCKS4_REP_GRANTED      0x5A
#define SOCKS4_REP_REJECTED     0x5B
#define SOCKS4_REP_NO_IDENTD    0x5C
#define SOCKS4_REP_BAD_USERID   0x5D

/* SOCKS4 Request Structure */
struct socks4_request {
	__u8 version;           /* SOCKS version (4) */
	__u8 command;           /* Command code */
	__be16 dest_port;       /* Destination port (network byte order) */
	__be32 dest_ip;         /* Destination IP (network byte order) */
	/* Variable length user ID string follows (null-terminated) */
} __attribute__((packed));

/* SOCKS4 Response Structure */
struct socks4_response {
	__u8 null_byte;         /* Must be 0 */
	__u8 status;            /* Status code */
	__be16 dest_port;       /* Destination port */
	__be32 dest_ip;         /* Destination IP */
} __attribute__((packed));

/* SOCKS4a (with domain name support) */
#define SOCKS4A_MAGIC_IP        0x00000001  /* 0.0.0.x signals domain name */

/* ========== SOCKS5 Protocol Definitions ========== */

#define SOCKS5_VERSION          0x05

/* SOCKS5 Authentication Methods */
#define SOCKS5_AUTH_NONE        0x00  /* No authentication required */
#define SOCKS5_AUTH_GSSAPI      0x01  /* GSSAPI */
#define SOCKS5_AUTH_USERPASS    0x02  /* Username/password */
#define SOCKS5_AUTH_NO_ACCEPT   0xFF  /* No acceptable methods */

/* SOCKS5 Commands */
#define SOCKS5_CMD_CONNECT      0x01  /* TCP connect */
#define SOCKS5_CMD_BIND         0x02  /* TCP bind */
#define SOCKS5_CMD_UDP_ASSOC    0x03  /* UDP associate */

/* SOCKS5 Address Types */
#define SOCKS5_ATYP_IPV4        0x01  /* IPv4 address */
#define SOCKS5_ATYP_DOMAIN      0x03  /* Domain name */
#define SOCKS5_ATYP_IPV6        0x04  /* IPv6 address */

/* SOCKS5 Reply Codes */
#define SOCKS5_REP_SUCCESS      0x00  /* Succeeded */
#define SOCKS5_REP_FAILURE      0x01  /* General SOCKS server failure */
#define SOCKS5_REP_NOT_ALLOWED  0x02  /* Connection not allowed by ruleset */
#define SOCKS5_REP_NET_UNREACH  0x03  /* Network unreachable */
#define SOCKS5_REP_HOST_UNREACH 0x04  /* Host unreachable */
#define SOCKS5_REP_REFUSED      0x05  /* Connection refused */
#define SOCKS5_REP_TTL_EXPIRED  0x06  /* TTL expired */
#define SOCKS5_REP_CMD_UNSUP    0x07  /* Command not supported */
#define SOCKS5_REP_ATYP_UNSUP   0x08  /* Address type not supported */

/* SOCKS5 Method Selection Request */
struct socks5_method_request {
	__u8 version;           /* SOCKS version (5) */
	__u8 nmethods;          /* Number of methods */
	__u8 methods[1];        /* Variable length method list */
} __attribute__((packed));

/* SOCKS5 Method Selection Response */
struct socks5_method_response {
	__u8 version;           /* SOCKS version (5) */
	__u8 method;            /* Selected method */
} __attribute__((packed));

/* SOCKS5 Request Header */
struct socks5_request_header {
	__u8 version;           /* SOCKS version (5) */
	__u8 command;           /* Command code */
	__u8 reserved;          /* Reserved, must be 0 */
	__u8 address_type;      /* Address type */
	/* Variable length address and port follow */
} __attribute__((packed));

/* SOCKS5 Response Header */
struct socks5_response_header {
	__u8 version;           /* SOCKS version (5) */
	__u8 reply;             /* Reply code */
	__u8 reserved;          /* Reserved, must be 0 */
	__u8 address_type;      /* Address type */
	/* Variable length address and port follow */
} __attribute__((packed));

/* SOCKS5 Username/Password Authentication Request */
struct socks5_userpass_request {
	__u8 version;           /* Authentication version (1) */
	__u8 username_len;      /* Username length */
	/* Variable length username and password follow */
} __attribute__((packed));

/* SOCKS5 Username/Password Authentication Response */
struct socks5_userpass_response {
	__u8 version;           /* Authentication version (1) */
	__u8 status;            /* Status (0 = success) */
} __attribute__((packed));

/* SOCKS5 UDP Request Header */
struct socks5_udp_header {
	__be16 reserved;        /* Reserved, must be 0 */
	__u8 fragment;          /* Fragment number */
	__u8 address_type;      /* Address type */
	/* Variable length address, port, and data follow */
} __attribute__((packed));

/* ========== SOCKS State Machine ========== */

enum socks_state {
	SOCKS_STATE_INIT,               /* Initial state */
	SOCKS_STATE_METHOD_SENT,        /* Method request sent (SOCKS5) */
	SOCKS_STATE_METHOD_RECEIVED,    /* Method response received (SOCKS5) */
	SOCKS_STATE_AUTH_SENT,          /* Authentication sent (SOCKS5) */
	SOCKS_STATE_AUTH_RECEIVED,      /* Authentication response received */
	SOCKS_STATE_REQUEST_SENT,       /* Connection request sent */
	SOCKS_STATE_REQUEST_RECEIVED,   /* Connection response received */
	SOCKS_STATE_CONNECTED,          /* Connection established */
	SOCKS_STATE_UDP_READY,          /* UDP association ready */
	SOCKS_STATE_ERROR,              /* Error state */
	SOCKS_STATE_CLOSED              /* Connection closed */
};

enum socks_version {
	SOCKS_VERSION_4,
	SOCKS_VERSION_4A,
	SOCKS_VERSION_5
};

/* ========== SOCKS Connection Context ========== */

struct socks_auth_info {
	__u8 method;                    /* Authentication method */
	char username[256];             /* Username (SOCKS5) */
	char password[256];             /* Password (SOCKS5) */
	__u8 username_len;
	__u8 password_len;
};

struct socks_addr {
	__u8 address_type;              /* Address type */
	union {
		__be32 ipv4;            /* IPv4 address */
		struct in6_addr ipv6;   /* IPv6 address */
		struct {
			__u8 len;
			char name[256];
		} domain;               /* Domain name */
	} addr;
	__be16 port;                    /* Port number */
};

struct socks_connection {
	enum socks_version version;     /* SOCKS version */
	enum socks_state state;         /* Current state */

	__u8 command;                   /* SOCKS command */
	struct socks_auth_info auth;    /* Authentication info */

	struct socks_addr dest;         /* Destination address */
	struct socks_addr bound;        /* Bound address (for replies) */

	__u8 reply_code;                /* Last reply code */

	/* Buffer for building/parsing messages */
	void *buffer;
	size_t buffer_len;
	size_t buffer_used;

	/* UDP association info (SOCKS5) */
	struct socket *udp_sock;        /* UDP socket for association */
	struct socks_addr udp_relay;    /* UDP relay address */

	/* Timestamps */
	unsigned long created;          /* Connection creation time */
	unsigned long last_activity;    /* Last activity timestamp */

	/* Error information */
	int error;                      /* Last error code */

	/* Reference to proxy configuration */
	void *proxy_config;
};

/* ========== SOCKS Protocol Functions ========== */

/* Initialize SOCKS connection context */
struct socks_connection *socks_connection_alloc(enum socks_version version);
void socks_connection_free(struct socks_connection *conn);

/* SOCKS4 Protocol Functions */
int socks4_build_connect_request(struct socks_connection *conn,
				 const struct socks_addr *dest,
				 const char *userid);
int socks4_parse_response(struct socks_connection *conn,
			  const void *data, size_t len);

/* SOCKS5 Protocol Functions */
int socks5_build_method_request(struct socks_connection *conn,
				const __u8 *methods, __u8 nmethods);
int socks5_parse_method_response(struct socks_connection *conn,
				 const void *data, size_t len);

int socks5_build_auth_request(struct socks_connection *conn,
			      const char *username, const char *password);
int socks5_parse_auth_response(struct socks_connection *conn,
			       const void *data, size_t len);

int socks5_build_connect_request(struct socks_connection *conn,
				 const struct socks_addr *dest);
int socks5_build_bind_request(struct socks_connection *conn,
			      const struct socks_addr *dest);
int socks5_build_udp_assoc_request(struct socks_connection *conn,
				   const struct socks_addr *client_addr);

int socks5_parse_response(struct socks_connection *conn,
			  const void *data, size_t len);

/* SOCKS5 UDP Functions */
int socks5_build_udp_header(struct socks_connection *conn,
			    const struct socks_addr *dest,
			    void *buffer, size_t buffer_len);
int socks5_parse_udp_header(struct socks_connection *conn,
			    const void *data, size_t len,
			    struct socks_addr *dest);

/* Helper Functions */
int socks_addr_from_sockaddr(struct socks_addr *socks_addr,
			     const struct sockaddr *sa);
int socks_addr_to_sockaddr(const struct socks_addr *socks_addr,
			   struct sockaddr_storage *ss);

const char *socks_state_name(enum socks_state state);
const char *socks_version_name(enum socks_version version);
const char *socks5_reply_name(__u8 reply);
const char *socks4_reply_name(__u8 reply);

/* SOCKS DNS Resolution */
int socks_resolve_dns(struct socks_connection *conn,
		      const char *hostname,
		      struct socks_addr *result);

/* State Machine Validation */
bool socks_state_is_valid_transition(enum socks_state from,
				     enum socks_state to);
int socks_validate_state(struct socks_connection *conn,
			enum socks_state expected);

/* ========== SOCKS Integration with Connection Tracking ========== */

/* Forward declaration from mutex_conn_track.h */
struct mutex_connection;

/* Attach SOCKS context to a tracked connection */
int mutex_conn_attach_socks(struct mutex_connection *conn,
			    struct socks_connection *socks);

/* Get SOCKS context from a tracked connection */
struct socks_connection *mutex_conn_get_socks(struct mutex_connection *conn);

/* Process SOCKS handshake for a connection */
int mutex_socks_process_handshake(struct mutex_connection *conn,
				  struct sk_buff *skb);

/* Handle SOCKS proxy connection establishment */
int mutex_socks_establish_connection(struct mutex_connection *conn);

/* Handle SOCKS UDP association */
int mutex_socks_setup_udp_assoc(struct mutex_connection *conn);

/* Handle SOCKS errors */
void mutex_socks_handle_error(struct mutex_connection *conn, int error);

/* ========== Statistics and Monitoring ========== */

struct socks_statistics {
	atomic64_t socks4_connections;
	atomic64_t socks5_connections;
	atomic64_t handshakes_success;
	atomic64_t handshakes_failed;
	atomic64_t auth_attempts;
	atomic64_t auth_failures;
	atomic64_t udp_associations;
	atomic64_t dns_resolutions;
	atomic64_t protocol_errors;
};

extern struct socks_statistics socks_stats;

void socks_stats_init(void);
void socks_stats_print(void);

/* ========== SOCKS Module Initialization ========== */

int mutex_socks_init(void);
void mutex_socks_exit(void);

#endif /* _MUTEX_SOCKS_H */
