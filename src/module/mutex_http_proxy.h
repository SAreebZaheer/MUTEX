/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * HTTP/HTTPS Proxy Support (CONNECT Method)
 *
 * This file defines structures and functions for HTTP proxy handling
 * in kernel space, specifically for HTTP CONNECT tunneling.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#ifndef _MUTEX_HTTP_PROXY_H
#define _MUTEX_HTTP_PROXY_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>

/* ========== HTTP Protocol Definitions ========== */

#define HTTP_VERSION_1_0        "HTTP/1.0"
#define HTTP_VERSION_1_1        "HTTP/1.1"

#define HTTP_METHOD_CONNECT     "CONNECT"
#define HTTP_METHOD_GET         "GET"
#define HTTP_METHOD_POST        "POST"

/* HTTP Status Codes */
#define HTTP_STATUS_OK                  200
#define HTTP_STATUS_CREATED             201
#define HTTP_STATUS_ACCEPTED            202
#define HTTP_STATUS_NO_CONTENT          204

#define HTTP_STATUS_MOVED_PERMANENTLY   301
#define HTTP_STATUS_FOUND               302
#define HTTP_STATUS_SEE_OTHER           303
#define HTTP_STATUS_NOT_MODIFIED        304
#define HTTP_STATUS_TEMPORARY_REDIRECT  307
#define HTTP_STATUS_PERMANENT_REDIRECT  308

#define HTTP_STATUS_BAD_REQUEST         400
#define HTTP_STATUS_UNAUTHORIZED        401
#define HTTP_STATUS_FORBIDDEN           403
#define HTTP_STATUS_NOT_FOUND           404
#define HTTP_STATUS_METHOD_NOT_ALLOWED  405
#define HTTP_STATUS_PROXY_AUTH_REQUIRED 407
#define HTTP_STATUS_REQUEST_TIMEOUT     408
#define HTTP_STATUS_CONFLICT            409
#define HTTP_STATUS_GONE                410

#define HTTP_STATUS_INTERNAL_ERROR      500
#define HTTP_STATUS_NOT_IMPLEMENTED     501
#define HTTP_STATUS_BAD_GATEWAY         502
#define HTTP_STATUS_SERVICE_UNAVAILABLE 503
#define HTTP_STATUS_GATEWAY_TIMEOUT     504
#define HTTP_STATUS_VERSION_NOT_SUPP    505

/* HTTP Header Names */
#define HTTP_HDR_HOST                   "Host"
#define HTTP_HDR_USER_AGENT             "User-Agent"
#define HTTP_HDR_PROXY_AUTH             "Proxy-Authorization"
#define HTTP_HDR_PROXY_AUTHENTICATE     "Proxy-Authenticate"
#define HTTP_HDR_CONNECTION             "Connection"
#define HTTP_HDR_CONTENT_LENGTH         "Content-Length"
#define HTTP_HDR_CONTENT_TYPE           "Content-Type"
#define HTTP_HDR_TRANSFER_ENCODING      "Transfer-Encoding"

/* HTTP Header Values */
#define HTTP_VAL_KEEP_ALIVE             "keep-alive"
#define HTTP_VAL_CLOSE                  "close"

/* Authentication Schemes */
#define HTTP_AUTH_BASIC                 "Basic"
#define HTTP_AUTH_DIGEST                "Digest"
#define HTTP_AUTH_BEARER                "Bearer"

/* Buffer Sizes */
#define HTTP_MAX_REQUEST_LINE           2048
#define HTTP_MAX_HEADER_LINE            2048
#define HTTP_MAX_HEADERS                32
#define HTTP_MAX_URI_LENGTH             2048
#define HTTP_MAX_AUTH_LENGTH            512

/* ========== HTTP State Machine ========== */

enum http_state {
	HTTP_STATE_INIT,                /* Initial state */
	HTTP_STATE_REQUEST_SENT,        /* CONNECT request sent */
	HTTP_STATE_RESPONSE_HEADERS,    /* Reading response headers */
	HTTP_STATE_TUNNEL_ESTABLISHED,  /* Tunnel established (200 OK) */
	HTTP_STATE_AUTH_REQUIRED,       /* Authentication required (407) */
	HTTP_STATE_ERROR,               /* Error state */
	HTTP_STATE_CLOSED               /* Connection closed */
};

enum http_auth_type {
	HTTP_AUTH_NONE,
	HTTP_AUTH_TYPE_BASIC,
	HTTP_AUTH_TYPE_DIGEST,
	HTTP_AUTH_TYPE_BEARER
};

/* ========== HTTP Request/Response Structures ========== */

struct http_request_line {
	char method[16];                /* HTTP method (CONNECT) */
	char uri[HTTP_MAX_URI_LENGTH];  /* Request URI (host:port) */
	char version[16];               /* HTTP version */
};

struct http_status_line {
	char version[16];               /* HTTP version */
	int status_code;                /* Status code (200, 407, etc.) */
	char reason_phrase[128];        /* Reason phrase */
};

struct http_header {
	char name[128];                 /* Header name */
	char value[HTTP_MAX_HEADER_LINE]; /* Header value */
};

struct http_message {
	union {
		struct http_request_line request;
		struct http_status_line status;
	} start_line;

	struct http_header headers[HTTP_MAX_HEADERS];
	int header_count;

	/* Body (usually not used for CONNECT) */
	void *body;
	size_t body_length;

	bool is_request;                /* true if request, false if response */
};

/* ========== HTTP Authentication ========== */

struct http_auth_basic {
	char username[256];
	char password[256];
	char encoded[512];              /* Base64 encoded credentials */
};

struct http_auth_digest {
	char username[256];
	char password[256];
	char realm[256];
	char nonce[256];
	char opaque[256];
	char algorithm[32];             /* MD5, SHA-256, etc. */
	char qop[32];                   /* Quality of protection */
	char nc[16];                    /* Nonce count */
	char cnonce[64];                /* Client nonce */
	char uri[HTTP_MAX_URI_LENGTH];
	char response[128];             /* Digest response hash */
};

struct http_auth_info {
	enum http_auth_type type;
	bool credentials_set;

	union {
		struct http_auth_basic basic;
		struct http_auth_digest digest;
		struct {
			char token[512];
		} bearer;
	} creds;
};

/* ========== HTTP Proxy Connection Context ========== */

struct http_proxy_connection {
	enum http_state state;          /* Current state */

	/* Target address (host:port from CONNECT) */
	char target_host[256];
	__u16 target_port;

	/* Authentication */
	struct http_auth_info auth;
	bool auth_challenged;           /* Received 407 */
	int auth_attempts;              /* Number of auth attempts */

	/* Connection settings */
	bool keep_alive;                /* Connection: keep-alive */
	unsigned long timeout;          /* Connection timeout */

	/* Buffer for building/parsing messages */
	void *buffer;
	size_t buffer_len;
	size_t buffer_used;

	/* Parsing state */
	char *parse_ptr;                /* Current parse position */
	size_t parse_remaining;         /* Remaining bytes to parse */

	/* Last response */
	int last_status_code;
	char last_error[256];

	/* Timestamps */
	unsigned long created;          /* Connection creation time */
	unsigned long last_activity;    /* Last activity timestamp */

	/* Statistics */
	unsigned long requests_sent;
	unsigned long responses_received;
	unsigned long auth_challenges;
	unsigned long tunnels_established;

	/* Reference to proxy configuration */
	void *proxy_config;
};

/* ========== HTTP Protocol Functions ========== */

/* Connection Management */
struct http_proxy_connection *http_proxy_connection_alloc(void);
void http_proxy_connection_free(struct http_proxy_connection *conn);

/* Request Building */
int http_build_connect_request(struct http_proxy_connection *conn,
				const char *host, __u16 port);
int http_build_auth_header(struct http_proxy_connection *conn,
			    char *buffer, size_t buffer_len);

/* Response Parsing */
int http_parse_response(struct http_proxy_connection *conn,
			const void *data, size_t len);
int http_parse_status_line(const char *line,
			    struct http_status_line *status);
int http_parse_header_line(const char *line,
			    struct http_header *header);

/* Header Manipulation */
const char *http_get_header(const struct http_message *msg,
			    const char *name);
int http_add_header(struct http_message *msg,
		    const char *name, const char *value);

/* Authentication */
int http_auth_set_credentials(struct http_proxy_connection *conn,
			       enum http_auth_type type,
			       const char *username,
			       const char *password);
int http_auth_process_challenge(struct http_proxy_connection *conn,
				 const char *challenge);
int http_auth_build_basic(const char *username, const char *password,
			   char *output, size_t output_len);
int http_auth_build_digest(struct http_auth_digest *digest,
			    const char *method, const char *uri,
			    char *output, size_t output_len);

/* Utility Functions */
const char *http_status_reason(int status_code);
const char *http_state_name(enum http_state state);
bool http_status_is_success(int status_code);
bool http_status_is_redirect(int status_code);
bool http_status_is_error(int status_code);

/* String Utilities */
char *http_trim_whitespace(char *str);
int http_strcasecmp(const char *s1, const char *s2);
char *http_strncpy_safe(char *dest, const char *src, size_t n);

/* Base64 Encoding (for Basic auth) */
int base64_encode(const char *input, size_t input_len,
		  char *output, size_t output_len);
int base64_decode(const char *input, size_t input_len,
		  char *output, size_t output_len);

/* MD5 Hash (for Digest auth) */
int md5_hash(const char *input, size_t input_len,
	     char *output, size_t output_len);
int md5_hash_hex(const char *input, size_t input_len,
		 char *output, size_t output_len);

/* ========== HTTP Integration with Connection Tracking ========== */

/* Forward declaration from mutex_conn_track.h */
struct mutex_connection;

/* Attach HTTP proxy context to a tracked connection */
int mutex_conn_attach_http_proxy(struct mutex_connection *conn,
				  struct http_proxy_connection *http);

/* Get HTTP proxy context from a tracked connection */
struct http_proxy_connection *mutex_conn_get_http_proxy(
	struct mutex_connection *conn);

/* Process HTTP CONNECT handshake */
int mutex_http_proxy_process_connect(struct mutex_connection *conn,
				      struct sk_buff *skb);

/* Establish HTTP proxy tunnel */
int mutex_http_proxy_establish_tunnel(struct mutex_connection *conn);

/* Handle HTTP proxy errors */
void mutex_http_proxy_handle_error(struct mutex_connection *conn, int error);

/* ========== Statistics and Monitoring ========== */

struct http_proxy_statistics {
	atomic64_t connect_requests;
	atomic64_t tunnels_established;
	atomic64_t auth_basic_used;
	atomic64_t auth_digest_used;
	atomic64_t status_2xx;          /* Success responses */
	atomic64_t status_3xx;          /* Redirect responses */
	atomic64_t status_4xx;          /* Client error responses */
	atomic64_t status_5xx;          /* Server error responses */
	atomic64_t status_407;          /* Proxy auth required */
	atomic64_t auth_failures;
	atomic64_t parse_errors;
	atomic64_t connection_errors;
};

extern struct http_proxy_statistics http_proxy_stats;

void http_proxy_stats_init(void);
void http_proxy_stats_print(void);

/* ========== HTTP Proxy Module Initialization ========== */

int mutex_http_proxy_init(void);
void mutex_http_proxy_exit(void);

#endif /* _MUTEX_HTTP_PROXY_H */
