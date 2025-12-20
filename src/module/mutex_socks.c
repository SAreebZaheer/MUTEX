// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * SOCKS Protocol Implementation (SOCKS4/SOCKS5)
 *
 * This file implements SOCKS protocol handling in kernel space for
 * transparent proxy support.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <net/sock.h>

#include "mutex_socks.h"

/* ========== Module Parameters ========== */

static unsigned int socks_timeout = 30; /* Default timeout in seconds */
module_param(socks_timeout, uint, 0644);
MODULE_PARM_DESC(socks_timeout, "SOCKS connection timeout in seconds");

static bool socks_debug = false;
module_param(socks_debug, bool, 0644);
MODULE_PARM_DESC(socks_debug, "Enable SOCKS protocol debug logging");

/* ========== Global Statistics ========== */

struct socks_statistics socks_stats;

/* ========== Helper Macros ========== */

#define SOCKS_DEBUG(fmt, ...) \
	do { \
		if (socks_debug) \
			pr_debug("MUTEX SOCKS: " fmt, ##__VA_ARGS__); \
	} while (0)

#define SOCKS_INFO(fmt, ...) \
	pr_info("MUTEX SOCKS: " fmt, ##__VA_ARGS__)

#define SOCKS_WARN(fmt, ...) \
	pr_warn("MUTEX SOCKS: " fmt, ##__VA_ARGS__)

#define SOCKS_ERR(fmt, ...) \
	pr_err("MUTEX SOCKS: " fmt, ##__VA_ARGS__)

/* ========== SOCKS Connection Management ========== */

/**
 * socks_connection_alloc - Allocate and initialize SOCKS connection context
 * @version: SOCKS protocol version to use
 *
 * Returns: Pointer to allocated connection context, or NULL on failure
 */
struct socks_connection *socks_connection_alloc(enum socks_version version)
{
	struct socks_connection *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		SOCKS_ERR("Failed to allocate SOCKS connection\n");
		return NULL;
	}

	conn->version = version;
	conn->state = SOCKS_STATE_INIT;
	conn->created = jiffies;
	conn->last_activity = jiffies;

	/* Allocate working buffer */
	conn->buffer_len = 4096; /* Should be enough for most operations */
	conn->buffer = kmalloc(conn->buffer_len, GFP_KERNEL);
	if (!conn->buffer) {
		SOCKS_ERR("Failed to allocate SOCKS buffer\n");
		kfree(conn);
		return NULL;
	}

	SOCKS_DEBUG("Allocated SOCKS%s connection context\n",
		    socks_version_name(version));

	return conn;
}

/**
 * socks_connection_free - Free SOCKS connection context
 * @conn: SOCKS connection to free
 */
void socks_connection_free(struct socks_connection *conn)
{
	if (!conn)
		return;

	/* Close UDP socket if open */
	if (conn->udp_sock) {
		sock_release(conn->udp_sock);
		conn->udp_sock = NULL;
	}

	/* Free buffer */
	if (conn->buffer) {
		kfree(conn->buffer);
		conn->buffer = NULL;
	}

	/* Clear sensitive data */
	memset(&conn->auth, 0, sizeof(conn->auth));

	kfree(conn);

	SOCKS_DEBUG("Freed SOCKS connection context\n");
}

/* ========== SOCKS4 Protocol Implementation ========== */

/**
 * socks4_build_connect_request - Build SOCKS4 CONNECT request
 * @conn: SOCKS connection context
 * @dest: Destination address
 * @userid: User ID string (can be NULL)
 *
 * Returns: Length of request on success, negative error code on failure
 */
int socks4_build_connect_request(struct socks_connection *conn,
				 const struct socks_addr *dest,
				 const char *userid)
{
	struct socks4_request *req;
	size_t userid_len;
	size_t total_len;
	char *ptr;

	if (!conn || !dest)
		return -EINVAL;

	if (conn->state != SOCKS_STATE_INIT) {
		SOCKS_ERR("Invalid state for SOCKS4 request: %s\n",
			  socks_state_name(conn->state));
		return -EINVAL;
	}

	/* Check address type */
	if (dest->address_type == SOCKS5_ATYP_IPV4) {
		/* Standard SOCKS4 */
		conn->version = SOCKS_VERSION_4;
	} else if (dest->address_type == SOCKS5_ATYP_DOMAIN) {
		/* SOCKS4a with domain name */
		conn->version = SOCKS_VERSION_4A;
	} else {
		SOCKS_ERR("SOCKS4 does not support IPv6\n");
		return -EAFNOSUPPORT;
	}

	userid_len = userid ? strlen(userid) : 0;
	total_len = sizeof(struct socks4_request) + userid_len + 1;

	if (conn->version == SOCKS_VERSION_4A &&
	    dest->address_type == SOCKS5_ATYP_DOMAIN) {
		total_len += dest->addr.domain.len + 1;
	}

	if (total_len > conn->buffer_len)
		return -ENOMEM;

	/* Build request */
	req = (struct socks4_request *)conn->buffer;
	req->version = SOCKS4_VERSION;
	req->command = SOCKS4_CMD_CONNECT;
	req->dest_port = dest->port;

	if (conn->version == SOCKS_VERSION_4A &&
	    dest->address_type == SOCKS5_ATYP_DOMAIN) {
		/* SOCKS4a: use magic IP and append domain name */
		req->dest_ip = htonl(SOCKS4A_MAGIC_IP);
	} else {
		req->dest_ip = dest->addr.ipv4;
	}

	/* Append user ID */
	ptr = (char *)(req + 1);
	if (userid_len > 0) {
		memcpy(ptr, userid, userid_len);
		ptr += userid_len;
	}
	*ptr++ = '\0'; /* Null terminator */

	/* Append domain name for SOCKS4a */
	if (conn->version == SOCKS_VERSION_4A &&
	    dest->address_type == SOCKS5_ATYP_DOMAIN) {
		memcpy(ptr, dest->addr.domain.name, dest->addr.domain.len);
		ptr += dest->addr.domain.len;
		*ptr++ = '\0'; /* Null terminator */
	}

	conn->buffer_used = ptr - (char *)conn->buffer;
	conn->dest = *dest;
	conn->command = SOCKS4_CMD_CONNECT;
	conn->state = SOCKS_STATE_REQUEST_SENT;

	atomic64_inc(&socks_stats.socks4_connections);

	SOCKS_DEBUG("Built SOCKS4%s CONNECT request (%zu bytes)\n",
		    conn->version == SOCKS_VERSION_4A ? "a" : "",
		    conn->buffer_used);

	return conn->buffer_used;
}

/**
 * socks4_parse_response - Parse SOCKS4 response
 * @conn: SOCKS connection context
 * @data: Response data
 * @len: Length of response data
 *
 * Returns: 0 on success, negative error code on failure
 */
int socks4_parse_response(struct socks_connection *conn,
			  const void *data, size_t len)
{
	const struct socks4_response *resp;

	if (!conn || !data)
		return -EINVAL;

	if (len < sizeof(struct socks4_response)) {
		SOCKS_DEBUG("SOCKS4 response too short: %zu bytes\n", len);
		return -EINVAL;
	}

	resp = (const struct socks4_response *)data;

	/* First byte should be 0 */
	if (resp->null_byte != 0) {
		SOCKS_WARN("Invalid SOCKS4 response (null_byte=%u)\n",
			   resp->null_byte);
		return -EPROTO;
	}

	conn->reply_code = resp->status;
	conn->bound.address_type = SOCKS5_ATYP_IPV4;
	conn->bound.addr.ipv4 = resp->dest_ip;
	conn->bound.port = resp->dest_port;

	if (resp->status == SOCKS4_REP_GRANTED) {
		conn->state = SOCKS_STATE_CONNECTED;
		atomic64_inc(&socks_stats.handshakes_success);
		SOCKS_INFO("SOCKS4 connection established\n");
		return 0;
	}

	/* Handle errors */
	conn->state = SOCKS_STATE_ERROR;
	atomic64_inc(&socks_stats.handshakes_failed);

	switch (resp->status) {
	case SOCKS4_REP_REJECTED:
		SOCKS_ERR("SOCKS4 request rejected or failed\n");
		conn->error = -ECONNREFUSED;
		break;
	case SOCKS4_REP_NO_IDENTD:
		SOCKS_ERR("SOCKS4 identd not reachable\n");
		conn->error = -ENETUNREACH;
		break;
	case SOCKS4_REP_BAD_USERID:
		SOCKS_ERR("SOCKS4 user ID does not match\n");
		conn->error = -EACCES;
		break;
	default:
		SOCKS_ERR("Unknown SOCKS4 error code: %u\n", resp->status);
		conn->error = -EPROTO;
		break;
	}

	return conn->error;
}

/* ========== SOCKS5 Method Selection ========== */

/**
 * socks5_build_method_request - Build SOCKS5 method selection request
 * @conn: SOCKS connection context
 * @methods: Array of authentication methods
 * @nmethods: Number of methods
 *
 * Returns: Length of request on success, negative error code on failure
 */
int socks5_build_method_request(struct socks_connection *conn,
				const __u8 *methods, __u8 nmethods)
{
	struct socks5_method_request *req;
	size_t total_len;

	if (!conn || !methods || nmethods == 0)
		return -EINVAL;

	if (conn->state != SOCKS_STATE_INIT) {
		SOCKS_ERR("Invalid state for method request: %s\n",
			  socks_state_name(conn->state));
		return -EINVAL;
	}

	total_len = sizeof(struct socks5_method_request) - 1 + nmethods;
	if (total_len > conn->buffer_len)
		return -ENOMEM;

	req = (struct socks5_method_request *)conn->buffer;
	req->version = SOCKS5_VERSION;
	req->nmethods = nmethods;
	memcpy(req->methods, methods, nmethods);

	conn->buffer_used = total_len;
	conn->state = SOCKS_STATE_METHOD_SENT;

	SOCKS_DEBUG("Built SOCKS5 method request (%u methods)\n", nmethods);

	return total_len;
}

/**
 * socks5_parse_method_response - Parse SOCKS5 method selection response
 * @conn: SOCKS connection context
 * @data: Response data
 * @len: Length of response data
 *
 * Returns: 0 on success, negative error code on failure
 */
int socks5_parse_method_response(struct socks_connection *conn,
				 const void *data, size_t len)
{
	const struct socks5_method_response *resp;

	if (!conn || !data)
		return -EINVAL;

	if (len < sizeof(struct socks5_method_response)) {
		SOCKS_DEBUG("SOCKS5 method response too short: %zu bytes\n",
			    len);
		return -EINVAL;
	}

	resp = (const struct socks5_method_response *)data;

	if (resp->version != SOCKS5_VERSION) {
		SOCKS_ERR("Invalid SOCKS version in response: %u\n",
			  resp->version);
		return -EPROTO;
	}

	if (resp->method == SOCKS5_AUTH_NO_ACCEPT) {
		SOCKS_ERR("No acceptable authentication method\n");
		conn->state = SOCKS_STATE_ERROR;
		conn->error = -EACCES;
		return -EACCES;
	}

	conn->auth.method = resp->method;
	conn->state = SOCKS_STATE_METHOD_RECEIVED;

	SOCKS_DEBUG("SOCKS5 selected method: %u\n", resp->method);

	return 0;
}

/* ========== SOCKS5 Authentication ========== */

/**
 * socks5_build_auth_request - Build username/password authentication request
 * @conn: SOCKS connection context
 * @username: Username string
 * @password: Password string
 *
 * Returns: Length of request on success, negative error code on failure
 */
int socks5_build_auth_request(struct socks_connection *conn,
			      const char *username, const char *password)
{
	struct socks5_userpass_request *req;
	size_t username_len, password_len, total_len;
	char *ptr;

	if (!conn || !username || !password)
		return -EINVAL;

	if (conn->state != SOCKS_STATE_METHOD_RECEIVED) {
		SOCKS_ERR("Invalid state for auth request: %s\n",
			  socks_state_name(conn->state));
		return -EINVAL;
	}

	username_len = strlen(username);
	password_len = strlen(password);

	if (username_len > 255 || password_len > 255) {
		SOCKS_ERR("Username or password too long\n");
		return -EINVAL;
	}

	total_len = sizeof(struct socks5_userpass_request) +
		    username_len + 1 + password_len;

	if (total_len > conn->buffer_len)
		return -ENOMEM;

	req = (struct socks5_userpass_request *)conn->buffer;
	req->version = 1; /* Username/password auth version */
	req->username_len = username_len;

	ptr = (char *)(req + 1);
	memcpy(ptr, username, username_len);
	ptr += username_len;

	*ptr++ = password_len;
	memcpy(ptr, password, password_len);
	ptr += password_len;

	/* Store credentials */
	strncpy(conn->auth.username, username, sizeof(conn->auth.username) - 1);
	strncpy(conn->auth.password, password, sizeof(conn->auth.password) - 1);
	conn->auth.username_len = username_len;
	conn->auth.password_len = password_len;

	conn->buffer_used = ptr - (char *)conn->buffer;
	conn->state = SOCKS_STATE_AUTH_SENT;

	atomic64_inc(&socks_stats.auth_attempts);

	SOCKS_DEBUG("Built SOCKS5 auth request (username: %s)\n", username);

	return conn->buffer_used;
}

/**
 * socks5_parse_auth_response - Parse username/password auth response
 * @conn: SOCKS connection context
 * @data: Response data
 * @len: Length of response data
 *
 * Returns: 0 on success, negative error code on failure
 */
int socks5_parse_auth_response(struct socks_connection *conn,
			       const void *data, size_t len)
{
	const struct socks5_userpass_response *resp;

	if (!conn || !data)
		return -EINVAL;

	if (len < sizeof(struct socks5_userpass_response)) {
		SOCKS_DEBUG("SOCKS5 auth response too short: %zu bytes\n", len);
		return -EINVAL;
	}

	resp = (const struct socks5_userpass_response *)data;

	if (resp->version != 1) {
		SOCKS_ERR("Invalid auth version in response: %u\n",
			  resp->version);
		return -EPROTO;
	}

	if (resp->status != 0) {
		SOCKS_ERR("SOCKS5 authentication failed\n");
		conn->state = SOCKS_STATE_ERROR;
		conn->error = -EACCES;
		atomic64_inc(&socks_stats.auth_failures);
		return -EACCES;
	}

	conn->state = SOCKS_STATE_AUTH_RECEIVED;

	SOCKS_DEBUG("SOCKS5 authentication successful\n");

	return 0;
}

/* ========== SOCKS5 Connection Request ========== */

/**
 * socks5_build_request - Build generic SOCKS5 request
 * @conn: SOCKS connection context
 * @command: SOCKS5 command
 * @dest: Destination address
 *
 * Returns: Length of request on success, negative error code on failure
 */
static int socks5_build_request(struct socks_connection *conn,
				__u8 command,
				const struct socks_addr *dest)
{
	struct socks5_request_header *req;
	char *ptr;
	size_t addr_len = 0;

	if (!conn || !dest)
		return -EINVAL;

	if (conn->state != SOCKS_STATE_METHOD_RECEIVED &&
	    conn->state != SOCKS_STATE_AUTH_RECEIVED) {
		SOCKS_ERR("Invalid state for request: %s\n",
			  socks_state_name(conn->state));
		return -EINVAL;
	}

	req = (struct socks5_request_header *)conn->buffer;
	req->version = SOCKS5_VERSION;
	req->command = command;
	req->reserved = 0;
	req->address_type = dest->address_type;

	ptr = (char *)(req + 1);

	/* Add address */
	switch (dest->address_type) {
	case SOCKS5_ATYP_IPV4:
		memcpy(ptr, &dest->addr.ipv4, 4);
		ptr += 4;
		addr_len = 4;
		break;

	case SOCKS5_ATYP_IPV6:
		memcpy(ptr, &dest->addr.ipv6, 16);
		ptr += 16;
		addr_len = 16;
		break;

	case SOCKS5_ATYP_DOMAIN:
		*ptr++ = dest->addr.domain.len;
		memcpy(ptr, dest->addr.domain.name, dest->addr.domain.len);
		ptr += dest->addr.domain.len;
		addr_len = 1 + dest->addr.domain.len;
		break;

	default:
		SOCKS_ERR("Invalid address type: %u\n", dest->address_type);
		return -EINVAL;
	}

	/* Add port */
	memcpy(ptr, &dest->port, 2);
	ptr += 2;

	conn->buffer_used = ptr - (char *)conn->buffer;
	conn->dest = *dest;
	conn->command = command;
	conn->state = SOCKS_STATE_REQUEST_SENT;

	SOCKS_DEBUG("Built SOCKS5 request (cmd=%u, atyp=%u, len=%zu)\n",
		    command, dest->address_type, conn->buffer_used);

	return conn->buffer_used;
}

/**
 * socks5_build_connect_request - Build SOCKS5 CONNECT request
 */
int socks5_build_connect_request(struct socks_connection *conn,
				 const struct socks_addr *dest)
{
	int ret;

	ret = socks5_build_request(conn, SOCKS5_CMD_CONNECT, dest);
	if (ret > 0)
		atomic64_inc(&socks_stats.socks5_connections);

	return ret;
}

/**
 * socks5_build_bind_request - Build SOCKS5 BIND request
 */
int socks5_build_bind_request(struct socks_connection *conn,
			      const struct socks_addr *dest)
{
	return socks5_build_request(conn, SOCKS5_CMD_BIND, dest);
}

/**
 * socks5_build_udp_assoc_request - Build SOCKS5 UDP ASSOCIATE request
 */
int socks5_build_udp_assoc_request(struct socks_connection *conn,
				   const struct socks_addr *client_addr)
{
	int ret;

	ret = socks5_build_request(conn, SOCKS5_CMD_UDP_ASSOC, client_addr);
	if (ret > 0)
		atomic64_inc(&socks_stats.udp_associations);

	return ret;
}

/**
 * socks5_parse_response - Parse SOCKS5 response
 * @conn: SOCKS connection context
 * @data: Response data
 * @len: Length of response data
 *
 * Returns: 0 on success, negative error code on failure
 */
int socks5_parse_response(struct socks_connection *conn,
			  const void *data, size_t len)
{
	const struct socks5_response_header *resp;
	const char *ptr;
	size_t min_len = sizeof(struct socks5_response_header);

	if (!conn || !data)
		return -EINVAL;

	if (len < min_len) {
		SOCKS_DEBUG("SOCKS5 response too short: %zu bytes\n", len);
		return -EINVAL;
	}

	resp = (const struct socks5_response_header *)data;

	if (resp->version != SOCKS5_VERSION) {
		SOCKS_ERR("Invalid SOCKS version in response: %u\n",
			  resp->version);
		return -EPROTO;
	}

	conn->reply_code = resp->reply;
	ptr = (const char *)(resp + 1);

	/* Parse bound address */
	conn->bound.address_type = resp->address_type;

	switch (resp->address_type) {
	case SOCKS5_ATYP_IPV4:
		if (len < min_len + 4 + 2)
			return -EINVAL;
		memcpy(&conn->bound.addr.ipv4, ptr, 4);
		ptr += 4;
		break;

	case SOCKS5_ATYP_IPV6:
		if (len < min_len + 16 + 2)
			return -EINVAL;
		memcpy(&conn->bound.addr.ipv6, ptr, 16);
		ptr += 16;
		break;

	case SOCKS5_ATYP_DOMAIN:
		conn->bound.addr.domain.len = *ptr++;
		if (len < min_len + 1 + conn->bound.addr.domain.len + 2)
			return -EINVAL;
		memcpy(conn->bound.addr.domain.name, ptr,
		       conn->bound.addr.domain.len);
		ptr += conn->bound.addr.domain.len;
		break;

	default:
		SOCKS_ERR("Invalid address type in response: %u\n",
			  resp->address_type);
		return -EPROTO;
	}

	/* Parse port */
	memcpy(&conn->bound.port, ptr, 2);

	/* Check reply code */
	if (resp->reply != SOCKS5_REP_SUCCESS) {
		conn->state = SOCKS_STATE_ERROR;
		atomic64_inc(&socks_stats.handshakes_failed);

		SOCKS_ERR("SOCKS5 request failed: %s\n",
			  socks5_reply_name(resp->reply));

		switch (resp->reply) {
		case SOCKS5_REP_FAILURE:
			conn->error = -ECONNREFUSED;
			break;
		case SOCKS5_REP_NOT_ALLOWED:
			conn->error = -EACCES;
			break;
		case SOCKS5_REP_NET_UNREACH:
		case SOCKS5_REP_HOST_UNREACH:
			conn->error = -ENETUNREACH;
			break;
		case SOCKS5_REP_REFUSED:
			conn->error = -ECONNREFUSED;
			break;
		case SOCKS5_REP_TTL_EXPIRED:
			conn->error = -ETIMEDOUT;
			break;
		case SOCKS5_REP_CMD_UNSUP:
		case SOCKS5_REP_ATYP_UNSUP:
			conn->error = -EOPNOTSUPP;
			break;
		default:
			conn->error = -EPROTO;
			break;
		}

		return conn->error;
	}

	/* Success */
	if (conn->command == SOCKS5_CMD_UDP_ASSOC) {
		conn->state = SOCKS_STATE_UDP_READY;
		conn->udp_relay = conn->bound;
		SOCKS_INFO("SOCKS5 UDP association established\n");
	} else {
		conn->state = SOCKS_STATE_CONNECTED;
		SOCKS_INFO("SOCKS5 connection established\n");
	}

	atomic64_inc(&socks_stats.handshakes_success);

	return 0;
}

/* ========== SOCKS5 UDP Support ========== */

/**
 * socks5_build_udp_header - Build SOCKS5 UDP request header
 * @conn: SOCKS connection context
 * @dest: Destination address
 * @buffer: Output buffer
 * @buffer_len: Size of output buffer
 *
 * Returns: Length of header on success, negative error code on failure
 */
int socks5_build_udp_header(struct socks_connection *conn,
			    const struct socks_addr *dest,
			    void *buffer, size_t buffer_len)
{
	struct socks5_udp_header *hdr;
	char *ptr;
	size_t header_len;

	if (!conn || !dest || !buffer)
		return -EINVAL;

	if (conn->state != SOCKS_STATE_UDP_READY) {
		SOCKS_ERR("UDP association not ready\n");
		return -EINVAL;
	}

	hdr = (struct socks5_udp_header *)buffer;
	hdr->reserved = 0;
	hdr->fragment = 0; /* We don't support fragmentation yet */
	hdr->address_type = dest->address_type;

	ptr = (char *)(hdr + 1);

	/* Add address */
	switch (dest->address_type) {
	case SOCKS5_ATYP_IPV4:
		if (buffer_len < sizeof(*hdr) + 4 + 2)
			return -ENOMEM;
		memcpy(ptr, &dest->addr.ipv4, 4);
		ptr += 4;
		break;

	case SOCKS5_ATYP_IPV6:
		if (buffer_len < sizeof(*hdr) + 16 + 2)
			return -ENOMEM;
		memcpy(ptr, &dest->addr.ipv6, 16);
		ptr += 16;
		break;

	case SOCKS5_ATYP_DOMAIN:
		if (buffer_len < sizeof(*hdr) + 1 + dest->addr.domain.len + 2)
			return -ENOMEM;
		*ptr++ = dest->addr.domain.len;
		memcpy(ptr, dest->addr.domain.name, dest->addr.domain.len);
		ptr += dest->addr.domain.len;
		break;

	default:
		return -EINVAL;
	}

	/* Add port */
	memcpy(ptr, &dest->port, 2);
	ptr += 2;

	header_len = ptr - (char *)buffer;

	SOCKS_DEBUG("Built SOCKS5 UDP header (%zu bytes)\n", header_len);

	return header_len;
}

/**
 * socks5_parse_udp_header - Parse SOCKS5 UDP request header
 * @conn: SOCKS connection context
 * @data: Header data
 * @len: Length of header data
 * @dest: Output destination address
 *
 * Returns: Length of header on success, negative error code on failure
 */
int socks5_parse_udp_header(struct socks_connection *conn,
			    const void *data, size_t len,
			    struct socks_addr *dest)
{
	const struct socks5_udp_header *hdr;
	const char *ptr;
	size_t header_len;

	if (!conn || !data || !dest)
		return -EINVAL;

	if (len < sizeof(struct socks5_udp_header))
		return -EINVAL;

	hdr = (const struct socks5_udp_header *)data;
	ptr = (const char *)(hdr + 1);

	dest->address_type = hdr->address_type;

	/* Parse address */
	switch (hdr->address_type) {
	case SOCKS5_ATYP_IPV4:
		if (len < sizeof(*hdr) + 4 + 2)
			return -EINVAL;
		memcpy(&dest->addr.ipv4, ptr, 4);
		ptr += 4;
		break;

	case SOCKS5_ATYP_IPV6:
		if (len < sizeof(*hdr) + 16 + 2)
			return -EINVAL;
		memcpy(&dest->addr.ipv6, ptr, 16);
		ptr += 16;
		break;

	case SOCKS5_ATYP_DOMAIN:
		dest->addr.domain.len = *ptr++;
		if (len < sizeof(*hdr) + 1 + dest->addr.domain.len + 2)
			return -EINVAL;
		memcpy(dest->addr.domain.name, ptr, dest->addr.domain.len);
		ptr += dest->addr.domain.len;
		break;

	default:
		SOCKS_ERR("Invalid address type in UDP header: %u\n",
			  hdr->address_type);
		return -EPROTO;
	}

	/* Parse port */
	memcpy(&dest->port, ptr, 2);
	ptr += 2;

	header_len = ptr - (const char *)data;

	SOCKS_DEBUG("Parsed SOCKS5 UDP header (%zu bytes)\n", header_len);

	return header_len;
}

/* ========== Helper Functions ========== */

/**
 * socks_addr_from_sockaddr - Convert sockaddr to socks_addr
 */
int socks_addr_from_sockaddr(struct socks_addr *socks_addr,
			     const struct sockaddr *sa)
{
	if (!socks_addr || !sa)
		return -EINVAL;

	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)sa;
		socks_addr->address_type = SOCKS5_ATYP_IPV4;
		socks_addr->addr.ipv4 = sin->sin_addr.s_addr;
		socks_addr->port = sin->sin_port;
		break;
	}

	case AF_INET6: {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)sa;
		socks_addr->address_type = SOCKS5_ATYP_IPV6;
		memcpy(&socks_addr->addr.ipv6, &sin6->sin6_addr, 16);
		socks_addr->port = sin6->sin6_port;
		break;
	}

	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

/**
 * socks_addr_to_sockaddr - Convert socks_addr to sockaddr
 */
int socks_addr_to_sockaddr(const struct socks_addr *socks_addr,
			   struct sockaddr_storage *ss)
{
	if (!socks_addr || !ss)
		return -EINVAL;

	memset(ss, 0, sizeof(*ss));

	switch (socks_addr->address_type) {
	case SOCKS5_ATYP_IPV4: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = socks_addr->addr.ipv4;
		sin->sin_port = socks_addr->port;
		break;
	}

	case SOCKS5_ATYP_IPV6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &socks_addr->addr.ipv6, 16);
		sin6->sin6_port = socks_addr->port;
		break;
	}

	case SOCKS5_ATYP_DOMAIN:
		/* Domain names need to be resolved first */
		return -EINVAL;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * socks_state_name - Get string name for SOCKS state
 */
const char *socks_state_name(enum socks_state state)
{
	switch (state) {
	case SOCKS_STATE_INIT:
		return "INIT";
	case SOCKS_STATE_METHOD_SENT:
		return "METHOD_SENT";
	case SOCKS_STATE_METHOD_RECEIVED:
		return "METHOD_RECEIVED";
	case SOCKS_STATE_AUTH_SENT:
		return "AUTH_SENT";
	case SOCKS_STATE_AUTH_RECEIVED:
		return "AUTH_RECEIVED";
	case SOCKS_STATE_REQUEST_SENT:
		return "REQUEST_SENT";
	case SOCKS_STATE_REQUEST_RECEIVED:
		return "REQUEST_RECEIVED";
	case SOCKS_STATE_CONNECTED:
		return "CONNECTED";
	case SOCKS_STATE_UDP_READY:
		return "UDP_READY";
	case SOCKS_STATE_ERROR:
		return "ERROR";
	case SOCKS_STATE_CLOSED:
		return "CLOSED";
	default:
		return "UNKNOWN";
	}
}

/**
 * socks_version_name - Get string name for SOCKS version
 */
const char *socks_version_name(enum socks_version version)
{
	switch (version) {
	case SOCKS_VERSION_4:
		return "4";
	case SOCKS_VERSION_4A:
		return "4a";
	case SOCKS_VERSION_5:
		return "5";
	default:
		return "Unknown";
	}
}

/**
 * socks5_reply_name - Get string name for SOCKS5 reply code
 */
const char *socks5_reply_name(__u8 reply)
{
	switch (reply) {
	case SOCKS5_REP_SUCCESS:
		return "Success";
	case SOCKS5_REP_FAILURE:
		return "General failure";
	case SOCKS5_REP_NOT_ALLOWED:
		return "Connection not allowed";
	case SOCKS5_REP_NET_UNREACH:
		return "Network unreachable";
	case SOCKS5_REP_HOST_UNREACH:
		return "Host unreachable";
	case SOCKS5_REP_REFUSED:
		return "Connection refused";
	case SOCKS5_REP_TTL_EXPIRED:
		return "TTL expired";
	case SOCKS5_REP_CMD_UNSUP:
		return "Command not supported";
	case SOCKS5_REP_ATYP_UNSUP:
		return "Address type not supported";
	default:
		return "Unknown error";
	}
}

/**
 * socks4_reply_name - Get string name for SOCKS4 reply code
 */
const char *socks4_reply_name(__u8 reply)
{
	switch (reply) {
	case SOCKS4_REP_GRANTED:
		return "Request granted";
	case SOCKS4_REP_REJECTED:
		return "Request rejected or failed";
	case SOCKS4_REP_NO_IDENTD:
		return "Cannot connect to identd";
	case SOCKS4_REP_BAD_USERID:
		return "User ID mismatch";
	default:
		return "Unknown error";
	}
}

/* ========== State Machine Validation ========== */

/**
 * socks_state_is_valid_transition - Check if state transition is valid
 */
bool socks_state_is_valid_transition(enum socks_state from,
				     enum socks_state to)
{
	/* Allow transition to ERROR and CLOSED from any state */
	if (to == SOCKS_STATE_ERROR || to == SOCKS_STATE_CLOSED)
		return true;

	switch (from) {
	case SOCKS_STATE_INIT:
		return (to == SOCKS_STATE_METHOD_SENT ||
			to == SOCKS_STATE_REQUEST_SENT);

	case SOCKS_STATE_METHOD_SENT:
		return (to == SOCKS_STATE_METHOD_RECEIVED);

	case SOCKS_STATE_METHOD_RECEIVED:
		return (to == SOCKS_STATE_AUTH_SENT ||
			to == SOCKS_STATE_REQUEST_SENT);

	case SOCKS_STATE_AUTH_SENT:
		return (to == SOCKS_STATE_AUTH_RECEIVED);

	case SOCKS_STATE_AUTH_RECEIVED:
		return (to == SOCKS_STATE_REQUEST_SENT);

	case SOCKS_STATE_REQUEST_SENT:
		return (to == SOCKS_STATE_REQUEST_RECEIVED);

	case SOCKS_STATE_REQUEST_RECEIVED:
		return (to == SOCKS_STATE_CONNECTED ||
			to == SOCKS_STATE_UDP_READY);

	case SOCKS_STATE_CONNECTED:
	case SOCKS_STATE_UDP_READY:
		return false; /* Terminal states */

	default:
		return false;
	}
}

/**
 * socks_validate_state - Validate current state matches expected
 */
int socks_validate_state(struct socks_connection *conn,
			enum socks_state expected)
{
	if (!conn)
		return -EINVAL;

	if (conn->state != expected) {
		SOCKS_ERR("Invalid state: expected %s, got %s\n",
			  socks_state_name(expected),
			  socks_state_name(conn->state));
		return -EINVAL;
	}

	return 0;
}

/* ========== Statistics ========== */

/**
 * socks_stats_init - Initialize statistics
 */
void socks_stats_init(void)
{
	atomic64_set(&socks_stats.socks4_connections, 0);
	atomic64_set(&socks_stats.socks5_connections, 0);
	atomic64_set(&socks_stats.handshakes_success, 0);
	atomic64_set(&socks_stats.handshakes_failed, 0);
	atomic64_set(&socks_stats.auth_attempts, 0);
	atomic64_set(&socks_stats.auth_failures, 0);
	atomic64_set(&socks_stats.udp_associations, 0);
	atomic64_set(&socks_stats.dns_resolutions, 0);
	atomic64_set(&socks_stats.protocol_errors, 0);

	SOCKS_INFO("Statistics initialized\n");
}

/**
 * socks_stats_print - Print current statistics
 */
void socks_stats_print(void)
{
	pr_info("MUTEX SOCKS Statistics:\n");
	pr_info("  SOCKS4 connections: %lld\n",
		atomic64_read(&socks_stats.socks4_connections));
	pr_info("  SOCKS5 connections: %lld\n",
		atomic64_read(&socks_stats.socks5_connections));
	pr_info("  Handshakes success: %lld\n",
		atomic64_read(&socks_stats.handshakes_success));
	pr_info("  Handshakes failed: %lld\n",
		atomic64_read(&socks_stats.handshakes_failed));
	pr_info("  Auth attempts: %lld\n",
		atomic64_read(&socks_stats.auth_attempts));
	pr_info("  Auth failures: %lld\n",
		atomic64_read(&socks_stats.auth_failures));
	pr_info("  UDP associations: %lld\n",
		atomic64_read(&socks_stats.udp_associations));
	pr_info("  DNS resolutions: %lld\n",
		atomic64_read(&socks_stats.dns_resolutions));
	pr_info("  Protocol errors: %lld\n",
		atomic64_read(&socks_stats.protocol_errors));
}

/* ========== Module Initialization ========== */

/**
 * mutex_socks_init - Initialize SOCKS protocol module
 */
int mutex_socks_init(void)
{
	SOCKS_INFO("Initializing SOCKS protocol support\n");

	socks_stats_init();

	SOCKS_INFO("SOCKS module initialized (timeout=%u seconds)\n",
		   socks_timeout);

	return 0;
}

/**
 * mutex_socks_exit - Cleanup SOCKS protocol module
 */
void mutex_socks_exit(void)
{
	SOCKS_INFO("Cleaning up SOCKS protocol support\n");

	socks_stats_print();

	SOCKS_INFO("SOCKS module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Development Team");
MODULE_DESCRIPTION("SOCKS Protocol Support for MUTEX");
MODULE_VERSION("1.0");
