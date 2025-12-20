// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * HTTP/HTTPS Proxy Implementation (CONNECT Method)
 *
 * This file implements HTTP proxy handling in kernel space for
 * transparent HTTPS tunneling via the CONNECT method.
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
#include <linux/ctype.h>
#include <crypto/hash.h>
#include <net/sock.h>

#include "mutex_http_proxy.h"

/* ========== Module Parameters ========== */

static unsigned int http_timeout = 30; /* Default timeout in seconds */
module_param(http_timeout, uint, 0644);
MODULE_PARM_DESC(http_timeout, "HTTP proxy connection timeout in seconds");

static bool http_debug = false;
module_param(http_debug, bool, 0644);
MODULE_PARM_DESC(http_debug, "Enable HTTP proxy debug logging");

static unsigned int http_max_auth_attempts = 3;
module_param(http_max_auth_attempts, uint, 0644);
MODULE_PARM_DESC(http_max_auth_attempts, "Maximum authentication attempts");

/* ========== Global Statistics ========== */

struct http_proxy_statistics http_proxy_stats;

/* ========== Helper Macros ========== */

#define HTTP_DEBUG(fmt, ...) \
	do { \
		if (http_debug) \
			pr_debug("MUTEX HTTP: " fmt, ##__VA_ARGS__); \
	} while (0)

#define HTTP_INFO(fmt, ...) \
	pr_info("MUTEX HTTP: " fmt, ##__VA_ARGS__)

#define HTTP_WARN(fmt, ...) \
	pr_warn("MUTEX HTTP: " fmt, ##__VA_ARGS__)

#define HTTP_ERR(fmt, ...) \
	pr_err("MUTEX HTTP: " fmt, ##__VA_ARGS__)

/* ========== Base64 Encoding/Decoding ========== */

static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Encode data to Base64
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer
 * @output_len: Size of output buffer
 *
 * Returns: Length of encoded data on success, negative error code on failure
 */
int base64_encode(const char *input, size_t input_len,
		  char *output, size_t output_len)
{
	size_t i, j;
	size_t encoded_len;

	if (!input || !output)
		return -EINVAL;

	encoded_len = 4 * ((input_len + 2) / 3);
	if (encoded_len >= output_len)
		return -ENOMEM;

	for (i = 0, j = 0; i < input_len;) {
		uint32_t octet_a = i < input_len ? (unsigned char)input[i++] : 0;
		uint32_t octet_b = i < input_len ? (unsigned char)input[i++] : 0;
		uint32_t octet_c = i < input_len ? (unsigned char)input[i++] : 0;
		uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

		output[j++] = base64_table[(triple >> 18) & 0x3F];
		output[j++] = base64_table[(triple >> 12) & 0x3F];
		output[j++] = base64_table[(triple >> 6) & 0x3F];
		output[j++] = base64_table[triple & 0x3F];
	}

	/* Add padding */
	for (i = 0; i < (3 - input_len % 3) % 3; i++)
		output[encoded_len - 1 - i] = '=';

	output[encoded_len] = '\0';

	return encoded_len;
}

/* ========== MD5 Hash Functions ========== */

/**
 * md5_hash_hex - Calculate MD5 hash and return as hex string
 * @input: Input data
 * @input_len: Length of input data
 * @output: Output buffer (must be at least 33 bytes)
 * @output_len: Size of output buffer
 *
 * Returns: 0 on success, negative error code on failure
 */
int md5_hash_hex(const char *input, size_t input_len,
		 char *output, size_t output_len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	unsigned char hash[16];
	int ret;
	int i;

	if (!input || !output || output_len < 33)
		return -EINVAL;

	tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(tfm)) {
		HTTP_ERR("Failed to allocate MD5 transform\n");
		return PTR_ERR(tfm);
	}

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	ret = crypto_shash_update(desc, input, input_len);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, hash);
	if (ret)
		goto out;

	/* Convert to hex string */
	for (i = 0; i < 16; i++)
		sprintf(output + (i * 2), "%02x", hash[i]);
	output[32] = '\0';

out:
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

/* ========== String Utility Functions ========== */

/**
 * http_trim_whitespace - Trim leading and trailing whitespace
 */
char *http_trim_whitespace(char *str)
{
	char *end;

	if (!str)
		return NULL;

	/* Trim leading space */
	while (isspace(*str))
		str++;

	if (*str == 0)
		return str;

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while (end > str && isspace(*end))
		end--;

	end[1] = '\0';

	return str;
}

/**
 * http_strcasecmp - Case-insensitive string comparison
 */
int http_strcasecmp(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return -EINVAL;

	while (*s1 && *s2) {
		int diff = tolower(*s1) - tolower(*s2);
		if (diff != 0)
			return diff;
		s1++;
		s2++;
	}

	return tolower(*s1) - tolower(*s2);
}

/**
 * http_strncpy_safe - Safe string copy with null termination
 */
char *http_strncpy_safe(char *dest, const char *src, size_t n)
{
	if (!dest || !src || n == 0)
		return dest;

	strncpy(dest, src, n - 1);
	dest[n - 1] = '\0';
	return dest;
}

/* ========== HTTP Connection Management ========== */

/**
 * http_proxy_connection_alloc - Allocate HTTP proxy connection context
 *
 * Returns: Pointer to allocated connection, or NULL on failure
 */
struct http_proxy_connection *http_proxy_connection_alloc(void)
{
	struct http_proxy_connection *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		HTTP_ERR("Failed to allocate HTTP proxy connection\n");
		return NULL;
	}

	conn->state = HTTP_STATE_INIT;
	conn->created = jiffies;
	conn->last_activity = jiffies;
	conn->keep_alive = true; /* Default to keep-alive */

	/* Allocate working buffer */
	conn->buffer_len = 8192; /* 8KB should be enough for headers */
	conn->buffer = kmalloc(conn->buffer_len, GFP_KERNEL);
	if (!conn->buffer) {
		HTTP_ERR("Failed to allocate HTTP buffer\n");
		kfree(conn);
		return NULL;
	}

	HTTP_DEBUG("Allocated HTTP proxy connection\n");

	return conn;
}

/**
 * http_proxy_connection_free - Free HTTP proxy connection context
 * @conn: HTTP connection to free
 */
void http_proxy_connection_free(struct http_proxy_connection *conn)
{
	if (!conn)
		return;

	/* Free buffer */
	if (conn->buffer) {
		kfree(conn->buffer);
		conn->buffer = NULL;
	}

	/* Clear sensitive data */
	memset(&conn->auth, 0, sizeof(conn->auth));

	kfree(conn);

	HTTP_DEBUG("Freed HTTP proxy connection\n");
}

/* ========== HTTP Request Building ========== */

/**
 * http_build_connect_request - Build HTTP CONNECT request
 * @conn: HTTP connection context
 * @host: Target host
 * @port: Target port
 *
 * Returns: Length of request on success, negative error code on failure
 */
int http_build_connect_request(struct http_proxy_connection *conn,
				const char *host, __u16 port)
{
	char *buf;
	int len;
	char auth_header[HTTP_MAX_AUTH_LENGTH];

	if (!conn || !host)
		return -EINVAL;

	if (conn->state != HTTP_STATE_INIT &&
	    conn->state != HTTP_STATE_AUTH_REQUIRED) {
		HTTP_ERR("Invalid state for CONNECT request: %s\n",
			 http_state_name(conn->state));
		return -EINVAL;
	}

	buf = conn->buffer;

	/* Build request line: CONNECT host:port HTTP/1.1 */
	len = snprintf(buf, conn->buffer_len,
		       "%s %s:%u %s\r\n",
		       HTTP_METHOD_CONNECT, host, port, HTTP_VERSION_1_1);

	if (len >= conn->buffer_len)
		return -ENOMEM;

	/* Add Host header */
	len += snprintf(buf + len, conn->buffer_len - len,
			"%s: %s:%u\r\n", HTTP_HDR_HOST, host, port);

	/* Add User-Agent header */
	len += snprintf(buf + len, conn->buffer_len - len,
			"User-Agent: MUTEX-Kernel-Proxy/1.0\r\n");

	/* Add Proxy-Authorization header if credentials are set */
	if (conn->auth.credentials_set) {
		if (http_build_auth_header(conn, auth_header,
					   sizeof(auth_header)) > 0) {
			len += snprintf(buf + len, conn->buffer_len - len,
					"%s: %s\r\n",
					HTTP_HDR_PROXY_AUTH, auth_header);
		}
	}

	/* Add Connection header */
	len += snprintf(buf + len, conn->buffer_len - len,
			"%s: %s\r\n",
			HTTP_HDR_CONNECTION,
			conn->keep_alive ? HTTP_VAL_KEEP_ALIVE : HTTP_VAL_CLOSE);

	/* End headers with CRLF */
	len += snprintf(buf + len, conn->buffer_len - len, "\r\n");

	if (len >= conn->buffer_len)
		return -ENOMEM;

	/* Store target information */
	http_strncpy_safe(conn->target_host, host, sizeof(conn->target_host));
	conn->target_port = port;

	conn->buffer_used = len;
	conn->state = HTTP_STATE_REQUEST_SENT;
	conn->requests_sent++;

	atomic64_inc(&http_proxy_stats.connect_requests);

	HTTP_DEBUG("Built CONNECT request for %s:%u (%d bytes)\n",
		   host, port, len);

	return len;
}

/**
 * http_build_auth_header - Build authentication header value
 * @conn: HTTP connection context
 * @buffer: Output buffer
 * @buffer_len: Size of output buffer
 *
 * Returns: Length of header value on success, negative error code on failure
 */
int http_build_auth_header(struct http_proxy_connection *conn,
			    char *buffer, size_t buffer_len)
{
	int len = 0;

	if (!conn || !buffer)
		return -EINVAL;

	if (!conn->auth.credentials_set)
		return -EINVAL;

	switch (conn->auth.type) {
	case HTTP_AUTH_TYPE_BASIC:
		len = snprintf(buffer, buffer_len, "%s %s",
			       HTTP_AUTH_BASIC,
			       conn->auth.creds.basic.encoded);
		atomic64_inc(&http_proxy_stats.auth_basic_used);
		break;

	case HTTP_AUTH_TYPE_DIGEST:
		len = http_auth_build_digest(&conn->auth.creds.digest,
					     HTTP_METHOD_CONNECT,
					     conn->target_host,
					     buffer, buffer_len);
		if (len > 0)
			atomic64_inc(&http_proxy_stats.auth_digest_used);
		break;

	case HTTP_AUTH_TYPE_BEARER:
		len = snprintf(buffer, buffer_len, "%s %s",
			       HTTP_AUTH_BEARER,
			       conn->auth.creds.bearer.token);
		break;

	default:
		HTTP_ERR("Unsupported authentication type: %d\n",
			 conn->auth.type);
		return -EINVAL;
	}

	HTTP_DEBUG("Built auth header (type=%d, len=%d)\n",
		   conn->auth.type, len);

	return len;
}

/* ========== HTTP Response Parsing ========== */

/**
 * http_parse_status_line - Parse HTTP status line
 * @line: Status line string
 * @status: Output status line structure
 *
 * Returns: 0 on success, negative error code on failure
 */
int http_parse_status_line(const char *line,
			    struct http_status_line *status)
{
	int ret;
	char *space1, *space2;
	char line_copy[512];

	if (!line || !status)
		return -EINVAL;

	http_strncpy_safe(line_copy, line, sizeof(line_copy));

	/* Format: HTTP/1.1 200 OK */
	space1 = strchr(line_copy, ' ');
	if (!space1)
		return -EINVAL;

	*space1 = '\0';
	http_strncpy_safe(status->version, line_copy, sizeof(status->version));

	space2 = strchr(space1 + 1, ' ');
	if (!space2) {
		/* No reason phrase */
		ret = kstrtoint(space1 + 1, 10, &status->status_code);
		if (ret)
			return ret;
		status->reason_phrase[0] = '\0';
	} else {
		*space2 = '\0';
		ret = kstrtoint(space1 + 1, 10, &status->status_code);
		if (ret)
			return ret;
		http_strncpy_safe(status->reason_phrase, space2 + 1,
				  sizeof(status->reason_phrase));
	}

	HTTP_DEBUG("Parsed status line: %s %d %s\n",
		   status->version, status->status_code,
		   status->reason_phrase);

	return 0;
}

/**
 * http_parse_header_line - Parse HTTP header line
 * @line: Header line string
 * @header: Output header structure
 *
 * Returns: 0 on success, negative error code on failure
 */
int http_parse_header_line(const char *line,
			    struct http_header *header)
{
	char *colon;
	char line_copy[HTTP_MAX_HEADER_LINE];

	if (!line || !header)
		return -EINVAL;

	http_strncpy_safe(line_copy, line, sizeof(line_copy));

	/* Format: Header-Name: Header Value */
	colon = strchr(line_copy, ':');
	if (!colon)
		return -EINVAL;

	*colon = '\0';
	http_strncpy_safe(header->name, line_copy, sizeof(header->name));

	/* Skip whitespace after colon */
	colon++;
	while (isspace(*colon))
		colon++;

	http_strncpy_safe(header->value, colon, sizeof(header->value));

	HTTP_DEBUG("Parsed header: %s: %s\n", header->name, header->value);

	return 0;
}

/**
 * http_parse_response - Parse HTTP response
 * @conn: HTTP connection context
 * @data: Response data
 * @len: Length of response data
 *
 * Returns: 0 on success, negative error code on failure
 */
int http_parse_response(struct http_proxy_connection *conn,
			const void *data, size_t len)
{
	const char *ptr = data;
	const char *end = ptr + len;
	char line[HTTP_MAX_HEADER_LINE];
	struct http_status_line status;
	struct http_header header;
	const char *line_end;
	size_t line_len;
	int ret;

	if (!conn || !data)
		return -EINVAL;

	HTTP_DEBUG("Parsing HTTP response (%zu bytes)\n", len);

	/* Parse status line */
	line_end = strnstr(ptr, "\r\n", end - ptr);
	if (!line_end) {
		HTTP_DEBUG("Incomplete status line\n");
		return -EAGAIN; /* Need more data */
	}

	line_len = line_end - ptr;
	if (line_len >= sizeof(line))
		return -EINVAL;

	memcpy(line, ptr, line_len);
	line[line_len] = '\0';

	ret = http_parse_status_line(line, &status);
	if (ret) {
		HTTP_ERR("Failed to parse status line\n");
		atomic64_inc(&http_proxy_stats.parse_errors);
		return ret;
	}

	conn->last_status_code = status.status_code;
	ptr = line_end + 2; /* Skip CRLF */

	/* Update statistics */
	if (status.status_code >= 200 && status.status_code < 300)
		atomic64_inc(&http_proxy_stats.status_2xx);
	else if (status.status_code >= 300 && status.status_code < 400)
		atomic64_inc(&http_proxy_stats.status_3xx);
	else if (status.status_code >= 400 && status.status_code < 500)
		atomic64_inc(&http_proxy_stats.status_4xx);
	else if (status.status_code >= 500 && status.status_code < 600)
		atomic64_inc(&http_proxy_stats.status_5xx);

	/* Parse headers */
	while (ptr < end) {
		line_end = strnstr(ptr, "\r\n", end - ptr);
		if (!line_end) {
			HTTP_DEBUG("Incomplete header\n");
			return -EAGAIN; /* Need more data */
		}

		line_len = line_end - ptr;

		/* Empty line signals end of headers */
		if (line_len == 0) {
			ptr = line_end + 2;
			break;
		}

		if (line_len >= sizeof(line))
			return -EINVAL;

		memcpy(line, ptr, line_len);
		line[line_len] = '\0';

		ret = http_parse_header_line(line, &header);
		if (ret == 0) {
			/* Process important headers */
			if (http_strcasecmp(header.name, HTTP_HDR_PROXY_AUTHENTICATE) == 0) {
				http_auth_process_challenge(conn, header.value);
			} else if (http_strcasecmp(header.name, HTTP_HDR_CONNECTION) == 0) {
				if (http_strcasecmp(header.value, HTTP_VAL_CLOSE) == 0)
					conn->keep_alive = false;
			}
		}

		ptr = line_end + 2; /* Skip CRLF */
	}

	conn->responses_received++;

	/* Handle response based on status code */
	switch (status.status_code) {
	case HTTP_STATUS_OK:
		/* Tunnel established */
		conn->state = HTTP_STATE_TUNNEL_ESTABLISHED;
		conn->tunnels_established++;
		atomic64_inc(&http_proxy_stats.tunnels_established);
		HTTP_INFO("HTTP tunnel established to %s:%u\n",
			  conn->target_host, conn->target_port);
		break;

	case HTTP_STATUS_PROXY_AUTH_REQUIRED:
		/* Authentication required */
		conn->state = HTTP_STATE_AUTH_REQUIRED;
		conn->auth_challenged = true;
		conn->auth_challenges++;
		conn->auth_attempts++;
		atomic64_inc(&http_proxy_stats.status_407);

		if (conn->auth_attempts >= http_max_auth_attempts) {
			HTTP_ERR("Max auth attempts exceeded\n");
			conn->state = HTTP_STATE_ERROR;
			atomic64_inc(&http_proxy_stats.auth_failures);
			return -EACCES;
		}

		HTTP_INFO("Proxy authentication required\n");
		break;

	default:
		/* Error response */
		conn->state = HTTP_STATE_ERROR;
		snprintf(conn->last_error, sizeof(conn->last_error),
			 "HTTP %d %s", status.status_code, status.reason_phrase);
		HTTP_ERR("HTTP error: %s\n", conn->last_error);
		atomic64_inc(&http_proxy_stats.connection_errors);
		return -ECONNREFUSED;
	}

	return 0;
}

/* ========== HTTP Authentication ========== */

/**
 * http_auth_set_credentials - Set authentication credentials
 * @conn: HTTP connection context
 * @type: Authentication type
 * @username: Username
 * @password: Password
 *
 * Returns: 0 on success, negative error code on failure
 */
int http_auth_set_credentials(struct http_proxy_connection *conn,
			       enum http_auth_type type,
			       const char *username,
			       const char *password)
{
	char combined[512];
	int ret;

	if (!conn || !username || !password)
		return -EINVAL;

	conn->auth.type = type;

	switch (type) {
	case HTTP_AUTH_TYPE_BASIC:
		/* Store credentials */
		http_strncpy_safe(conn->auth.creds.basic.username,
				  username,
				  sizeof(conn->auth.creds.basic.username));
		http_strncpy_safe(conn->auth.creds.basic.password,
				  password,
				  sizeof(conn->auth.creds.basic.password));

		/* Encode username:password in Base64 */
		snprintf(combined, sizeof(combined), "%s:%s",
			 username, password);
		ret = base64_encode(combined, strlen(combined),
				    conn->auth.creds.basic.encoded,
				    sizeof(conn->auth.creds.basic.encoded));
		if (ret < 0) {
			HTTP_ERR("Failed to encode Basic auth credentials\n");
			return ret;
		}

		HTTP_DEBUG("Set Basic authentication credentials\n");
		break;

	case HTTP_AUTH_TYPE_DIGEST:
		/* Store credentials (will be used when challenge is received) */
		http_strncpy_safe(conn->auth.creds.digest.username,
				  username,
				  sizeof(conn->auth.creds.digest.username));
		http_strncpy_safe(conn->auth.creds.digest.password,
				  password,
				  sizeof(conn->auth.creds.digest.password));

		HTTP_DEBUG("Set Digest authentication credentials\n");
		break;

	default:
		HTTP_ERR("Unsupported authentication type: %d\n", type);
		return -EINVAL;
	}

	conn->auth.credentials_set = true;

	return 0;
}

/**
 * http_auth_process_challenge - Process Proxy-Authenticate challenge
 * @conn: HTTP connection context
 * @challenge: Challenge string
 *
 * Returns: 0 on success, negative error code on failure
 */
int http_auth_process_challenge(struct http_proxy_connection *conn,
				 const char *challenge)
{
	char *space;
	char challenge_copy[512];
	char *param;
	char *equals;

	if (!conn || !challenge)
		return -EINVAL;

	HTTP_DEBUG("Processing auth challenge: %s\n", challenge);

	http_strncpy_safe(challenge_copy, challenge, sizeof(challenge_copy));

	/* Find authentication scheme */
	space = strchr(challenge_copy, ' ');
	if (!space)
		return -EINVAL;

	*space = '\0';

	if (http_strcasecmp(challenge_copy, HTTP_AUTH_BASIC) == 0) {
		/* Basic authentication - no parameters needed */
		if (!conn->auth.credentials_set) {
			HTTP_ERR("No credentials set for Basic auth\n");
			return -EINVAL;
		}
		/* Credentials already encoded */
		return 0;

	} else if (http_strcasecmp(challenge_copy, HTTP_AUTH_DIGEST) == 0) {
		/* Digest authentication - parse parameters */
		if (!conn->auth.credentials_set) {
			HTTP_ERR("No credentials set for Digest auth\n");
			return -EINVAL;
		}

		/* Parse Digest parameters (realm, nonce, etc.) */
		param = space + 1;
		while (param && *param) {
			/* Skip whitespace and commas */
			while (*param && (isspace(*param) || *param == ','))
				param++;

			if (!*param)
				break;

			equals = strchr(param, '=');
			if (!equals)
				break;

			*equals = '\0';

			/* Remove quotes from value */
			char *value = equals + 1;
			if (*value == '"')
				value++;
			char *end = strchr(value, '"');
			if (end)
				*end = '\0';

			/* Store parameter */
			if (strcmp(param, "realm") == 0) {
				http_strncpy_safe(conn->auth.creds.digest.realm,
						  value,
						  sizeof(conn->auth.creds.digest.realm));
			} else if (strcmp(param, "nonce") == 0) {
				http_strncpy_safe(conn->auth.creds.digest.nonce,
						  value,
						  sizeof(conn->auth.creds.digest.nonce));
			} else if (strcmp(param, "opaque") == 0) {
				http_strncpy_safe(conn->auth.creds.digest.opaque,
						  value,
						  sizeof(conn->auth.creds.digest.opaque));
			} else if (strcmp(param, "algorithm") == 0) {
				http_strncpy_safe(conn->auth.creds.digest.algorithm,
						  value,
						  sizeof(conn->auth.creds.digest.algorithm));
			} else if (strcmp(param, "qop") == 0) {
				http_strncpy_safe(conn->auth.creds.digest.qop,
						  value,
						  sizeof(conn->auth.creds.digest.qop));
			}

			/* Find next parameter */
			param = end ? end + 1 : NULL;
			if (param) {
				param = strchr(param, ',');
				if (param)
					param++;
			}
		}

		HTTP_DEBUG("Parsed Digest challenge (realm=%s)\n",
			   conn->auth.creds.digest.realm);
		return 0;
	}

	HTTP_ERR("Unsupported authentication scheme: %s\n", challenge_copy);
	return -EINVAL;
}

/**
 * http_auth_build_digest - Build Digest authentication response
 * @digest: Digest authentication info
 * @method: HTTP method
 * @uri: Request URI
 * @output: Output buffer
 * @output_len: Size of output buffer
 *
 * Returns: Length of response on success, negative error code on failure
 */
int http_auth_build_digest(struct http_auth_digest *digest,
			    const char *method, const char *uri,
			    char *output, size_t output_len)
{
	char ha1[33], ha2[33], response[33];
	char a1[512], a2[512];
	int len;

	if (!digest || !method || !uri || !output)
		return -EINVAL;

	/* Calculate HA1 = MD5(username:realm:password) */
	snprintf(a1, sizeof(a1), "%s:%s:%s",
		 digest->username, digest->realm, digest->password);
	if (md5_hash_hex(a1, strlen(a1), ha1, sizeof(ha1)) < 0)
		return -EINVAL;

	/* Calculate HA2 = MD5(method:uri) */
	snprintf(a2, sizeof(a2), "%s:%s", method, uri);
	if (md5_hash_hex(a2, strlen(a2), ha2, sizeof(ha2)) < 0)
		return -EINVAL;

	/* Calculate response = MD5(HA1:nonce:HA2) */
	snprintf(a1, sizeof(a1), "%s:%s:%s", ha1, digest->nonce, ha2);
	if (md5_hash_hex(a1, strlen(a1), response, sizeof(response)) < 0)
		return -EINVAL;

	/* Build Digest header */
	len = snprintf(output, output_len,
		       "Digest username=\"%s\", realm=\"%s\", "
		       "nonce=\"%s\", uri=\"%s\", response=\"%s\"",
		       digest->username, digest->realm,
		       digest->nonce, uri, response);

	if (digest->opaque[0]) {
		len += snprintf(output + len, output_len - len,
				", opaque=\"%s\"", digest->opaque);
	}

	if (digest->algorithm[0]) {
		len += snprintf(output + len, output_len - len,
				", algorithm=%s", digest->algorithm);
	}

	HTTP_DEBUG("Built Digest auth response\n");

	return len;
}

/* ========== Utility Functions ========== */

/**
 * http_status_reason - Get reason phrase for status code
 */
const char *http_status_reason(int status_code)
{
	switch (status_code) {
	case HTTP_STATUS_OK:
		return "OK";
	case HTTP_STATUS_BAD_REQUEST:
		return "Bad Request";
	case HTTP_STATUS_UNAUTHORIZED:
		return "Unauthorized";
	case HTTP_STATUS_FORBIDDEN:
		return "Forbidden";
	case HTTP_STATUS_NOT_FOUND:
		return "Not Found";
	case HTTP_STATUS_PROXY_AUTH_REQUIRED:
		return "Proxy Authentication Required";
	case HTTP_STATUS_INTERNAL_ERROR:
		return "Internal Server Error";
	case HTTP_STATUS_BAD_GATEWAY:
		return "Bad Gateway";
	case HTTP_STATUS_SERVICE_UNAVAILABLE:
		return "Service Unavailable";
	case HTTP_STATUS_GATEWAY_TIMEOUT:
		return "Gateway Timeout";
	default:
		return "Unknown";
	}
}

/**
 * http_state_name - Get string name for HTTP state
 */
const char *http_state_name(enum http_state state)
{
	switch (state) {
	case HTTP_STATE_INIT:
		return "INIT";
	case HTTP_STATE_REQUEST_SENT:
		return "REQUEST_SENT";
	case HTTP_STATE_RESPONSE_HEADERS:
		return "RESPONSE_HEADERS";
	case HTTP_STATE_TUNNEL_ESTABLISHED:
		return "TUNNEL_ESTABLISHED";
	case HTTP_STATE_AUTH_REQUIRED:
		return "AUTH_REQUIRED";
	case HTTP_STATE_ERROR:
		return "ERROR";
	case HTTP_STATE_CLOSED:
		return "CLOSED";
	default:
		return "UNKNOWN";
	}
}

/**
 * http_status_is_success - Check if status code is success (2xx)
 */
bool http_status_is_success(int status_code)
{
	return status_code >= 200 && status_code < 300;
}

/**
 * http_status_is_redirect - Check if status code is redirect (3xx)
 */
bool http_status_is_redirect(int status_code)
{
	return status_code >= 300 && status_code < 400;
}

/**
 * http_status_is_error - Check if status code is error (4xx or 5xx)
 */
bool http_status_is_error(int status_code)
{
	return status_code >= 400;
}

/* ========== Statistics ========== */

/**
 * http_proxy_stats_init - Initialize statistics
 */
void http_proxy_stats_init(void)
{
	atomic64_set(&http_proxy_stats.connect_requests, 0);
	atomic64_set(&http_proxy_stats.tunnels_established, 0);
	atomic64_set(&http_proxy_stats.auth_basic_used, 0);
	atomic64_set(&http_proxy_stats.auth_digest_used, 0);
	atomic64_set(&http_proxy_stats.status_2xx, 0);
	atomic64_set(&http_proxy_stats.status_3xx, 0);
	atomic64_set(&http_proxy_stats.status_4xx, 0);
	atomic64_set(&http_proxy_stats.status_5xx, 0);
	atomic64_set(&http_proxy_stats.status_407, 0);
	atomic64_set(&http_proxy_stats.auth_failures, 0);
	atomic64_set(&http_proxy_stats.parse_errors, 0);
	atomic64_set(&http_proxy_stats.connection_errors, 0);

	HTTP_INFO("Statistics initialized\n");
}

/**
 * http_proxy_stats_print - Print current statistics
 */
void http_proxy_stats_print(void)
{
	pr_info("MUTEX HTTP Proxy Statistics:\n");
	pr_info("  CONNECT requests: %lld\n",
		atomic64_read(&http_proxy_stats.connect_requests));
	pr_info("  Tunnels established: %lld\n",
		atomic64_read(&http_proxy_stats.tunnels_established));
	pr_info("  Basic auth used: %lld\n",
		atomic64_read(&http_proxy_stats.auth_basic_used));
	pr_info("  Digest auth used: %lld\n",
		atomic64_read(&http_proxy_stats.auth_digest_used));
	pr_info("  2xx responses: %lld\n",
		atomic64_read(&http_proxy_stats.status_2xx));
	pr_info("  3xx responses: %lld\n",
		atomic64_read(&http_proxy_stats.status_3xx));
	pr_info("  4xx responses: %lld\n",
		atomic64_read(&http_proxy_stats.status_4xx));
	pr_info("  5xx responses: %lld\n",
		atomic64_read(&http_proxy_stats.status_5xx));
	pr_info("  407 auth required: %lld\n",
		atomic64_read(&http_proxy_stats.status_407));
	pr_info("  Auth failures: %lld\n",
		atomic64_read(&http_proxy_stats.auth_failures));
	pr_info("  Parse errors: %lld\n",
		atomic64_read(&http_proxy_stats.parse_errors));
	pr_info("  Connection errors: %lld\n",
		atomic64_read(&http_proxy_stats.connection_errors));
}

/* ========== Module Initialization ========== */

/**
 * mutex_http_proxy_init - Initialize HTTP proxy module
 */
int mutex_http_proxy_init(void)
{
	HTTP_INFO("Initializing HTTP proxy support\n");

	http_proxy_stats_init();

	HTTP_INFO("HTTP proxy module initialized (timeout=%u seconds)\n",
		  http_timeout);

	return 0;
}

/**
 * mutex_http_proxy_exit - Cleanup HTTP proxy module
 */
void mutex_http_proxy_exit(void)
{
	HTTP_INFO("Cleaning up HTTP proxy support\n");

	http_proxy_stats_print();

	HTTP_INFO("HTTP proxy module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Development Team");
MODULE_DESCRIPTION("HTTP Proxy Support for MUTEX");
MODULE_VERSION("1.0");
