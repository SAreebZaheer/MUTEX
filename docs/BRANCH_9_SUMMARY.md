# Branch 9: HTTP/HTTPS Proxy Implementation

## Overview

Branch 9 (`feature/http-proxy-support`) implements comprehensive HTTP/HTTPS proxy support using the CONNECT method in kernel space for the MUTEX proxy module. This implementation enables transparent HTTPS tunneling through HTTP proxy servers.

---

## Implementation Summary

### Files Created

1. **[src/module/mutex_http_proxy.h](../src/module/mutex_http_proxy.h)** - HTTP proxy protocol header
2. **[src/module/mutex_http_proxy.c](../src/module/mutex_http_proxy.c)** - HTTP proxy implementation

### Key Features Implemented

✅ **HTTP CONNECT Method**
- CONNECT request building
- Response parsing and validation
- Tunnel establishment
- Error handling

✅ **Authentication Support**
- Basic authentication (RFC 7617)
- Digest authentication (RFC 7616)
- Bearer token support
- Credential encoding (Base64, MD5)

✅ **HTTP Protocol Features**
- HTTP/1.0 and HTTP/1.1 support
- Header parsing and manipulation
- Status code handling
- Keep-alive connection management

✅ **State Machine**
- Connection lifecycle tracking
- Authentication challenge handling
- Error state management

---

## Architecture

### HTTP Proxy State Machine

```
                    ┌─────────────┐
                    │    INIT     │
                    └──────┬──────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ REQUEST_SENT   │
                  └────────┬───────┘
                           │
                  ┌────────┴────────┐
                  │                 │
                  ▼                 ▼
       ┌──────────────┐    ┌───────────────────┐
       │ 200 OK       │    │ 407 Auth Required │
       └──────┬───────┘    └────────┬──────────┘
              │                     │
              │            ┌────────┴────────┐
              │            │  AUTH_REQUIRED  │
              │            └────────┬────────┘
              │                     │
              │              Retry with auth
              │                     │
              │            ┌────────▼────────┐
              │            │ REQUEST_SENT    │
              │            └────────┬────────┘
              │                     │
              └─────────┬───────────┘
                        │
                        ▼
              ┌──────────────────┐
              │TUNNEL_ESTABLISHED│
              └──────────────────┘
```

### HTTP CONNECT Protocol Flow

#### Step 1: Initial CONNECT Request
```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
User-Agent: MUTEX-Kernel-Proxy/1.0
Connection: keep-alive

```

#### Step 2a: Success Response (No Auth)
```
HTTP/1.1 200 Connection Established

```
**Result:** Tunnel established, data flows transparently

#### Step 2b: Authentication Required
```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Proxy"
Connection: close

```

#### Step 3: Authenticated CONNECT Request
```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
User-Agent: MUTEX-Kernel-Proxy/1.0
Proxy-Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
Connection: keep-alive

```

#### Step 4: Success Response (With Auth)
```
HTTP/1.1 200 Connection Established

```
**Result:** Tunnel established with authentication

---

## API Reference

### Connection Management

```c
/* Allocate HTTP proxy connection context */
struct http_proxy_connection *http_proxy_connection_alloc(void);

/* Free HTTP proxy connection context */
void http_proxy_connection_free(struct http_proxy_connection *conn);
```

### Request Building

```c
/* Build HTTP CONNECT request */
int http_build_connect_request(struct http_proxy_connection *conn,
                               const char *host, __u16 port);

/* Build authentication header value */
int http_build_auth_header(struct http_proxy_connection *conn,
                           char *buffer, size_t buffer_len);
```

### Response Parsing

```c
/* Parse HTTP response */
int http_parse_response(struct http_proxy_connection *conn,
                       const void *data, size_t len);

/* Parse status line */
int http_parse_status_line(const char *line,
                           struct http_status_line *status);

/* Parse header line */
int http_parse_header_line(const char *line,
                           struct http_header *header);
```

### Authentication

```c
/* Set authentication credentials */
int http_auth_set_credentials(struct http_proxy_connection *conn,
                              enum http_auth_type type,
                              const char *username,
                              const char *password);

/* Process authentication challenge */
int http_auth_process_challenge(struct http_proxy_connection *conn,
                                const char *challenge);

/* Build Digest authentication response */
int http_auth_build_digest(struct http_auth_digest *digest,
                           const char *method, const char *uri,
                           char *output, size_t output_len);
```

### Utility Functions

```c
/* Status code helpers */
const char *http_status_reason(int status_code);
bool http_status_is_success(int status_code);
bool http_status_is_redirect(int status_code);
bool http_status_is_error(int status_code);

/* State information */
const char *http_state_name(enum http_state state);

/* String utilities */
char *http_trim_whitespace(char *str);
int http_strcasecmp(const char *s1, const char *s2);
char *http_strncpy_safe(char *dest, const char *src, size_t n);

/* Encoding functions */
int base64_encode(const char *input, size_t input_len,
                 char *output, size_t output_len);
int md5_hash_hex(const char *input, size_t input_len,
                char *output, size_t output_len);
```

---

## Usage Examples

### Example 1: Simple CONNECT Without Authentication

```c
struct http_proxy_connection *conn;
int ret;

/* Allocate connection */
conn = http_proxy_connection_alloc();
if (!conn)
    return -ENOMEM;

/* Build CONNECT request */
ret = http_build_connect_request(conn, "example.com", 443);
if (ret < 0) {
    http_proxy_connection_free(conn);
    return ret;
}

/* Send request to proxy server */
send_to_proxy(conn->buffer, conn->buffer_used);

/* Receive and parse response */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = http_parse_response(conn, response_buffer, response_len);

if (ret == 0 && conn->state == HTTP_STATE_TUNNEL_ESTABLISHED) {
    printk("HTTP tunnel established to example.com:443\n");
    /* Now data can flow transparently through the tunnel */
}

http_proxy_connection_free(conn);
```

### Example 2: CONNECT With Basic Authentication

```c
struct http_proxy_connection *conn;
int ret;

conn = http_proxy_connection_alloc();

/* Set Basic authentication credentials */
ret = http_auth_set_credentials(conn, HTTP_AUTH_TYPE_BASIC,
                                "myuser", "mypassword");
if (ret < 0)
    goto error;

/* Build CONNECT request (will include auth header) */
ret = http_build_connect_request(conn, "secure.example.com", 443);
if (ret < 0)
    goto error;

send_to_proxy(conn->buffer, conn->buffer_used);

/* Parse response */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = http_parse_response(conn, response_buffer, response_len);

if (ret == 0 && conn->state == HTTP_STATE_TUNNEL_ESTABLISHED) {
    printk("Authenticated tunnel established\n");
}

error:
    http_proxy_connection_free(conn);
    return ret;
```

### Example 3: Handling 407 Authentication Challenge

```c
struct http_proxy_connection *conn;
int ret;

conn = http_proxy_connection_alloc();

/* First attempt without authentication */
ret = http_build_connect_request(conn, "example.com", 443);
send_to_proxy(conn->buffer, conn->buffer_used);

recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = http_parse_response(conn, response_buffer, response_len);

if (ret == 0 && conn->state == HTTP_STATE_AUTH_REQUIRED) {
    printk("Authentication required (407 response)\n");

    /* Set credentials based on the challenge */
    if (conn->auth.type == HTTP_AUTH_TYPE_BASIC) {
        ret = http_auth_set_credentials(conn, HTTP_AUTH_TYPE_BASIC,
                                        "username", "password");
    } else if (conn->auth.type == HTTP_AUTH_TYPE_DIGEST) {
        ret = http_auth_set_credentials(conn, HTTP_AUTH_TYPE_DIGEST,
                                        "username", "password");
    }

    if (ret < 0)
        goto error;

    /* Retry CONNECT with authentication */
    ret = http_build_connect_request(conn, "example.com", 443);
    send_to_proxy(conn->buffer, conn->buffer_used);

    recv_from_proxy(response_buffer, sizeof(response_buffer));
    ret = http_parse_response(conn, response_buffer, response_len);

    if (ret == 0 && conn->state == HTTP_STATE_TUNNEL_ESTABLISHED) {
        printk("Tunnel established after authentication\n");
    }
}

error:
    http_proxy_connection_free(conn);
    return ret;
```

### Example 4: Digest Authentication

```c
struct http_proxy_connection *conn;
int ret;

conn = http_proxy_connection_alloc();

/* Set Digest credentials (will be used when challenge is received) */
ret = http_auth_set_credentials(conn, HTTP_AUTH_TYPE_DIGEST,
                                "alice", "secret123");

/* Send initial CONNECT (without auth) */
ret = http_build_connect_request(conn, "api.example.com", 443);
send_to_proxy(conn->buffer, conn->buffer_used);

/* Receive 407 with Digest challenge */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = http_parse_response(conn, response_buffer, response_len);

if (conn->state == HTTP_STATE_AUTH_REQUIRED) {
    /* Challenge parameters (realm, nonce, etc.) are now parsed */
    printk("Digest challenge received: realm=%s\n",
           conn->auth.creds.digest.realm);

    /* Build request with Digest response */
    ret = http_build_connect_request(conn, "api.example.com", 443);
    send_to_proxy(conn->buffer, conn->buffer_used);

    recv_from_proxy(response_buffer, sizeof(response_buffer));
    ret = http_parse_response(conn, response_buffer, response_len);

    if (conn->state == HTTP_STATE_TUNNEL_ESTABLISHED) {
        printk("Tunnel established with Digest auth\n");
    }
}

http_proxy_connection_free(conn);
```

---

## Integration with MUTEX

### Connection Tracking Integration

The HTTP proxy implementation integrates with the MUTEX connection tracking system:

```c
/* Attach HTTP proxy context to tracked connection */
int mutex_conn_attach_http_proxy(struct mutex_connection *conn,
                                 struct http_proxy_connection *http);

/* Retrieve HTTP proxy context from tracked connection */
struct http_proxy_connection *mutex_conn_get_http_proxy(
    struct mutex_connection *conn);

/* Process HTTP CONNECT handshake */
int mutex_http_proxy_process_connect(struct mutex_connection *conn,
                                     struct sk_buff *skb);

/* Establish HTTP proxy tunnel */
int mutex_http_proxy_establish_tunnel(struct mutex_connection *conn);

/* Handle HTTP proxy errors */
void mutex_http_proxy_handle_error(struct mutex_connection *conn, int error);
```

### Typical Integration Flow

```
1. Application initiates HTTPS connection
2. Netfilter hook intercepts SYN packet
3. Connection tracking creates new connection entry
4. HTTP proxy context allocated and attached
5. HTTP CONNECT handshake:
   a. Build and send CONNECT request
   b. Parse response
   c. Handle authentication if required (407)
   d. Retry with credentials
   e. Receive 200 OK
6. Tunnel established
7. TLS handshake passes through tunnel transparently
8. Data flows through HTTP proxy tunnel
```

---

## Statistics and Monitoring

### Statistics Structure

```c
struct http_proxy_statistics {
    atomic64_t connect_requests;      /* CONNECT requests sent */
    atomic64_t tunnels_established;   /* Successful tunnels */
    atomic64_t auth_basic_used;       /* Basic auth usage */
    atomic64_t auth_digest_used;      /* Digest auth usage */
    atomic64_t status_2xx;            /* 2xx responses */
    atomic64_t status_3xx;            /* 3xx responses */
    atomic64_t status_4xx;            /* 4xx responses */
    atomic64_t status_5xx;            /* 5xx responses */
    atomic64_t status_407;            /* 407 auth required */
    atomic64_t auth_failures;         /* Authentication failures */
    atomic64_t parse_errors;          /* Parsing errors */
    atomic64_t connection_errors;     /* Connection errors */
};
```

### Viewing Statistics

Statistics are printed when the module is unloaded:

```bash
$ sudo rmmod mutex
[  456.789] MUTEX HTTP Proxy Statistics:
[  456.789]   CONNECT requests: 325
[  456.789]   Tunnels established: 318
[  456.789]   Basic auth used: 150
[  456.789]   Digest auth used: 45
[  456.789]   2xx responses: 318
[  456.789]   4xx responses: 5
[  456.789]   5xx responses: 2
[  456.789]   407 auth required: 195
[  456.789]   Auth failures: 3
[  456.789]   Parse errors: 0
[  456.789]   Connection errors: 2
```

---

## Module Parameters

### http_timeout
**Type:** unsigned int  
**Default:** 30  
**Description:** HTTP proxy connection timeout in seconds

```bash
# Load module with custom timeout
sudo insmod mutex.ko http_timeout=60

# Change at runtime
echo 45 | sudo tee /sys/module/mutex/parameters/http_timeout
```

### http_debug
**Type:** bool  
**Default:** false  
**Description:** Enable verbose debug logging

```bash
# Enable debug logging
sudo insmod mutex.ko http_debug=1

# Toggle at runtime
echo 1 | sudo tee /sys/module/mutex/parameters/http_debug
```

### http_max_auth_attempts
**Type:** unsigned int  
**Default:** 3  
**Description:** Maximum authentication retry attempts

```bash
# Set max auth attempts
sudo insmod mutex.ko http_max_auth_attempts=5

# Change at runtime
echo 5 | sudo tee /sys/module/mutex/parameters/http_max_auth_attempts
```

---

## Protocol Support Matrix

| Feature                    | Support | Notes |
|----------------------------|:-------:|-------|
| HTTP/1.0                   |   ✅   | Fully supported |
| HTTP/1.1                   |   ✅   | Fully supported |
| CONNECT method             |   ✅   | Primary method |
| GET/POST                   |   ❌   | Not needed for tunneling |
| Basic authentication       |   ✅   | RFC 7617 |
| Digest authentication      |   ✅   | RFC 7616 (MD5) |
| Bearer authentication      |   ✅   | Token-based |
| Keep-alive connections     |   ✅   | Connection reuse |
| Chunked transfer encoding  |   ❌   | Not needed for CONNECT |
| HTTP/2                     |   ❌   | Future enhancement |
| HTTP/3 (QUIC)              |   ❌   | Future enhancement |

Legend: ✅ Implemented, ❌ Not supported

---

## Error Handling

### HTTP Status Codes

| Code | Status | Description | Action |
|------|--------|-------------|--------|
| 200 | OK | Connection established | Tunnel ready |
| 400 | Bad Request | Invalid CONNECT request | Fail connection |
| 401 | Unauthorized | Need authentication (wrong header) | Use 407 instead |
| 403 | Forbidden | Connection not allowed | Fail connection |
| 404 | Not Found | Proxy misconfiguration | Fail connection |
| 407 | Proxy Auth Required | Need proxy authentication | Retry with credentials |
| 408 | Request Timeout | Timeout waiting for request | Fail connection |
| 500 | Internal Error | Proxy server error | Fail connection |
| 502 | Bad Gateway | Cannot reach target | Fail connection |
| 503 | Service Unavailable | Proxy overloaded | Retry or fail |
| 504 | Gateway Timeout | Timeout reaching target | Fail connection |

### Error Codes Returned

| Error Code | Condition | Description |
|------------|-----------|-------------|
| -EINVAL | Invalid parameter | NULL pointer or invalid state |
| -ENOMEM | Out of memory | Buffer allocation failed |
| -EPROTO | Protocol error | Invalid HTTP response |
| -EACCES | Auth failed | Authentication rejected |
| -ECONNREFUSED | Connection refused | Proxy rejected connection |
| -ENETUNREACH | Network unreachable | Cannot reach target |
| -ETIMEDOUT | Timeout | Connection or request timeout |
| -EAGAIN | Need more data | Incomplete response |

---

## Testing

### Unit Tests

```bash
# Build with test support
make test

# Run HTTP proxy tests
./test_http_proxy
```

### Manual Testing with Real Proxy

```bash
# Start an HTTP proxy with authentication (using squid)
# /etc/squid/squid.conf:
#   http_port 3128
#   auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
#   acl authenticated proxy_auth REQUIRED
#   http_access allow authenticated

sudo squid -f /etc/squid/squid.conf

# Load MUTEX module
sudo insmod mutex.ko http_debug=1

# Configure to use HTTP proxy
# (Configuration commands depend on Branch 5 implementation)

# Test HTTPS connection through proxy
curl --proxy http://localhost:3128 \
     --proxy-user username:password \
     https://www.example.com

# Check kernel logs
dmesg | grep "MUTEX HTTP"
```

### Testing Without Authentication

```bash
# Configure Squid without authentication
# /etc/squid/squid.conf:
#   http_port 3128
#   http_access allow all

# Test connection
curl --proxy http://localhost:3128 https://www.google.com
```

---

## Performance Considerations

### Memory Usage

- **Per-connection overhead:** ~10 KB
  - Connection structure: ~2 KB
  - Working buffer: 8 KB (configurable)
  - Authentication data: ~512 bytes

### Processing Overhead

- **No authentication:** Minimal (single CONNECT request/response)
- **Basic auth:** Low (Base64 encoding overhead)
- **Digest auth:** Medium (MD5 hash calculations)

### Optimizations

1. **Connection reuse:** Keep-alive connections reduce overhead
2. **Credential caching:** Encode credentials once, reuse for multiple requests
3. **Buffer pooling:** Reuse buffers across connections
4. **Fast-path:** Direct tunnel once established (no per-packet overhead)

---

## Known Limitations

1. **HTTP/2 and HTTP/3:** Not supported (HTTP/1.1 only)
2. **Chunked encoding:** Not implemented (not needed for CONNECT)
3. **NTLM authentication:** Not supported (complex challenge-response)
4. **Kerberos/GSSAPI:** Not fully implemented
5. **Proxy chaining:** Not yet supported (single proxy only)

---

## Security Considerations

### Credential Handling

- Credentials stored in kernel memory (non-pageable)
- Cleared on connection close with `memset()`
- Base64 encoded strings cleared after use
- Not written to logs (even in debug mode)

### Buffer Security

- All buffers bounds-checked
- Input validation on all received data
- HTTP header length limits enforced
- Protection against buffer overflow

### Authentication Security

- **Basic auth:** Credentials encoded but not encrypted (use with TLS)
- **Digest auth:** Password never sent in clear (MD5 hash)
- **Token security:** Bearer tokens treated as sensitive data
- **Retry limits:** Maximum auth attempts prevents brute force

---

## Future Enhancements

### Planned for Branch 10 (Transparent Proxying)
- [ ] Automatic HTTP CONNECT for intercepted HTTPS connections
- [ ] Transparent HTTP proxy selection
- [ ] Connection pooling and reuse
- [ ] Automatic failover between proxies

### Planned for Branch 13 (Performance Optimization)
- [ ] Connection caching
- [ ] Credential caching across connections
- [ ] Fast-path for established tunnels
- [ ] Zero-copy data forwarding

### Planned for Branch 14 (Security Hardening)
- [ ] NTLM authentication support
- [ ] Kerberos/GSSAPI support
- [ ] Certificate validation for HTTPS proxies
- [ ] Secure credential storage

### Future Protocol Support
- [ ] HTTP/2 CONNECT support
- [ ] HTTP/3 (QUIC) support
- [ ] WebSocket tunneling
- [ ] Proxy chaining support

---

## References

### Standards

- **RFC 7230:** HTTP/1.1 Message Syntax and Routing
- **RFC 7231:** HTTP/1.1 Semantics and Content
- **RFC 7235:** HTTP/1.1 Authentication
- **RFC 7617:** The 'Basic' HTTP Authentication Scheme
- **RFC 7616:** HTTP Digest Access Authentication
- **RFC 2817:** Upgrading to TLS Within HTTP/1.1 (CONNECT method)

### Related Documentation

- [Branch Plan](BRANCH_PLAN.md)
- [Branch 6: Connection Tracking](BRANCH_6_SUMMARY.md)
- [Branch 7: Packet Rewriting](BRANCH_7_SUMMARY.md)
- [Branch 8: SOCKS Protocol](BRANCH_8_SUMMARY.md)
- [Netfilter Hooks Documentation](NETFILTER_HOOKS.md)

---

## Changelog

### Version 1.0 (December 20, 2025)

**Initial implementation:**
- ✅ HTTP CONNECT method support
- ✅ HTTP/1.0 and HTTP/1.1 support
- ✅ Status line and header parsing
- ✅ Basic authentication (RFC 7617)
- ✅ Digest authentication (RFC 7616)
- ✅ Bearer token support
- ✅ Keep-alive connection management
- ✅ State machine implementation
- ✅ Base64 encoding
- ✅ MD5 hashing for Digest auth
- ✅ Error handling and reporting
- ✅ Statistics collection
- ✅ Debug logging support

---

## Contributors

- **Implementation:** MUTEX Development Team
- **Testing:** TBD
- **Documentation:** MUTEX Development Team

---

## License

This implementation is part of the MUTEX project and is licensed under GPL-2.0.

---

*Document Version: 1.0*  
*Last Updated: December 20, 2025*  
*Branch: feature/http-proxy-support*  
*Status: Complete*
