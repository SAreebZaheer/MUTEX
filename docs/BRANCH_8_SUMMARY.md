# Branch 8: SOCKS Protocol Implementation

## Overview

Branch 8 (`feature/socks-protocol`) implements comprehensive SOCKS4, SOCKS4a, and SOCKS5 protocol support in kernel space for the MUTEX proxy module. This implementation provides the foundation for transparent proxying through SOCKS proxy servers.

---

## Implementation Summary

### Files Created

1. **[src/module/mutex_socks.h](../src/module/mutex_socks.h)** - SOCKS protocol header definitions
2. **[src/module/mutex_socks.c](../src/module/mutex_socks.c)** - SOCKS protocol implementation

### Key Features Implemented

✅ **SOCKS4 Protocol Support**
- CONNECT command implementation
- BIND command support
- Response parsing and error handling
- User ID authentication

✅ **SOCKS4a Protocol Support**
- Domain name resolution through proxy
- Backward compatibility with SOCKS4
- Magic IP (0.0.0.x) detection

✅ **SOCKS5 Protocol Support**
- Method selection negotiation
- Multiple authentication methods (none, username/password, GSSAPI)
- CONNECT, BIND, and UDP ASSOCIATE commands
- IPv4, IPv6, and domain name addressing
- UDP relay support

✅ **State Machine**
- Comprehensive state tracking
- State transition validation
- Error state handling

✅ **Protocol Features**
- Authentication handling (username/password)
- Multiple address types (IPv4, IPv6, domain)
- UDP association for SOCKS5
- DNS resolution through proxy

---

## Architecture

### SOCKS Connection State Machine

```
                    ┌─────────────┐
                    │    INIT     │
                    └──────┬──────┘
                           │
          ┌────────────────┴────────────────┐
          │ SOCKS4                    SOCKS5│
          ▼                                 ▼
    ┌──────────┐                  ┌─────────────────┐
    │ REQUEST  │                  │  METHOD_SENT    │
    │   SENT   │                  └────────┬────────┘
    └────┬─────┘                           │
         │                                 ▼
         │                        ┌─────────────────┐
         │                        │METHOD_RECEIVED  │
         │                        └────────┬────────┘
         │                                 │
         │                        ┌────────┴────────┐
         │                        │ No Auth    Auth │
         │                        │         ▼       │
         │                        │  ┌─────────┐   │
         │                        │  │  AUTH   │   │
         │                        │  │  SENT   │   │
         │                        │  └────┬────┘   │
         │                        │       │        │
         │                        │       ▼        │
         │                        │  ┌──────────┐  │
         │                        │  │  AUTH    │  │
         │                        │  │ RECEIVED │  │
         │                        │  └────┬─────┘  │
         │                        └───────┴────────┘
         │                                 │
         │                                 ▼
         │                        ┌─────────────────┐
         │                        │  REQUEST_SENT   │
         │                        └────────┬────────┘
         └────────────────────────────────┬┘
                                          │
                                          ▼
                                ┌──────────────────┐
                                │REQUEST_RECEIVED  │
                                └────────┬─────────┘
                                         │
                        ┌────────────────┴───────────────┐
                        │ TCP                      UDP   │
                        ▼                               ▼
                ┌─────────────┐               ┌──────────────┐
                │  CONNECTED  │               │  UDP_READY   │
                └─────────────┘               └──────────────┘
```

### Protocol Structures

#### SOCKS4 Request
```
+----+----+--------+--------+----------+----------+
|VER |CMD | DSTPORT| DSTIP  |  USERID  |   NULL   |
+----+----+--------+--------+----------+----------+
| 1  | 1  |   2    |   4    | variable |    1     |
+----+----+--------+--------+----------+----------+
```

#### SOCKS4 Response
```
+----+----+--------+--------+
|NULL|REP | BNDPORT| BNDIP  |
+----+----+--------+--------+
| 1  | 1  |   2    |   4    |
+----+----+--------+--------+
```

#### SOCKS5 Method Selection
```
Client Request:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

Server Response:
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
```

#### SOCKS5 Connection Request
```
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:
- ATYP = 0x01: DST.ADDR = 4 bytes (IPv4)
- ATYP = 0x03: DST.ADDR = 1 byte length + domain name
- ATYP = 0x04: DST.ADDR = 16 bytes (IPv6)
```

#### SOCKS5 Connection Response
```
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```

---

## API Reference

### Connection Management

```c
/* Allocate SOCKS connection context */
struct socks_connection *socks_connection_alloc(enum socks_version version);

/* Free SOCKS connection context */
void socks_connection_free(struct socks_connection *conn);
```

### SOCKS4 Functions

```c
/* Build SOCKS4 CONNECT request */
int socks4_build_connect_request(struct socks_connection *conn,
                                 const struct socks_addr *dest,
                                 const char *userid);

/* Parse SOCKS4 response */
int socks4_parse_response(struct socks_connection *conn,
                         const void *data, size_t len);
```

### SOCKS5 Functions

```c
/* Method selection */
int socks5_build_method_request(struct socks_connection *conn,
                               const __u8 *methods, __u8 nmethods);
int socks5_parse_method_response(struct socks_connection *conn,
                                const void *data, size_t len);

/* Authentication */
int socks5_build_auth_request(struct socks_connection *conn,
                             const char *username, const char *password);
int socks5_parse_auth_response(struct socks_connection *conn,
                              const void *data, size_t len);

/* Connection requests */
int socks5_build_connect_request(struct socks_connection *conn,
                                const struct socks_addr *dest);
int socks5_build_bind_request(struct socks_connection *conn,
                             const struct socks_addr *dest);
int socks5_build_udp_assoc_request(struct socks_connection *conn,
                                  const struct socks_addr *client_addr);

/* Response parsing */
int socks5_parse_response(struct socks_connection *conn,
                         const void *data, size_t len);

/* UDP support */
int socks5_build_udp_header(struct socks_connection *conn,
                           const struct socks_addr *dest,
                           void *buffer, size_t buffer_len);
int socks5_parse_udp_header(struct socks_connection *conn,
                           const void *data, size_t len,
                           struct socks_addr *dest);
```

### Helper Functions

```c
/* Address conversion */
int socks_addr_from_sockaddr(struct socks_addr *socks_addr,
                            const struct sockaddr *sa);
int socks_addr_to_sockaddr(const struct socks_addr *socks_addr,
                          struct sockaddr_storage *ss);

/* State information */
const char *socks_state_name(enum socks_state state);
const char *socks_version_name(enum socks_version version);
const char *socks5_reply_name(__u8 reply);
const char *socks4_reply_name(__u8 reply);

/* State validation */
bool socks_state_is_valid_transition(enum socks_state from,
                                     enum socks_state to);
int socks_validate_state(struct socks_connection *conn,
                        enum socks_state expected);
```

---

## Usage Examples

### Example 1: SOCKS5 Connection with No Authentication

```c
struct socks_connection *conn;
struct socks_addr dest;
__u8 methods[] = { SOCKS5_AUTH_NONE };
int ret;

/* Allocate connection */
conn = socks_connection_alloc(SOCKS_VERSION_5);
if (!conn)
    return -ENOMEM;

/* Build method request */
ret = socks5_build_method_request(conn, methods, 1);
if (ret < 0)
    goto error;

/* Send request to proxy server */
send_to_proxy(conn->buffer, ret);

/* Receive and parse method response */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = socks5_parse_method_response(conn, response_buffer, response_len);
if (ret < 0)
    goto error;

/* Build connection request */
dest.address_type = SOCKS5_ATYP_IPV4;
dest.addr.ipv4 = inet_addr("192.168.1.1");
dest.port = htons(80);

ret = socks5_build_connect_request(conn, &dest);
if (ret < 0)
    goto error;

/* Send connect request */
send_to_proxy(conn->buffer, ret);

/* Receive and parse response */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = socks5_parse_response(conn, response_buffer, response_len);
if (ret < 0)
    goto error;

/* Connection established! */
if (conn->state == SOCKS_STATE_CONNECTED) {
    printk("SOCKS5 connection successful\n");
}

error:
    socks_connection_free(conn);
    return ret;
```

### Example 2: SOCKS5 with Username/Password Authentication

```c
struct socks_connection *conn;
struct socks_addr dest;
__u8 methods[] = { SOCKS5_AUTH_USERPASS, SOCKS5_AUTH_NONE };
int ret;

conn = socks_connection_alloc(SOCKS_VERSION_5);

/* Offer username/password or no auth */
ret = socks5_build_method_request(conn, methods, 2);
send_to_proxy(conn->buffer, ret);

recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = socks5_parse_method_response(conn, response_buffer, response_len);

/* If server requires auth */
if (conn->auth.method == SOCKS5_AUTH_USERPASS) {
    ret = socks5_build_auth_request(conn, "username", "password");
    send_to_proxy(conn->buffer, ret);

    recv_from_proxy(response_buffer, sizeof(response_buffer));
    ret = socks5_parse_auth_response(conn, response_buffer, response_len);
    if (ret < 0) {
        printk("Authentication failed\n");
        goto error;
    }
}

/* Proceed with connection request... */
```

### Example 3: SOCKS4 Connection

```c
struct socks_connection *conn;
struct socks_addr dest;
int ret;

conn = socks_connection_alloc(SOCKS_VERSION_4);

/* Build SOCKS4 request */
dest.address_type = SOCKS5_ATYP_IPV4;
dest.addr.ipv4 = inet_addr("10.0.0.1");
dest.port = htons(443);

ret = socks4_build_connect_request(conn, &dest, "myuserid");
if (ret < 0)
    goto error;

send_to_proxy(conn->buffer, ret);

/* Parse response */
recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = socks4_parse_response(conn, response_buffer, response_len);

if (ret == 0 && conn->state == SOCKS_STATE_CONNECTED) {
    printk("SOCKS4 connection successful\n");
}

error:
    socks_connection_free(conn);
    return ret;
```

### Example 4: SOCKS5 UDP Association

```c
struct socks_connection *conn;
struct socks_addr client_addr;
struct socks_addr udp_dest;
char udp_packet[2048];
int header_len, ret;

conn = socks_connection_alloc(SOCKS_VERSION_5);

/* Perform method selection and auth (if needed) */
/* ... */

/* Request UDP association */
client_addr.address_type = SOCKS5_ATYP_IPV4;
client_addr.addr.ipv4 = my_ip;
client_addr.port = htons(0); /* Let server assign port */

ret = socks5_build_udp_assoc_request(conn, &client_addr);
send_to_proxy(conn->buffer, ret);

recv_from_proxy(response_buffer, sizeof(response_buffer));
ret = socks5_parse_response(conn, response_buffer, response_len);

if (ret == 0 && conn->state == SOCKS_STATE_UDP_READY) {
    /* UDP relay address is now in conn->udp_relay */
    printk("UDP association established at %pI4:%u\n",
           &conn->udp_relay.addr.ipv4,
           ntohs(conn->udp_relay.port));

    /* Build UDP packet with SOCKS5 header */
    udp_dest.address_type = SOCKS5_ATYP_DOMAIN;
    udp_dest.addr.domain.len = strlen("example.com");
    memcpy(udp_dest.addr.domain.name, "example.com", udp_dest.addr.domain.len);
    udp_dest.port = htons(53); /* DNS */

    header_len = socks5_build_udp_header(conn, &udp_dest,
                                        udp_packet, sizeof(udp_packet));

    /* Append actual data after header */
    memcpy(udp_packet + header_len, dns_query, dns_query_len);

    /* Send to UDP relay address */
    sendto(udp_sock, udp_packet, header_len + dns_query_len,
           (struct sockaddr *)&conn->udp_relay, ...);
}

socks_connection_free(conn);
```

---

## Integration with MUTEX

### Connection Tracking Integration

The SOCKS implementation integrates with the MUTEX connection tracking system:

```c
/* Attach SOCKS context to tracked connection */
int mutex_conn_attach_socks(struct mutex_connection *conn,
                           struct socks_connection *socks);

/* Retrieve SOCKS context from tracked connection */
struct socks_connection *mutex_conn_get_socks(struct mutex_connection *conn);

/* Process SOCKS handshake during connection establishment */
int mutex_socks_process_handshake(struct mutex_connection *conn,
                                 struct sk_buff *skb);

/* Establish SOCKS proxy connection */
int mutex_socks_establish_connection(struct mutex_connection *conn);

/* Setup UDP association for UDP traffic */
int mutex_socks_setup_udp_assoc(struct mutex_connection *conn);

/* Handle SOCKS protocol errors */
void mutex_socks_handle_error(struct mutex_connection *conn, int error);
```

### Typical Integration Flow

```
1. Application initiates connection
2. Netfilter hook intercepts packet
3. Connection tracking creates new connection entry
4. SOCKS context allocated and attached to connection
5. SOCKS handshake performed:
   a. Method selection (SOCKS5)
   b. Authentication (if required)
   c. Connection request
6. SOCKS proxy establishes actual connection
7. Connection marked as established
8. Data flows through proxy connection
```

---

## Statistics and Monitoring

### Statistics Structure

```c
struct socks_statistics {
    atomic64_t socks4_connections;     /* SOCKS4 connections */
    atomic64_t socks5_connections;     /* SOCKS5 connections */
    atomic64_t handshakes_success;     /* Successful handshakes */
    atomic64_t handshakes_failed;      /* Failed handshakes */
    atomic64_t auth_attempts;          /* Authentication attempts */
    atomic64_t auth_failures;          /* Authentication failures */
    atomic64_t udp_associations;       /* UDP associations */
    atomic64_t dns_resolutions;        /* DNS resolutions */
    atomic64_t protocol_errors;        /* Protocol errors */
};
```

### Viewing Statistics

Statistics are printed when the module is unloaded:

```bash
$ sudo rmmod mutex
[  123.456] MUTEX SOCKS Statistics:
[  123.456]   SOCKS4 connections: 42
[  123.456]   SOCKS5 connections: 158
[  123.456]   Handshakes success: 195
[  123.456]   Handshakes failed: 5
[  123.456]   Auth attempts: 120
[  123.456]   Auth failures: 2
[  123.456]   UDP associations: 15
[  123.456]   DNS resolutions: 87
[  123.456]   Protocol errors: 3
```

---

## Module Parameters

### socks_timeout
**Type:** unsigned int  
**Default:** 30  
**Description:** SOCKS connection timeout in seconds

```bash
# Load module with custom timeout
sudo insmod mutex.ko socks_timeout=60

# Change at runtime
echo 45 | sudo tee /sys/module/mutex/parameters/socks_timeout
```

### socks_debug
**Type:** bool  
**Default:** false  
**Description:** Enable verbose debug logging

```bash
# Enable debug logging
sudo insmod mutex.ko socks_debug=1

# Toggle at runtime
echo 1 | sudo tee /sys/module/mutex/parameters/socks_debug
```

---

## Protocol Support Matrix

| Feature                    | SOCKS4 | SOCKS4a | SOCKS5 |
|----------------------------|:------:|:-------:|:------:|
| IPv4 addressing            |   ✅   |   ✅    |   ✅   |
| IPv6 addressing            |   ❌   |   ❌    |   ✅   |
| Domain name resolution     |   ❌   |   ✅    |   ✅   |
| TCP CONNECT                |   ✅   |   ✅    |   ✅   |
| TCP BIND                   |   ✅   |   ✅    |   ✅   |
| UDP ASSOCIATE              |   ❌   |   ❌    |   ✅   |
| No authentication          |   ✅   |   ✅    |   ✅   |
| Username/Password auth     |   ❌   |   ❌    |   ✅   |
| GSSAPI auth                |   ❌   |   ❌    |   🔜   |
| User ID                    |   ✅   |   ✅    |   ❌   |

Legend: ✅ Implemented, ❌ Not supported, 🔜 Planned

---

## Error Handling

### SOCKS4 Reply Codes

| Code | Value | Description                  | Error Code      |
|------|-------|------------------------------|-----------------|
| 0x5A | 90    | Request granted              | 0 (success)     |
| 0x5B | 91    | Request rejected/failed      | -ECONNREFUSED   |
| 0x5C | 92    | Cannot connect to identd     | -ENETUNREACH    |
| 0x5D | 93    | User ID mismatch            | -EACCES         |

### SOCKS5 Reply Codes

| Code | Value | Description                  | Error Code      |
|------|-------|------------------------------|-----------------|
| 0x00 | 0     | Succeeded                    | 0 (success)     |
| 0x01 | 1     | General SOCKS failure        | -ECONNREFUSED   |
| 0x02 | 2     | Connection not allowed       | -EACCES         |
| 0x03 | 3     | Network unreachable          | -ENETUNREACH    |
| 0x04 | 4     | Host unreachable             | -ENETUNREACH    |
| 0x05 | 5     | Connection refused           | -ECONNREFUSED   |
| 0x06 | 6     | TTL expired                  | -ETIMEDOUT      |
| 0x07 | 7     | Command not supported        | -EOPNOTSUPP     |
| 0x08 | 8     | Address type not supported   | -EOPNOTSUPP     |
| 0xFF | 255   | No acceptable methods        | -EACCES         |

---

## Testing

### Unit Tests

```bash
# Build with test support
make test

# Run SOCKS protocol tests
./test_socks
```

### Manual Testing with Real Proxy

```bash
# Start a SOCKS5 proxy (e.g., using ssh)
ssh -D 1080 user@remote-host

# Load MUTEX module
sudo insmod mutex.ko socks_debug=1

# Configure to use SOCKS5 proxy
# (Configuration commands depend on implementation in Branch 5)

# Test connection
curl --proxy socks5://localhost:1080 http://example.com

# Check kernel logs
dmesg | grep "MUTEX SOCKS"
```

### Testing SOCKS4

```bash
# Configure for SOCKS4 proxy
# (Using dante-server or similar)

# Test connection
curl --proxy socks4://localhost:1080 http://example.com
```

---

## Performance Considerations

### Memory Usage

- **Per-connection overhead:** ~5 KB
  - Connection structure: ~1 KB
  - Working buffer: 4 KB (configurable)
  - Authentication data: 512 bytes

### Processing Overhead

- **SOCKS4:** Minimal (single request/response exchange)
- **SOCKS5 (no auth):** Low (two request/response exchanges)
- **SOCKS5 (with auth):** Medium (three request/response exchanges)

### Optimizations

1. **Connection pooling:** Reuse SOCKS connections for multiple data streams
2. **Authentication caching:** Cache successful credentials
3. **Buffer reuse:** Single buffer per connection, not per packet
4. **Zero-copy:** Minimize memory copies during packet processing

---

## Known Limitations

1. **GSSAPI authentication:** Not yet implemented (planned)
2. **UDP fragmentation:** Not supported in current implementation
3. **IPv6 in SOCKS4:** Not supported (use SOCKS5 for IPv6)
4. **Multiple authentication methods:** Server can only select one method

---

## Security Considerations

### Credential Handling

- Credentials stored in kernel memory (non-pageable)
- Cleared on connection close with `memset()`
- Not written to logs (even in debug mode)

### Buffer Security

- All buffers bounds-checked
- Input validation on all received data
- Protocol version validation
- Address type validation

### State Machine Security

- State transitions validated
- Invalid transitions rejected
- Error states properly handled
- Timeout enforcement (planned)

---

## Future Enhancements

### Planned for Branch 10 (Transparent Proxying)
- [ ] Automatic SOCKS handshake for intercepted connections
- [ ] DNS resolution through SOCKS proxy
- [ ] Connection pooling and reuse
- [ ] Automatic failover between proxies

### Planned for Branch 13 (Performance Optimization)
- [ ] Connection caching
- [ ] Authentication credential caching
- [ ] Fast-path for established connections
- [ ] Zero-copy packet handling

### Planned for Branch 14 (Security Hardening)
- [ ] GSSAPI authentication support
- [ ] Credential encryption at rest
- [ ] Secure random number generation
- [ ] Audit logging

---

## References

### Standards

- **RFC 1928:** SOCKS Protocol Version 5
- **RFC 1929:** Username/Password Authentication for SOCKS V5
- **RFC 1961:** GSS-API Authentication Method for SOCKS Version 5
- **SOCKS4 Protocol:** http://www.openssh.com/txt/socks4.protocol
- **SOCKS4a Extension:** http://www.openssh.com/txt/socks4a.protocol

### Related Documentation

- [Branch Plan](BRANCH_PLAN.md)
- [Branch 6: Connection Tracking](BRANCH_6_SUMMARY.md)
- [Branch 7: Packet Rewriting](BRANCH_7_SUMMARY.md)
- [Netfilter Hooks Documentation](NETFILTER_HOOKS.md)

---

## Changelog

### Version 1.0 (December 20, 2025)

**Initial implementation:**
- ✅ SOCKS4 protocol support
- ✅ SOCKS4a protocol support  
- ✅ SOCKS5 protocol support
- ✅ Method selection (no auth, username/password)
- ✅ TCP CONNECT command
- ✅ TCP BIND command
- ✅ UDP ASSOCIATE command
- ✅ IPv4, IPv6, and domain addressing
- ✅ UDP header building/parsing
- ✅ State machine implementation
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
*Branch: feature/socks-protocol*  
*Status: Complete*
