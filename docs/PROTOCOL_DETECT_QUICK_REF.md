# Protocol Detection Quick Reference

## Quick Start

### 1. Enable Protocol Detection

```c
#include "mutex_protocol_detect_api.h"

int fd = mutex_proto_open();
if (fd < 0) {
    fprintf(stderr, "Error: %s\n", mutex_proto_get_error_string(fd));
    return 1;
}

mutex_proto_enable(fd);
```

### 2. Add Detection Rules

```c
// Detect HTTPS on port 443
struct protocol_rule rule;
mutex_proto_create_port_rule(PROTO_HTTPS, 443, IPPROTO_TCP, &rule);
mutex_proto_add_rule(fd, &rule);
```

### 3. Add Routing Rules

```c
// Route all HTTPS through proxy
struct protocol_routing_rule route;
mutex_proto_create_routing_rule(PROTO_HTTPS, ACTION_PROXY, 100, &route);
mutex_proto_add_route(fd, &route);
```

### 4. Get Statistics

```c
struct protocol_detection_stats stats;
mutex_proto_get_stats(fd, &stats);
mutex_proto_print_stats(&stats);
```

### 5. Cleanup

```c
mutex_proto_disable(fd);
mutex_proto_close(fd);
```

## Protocol Types

| Enum Value | Protocol | Common Port(s) |
|------------|----------|----------------|
| `PROTO_HTTP` | HTTP | 80, 8080 |
| `PROTO_HTTPS` | HTTPS/TLS | 443, 8443 |
| `PROTO_DNS` | DNS | 53 |
| `PROTO_SSH` | SSH | 22 |
| `PROTO_FTP` | FTP | 21 |
| `PROTO_SMTP` | SMTP | 25, 587 |
| `PROTO_POP3` | POP3 | 110, 995 |
| `PROTO_IMAP` | IMAP | 143, 993 |
| `PROTO_TELNET` | Telnet | 23 |
| `PROTO_RDP` | RDP | 3389 |
| `PROTO_VNC` | VNC | 5900+ |
| `PROTO_SOCKS4` | SOCKS4 | 1080 |
| `PROTO_SOCKS5` | SOCKS5 | 1080 |
| `PROTO_BITTORRENT` | BitTorrent | Various |
| `PROTO_QUIC` | QUIC | 443 |
| `PROTO_RTSP` | RTSP | 554 |
| `PROTO_SIP` | SIP | 5060 |
| `PROTO_IRC` | IRC | 6667-6669 |
| `PROTO_XMPP` | XMPP | 5222, 5269 |
| `PROTO_OPENVPN` | OpenVPN | 1194 |
| `PROTO_WIREGUARD` | WireGuard | 51820 |
| `PROTO_TLS_GENERIC` | TLS (no SNI) | 443 |
| `PROTO_DTLS` | DTLS | Various |

## Routing Actions

| Action | Description |
|--------|-------------|
| `ACTION_PROXY` | Route through proxy server |
| `ACTION_DIRECT` | Allow direct connection |
| `ACTION_BLOCK` | Block the connection |
| `ACTION_INSPECT` | Continue inspecting |
| `ACTION_DEFAULT` | Use default policy |

## Confidence Levels

| Level | Value | Description |
|-------|-------|-------------|
| `CONFIDENCE_NONE` | 0 | No detection |
| `CONFIDENCE_LOW` | 1 | Port-based detection |
| `CONFIDENCE_MEDIUM` | 2 | Port + pattern match |
| `CONFIDENCE_HIGH` | 3 | Deep inspection match |
| `CONFIDENCE_CERTAIN` | 4 | Handshake verified |

## Detection Methods

| Method | Bitmask | Description |
|--------|---------|-------------|
| `METHOD_PORT` | 0x01 | Port-based detection |
| `METHOD_PATTERN` | 0x02 | Pattern matching |
| `METHOD_HEURISTIC` | 0x04 | Heuristic analysis |
| `METHOD_DPI` | 0x08 | Deep packet inspection |
| `METHOD_SNI` | 0x10 | SNI parsing for TLS |
| `METHOD_HANDSHAKE` | 0x20 | Handshake analysis |

## Common Use Cases

### Use Case 1: Route All HTTPS Through Proxy

```c
// Enable protocol detection
mutex_proto_enable(fd);

// Add HTTPS routing rule
struct protocol_routing_rule route;
mutex_proto_create_routing_rule(PROTO_HTTPS, ACTION_PROXY, 100, &route);
mutex_proto_add_route(fd, &route);

// Set default action for other protocols
mutex_proto_set_default_action(fd, ACTION_DIRECT);
```

### Use Case 2: Block BitTorrent Traffic

```c
// Create routing rule to block BitTorrent
struct protocol_routing_rule route;
mutex_proto_create_routing_rule(PROTO_BITTORRENT, ACTION_BLOCK, 200, &route);
mutex_proto_add_route(fd, &route);
```

### Use Case 3: Direct Connection for Specific Domains

```c
// Route example.com directly (bypass proxy)
struct protocol_routing_rule route;
mutex_proto_create_host_routing_rule(
    PROTO_HTTPS,
    "example.com",
    ACTION_DIRECT,
    300,  // High priority
    &route
);
mutex_proto_add_route(fd, &route);

// Default: proxy all other HTTPS
struct protocol_routing_rule default_route;
mutex_proto_create_routing_rule(PROTO_HTTPS, ACTION_PROXY, 100, &default_route);
mutex_proto_add_route(fd, &default_route);
```

### Use Case 4: Custom Pattern Detection

```c
// Detect custom protocol by pattern
uint8_t pattern[] = { 0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't' };
struct protocol_rule rule;
mutex_proto_create_pattern_rule(
    PROTO_BITTORRENT,
    pattern,
    sizeof(pattern),
    0,  // Offset at start of packet
    &rule
);
mutex_proto_add_rule(fd, &rule);
```

### Use Case 5: Monitor Protocol Statistics

```c
// Get statistics periodically
while (running) {
    struct protocol_detection_stats stats;
    mutex_proto_get_stats(fd, &stats);

    printf("HTTPS detected: %lu\n", stats.proto_detected[PROTO_HTTPS]);
    printf("Cache hit rate: %.2f%%\n",
           (double)stats.cache_hits / (stats.cache_hits + stats.cache_misses) * 100);

    sleep(5);
}
```

## Configuration Options

### Set Inspection Depth

```c
// Inspect up to 2KB of each packet
mutex_proto_set_depth(fd, 2048);
```

### Set Connection Timeout

```c
// Cache connections for 10 minutes
mutex_proto_set_timeout(fd, 600);
```

### Set Default Action

```c
// Default: route unknown protocols through proxy
mutex_proto_set_default_action(fd, ACTION_PROXY);
```

## Cache Management

### Flush Connection Cache

```c
// Clear all cached connection states
mutex_proto_flush_cache(fd);
```

### Reset Statistics

```c
// Reset all counters to zero
mutex_proto_reset_stats(fd);
```

## Error Handling

```c
int ret = mutex_proto_add_rule(fd, &rule);
if (ret != PROTO_API_SUCCESS) {
    fprintf(stderr, "Error: %s\n", mutex_proto_get_error_string(ret));
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `PROTO_API_SUCCESS` | Operation successful |
| `PROTO_API_ERROR` | Generic error |
| `PROTO_API_INVALID_FD` | Invalid file descriptor |
| `PROTO_API_INVALID_ARG` | Invalid argument |
| `PROTO_API_NO_DEVICE` | Device not found |
| `PROTO_API_PERMISSION` | Permission denied |

## Performance Tips

1. **Enable Caching** - Default is enabled, keeps connection state cached
2. **Limit Inspection Depth** - Lower depth = faster inspection
3. **Use Port-based Rules** - Fastest detection method
4. **Monitor Cache Hit Rate** - High hit rate = better performance
5. **Clear Stale Connections** - Adjust timeout based on traffic patterns

## Statistics Fields

```c
struct protocol_detection_stats {
    uint64_t proto_detected[PROTO_MAX];      // Per-protocol counters
    uint64_t proto_errors[PROTO_MAX];        // Per-protocol errors
    uint64_t method_port_hits;               // Port detection hits
    uint64_t method_pattern_hits;            // Pattern match hits
    uint64_t method_heuristic_hits;          // Heuristic hits
    uint64_t method_dpi_hits;                // DPI hits
    uint64_t method_sni_hits;                // SNI parsing hits
    uint64_t method_handshake_hits;          // Handshake hits
    uint64_t routed_proxy;                   // Routed via proxy
    uint64_t routed_direct;                  // Routed directly
    uint64_t routed_blocked;                 // Blocked connections
    uint64_t total_packets;                  // Total packets seen
    uint64_t total_inspections;              // Total inspections
    uint64_t cache_hits;                     // Cache hits
    uint64_t cache_misses;                   // Cache misses
};
```

## Helper Functions

### Get Protocol Name

```c
const char *name = protocol_name(PROTO_HTTPS);
printf("Protocol: %s\n", name);  // "https"
```

### Get Confidence Name

```c
const char *conf = protocol_confidence_name(CONFIDENCE_HIGH);
printf("Confidence: %s\n", conf);  // "high"
```

### Get Action Name

```c
const char *action = protocol_action_name(ACTION_PROXY);
printf("Action: %s\n", action);  // "proxy"
```

## Rule Priority System

Rules are evaluated by priority (higher = first):

```c
// Priority 300: High priority - evaluated first
mutex_proto_create_host_routing_rule(PROTO_HTTPS, "important.com",
                                     ACTION_DIRECT, 300, &rule);

// Priority 200: Medium priority
mutex_proto_create_host_routing_rule(PROTO_HTTPS, "work.com",
                                     ACTION_PROXY, 200, &rule);

// Priority 100: Low priority - default for all HTTPS
mutex_proto_create_routing_rule(PROTO_HTTPS, ACTION_PROXY, 100, &rule);
```

## Complete Example Program

```c
#include <stdio.h>
#include "mutex_protocol_detect_api.h"

int main(void)
{
    int fd;
    struct protocol_routing_rule route;
    struct protocol_detection_stats stats;

    // Open device
    fd = mutex_proto_open();
    if (fd < 0) {
        fprintf(stderr, "Failed to open: %s\n",
                mutex_proto_get_error_string(fd));
        return 1;
    }

    // Enable detection
    if (mutex_proto_enable(fd) != 0) {
        fprintf(stderr, "Failed to enable\n");
        mutex_proto_close(fd);
        return 1;
    }

    // Route HTTPS through proxy
    mutex_proto_create_routing_rule(PROTO_HTTPS, ACTION_PROXY, 100, &route);
    mutex_proto_add_route(fd, &route);

    // Block BitTorrent
    mutex_proto_create_routing_rule(PROTO_BITTORRENT, ACTION_BLOCK, 200, &route);
    mutex_proto_add_route(fd, &route);

    // Get statistics
    mutex_proto_get_stats(fd, &stats);
    mutex_proto_print_stats(&stats);

    // Cleanup
    mutex_proto_disable(fd);
    mutex_proto_close(fd);

    return 0;
}
```

## Compilation

```bash
gcc -o myapp myapp.c mutex_protocol_detect_api.c -Wall -Wextra
```

## See Also

- Full API documentation: `src/module/mutex_protocol_detect.h`
- Implementation summary: `docs/BRANCH_12_SUMMARY.md`
- Test suite: `src/userspace/test_protocol_detect.c`
