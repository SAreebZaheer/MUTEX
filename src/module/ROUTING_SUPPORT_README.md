# Advanced Routing Support for MUTEX Proxy

This module provides comprehensive routing and load balancing capabilities for the MUTEX transparent proxy system, enabling sophisticated traffic distribution, policy-based routing, and high availability configurations.

## Features

- **Multiple Routing Tables**: Support for multiple independent routing tables with priority-based lookup
- **Policy-Based Routing**: Route traffic based on source/destination IP, port, protocol, time, and other criteria
- **Load Balancing**: Six different algorithms to distribute traffic across multiple proxy servers
- **Failover**: Automatic detection and handling of server failures
- **Routing Cache**: High-performance cache with hash-based lookups
- **GeoIP Support**: Infrastructure for geographic routing (requires external GeoIP database)
- **Connection Tracking**: Integration with connection tracking for consistent routing
- **Statistics**: Comprehensive per-server and per-group statistics

## Architecture

### Components

1. **Routing Tables**: Red-black tree-based routing tables for efficient prefix matching
2. **Server Groups**: Collections of proxy servers with load balancing
3. **Policy Rules**: Priority-based rules for traffic classification
4. **Routing Cache**: Hash table for caching routing decisions
5. **Statistics**: Per-server and per-group counters

### Data Flow

```
Packet → Policy Rules → Routing Table → Server Group → Load Balancing → Proxy Server
         ↓                                               ↓
         Route Cache ← Cache Lookup                     Statistics
```

## Load Balancing Algorithms

### 1. Round Robin (ROUTING_LB_ROUND_ROBIN)
Simple round-robin distribution across all available servers.

**Use Cases:**
- Uniform traffic distribution
- Servers with similar capacity
- Stateless applications

**Example:**
```c
struct routing_server_group *group = routing_group_create("web-proxies");
routing_group_set_lb_algorithm(group, ROUTING_LB_ROUND_ROBIN);
```

### 2. Least Connections (ROUTING_LB_LEAST_CONN)
Routes traffic to the server with the fewest active connections.

**Use Cases:**
- Long-lived connections
- Servers with varying capacity
- Load-sensitive applications

**Performance:**
- Best for: Connection-based load distribution
- Overhead: O(n) server scan per routing decision

### 3. Weighted (ROUTING_LB_WEIGHTED)
Distributes traffic based on server weights (capacity/performance).

**Use Cases:**
- Heterogeneous server capacities
- Gradual traffic migration
- A/B testing with controlled ratios

**Configuration:**
```c
routing_group_add_server(group, "10.0.1.1", 8080, 100);  // Weight: 100
routing_group_add_server(group, "10.0.1.2", 8080, 50);   // Weight: 50
// Traffic ratio will be 2:1
```

### 4. Random (ROUTING_LB_RANDOM)
Randomly selects an available server.

**Use Cases:**
- Simple distribution without state
- Testing/development
- Uniform server capacity

### 5. Hash-Based (ROUTING_LB_HASH)
Consistent hash based on source IP, ensuring same client always routes to same server.

**Use Cases:**
- Session affinity
- Cache locality
- Stateful applications

**Benefits:**
- Client consistency across requests
- Cache hit rate improvement
- No session state required

### 6. Least Latency (ROUTING_LB_LEAST_LATENCY)
Routes to the server with the lowest average response latency.

**Use Cases:**
- Performance-critical applications
- Geographic distribution
- Latency-sensitive workloads

**Metrics:**
- Tracks average latency per server
- Updates based on actual response times

## API Reference

### Initialization

```c
int routing_init(void);
void routing_cleanup(void);
```

Initialize and cleanup the routing subsystem. Must be called before/after using any routing functions.

### Routing Table Management

#### Create/Destroy Tables

```c
struct routing_table *routing_table_create(const char *name, int priority);
void routing_table_destroy(struct routing_table *table);
```

**Parameters:**
- `name`: Human-readable table identifier
- `priority`: Table lookup priority (higher = checked first)

**Example:**
```c
struct routing_table *table = routing_table_create("main", 100);
```

#### Add/Remove Routes

```c
int routing_table_add_route(struct routing_table *table,
                            const struct in6_addr *prefix,
                            int prefix_len,
                            struct routing_server_group *group,
                            u32 metric);

void routing_table_remove_route(struct routing_table *table,
                                const struct in6_addr *prefix,
                                int prefix_len);
```

**Parameters:**
- `prefix`: IPv6 prefix (supports both IPv4-mapped and native IPv6)
- `prefix_len`: Prefix length (0-128 for IPv6, 0-32 for IPv4)
- `group`: Server group to use for this route
- `metric`: Route metric (lower = preferred)

**Example:**
```c
struct in6_addr prefix;
inet_pton(AF_INET6, "2001:db8::/32", &prefix);
routing_table_add_route(table, &prefix, 32, group, 100);
```

### Server Group Management

#### Create Groups

```c
struct routing_server_group *routing_group_create(const char *name);
void routing_group_destroy(struct routing_server_group *group);
```

#### Add Servers

```c
int routing_group_add_server(struct routing_server_group *group,
                             const char *ip,
                             u16 port,
                             u32 weight);
```

**Parameters:**
- `ip`: Server IP address (IPv4 or IPv6)
- `port`: Server port
- `weight`: Server weight for weighted load balancing (1-10000)

**Example:**
```c
struct routing_server_group *group = routing_group_create("us-west");
routing_group_add_server(group, "10.1.1.1", 8080, 100);
routing_group_add_server(group, "10.1.1.2", 8080, 100);
routing_group_add_server(group, "10.1.1.3", 8080, 50);
```

#### Configure Load Balancing

```c
void routing_group_set_lb_algorithm(struct routing_server_group *group,
                                    enum routing_lb_algorithm algo);
void routing_group_set_failover_strategy(struct routing_server_group *group,
                                         enum routing_failover_strategy strategy);
```

**Failover Strategies:**
- `ROUTING_FAILOVER_IMMEDIATE`: Fail over immediately on error
- `ROUTING_FAILOVER_DELAYED`: Wait for multiple failures before failover
- `ROUTING_FAILOVER_PROBE`: Active health checking

### Policy-Based Routing

#### Add/Remove Rules

```c
int routing_add_policy_rule(struct routing_policy_rule *rule);
void routing_remove_policy_rule(u32 rule_id);
```

**Rule Structure:**
```c
struct routing_policy_rule {
    u32 rule_id;
    int priority;  // Higher = checked first

    // Match criteria
    struct in6_addr src_prefix;
    int src_prefix_len;
    struct in6_addr dst_prefix;
    int dst_prefix_len;
    u16 src_port_min, src_port_max;
    u16 dst_port_min, dst_port_max;
    u8 protocol;  // 0 = any
    u32 mark;     // fwmark
    char iif[IFNAMSIZ];  // Input interface
    char oif[IFNAMSIZ];  // Output interface

    // Time-based routing
    struct {
        u8 enabled;
        u8 hour_start, hour_end;
        u8 day_start, day_end;
    } time_range;

    // Action
    struct routing_table *table;  // Route table to use
    struct routing_server_group *group;  // Or direct group
};
```

**Example: Route HTTP traffic to specific group:**
```c
struct routing_policy_rule rule = {
    .rule_id = 1,
    .priority = 100,
    .dst_port_min = 80,
    .dst_port_max = 80,
    .protocol = IPPROTO_TCP,
    .group = web_group,
};
routing_add_policy_rule(&rule);
```

**Example: Time-based routing:**
```c
struct routing_policy_rule rule = {
    .rule_id = 2,
    .priority = 200,
    .time_range = {
        .enabled = 1,
        .hour_start = 9,   // 9 AM
        .hour_end = 17,    // 5 PM
        .day_start = 1,    // Monday
        .day_end = 5,      // Friday
    },
    .table = business_hours_table,
};
routing_add_policy_rule(&rule);
```

### Routing Lookups

```c
struct routing_server *routing_lookup(const struct sk_buff *skb,
                                     const struct in6_addr *dst,
                                     u16 dst_port,
                                     u8 protocol);
```

Performs complete routing lookup including policy rules, routing tables, and load balancing.

**Returns:**
- Pointer to selected server, or NULL if no route found

**Process:**
1. Check routing cache
2. Match policy rules by priority
3. Lookup route in appropriate table
4. Select server from group using load balancing
5. Cache decision

### Routing Cache

```c
int routing_cache_init(void);
void routing_cache_destroy(void);
void routing_cache_flush(void);
```

**Cache Characteristics:**
- Hash table with 4096 buckets
- Per-entry spinlocks for concurrency
- 300 second entry timeout
- Automatic cleanup of stale entries

### Statistics

#### Per-Server Statistics

```c
struct routing_server_stats {
    atomic64_t total_packets;      // Total packets routed
    atomic64_t total_bytes;        // Total bytes routed
    atomic_t active_connections;   // Current active connections
    atomic64_t total_connections;  // Total connections ever
    atomic64_t failed_connections; // Failed connection attempts

    // Latency tracking (microseconds)
    atomic64_t total_latency_us;   // Sum of all latencies
    atomic64_t min_latency_us;     // Minimum observed latency
    atomic64_t max_latency_us;     // Maximum observed latency
    atomic_t latency_samples;      // Number of samples
};
```

#### Access Statistics

```c
// Per-server
server->stats.total_packets++;
atomic_inc(&server->stats.active_connections);

// Per-group
group->stats.total_requests++;
group->stats.total_load_balanced++;
```

## Integration with MUTEX Proxy

### Connection Tracking Integration

The routing system integrates with connection tracking to maintain consistent routing for established connections:

```c
// In packet processing
struct routing_server *server = routing_lookup(skb, &dst, dst_port, protocol);
if (server) {
    // Store routing decision in connection tracking
    conn_entry->routing_server = server;

    // Update statistics
    atomic64_inc(&server->stats.total_packets);
    atomic_inc(&server->stats.active_connections);
}
```

### Proxy Configuration Integration

Server groups can be automatically populated from proxy configuration:

```c
void routing_sync_from_proxy_config(struct mutex_proxy_context *ctx) {
    struct routing_server_group *group = routing_group_create("default");

    list_for_each_entry(proxy, &ctx->proxy_list, list) {
        routing_group_add_server(group, proxy->ip, proxy->port, 100);
    }

    routing_table_add_route(default_table, &any_prefix, 0, group, 1000);
}
```

## Configuration Examples

### Basic Setup: Single Routing Table

```c
// Initialize routing subsystem
routing_init();

// Create default table
struct routing_table *table = routing_table_create("default", 100);

// Create server group
struct routing_server_group *group = routing_group_create("proxies");
routing_group_set_lb_algorithm(group, ROUTING_LB_ROUND_ROBIN);

// Add servers
routing_group_add_server(group, "10.0.1.1", 8080, 100);
routing_group_add_server(group, "10.0.1.2", 8080, 100);

// Add default route
struct in6_addr any = IN6ADDR_ANY_INIT;
routing_table_add_route(table, &any, 0, group, 100);
```

### Advanced: Multi-Table with Policy Routing

```c
// Initialize
routing_init();

// Create multiple tables
struct routing_table *web_table = routing_table_create("web", 200);
struct routing_table *api_table = routing_table_create("api", 200);
struct routing_table *default_table = routing_table_create("default", 100);

// Create server groups
struct routing_server_group *web_group = routing_group_create("web-servers");
routing_group_set_lb_algorithm(web_group, ROUTING_LB_LEAST_CONN);
routing_group_add_server(web_group, "10.0.1.1", 80, 100);
routing_group_add_server(web_group, "10.0.1.2", 80, 100);

struct routing_server_group *api_group = routing_group_create("api-servers");
routing_group_set_lb_algorithm(api_group, ROUTING_LB_HASH);
routing_group_add_server(api_group, "10.0.2.1", 8080, 100);
routing_group_add_server(api_group, "10.0.2.2", 8080, 100);

// Add routes to tables
struct in6_addr any = IN6ADDR_ANY_INIT;
routing_table_add_route(web_table, &any, 0, web_group, 100);
routing_table_add_route(api_table, &any, 0, api_group, 100);

// Add policy rules
struct routing_policy_rule web_rule = {
    .rule_id = 1,
    .priority = 200,
    .dst_port_min = 80,
    .dst_port_max = 80,
    .protocol = IPPROTO_TCP,
    .table = web_table,
};
routing_add_policy_rule(&web_rule);

struct routing_policy_rule api_rule = {
    .rule_id = 2,
    .priority = 200,
    .dst_port_min = 8080,
    .dst_port_max = 8080,
    .protocol = IPPROTO_TCP,
    .table = api_table,
};
routing_add_policy_rule(&api_rule);
```

### Geographic Routing with GeoIP

```c
// Create region-specific groups
struct routing_server_group *us_group = routing_group_create("us-servers");
struct routing_server_group *eu_group = routing_group_create("eu-servers");
struct routing_server_group *asia_group = routing_group_create("asia-servers");

routing_group_add_server(us_group, "10.1.1.1", 8080, 100);
routing_group_add_server(eu_group, "10.2.1.1", 8080, 100);
routing_group_add_server(asia_group, "10.3.1.1", 8080, 100);

// Add GeoIP data to policy rules
struct routing_policy_rule us_rule = {
    .rule_id = 10,
    .priority = 300,
    .geoip_country = "US",
    .group = us_group,
};

struct routing_policy_rule eu_rule = {
    .rule_id = 11,
    .priority = 300,
    .geoip_country = "EU",
    .group = eu_group,
};
```

## Performance Considerations

### Routing Cache

- **Hit Rate**: Typically 95%+ for established connections
- **Lookup Time**: O(1) hash lookup vs O(log n) routing table lookup
- **Memory Usage**: ~256 bytes per cached entry
- **Timeout**: 300 seconds (adjustable)

### Load Balancing Performance

| Algorithm | Lookup Time | State Required | Best Use Case |
|-----------|-------------|----------------|---------------|
| Round Robin | O(1) | Minimal | Uniform distribution |
| Least Conn | O(n) | Per-server counters | Load-based |
| Weighted | O(n) | Per-server weights | Capacity-based |
| Random | O(1) | None | Simple distribution |
| Hash | O(1) | None | Session affinity |
| Least Latency | O(n) | Latency tracking | Performance-critical |

### Scalability

- **Routing Tables**: Red-black trees scale to millions of routes (O(log n) lookup)
- **Server Groups**: Linear scan of servers (keep groups small, typically <100 servers)
- **Policy Rules**: Linear scan by priority (keep rules <1000 for best performance)
- **Cache**: Hash table with O(1) lookups

## Monitoring and Debugging

### Statistics Access

```c
// Print server statistics
printk(KERN_INFO "Server %s: packets=%llu, conns=%llu, avg_latency=%llu us\n",
       server->ip,
       atomic64_read(&server->stats.total_packets),
       atomic64_read(&server->stats.total_connections),
       atomic64_read(&server->stats.total_latency_us) /
           max(1, atomic_read(&server->stats.latency_samples)));
```

### Debug Logging

Enable debug logging by defining `ROUTING_DEBUG`:

```c
#define ROUTING_DEBUG 1
```

This will log:
- Routing decisions
- Load balancing selections
- Cache hits/misses
- Failover events

## Testing

See [test_routing.c](test_routing.c) for comprehensive test suite covering:

1. Routing table operations
2. Server group management
3. Load balancing algorithms
4. Policy rule matching
5. Routing cache
6. Failover handling
7. Statistics tracking
8. IPv4/IPv6 dual-stack
9. Performance benchmarks

Run tests:
```bash
cd /home/areeb/MUTEX/src/module
make test_routing
./test_routing
```

## Troubleshooting

### No Route Found

**Symptoms**: routing_lookup returns NULL

**Causes:**
- No matching policy rule
- Empty routing table
- All servers in group are down

**Solution:**
```c
// Add default catch-all route
struct in6_addr any = IN6ADDR_ANY_INIT;
routing_table_add_route(default_table, &any, 0, fallback_group, 1000);
```

### Uneven Load Distribution

**Symptoms**: One server receives disproportionate traffic

**Causes:**
- Wrong load balancing algorithm
- Incorrect server weights
- Hash-based algorithm with skewed client IPs

**Solution:**
- Switch to ROUTING_LB_LEAST_CONN or ROUTING_LB_ROUND_ROBIN
- Adjust server weights
- Check routing cache (may be caching old decisions)

### High Memory Usage

**Symptoms**: Kernel memory usage growing

**Causes:**
- Routing cache not expiring entries
- Too many routing tables/rules
- Memory leak

**Solution:**
```c
// Flush routing cache
routing_cache_flush();

// Check cache size
printk(KERN_INFO "Cache entries: %d\n", routing_cache_count());
```

## Future Enhancements

1. **Active Health Checking**: Periodic probes to detect server failures
2. **Dynamic Weights**: Adjust weights based on server load
3. **Connection Draining**: Graceful server removal
4. **Rate Limiting**: Per-server/per-group rate limits
5. **GeoIP Integration**: Built-in GeoIP database support
6. **BGP Integration**: Dynamic route updates from BGP
7. **ECMP Support**: Equal-cost multi-path routing
8. **QoS**: Priority queues and traffic shaping

## License

This module is part of MUTEX and is licensed under GPL-2.0.

## References

- [BRANCH_PLAN.md](../../docs/BRANCH_PLAN.md) - Branch 16 specification
- [mutex_routing.h](mutex_routing.h) - API header
- [mutex_routing.c](mutex_routing.c) - Implementation
- [test_routing.c](test_routing.c) - Test suite
