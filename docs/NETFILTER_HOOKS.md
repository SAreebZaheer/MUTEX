# Netfilter Hooks Documentation

## Overview

The MUTEX proxy module integrates with Linux's Netfilter framework to intercept network packets at strategic points in the kernel's packet processing pipeline. This allows for transparent proxying without requiring application modifications.

## Hook Architecture

### Hook Points

The module registers three Netfilter hooks:

1. **NF_INET_PRE_ROUTING** - Intercepts incoming packets before routing decision
2. **NF_INET_POST_ROUTING** - Modifies outgoing packets after routing, before egress
3. **NF_INET_LOCAL_OUT** - Intercepts locally-generated packets

### Hook Priorities

Hook priorities determine the order of execution relative to other Netfilter modules:

- **PRE_ROUTING**: `MUTEX_PROXY_PRI_FIRST` (NF_IP_PRI_FIRST)
  - Executes early to see packets before NAT and routing decisions
  - Allows inspection of original destination addresses

- **POST_ROUTING**: `MUTEX_PROXY_PRI_LAST` (NF_IP_PRI_LAST)
  - Executes late to perform final packet modifications before egress
  - Ensures modifications happen after other netfilter processing

- **LOCAL_OUT**: `MUTEX_PROXY_PRI_FIRST` (NF_IP_PRI_FIRST)
  - Executes early to intercept local connections before routing
  - Enables transparent redirection of local traffic

### Runtime Priority Adjustment

Priorities can be adjusted via module parameters:

```bash
sudo insmod mutex_proxy.ko pre_routing_priority=-200 post_routing_priority=100 local_out_priority=-200
```

Valid priority range: `NF_IP_PRI_FIRST` (-200) to `NF_IP_PRI_LAST` (100)

## Protocol Support

The hooks currently support:

- **TCP**: Full header extraction and validation
- **UDP**: Full header extraction and validation  
- **ICMP**: Type and code extraction

Protocol-specific handlers extract connection information into a common `struct packet_info` format for uniform processing.

## Packet Flow

```
┌─────────────────────────────────────────────────────────┐
│                    Incoming Packet                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  PRE_ROUTING Hook     │
         │  - Extract headers    │
         │  - Check if proxied   │
         │  - Mark packet        │
         └───────────┬───────────┘
                     │
                     ▼
              Routing Decision
                     │
                     ▼
         ┌───────────────────────┐
         │  POST_ROUTING Hook    │
         │  - Rewrite headers    │
         │  - Update checksums   │
         └───────────┬───────────┘
                     │
                     ▼
              Network Device


         ┌───────────────────────┐
         │  Application          │
         │  (local packet)       │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  LOCAL_OUT Hook       │
         │  - Extract socket     │
         │  - Check process      │
         │  - Redirect to proxy  │
         └───────────┬───────────┘
                     │
                     ▼
              Routing Decision
```

## Hook Implementation Details

### PRE_ROUTING Hook (`mutex_proxy_pre_routing`)

**Purpose**: Intercepts incoming packets before routing decision

**Processing**:
1. Validates socket buffer (skb)
2. Extracts IP header
3. Filters by protocol (TCP/UDP/ICMP)
4. Extracts protocol-specific headers
5. Checks if packet should be proxied (based on proxy contexts)
6. Marks packet for further processing
7. Returns NF_ACCEPT (allows packet to continue)

**Return Values**:
- `NF_ACCEPT`: Continue processing (current behavior for all packets)

### POST_ROUTING Hook (`mutex_proxy_post_routing`)

**Purpose**: Modifies outgoing packets before they leave the system

**Processing**:
1. Validates skb and extracts headers
2. Filters by protocol
3. Checks if packet is marked for proxying
4. Rewrites headers if needed (TODO)
5. Updates checksums (TODO)
6. Returns NF_ACCEPT

**Return Values**:
- `NF_ACCEPT`: Allow packet to egress

### LOCAL_OUT Hook (`mutex_proxy_local_out`)

**Purpose**: Intercepts locally-generated packets

**Processing**:
1. Validates skb and extracts headers
2. Extracts socket information from skb->sk (TODO)
3. Determines owning process (TODO)
4. Checks if process has active proxy fd (TODO)
5. Redirects to proxy if configured (TODO)
6. Returns NF_ACCEPT

**Return Values**:
- `NF_ACCEPT`: Continue with original packet

## Packet Context Association

### Current Implementation

Currently, the hooks perform basic packet inspection and filtering without full process-to-fd association.

### Future Work (Commit 11 - Not Yet Implemented)

The following features are planned for commit 11:

#### Global Context List
- Add RCU-protected list of all active proxy contexts
- Track contexts across multiple file descriptors
- Handle context insertion on fd creation
- Handle context removal on fd close

#### Socket-to-Process Mapping
- Extract socket from `skb->sk` in LOCAL_OUT hook
- Determine owning process from socket credentials
- Look up associated proxy file descriptor(s)
- Handle multiple fds per process

#### Cross-Hook Context Passing
- Store context reference in `skb->cb[]` (control buffer)
- Pass context between hooks for same packet
- Add reference counting to prevent context disappearing mid-flight

#### Process Tracking Functions
- `find_context_by_pid()`: Look up context by process ID
- `find_context_by_socket()`: Look up context by socket inode
- `get_socket_owner()`: Extract process info from socket

This infrastructure will enable true per-process proxy configuration where each process with an active proxy fd gets its traffic proxied according to that fd's configuration.

## Debug Logging

Debug logging can be enabled via kernel log level:

```bash
# View hook activity
dmesg | grep mutex_proxy

# Enable debug output
echo 8 > /proc/sys/kernel/printk
```

Hook debug logs show:
- Packet source/destination IP and ports
- Protocol type
- Hook point where packet was intercepted

## Performance Considerations

### Optimization Strategies

1. **Early Exit**: Non-proxied traffic exits hooks quickly
2. **Protocol Filtering**: Only handle configured protocols
3. **Header Validation**: Ensure headers are accessible before processing
4. **RCU Locking**: Lock-free reads for context lookups (when implemented)

### Overhead

Current implementation adds minimal overhead:
- Simple validation and header extraction
- No packet modification or copying
- All packets currently return NF_ACCEPT immediately after inspection

## Interaction with Other Netfilter Modules

### iptables/nftables

MUTEX hooks can coexist with iptables/nftables rules. Priority settings determine execution order:

- **Before MUTEX**: Use priority < MUTEX priority
- **After MUTEX**: Use priority > MUTEX priority

### Connection Tracking (conntrack)

MUTEX hooks do not currently interfere with conntrack. Future packet rewriting will need to update conntrack state appropriately.

### NAT

- PRE_ROUTING hook runs before DNAT
- POST_ROUTING hook runs after SNAT
- Ensures MUTEX sees original addresses and can modify final addresses

## Troubleshooting

### Hooks Not Intercepting Traffic

1. Verify module is loaded: `lsmod | grep mutex_proxy`
2. Check dmesg for registration errors: `dmesg | grep mutex_proxy`
3. Verify hook count: Should see "registered 3 netfilter hooks"
4. Check priorities don't conflict with other modules

### Packets Not Being Modified

Currently expected - packet modification is not yet implemented. Hooks only inspect and log packet information.

### Module Won't Unload

1. Ensure no active proxy file descriptors
2. Check for in-flight packets
3. Verify hooks were unregistered: `dmesg | tail`

## API for Other Modules

### Checking if Packet is Proxied

Future API (not yet implemented):

```c
bool mutex_proxy_is_packet_proxied(struct sk_buff *skb);
```

### Getting Packet's Proxy Context

Future API (not yet implemented):

```c
struct mutex_proxy_context *mutex_proxy_get_context(struct sk_buff *skb);
```

## Future Enhancements

1. **IPv6 Support**: Add NFPROTO_IPV6 hooks
2. **Connection Tracking Integration**: Full bidirectional connection state
3. **Packet Rewriting**: Actual header modification for proxying
4. **Per-Context Statistics**: Track packets/bytes per proxy fd
5. **Advanced Filtering**: Port ranges, IP ranges, etc.
6. **SOCKS/HTTP Protocol Support**: Protocol-specific proxying logic

## References

- Linux Netfilter Documentation: https://www.netfilter.org/
- Netfilter Hook Priorities: `include/uapi/linux/netfilter_ipv4.h`
- Socket Buffer Structure: `include/linux/skbuff.h`

---

*Last Updated: December 17, 2025*
*Branch: feature/netfilter-hooks*
