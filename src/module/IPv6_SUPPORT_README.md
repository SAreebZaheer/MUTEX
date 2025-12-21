# MUTEX IPv6 Support

## Overview

This module provides comprehensive IPv6 support for the MUTEX kernel-level proxy system. It implements all functionality required for Branch 15 (IPv6 support) of the project plan.

## Features

### 1. IPv6 Header Parsing
- Complete IPv6 header parsing with validation
- Support for all IPv6 extension headers:
  - Hop-by-Hop Options (Type 0)
  - Routing Header (Type 43)
  - Fragment Header (Type 44)
  - Destination Options (Type 60)
  - Authentication Header (Type 51)
  - Encapsulating Security Payload (Type 50)
  - Mobility Header (Type 135)
- Automatic detection and traversal of extension header chains
- Protection against excessive extension headers (max 8)

### 2. Extension Header Handling
- Parse and skip extension headers to find upper layer protocol
- Support for variable-length extension headers
- Handle fixed-length fragment headers
- Preserve extension headers during packet rewriting
- Extract next header and payload offset information

### 3. IPv6 Checksum Calculations
- TCP checksum calculation for IPv6
- UDP checksum calculation for IPv6 (mandatory, unlike IPv4)
- ICMPv6 checksum calculation
- Generic upper layer checksum calculation using pseudo-header
- Checksum verification for received packets
- Automatic checksum updates after address rewriting

### 4. IPv6 Address Translation
- Rewrite source and destination IPv6 addresses
- Automatic checksum updates after address changes
- Support for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
- IPv4-compatible IPv6 addresses (deprecated but supported)
- NAT64 support infrastructure

### 5. Dual-Stack (IPv4/IPv6) Support
- Simultaneous IPv4 and IPv6 operation
- IPv6 preference by default (RFC 6724)
- Support for IPv4-mapped IPv6 addresses
- NAT64 translation infrastructure
- Automatic protocol family selection

### 6. IPv6 Fragmentation Handling
- Parse fragment headers and extract fragment information
- Identify first, middle, and last fragments
- Track fragment offset and fragment ID
- Support for packet reassembly infrastructure
- Support for packet fragmentation when needed
- Path MTU Discovery (PMTUD) support

### 7. ICMPv6 Support
- ICMPv6 packet processing
- Checksum verification for ICMPv6
- Distinguish error messages from informational messages
- Support for common ICMPv6 types:
  - Destination Unreachable (Type 1)
  - Packet Too Big (Type 2)
  - Time Exceeded (Type 3)
  - Parameter Problem (Type 4)
  - Echo Request/Reply (Type 128/129)
  - Multicast Listener Discovery messages
- Neighbor Discovery protocol support infrastructure

### 8. Address Classification
- Classify IPv6 address types:
  - Unspecified (::)
  - Loopback (::1)
  - Multicast (ffxx::/8)
  - Link-local (fe80::/10)
  - Site-local (deprecated fec0::/10)
  - Unique local (fc00::/7)
  - Global unicast
  - IPv4-mapped (::ffff:0:0/96)
  - IPv4-compatible (::/96, deprecated)
- Check for special address types
- Validate address scopes

### 9. Statistics and Monitoring
- Track packets processed
- Count extension headers processed
- Monitor fragments processed
- Count ICMPv6 packets
- Track checksum errors
- Monitor parse errors
- Dual-stack translation statistics

## API Reference

### Header Parsing

```c
enum ipv6_parse_result ipv6_parse_headers(struct sk_buff *skb,
                                           struct ipv6_header_info *info);
```
Parse IPv6 headers and all extension headers.

```c
int ipv6_validate_packet(struct sk_buff *skb);
```
Validate IPv6 packet structure.

```c
__u8 ipv6_get_upper_protocol(struct sk_buff *skb);
```
Get the upper layer protocol (TCP, UDP, ICMPv6, etc.).

```c
__u16 ipv6_get_payload_offset(struct sk_buff *skb);
```
Get offset to upper layer payload in bytes.

### Extension Headers

```c
bool ipv6_is_extension_header(__u8 next_header);
```
Check if next header value represents an extension header.

```c
int ipv6_skip_extension_headers(struct sk_buff *skb, __u16 *offset,
                                 __u8 *next_proto);
```
Skip all extension headers to find upper layer protocol.

### Checksum Operations

```c
__sum16 ipv6_calculate_tcp_checksum(struct sk_buff *skb,
                                     const struct in6_addr *saddr,
                                     const struct in6_addr *daddr);
```
Calculate TCP checksum for IPv6 packet.

```c
__sum16 ipv6_calculate_udp_checksum(struct sk_buff *skb,
                                     const struct in6_addr *saddr,
                                     const struct in6_addr *daddr);
```
Calculate UDP checksum for IPv6 packet (mandatory).

```c
__sum16 ipv6_calculate_icmpv6_checksum(struct sk_buff *skb,
                                        const struct in6_addr *saddr,
                                        const struct in6_addr *daddr);
```
Calculate ICMPv6 checksum.

```c
int ipv6_update_checksum(struct sk_buff *skb, struct ipv6_header_info *info);
```
Update all upper layer checksums after packet modification.

```c
int ipv6_verify_checksum(struct sk_buff *skb, struct ipv6_header_info *info);
```
Verify upper layer checksum.

### Address Translation

```c
int ipv6_rewrite_addresses(struct sk_buff *skb,
                            const struct ipv6_rewrite_params *params);
```
Rewrite source and/or destination IPv6 addresses.

```c
bool ipv6_is_v4_mapped(const struct in6_addr *addr);
```
Check if address is IPv4-mapped IPv6 (::ffff:x.x.x.x).

```c
void ipv6_v4_to_v6_mapped(const __be32 v4_addr, struct in6_addr *v6_addr);
```
Convert IPv4 address to IPv4-mapped IPv6 address.

### Address Classification

```c
__u32 ipv6_classify_address(const struct in6_addr *addr);
```
Classify IPv6 address type (returns bitmask of IPV6_ADDR_* flags).

```c
bool ipv6_is_global_unicast(const struct in6_addr *addr);
```
Check if address is global unicast.

```c
bool ipv6_is_unique_local(const struct in6_addr *addr);
```
Check if address is unique local (fc00::/7).

### Fragmentation

```c
bool ipv6_is_fragmented(struct sk_buff *skb);
```
Check if packet contains a fragment header.

```c
int ipv6_parse_fragment_header(struct sk_buff *skb,
                                struct ipv6_fragment_info *frag_info);
```
Parse fragment header and extract fragment information.

### ICMPv6

```c
int ipv6_process_icmpv6(struct sk_buff *skb, struct ipv6_header_info *info);
```
Process ICMPv6 packet.

```c
bool ipv6_is_icmpv6_error(__u8 type);
```
Check if ICMPv6 type is an error message (types < 128).

### Dual-Stack

```c
int ipv6_dual_stack_init(struct ipv6_dual_stack_context *ctx);
```
Initialize dual-stack context with default settings.

### Utilities

```c
void ipv6_print_address(const struct in6_addr *addr, char *buf, size_t len);
```
Format IPv6 address as string.

```c
int ipv6_compare_addresses(const struct in6_addr *addr1,
                            const struct in6_addr *addr2);
```
Compare two IPv6 addresses (returns 0 if equal).

```c
void ipv6_copy_address(struct in6_addr *dst, const struct in6_addr *src);
```
Copy IPv6 address.

### Statistics

```c
int ipv6_get_stats(struct ipv6_stats *stats);
```
Get current IPv6 statistics.

```c
void ipv6_reset_stats(void);
```
Reset all statistics counters.

```c
void ipv6_dump_header(struct sk_buff *skb);
```
Dump IPv6 header information for debugging.

## Data Structures

### struct ipv6_header_info
Contains parsed IPv6 header information including all extension headers.

```c
struct ipv6_header_info {
    struct ipv6hdr *ipv6h;           // Pointer to IPv6 header
    __u16 payload_offset;             // Offset to upper layer data
    __u8 upper_protocol;              // Upper layer protocol
    __u8 num_ext_headers;             // Number of extension headers
    struct ipv6_ext_header ext_headers[IPV6_MAX_EXT_HEADERS];
    bool has_fragment;                // Fragment header present
    __u16 fragment_offset;            // Fragment offset
    bool is_first_fragment;           // First fragment flag
    bool is_last_fragment;            // Last fragment flag
    __u32 fragment_id;                // Fragment ID
};
```

### struct ipv6_rewrite_params
Parameters for rewriting IPv6 addresses.

```c
struct ipv6_rewrite_params {
    const struct in6_addr *new_saddr;  // New source address (NULL = no change)
    const struct in6_addr *new_daddr;  // New dest address (NULL = no change)
    bool update_checksums;             // Recalculate checksums
    bool preserve_ext_headers;         // Preserve extension headers
};
```

### struct ipv6_stats
IPv6 processing statistics.

```c
struct ipv6_stats {
    __u64 packets_processed;
    __u64 packets_proxied;
    __u64 packets_dropped;
    __u64 extension_headers_processed;
    __u64 fragments_processed;
    __u64 icmpv6_processed;
    __u64 checksum_errors;
    __u64 parse_errors;
    __u64 dual_stack_translations;
};
```

## Usage Examples

### Example 1: Parse IPv6 Headers

```c
struct sk_buff *skb = /* ... */;
struct ipv6_header_info info;
enum ipv6_parse_result result;

result = ipv6_parse_headers(skb, &info);
if (result == IPV6_PARSE_OK) {
    pr_info("Upper protocol: %u\n", info.upper_protocol);
    pr_info("Payload offset: %u\n", info.payload_offset);
    pr_info("Extension headers: %u\n", info.num_ext_headers);

    if (info.has_fragment) {
        pr_info("Fragment offset: %u\n", info.fragment_offset);
        pr_info("Fragment ID: %u\n", info.fragment_id);
    }
}
```

### Example 2: Rewrite IPv6 Addresses

```c
struct sk_buff *skb = /* ... */;
struct in6_addr new_dest;
struct ipv6_rewrite_params params = {0};

/* Set new destination address */
inet_pton(AF_INET6, "2001:db8::1", &new_dest);
params.new_daddr = &new_dest;
params.update_checksums = true;
params.preserve_ext_headers = true;

if (ipv6_rewrite_addresses(skb, &params) == 0) {
    pr_info("Address rewritten successfully\n");
}
```

### Example 3: Calculate and Verify Checksums

```c
struct sk_buff *skb = /* ... */;
struct ipv6_header_info info;
struct ipv6hdr *ipv6h = ipv6_hdr(skb);

/* Parse headers first */
if (ipv6_parse_headers(skb, &info) == IPV6_PARSE_OK) {
    /* Verify existing checksum */
    if (ipv6_verify_checksum(skb, &info) == 0) {
        pr_info("Checksum is valid\n");
    }

    /* After modifying addresses, update checksum */
    ipv6_update_checksum(skb, &info);
}
```

### Example 4: Handle IPv4-Mapped Addresses

```c
struct in6_addr v6_addr;
__be32 v4_addr = htonl(0xC0A80001); // 192.168.0.1

/* Convert IPv4 to IPv4-mapped IPv6 */
ipv6_v4_to_v6_mapped(v4_addr, &v6_addr);
// Result: ::ffff:192.168.0.1

/* Check if address is IPv4-mapped */
if (ipv6_is_v4_mapped(&v6_addr)) {
    pr_info("Address is IPv4-mapped\n");
}
```

### Example 5: Classify Addresses

```c
struct in6_addr addr;
__u32 type;

inet_pton(AF_INET6, "2001:db8::1", &addr);
type = ipv6_classify_address(&addr);

if (type & IPV6_ADDR_GLOBAL) {
    pr_info("Global unicast address\n");
}

if (type & IPV6_ADDR_LINKLOCAL) {
    pr_info("Link-local address\n");
}

if (ipv6_is_unique_local(&addr)) {
    pr_info("Unique local address\n");
}
```

### Example 6: Process ICMPv6

```c
struct sk_buff *skb = /* ... */;
struct ipv6_header_info info;

if (ipv6_parse_headers(skb, &info) == IPV6_PARSE_OK) {
    if (info.upper_protocol == IPPROTO_ICMPV6) {
        if (ipv6_process_icmpv6(skb, &info) == 0) {
            pr_info("ICMPv6 packet processed\n");
        }
    }
}
```

## Integration with Existing Modules

### Connection Tracking Integration

The connection tracking module already has IPv6 support through the `is_ipv6` flag in `struct conn_tuple`:

```c
struct conn_tuple {
    union conn_addr src_addr;  // Can hold IPv4 or IPv6
    union conn_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    bool is_ipv6;              // Set to true for IPv6 connections
};
```

### Packet Rewriting Integration

The packet rewriting module has `struct rewrite_params_v6` for IPv6:

```c
struct rewrite_params_v6 {
    __u32 flags;
    struct in6_addr new_saddr;
    struct in6_addr new_daddr;
    __be16 new_sport;
    __be16 new_dport;
    __s32 tcp_seq_delta;
    __s32 tcp_ack_delta;
};
```

Use the IPv6 module functions for address rewriting and checksum updates.

## Building

The IPv6 module is automatically built with the MUTEX kernel module:

```bash
cd /home/areeb/MUTEX/src/module
make clean
make
```

The compiled module will include IPv6 support: `build/mutex_proxy.ko`

## Testing

### Unit Testing

Test individual functions:

```bash
# Load the module
sudo insmod build/mutex_proxy.ko

# Check kernel log for initialization
dmesg | tail -20

# The module should report:
# "MUTEX IPv6 support module initialized"
```

### Functional Testing

1. **Test IPv6 header parsing:**
   - Send IPv6 packets with various extension headers
   - Verify correct parsing and upper protocol detection

2. **Test checksum calculation:**
   - Send packets with known checksums
   - Verify calculation matches expected values

3. **Test address rewriting:**
   - Rewrite source/destination addresses
   - Verify checksums are updated correctly

4. **Test fragmentation:**
   - Send fragmented IPv6 packets
   - Verify fragment detection and parsing

5. **Test ICMPv6:**
   - Send various ICMPv6 messages
   - Verify correct processing and checksum verification

6. **Test dual-stack:**
   - Mix IPv4 and IPv6 traffic
   - Verify both work correctly simultaneously

### Statistics Verification

```c
struct ipv6_stats stats;
ipv6_get_stats(&stats);

pr_info("IPv6 Statistics:\n");
pr_info("  Packets processed: %llu\n", stats.packets_processed);
pr_info("  Extension headers: %llu\n", stats.extension_headers_processed);
pr_info("  Fragments: %llu\n", stats.fragments_processed);
pr_info("  ICMPv6: %llu\n", stats.icmpv6_processed);
pr_info("  Checksum errors: %llu\n", stats.checksum_errors);
```

## Performance Considerations

1. **Extension Header Processing:** Limited to 8 extension headers to prevent DoS
2. **Checksum Calculation:** Uses kernel's optimized csum_ipv6_magic()
3. **Statistics:** Protected by spinlock, minimal contention
4. **Address Classification:** Fast bit operations and comparisons
5. **Parser Efficiency:** Single pass through extension headers

## Security Considerations

1. **Input Validation:** All inputs are validated before processing
2. **Buffer Bounds:** All memory accesses are bounds-checked
3. **DoS Protection:** Limited extension header chain length
4. **Checksum Verification:** Mandatory for all upper layer protocols
5. **Fragment Handling:** Proper fragment validation to prevent attacks

## Known Limitations

1. **Fragment Reassembly:** Infrastructure present but full reassembly not yet implemented
2. **NAT64:** Infrastructure present but translation not fully implemented
3. **Mobility Header:** Parsing supported but protocol handling not implemented
4. **Extension Header Insertion:** API present but not fully tested

## Future Enhancements

1. Complete fragment reassembly and refragmentation
2. Full NAT64 translation
3. IPv6 extension header insertion/removal
4. Router Advertisement/Neighbor Discovery full support
5. Flow label processing for QoS
6. Jumbogram support (payload > 65535 bytes)

## References

- RFC 8200: Internet Protocol, Version 6 (IPv6) Specification
- RFC 4443: Internet Control Message Protocol (ICMPv6) for IPv6
- RFC 6724: Default Address Selection for IPv6
- RFC 2460: IPv6 Specification (obsoleted by RFC 8200)
- RFC 8200: IPv6 Extension Headers
- Linux kernel IPv6 implementation: `net/ipv6/`

## Troubleshooting

### Common Issues

1. **Checksum errors:**
   - Verify addresses haven't changed without updating checksums
   - Check for hardware offloading interfering with calculations

2. **Parse errors:**
   - Check for truncated packets
   - Verify extension header chain is valid

3. **Fragment issues:**
   - Check fragment offset and more fragments flag
   - Verify fragment ID matches across fragments

4. **Extension header errors:**
   - Verify header lengths are correct
   - Check for unsupported extension headers

### Debug Tips

```c
// Enable verbose debugging
ipv6_dump_header(skb);

// Check statistics for errors
struct ipv6_stats stats;
ipv6_get_stats(&stats);
pr_info("Parse errors: %llu\n", stats.parse_errors);
pr_info("Checksum errors: %llu\n", stats.checksum_errors);
```

## Authors

- Syed Areeb Zaheer
- Azeem
- Hamza Bin Aamir

## License

GPL-2.0

---

*Last Updated: December 21, 2025*  
*Branch: feature/ipv6-support*  
*MUTEX Project - Multi-User Threaded Exchange Xfer*
