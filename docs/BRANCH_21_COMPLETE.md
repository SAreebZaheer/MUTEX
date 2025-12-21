# Branch 21: Logging Framework - Implementation Complete

## Overview
Comprehensive structured logging system for MUTEX with rate limiting, filtering, multiple output destinations, and context-aware logging capabilities.

## Files Created
- `src/module/mutex_logging.h` (276 lines) - Logging framework API and data structures
- `src/module/mutex_logging.c` (823 lines) - Logging framework implementation

## Key Features

### Log Levels (5 Levels)
- DEBUG (0): Detailed debugging information
- INFO (1): General informational messages
- WARN (2): Warning conditions
- ERROR (3): Error conditions
- CRITICAL (4): Critical system conditions

### Log Categories (10 Categories)
- GENERAL: General system operations
- NETWORK: Network stack operations
- CONNECTION: Connection tracking and management
- PROXY: Proxy operations and routing
- SECURITY: Security events and violations
- PERFORMANCE: Performance monitoring and optimization
- ERROR: Error conditions and recovery
- DNS: DNS resolution and caching
- PROTOCOL: Protocol handling (SOCKS, HTTP)
- STATS: Statistics collection and monitoring

### Rate Limiting
- Token bucket algorithm implementation
- Configurable tokens per second (default: 100/s)
- Maximum token capacity (default: 200)
- Automatic token refill every second
- Tracks dropped messages due to rate limiting

### Log Buffer
- Circular buffer with configurable size (default: 1000 entries)
- Automatic eviction of oldest entries when full
- Per-entry metadata: timestamp, level, category, CPU, PID, context
- Thread-safe operations with spinlock protection
- Sequence numbering for ordering

### Context-Aware Logging
- Per-connection context tracking
- Connection 5-tuple storage (src/dst IP, ports, protocol)
- Reference counting for context lifecycle
- Custom labels for connections
- Automatic context correlation in logs

### Multiple Destinations
- printk: Kernel log output
- Buffer: In-memory circular buffer
- Syslog-ready: Framework prepared for syslog integration

### Log Filtering
- Filter by minimum log level
- Filter by category bitmask
- Master enable/disable switch
- Runtime reconfigurable

### Export Functions
- Text format: Human-readable log output
- JSON format: Structured data export for analysis
- Direct buffer access for custom processing

### Statistics Tracking
- Total messages logged
- Messages per level (5 counters)
- Messages dropped due to buffer full
- Messages dropped due to rate limiting
- Allocation failures
- Buffer overflow events

## API Functions

### Initialization
- `mutex_log_init()` - Initialize logging subsystem
- `mutex_log_destroy()` - Cleanup and shutdown

### Configuration
- `mutex_log_set_level()` - Set minimum log level
- `mutex_log_set_categories()` - Set enabled categories
- `mutex_log_enable_category()` - Enable specific category
- `mutex_log_disable_category()` - Disable specific category
- `mutex_log_set_destinations()` - Configure output destinations
- `mutex_log_set_rate_limit()` - Configure rate limiter
- `mutex_log_enable()` / `mutex_log_disable()` - Master switch

### Core Logging
- `mutex_log_message()` - Core logging function
- Convenience macros: `mutex_log_debug()`, `mutex_log_info()`, `mutex_log_warn()`, `mutex_log_error()`, `mutex_log_critical()`
- Category-specific macros: `mutex_log_net()`, `mutex_log_conn()`, `mutex_log_proxy()`, `mutex_log_security()`, `mutex_log_perf()`

### Connection Context
- `mutex_log_conn_create()` - Create connection context
- `mutex_log_conn_get()` - Increment reference count
- `mutex_log_conn_put()` - Decrement reference count (auto-cleanup)
- `mutex_log_conn_find()` - Find context by connection ID
- `mutex_log_conn_destroy()` - Manually destroy context

### Buffer Management
- `mutex_log_get_entries()` - Retrieve filtered log entries
- `mutex_log_clear_buffer()` - Clear all buffered logs
- `mutex_log_get_buffer_count()` - Get current buffer size

### Statistics
- `mutex_log_get_stats()` - Retrieve logging statistics
- `mutex_log_reset_stats()` - Reset all statistics counters

### Export
- `mutex_log_export_text()` - Export logs as text
- `mutex_log_export_json()` - Export logs as JSON

## Procfs Interface
- Location: `/proc/mutex_log`
- Shows logging statistics, configuration, and recent log entries
- Read-only access
- Displays last 50 log entries by default

## Module Parameters
- `log_level` (default: INFO) - Initial log level
- `log_categories` (default: ALL) - Initial enabled categories
- `log_rate_limit` (default: 100) - Messages per second limit
- `log_buffer_size` (default: 1000) - Log buffer capacity

## Usage Examples

### Basic Logging
```c
mutex_log_info(MUTEX_LOG_CAT_GENERAL, NULL, "Module initialized");
mutex_log_error(MUTEX_LOG_CAT_NETWORK, "eth0", "Failed to send packet: %d", err);
```

### Connection Context
```c
struct log_conn_context *ctx = mutex_log_conn_create(
    conn_id, src_ip, dst_ip, src_port, dst_port, IPPROTO_TCP, "proxy1");
mutex_log_conn(MUTEX_LOG_INFO, ctx->label, "Connection established");
mutex_log_conn_put(ctx);
```

### Retrieve Logs
```c
struct log_entry entries[100];
int count = mutex_log_get_entries(entries, 100, MUTEX_LOG_WARN, MUTEX_LOG_CAT_ALL);
```

## Testing
- Build test: **PASSED** (compiles without errors)
- Module file: `mutex_proxy.ko`
- No symbol conflicts detected
- All logging functions properly exported

## Implementation Details
- Thread-safe: All operations protected by spinlocks
- Atomic statistics: Uses atomic64_t for counters
- Memory efficient: Circular buffer prevents unbounded growth
- Performance optimized: Early exits on filtering, GFP_ATOMIC allocations
- Timestamp precision: Uses ktime_t for nanosecond precision
- CPU tracking: Records CPU ID for each log entry
- Process tracking: Records PID for each log entry

## Integration Points
- Can be used by all MUTEX modules for consistent logging
- Replaces ad-hoc printk() calls throughout codebase
- Provides structured data for monitoring and debugging
- Ready for future syslog integration
- Compatible with existing error recovery and statistics modules

## Future Enhancements
- Syslog integration for remote logging
- Log rotation in userspace daemon
- Log analysis tools for pattern detection
- Dynamic log level adjustment per category
- Binary log format for reduced overhead
- Compression for archived logs

## Dependencies
- Branch 1: Basic module structure (for initialization)
- No other branch dependencies

## Notes
- Logging framework is independent and can be used from module init
- Rate limiting prevents log flooding during errors
- Buffer size should be tuned based on system memory and logging volume
- Category filtering allows focused debugging
- Connection contexts enable correlation across distributed operations
