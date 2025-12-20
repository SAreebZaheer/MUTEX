# Process Filtering Quick Reference

## Quick Start

### Enable Owner-Based Filtering (Simplest)

```c
int fd = mprox_create(0);
mutex_process_filter_capture_owner(fd);
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_OWNER);
// Now only this process uses the proxy
```

### Allow Specific User

```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
mutex_process_filter_create_uid_rule(&rule, 1000);  // UID 1000
mutex_process_filter_add_rule(fd, &rule);
```

### Block Root Processes

```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_BLACKLIST);
mutex_process_filter_create_uid_rule(&rule, 0);  // Block root
mutex_process_filter_add_rule(fd, &rule);
```

### Filter by Application

```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
mutex_process_filter_create_path_rule(&rule, "/usr/bin/firefox", true);
mutex_process_filter_add_rule(fd, &rule);
```

### Filter by Cgroup

```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_CGROUP);
mutex_process_filter_create_cgroup_rule(&rule, "/user.slice", false);
mutex_process_filter_add_rule(fd, &rule);
```

## Filter Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `NONE` | No filtering (all/none) | Disable filtering |
| `WHITELIST` | Only matching processes | Proxy specific apps |
| `BLACKLIST` | All except matching | Block specific apps |
| `CGROUP` | Based on cgroup | Container/systemd filtering |
| `OWNER` | Only fd owner + children | Per-application proxy |

## Match Types

| Type | What It Matches | Example |
|------|-----------------|---------|
| `PID` | Process ID | Current bash session |
| `UID` | User ID | All processes of user 'john' |
| `GID` | Group ID | All processes in 'developers' group |
| `COMM` | Command name | All 'bash' processes |
| `PATH` | Executable path | All binaries in /usr/bin |
| `CGROUP` | Cgroup path | All Docker containers |

## Scope Types

| Scope | Applies To | Example |
|-------|-----------|---------|
| `CURRENT` | Just the PID | Only firefox PID 1234 |
| `TREE` | Process + descendants | Firefox + all its child processes |
| `SESSION` | Entire session | All processes in terminal session |
| `GROUP` | Process group | All processes in job |

## Common Patterns

### Pattern 1: Proxy Only Firefox
```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
mutex_process_filter_create_comm_rule(&rule, "firefox", false);
mutex_process_filter_add_rule(fd, &rule);
```

### Pattern 2: Proxy All Except System Services
```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_BLACKLIST);
mutex_process_filter_create_cgroup_rule(&rule, "/system.slice", false);
mutex_process_filter_add_rule(fd, &rule);
```

### Pattern 3: Proxy Current Shell Session
```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
mutex_process_filter_create_pid_rule(&rule, getpid(), MUTEX_PROCESS_SCOPE_SESSION);
mutex_process_filter_add_rule(fd, &rule);
```

### Pattern 4: Proxy All User Applications
```c
struct mutex_process_filter_rule rule;
mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
mutex_process_filter_create_uid_rule(&rule, getuid());
mutex_process_filter_add_rule(fd, &rule);
```

### Pattern 5: Multi-Rule Whitelist
```c
struct mutex_process_filter_rule rule;

mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);

// Allow firefox
mutex_process_filter_create_comm_rule(&rule, "firefox", true);
mutex_process_filter_add_rule(fd, &rule);

// Allow chrome
mutex_process_filter_create_comm_rule(&rule, "chrome", true);
mutex_process_filter_add_rule(fd, &rule);

// Allow wget
mutex_process_filter_create_path_rule(&rule, "/usr/bin/wget", true);
mutex_process_filter_add_rule(fd, &rule);
```

## API Functions

### Configuration
- `mutex_process_filter_set_mode(fd, mode)` - Set filtering mode
- `mutex_process_filter_get_mode(fd)` - Get current mode
- `mutex_process_filter_capture_owner(fd)` - Capture current process

### Rules
- `mutex_process_filter_add_rule(fd, rule)` - Add a rule
- `mutex_process_filter_remove_rule(fd, index)` - Remove rule by index
- `mutex_process_filter_clear_rules(fd)` - Remove all rules

### Statistics
- `mutex_process_filter_get_stats(fd, stats)` - Get statistics
- `mutex_process_filter_reset_stats(fd)` - Reset counters

### Cache
- `mutex_process_filter_invalidate_cache(fd, pid)` - Invalidate cache entry
- `mutex_process_filter_invalidate_cache(fd, 0)` - Clear entire cache

## Rule Helpers

### PID Rule
```c
void mutex_process_filter_create_pid_rule(
    struct mutex_process_filter_rule *rule,
    pid_t pid,
    enum mutex_process_scope scope);
```

### UID Rule
```c
void mutex_process_filter_create_uid_rule(
    struct mutex_process_filter_rule *rule,
    uid_t uid);
```

### GID Rule
```c
void mutex_process_filter_create_gid_rule(
    struct mutex_process_filter_rule *rule,
    gid_t gid);
```

### Command Rule
```c
void mutex_process_filter_create_comm_rule(
    struct mutex_process_filter_rule *rule,
    const char *comm,
    bool exact_match);
```

### Path Rule
```c
void mutex_process_filter_create_path_rule(
    struct mutex_process_filter_rule *rule,
    const char *path,
    bool exact_match);
```

### Cgroup Rule
```c
void mutex_process_filter_create_cgroup_rule(
    struct mutex_process_filter_rule *rule,
    const char *cgroup,
    bool exact_match);
```

## Error Handling

All functions return:
- `0` on success
- `-1` on error (check `errno`)

Common errors:
- `EINVAL` - Invalid parameters
- `ENOSPC` - Too many rules (max 128)
- `ESRCH` - Process not found
- `ENOENT` - Resource not found
- `EPERM` - Permission denied

## Statistics Structure

```c
struct mutex_process_filter_stats {
    uint64_t packets_matched;    // Packets allowed
    uint64_t packets_filtered;   // Packets blocked
    uint64_t processes_checked;  // Total checks
    uint64_t cache_hits;         // Cache hits
    uint64_t cache_misses;       // Cache misses
};
```

## Tuning Parameters

```bash
# Cache timeout (seconds)
echo 60 > /sys/module/mutex_process_filter/parameters/cache_timeout_secs

# Max cache entries
echo 512 > /sys/module/mutex_process_filter/parameters/max_cache_entries
```

## Testing

```bash
cd /home/areeb/MUTEX/src/userspace
make test_process_filter
./test_process_filter
```

## Complete Example

```c
#include <stdio.h>
#include <unistd.h>
#include "mutex_process_filter_api.h"

int main(void) {
    struct mutex_process_filter_rule rule;
    struct mutex_process_filter_stats stats;
    int fd;

    // Create proxy fd (placeholder - would be mprox_create())
    fd = open("/dev/mutex0", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Set up whitelist for current user
    if (mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST) < 0) {
        perror("set_mode");
        return 1;
    }

    // Allow current user's processes
    mutex_process_filter_create_uid_rule(&rule, getuid());
    if (mutex_process_filter_add_rule(fd, &rule) < 0) {
        perror("add_rule");
        return 1;
    }

    printf("Process filter configured for UID %d\n", getuid());

    // Get statistics
    if (mutex_process_filter_get_stats(fd, &stats) == 0) {
        printf("Packets matched: %lu\n", stats.packets_matched);
        printf("Cache hit rate: %.2f%%\n",
               100.0 * stats.cache_hits /
               (stats.cache_hits + stats.cache_misses));
    }

    close(fd);
    return 0;
}
```

Compile:
```bash
gcc -o myapp myapp.c mutex_process_filter_api.c
```

---

*Quick Reference for MUTEX Process Filtering*  
*Version 1.0 - December 21, 2025*
