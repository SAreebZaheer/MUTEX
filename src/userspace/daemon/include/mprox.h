/**
 * mprox.h - Userspace interface to mprox_create() syscall
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#ifndef MUTEX_MPROX_H
#define MUTEX_MPROX_H

#include <stdint.h>
#include <sys/ioctl.h>

/* Syscall number - will be assigned when kernel is built */
#ifndef __NR_mprox_create
#define __NR_mprox_create 451  /* Placeholder, update with actual number */
#endif

/* Flags for mprox_create() */
#define MPROX_CLOEXEC    0x01  /* Close on exec */
#define MPROX_NONBLOCK   0x02  /* Non-blocking operations */

/* ioctl commands for proxy fd */
#define MPROX_IOC_MAGIC  'M'

#define MPROX_IOC_ENABLE         _IO(MPROX_IOC_MAGIC, 1)
#define MPROX_IOC_DISABLE        _IO(MPROX_IOC_MAGIC, 2)
#define MPROX_IOC_SET_PROXY      _IOW(MPROX_IOC_MAGIC, 3, struct mprox_proxy_config)
#define MPROX_IOC_GET_STATS      _IOR(MPROX_IOC_MAGIC, 4, struct mprox_stats)
#define MPROX_IOC_CLEAR_STATS    _IO(MPROX_IOC_MAGIC, 5)
#define MPROX_IOC_SET_FILTER     _IOW(MPROX_IOC_MAGIC, 6, struct mprox_filter)
#define MPROX_IOC_GET_STATUS     _IOR(MPROX_IOC_MAGIC, 7, struct mprox_status)

/* Proxy configuration structure for ioctl */
struct mprox_proxy_config {
    uint32_t type;              /* Proxy type (SOCKS5, HTTP, etc.) */
    uint32_t flags;             /* Configuration flags */
    uint8_t server_addr[16];    /* IPv4/IPv6 address */
    uint16_t port;              /* Proxy server port */
    uint8_t auth_user[64];      /* Username for authentication */
    uint8_t auth_pass[64];      /* Password for authentication */
};

/* Statistics structure */
struct mprox_stats {
    uint64_t packets_proxied;
    uint64_t packets_direct;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t connections_active;
    uint64_t connections_total;
    uint64_t errors;
};

/* Filter structure */
struct mprox_filter {
    uint32_t mode;              /* Whitelist/Blacklist/None */
    uint32_t pid_count;
    uint32_t pids[256];         /* List of PIDs to filter */
};

/* Status structure */
struct mprox_status {
    uint32_t enabled;           /* Proxy enabled flag */
    uint32_t proxy_type;        /* Current proxy type */
    uint32_t connection_count;  /* Active connections */
    uint64_t uptime_seconds;    /* Daemon uptime */
};

/* Function prototypes */

/**
 * mprox_create - Create a new proxy file descriptor
 * @flags: Creation flags (MPROX_CLOEXEC, MPROX_NONBLOCK)
 *
 * Returns: File descriptor on success, -1 on error
 */
static inline int mprox_create(unsigned int flags)
{
    return syscall(__NR_mprox_create, flags);
}

/**
 * mprox_enable - Enable proxying on the given fd
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_enable(int fd)
{
    return ioctl(fd, MPROX_IOC_ENABLE);
}

/**
 * mprox_disable - Disable proxying on the given fd
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_disable(int fd)
{
    return ioctl(fd, MPROX_IOC_DISABLE);
}

/**
 * mprox_set_proxy - Configure proxy settings
 * @fd: Proxy file descriptor
 * @config: Pointer to proxy configuration
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_set_proxy(int fd, const struct mprox_proxy_config *config)
{
    return ioctl(fd, MPROX_IOC_SET_PROXY, config);
}

/**
 * mprox_get_stats - Get proxy statistics
 * @fd: Proxy file descriptor
 * @stats: Pointer to statistics structure to fill
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_get_stats(int fd, struct mprox_stats *stats)
{
    return ioctl(fd, MPROX_IOC_GET_STATS, stats);
}

/**
 * mprox_clear_stats - Clear proxy statistics
 * @fd: Proxy file descriptor
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_clear_stats(int fd)
{
    return ioctl(fd, MPROX_IOC_CLEAR_STATS);
}

/**
 * mprox_set_filter - Set process filtering rules
 * @fd: Proxy file descriptor
 * @filter: Pointer to filter configuration
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_set_filter(int fd, const struct mprox_filter *filter)
{
    return ioctl(fd, MPROX_IOC_SET_FILTER, filter);
}

/**
 * mprox_get_status - Get proxy status
 * @fd: Proxy file descriptor
 * @status: Pointer to status structure to fill
 *
 * Returns: 0 on success, -1 on error
 */
static inline int mprox_get_status(int fd, struct mprox_status *status)
{
    return ioctl(fd, MPROX_IOC_GET_STATUS, status);
}

#endif /* MUTEX_MPROX_H */
