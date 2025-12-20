/**
 * config.h - Configuration file parser and validator for MUTEX daemon
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#ifndef MUTEX_CONFIG_H
#define MUTEX_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Configuration version */
#define CONFIG_VERSION "1.0"

/* Default paths */
#define DEFAULT_CONFIG_PATH "/etc/mutex/mutex.conf"
#define DEFAULT_PID_FILE "/var/run/mutexd.pid"
#define DEFAULT_LOG_FILE "/var/log/mutexd.log"

/* Proxy types */
typedef enum {
    PROXY_TYPE_NONE = 0,
    PROXY_TYPE_SOCKS4,
    PROXY_TYPE_SOCKS5,
    PROXY_TYPE_HTTP,
    PROXY_TYPE_HTTPS
} proxy_type_t;

/* Routing modes */
typedef enum {
    ROUTING_MODE_DIRECT = 0,
    ROUTING_MODE_TRANSPARENT,
    ROUTING_MODE_FORCED
} routing_mode_t;

/* Process filtering modes */
typedef enum {
    FILTER_MODE_NONE = 0,
    FILTER_MODE_WHITELIST,
    FILTER_MODE_BLACKLIST
} filter_mode_t;

/* Log levels */
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

/* Fallback server configuration */
struct fallback_server {
    char *server;
    uint16_t port;
    int priority;
    struct fallback_server *next;
};

/* Proxy authentication */
struct proxy_auth {
    bool enabled;
    char *username;
    char *password;
};

/* Proxy configuration */
struct proxy_config {
    bool enabled;
    proxy_type_t type;
    char *server;
    uint16_t port;
    struct proxy_auth auth;
    struct fallback_server *fallback_servers;
};

/* Routing configuration */
struct routing_config {
    routing_mode_t mode;
    bool bypass_local;
    char **bypass_cidrs;
    int bypass_cidr_count;
    char **force_proxy;
    int force_proxy_count;
};

/* DNS configuration */
struct dns_config {
    bool proxy_dns;
    char *dns_server;
    uint16_t dns_port;
    bool cache_enabled;
    int cache_ttl;
};

/* Process filtering configuration */
struct process_filter_config {
    bool enabled;
    filter_mode_t mode;
    char **processes;
    int process_count;
};

/* Performance configuration */
struct performance_config {
    int max_connections;
    int connection_timeout;
    int buffer_size;
};

/* Monitoring configuration */
struct monitoring_config {
    bool enabled;
    int stats_interval;
    char *export_format;
};

/* Daemon configuration */
struct daemon_config {
    char *name;
    char *pid_file;
    char *log_file;
    log_level_t log_level;
};

/* Main configuration structure */
struct mutex_config {
    char *version;
    struct daemon_config daemon;
    struct proxy_config proxy;
    struct routing_config routing;
    struct dns_config dns;
    struct process_filter_config process_filtering;
    struct performance_config performance;
    struct monitoring_config monitoring;
};

/* Function prototypes */

/**
 * config_init - Initialize a config structure with default values
 * @config: Pointer to config structure to initialize
 *
 * Returns: 0 on success, -1 on error
 */
int config_init(struct mutex_config *config);

/**
 * config_parse_file - Parse configuration from JSON file
 * @config: Pointer to config structure to populate
 * @path: Path to configuration file
 *
 * Returns: 0 on success, -1 on error
 */
int config_parse_file(struct mutex_config *config, const char *path);

/**
 * config_validate - Validate configuration values
 * @config: Pointer to config structure to validate
 *
 * Returns: 0 if valid, -1 if invalid
 */
int config_validate(const struct mutex_config *config);

/**
 * config_free - Free all allocated memory in config structure
 * @config: Pointer to config structure to free
 */
void config_free(struct mutex_config *config);

/**
 * config_print - Print configuration to stdout (for debugging)
 * @config: Pointer to config structure to print
 */
void config_print(const struct mutex_config *config);

/**
 * config_get_proxy_type_str - Get string representation of proxy type
 * @type: Proxy type enum value
 *
 * Returns: String representation of proxy type
 */
const char *config_get_proxy_type_str(proxy_type_t type);

/**
 * config_get_log_level_str - Get string representation of log level
 * @level: Log level enum value
 *
 * Returns: String representation of log level
 */
const char *config_get_log_level_str(log_level_t level);

/**
 * config_parse_log_level - Parse log level from string
 * @str: String representation of log level
 *
 * Returns: Log level enum value, or -1 if invalid
 */
int config_parse_log_level(const char *str);

/**
 * config_parse_proxy_type - Parse proxy type from string
 * @str: String representation of proxy type
 *
 * Returns: Proxy type enum value, or -1 if invalid
 */
int config_parse_proxy_type(const char *str);

#endif /* MUTEX_CONFIG_H */
