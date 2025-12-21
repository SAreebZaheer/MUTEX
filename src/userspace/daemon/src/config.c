/**
 * config.c - Configuration file parser and validator for MUTEX daemon
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#define _GNU_SOURCE
#include "../include/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <json-c/json.h>

/* Helper function to safely duplicate strings */
static char *safe_strdup(const char *str)
{
    if (!str)
        return NULL;
    return strdup(str);
}

/* Helper function to get string from JSON object */
static const char *json_get_string(struct json_object *obj, const char *key, const char *default_val)
{
    struct json_object *val;
    if (json_object_object_get_ex(obj, key, &val))
        return json_object_get_string(val);
    return default_val;
}

/* Helper function to get int from JSON object */
static int json_get_int(struct json_object *obj, const char *key, int default_val)
{
    struct json_object *val;
    if (json_object_object_get_ex(obj, key, &val))
        return json_object_get_int(val);
    return default_val;
}

/* Helper function to get bool from JSON object */
static bool json_get_bool(struct json_object *obj, const char *key, bool default_val)
{
    struct json_object *val;
    if (json_object_object_get_ex(obj, key, &val))
        return json_object_get_boolean(val);
    return default_val;
}

int config_parse_log_level(const char *str)
{
    if (!str)
        return -1;

    if (strcasecmp(str, "error") == 0)
        return LOG_LEVEL_ERROR;
    if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0)
        return LOG_LEVEL_WARN;
    if (strcasecmp(str, "info") == 0)
        return LOG_LEVEL_INFO;
    if (strcasecmp(str, "debug") == 0)
        return LOG_LEVEL_DEBUG;

    return -1;
}

int config_parse_proxy_type(const char *str)
{
    if (!str)
        return -1;

    if (strcasecmp(str, "none") == 0)
        return PROXY_TYPE_NONE;
    if (strcasecmp(str, "socks4") == 0)
        return PROXY_TYPE_SOCKS4;
    if (strcasecmp(str, "socks5") == 0)
        return PROXY_TYPE_SOCKS5;
    if (strcasecmp(str, "http") == 0)
        return PROXY_TYPE_HTTP;
    if (strcasecmp(str, "https") == 0)
        return PROXY_TYPE_HTTPS;

    return -1;
}

const char *config_get_proxy_type_str(proxy_type_t type)
{
    switch (type) {
    case PROXY_TYPE_NONE:
        return "none";
    case PROXY_TYPE_SOCKS4:
        return "socks4";
    case PROXY_TYPE_SOCKS5:
        return "socks5";
    case PROXY_TYPE_HTTP:
        return "http";
    case PROXY_TYPE_HTTPS:
        return "https";
    default:
        return "unknown";
    }
}

const char *config_get_log_level_str(log_level_t level)
{
    switch (level) {
    case LOG_LEVEL_ERROR:
        return "error";
    case LOG_LEVEL_WARN:
        return "warn";
    case LOG_LEVEL_INFO:
        return "info";
    case LOG_LEVEL_DEBUG:
        return "debug";
    default:
        return "unknown";
    }
}

int config_init(struct mutex_config *config)
{
    if (!config)
        return -1;

    memset(config, 0, sizeof(*config));

    /* Set defaults */
    config->version = safe_strdup(CONFIG_VERSION);
    config->daemon.name = safe_strdup("mutexd");
    config->daemon.pid_file = safe_strdup(DEFAULT_PID_FILE);
    config->daemon.log_file = safe_strdup(DEFAULT_LOG_FILE);
    config->daemon.log_level = LOG_LEVEL_INFO;

    config->proxy.enabled = false;
    config->proxy.type = PROXY_TYPE_SOCKS5;
    config->proxy.server = safe_strdup("127.0.0.1");
    config->proxy.port = 1080;
    config->proxy.auth.enabled = false;

    config->routing.mode = ROUTING_MODE_TRANSPARENT;
    config->routing.bypass_local = true;

    config->dns.proxy_dns = true;
    config->dns.dns_server = safe_strdup("8.8.8.8");
    config->dns.dns_port = 53;
    config->dns.cache_enabled = true;
    config->dns.cache_ttl = 300;

    config->process_filtering.enabled = false;
    config->process_filtering.mode = FILTER_MODE_NONE;

    config->performance.max_connections = 10000;
    config->performance.connection_timeout = 300;
    config->performance.buffer_size = 8192;

    config->monitoring.enabled = true;
    config->monitoring.stats_interval = 60;
    config->monitoring.export_format = safe_strdup("json");

    return 0;
}

static int parse_daemon_config(struct daemon_config *daemon, struct json_object *obj)
{
    const char *name = json_get_string(obj, "name", "mutexd");
    const char *pid_file = json_get_string(obj, "pid_file", DEFAULT_PID_FILE);
    const char *log_file = json_get_string(obj, "log_file", DEFAULT_LOG_FILE);
    const char *log_level_str = json_get_string(obj, "log_level", "info");

    free(daemon->name);
    free(daemon->pid_file);
    free(daemon->log_file);

    daemon->name = safe_strdup(name);
    daemon->pid_file = safe_strdup(pid_file);
    daemon->log_file = safe_strdup(log_file);
    daemon->log_level = config_parse_log_level(log_level_str);

    if (daemon->log_level < 0)
        daemon->log_level = LOG_LEVEL_INFO;

    return 0;
}

static int parse_proxy_config(struct proxy_config *proxy, struct json_object *obj)
{
    proxy->enabled = json_get_bool(obj, "enabled", false);

    const char *type_str = json_get_string(obj, "type", "socks5");
    proxy->type = config_parse_proxy_type(type_str);
    if (proxy->type < 0)
        proxy->type = PROXY_TYPE_SOCKS5;

    const char *server = json_get_string(obj, "server", "127.0.0.1");
    free(proxy->server);
    proxy->server = safe_strdup(server);

    proxy->port = json_get_int(obj, "port", 1080);

    /* Parse authentication */
    struct json_object *auth_obj;
    if (json_object_object_get_ex(obj, "authentication", &auth_obj)) {
        proxy->auth.enabled = json_get_bool(auth_obj, "enabled", false);

        const char *username = json_get_string(auth_obj, "username", "");
        const char *password = json_get_string(auth_obj, "password", "");

        free(proxy->auth.username);
        free(proxy->auth.password);

        proxy->auth.username = safe_strdup(username);
        proxy->auth.password = safe_strdup(password);
    }

    /* Parse fallback servers */
    struct json_object *fallback_arr;
    if (json_object_object_get_ex(obj, "fallback_servers", &fallback_arr)) {
        int len = json_object_array_length(fallback_arr);

        /* Free existing fallback list */
        struct fallback_server *curr = proxy->fallback_servers;
        while (curr) {
            struct fallback_server *next = curr->next;
            free(curr->server);
            free(curr);
            curr = next;
        }
        proxy->fallback_servers = NULL;

        /* Parse new fallback list */
        struct fallback_server **tail = &proxy->fallback_servers;
        for (int i = 0; i < len; i++) {
            struct json_object *fb_obj = json_object_array_get_idx(fallback_arr, i);

            struct fallback_server *fb = calloc(1, sizeof(*fb));
            if (!fb)
                continue;

            const char *fb_server = json_get_string(fb_obj, "server", "");
            fb->server = safe_strdup(fb_server);
            fb->port = json_get_int(fb_obj, "port", 1080);
            fb->priority = json_get_int(fb_obj, "priority", 10);
            fb->next = NULL;

            *tail = fb;
            tail = &fb->next;
        }
    }

    return 0;
}

static int parse_routing_config(struct routing_config *routing, struct json_object *obj)
{
    const char *mode_str = json_get_string(obj, "mode", "transparent");

    if (strcasecmp(mode_str, "direct") == 0)
        routing->mode = ROUTING_MODE_DIRECT;
    else if (strcasecmp(mode_str, "forced") == 0)
        routing->mode = ROUTING_MODE_FORCED;
    else
        routing->mode = ROUTING_MODE_TRANSPARENT;

    routing->bypass_local = json_get_bool(obj, "bypass_local", true);

    /* Parse bypass CIDRs */
    struct json_object *bypass_arr;
    if (json_object_object_get_ex(obj, "bypass_cidrs", &bypass_arr)) {
        int len = json_object_array_length(bypass_arr);

        /* Free existing array */
        for (int i = 0; i < routing->bypass_cidr_count; i++)
            free(routing->bypass_cidrs[i]);
        free(routing->bypass_cidrs);

        routing->bypass_cidrs = calloc(len, sizeof(char *));
        routing->bypass_cidr_count = len;

        for (int i = 0; i < len; i++) {
            struct json_object *item = json_object_array_get_idx(bypass_arr, i);
            routing->bypass_cidrs[i] = safe_strdup(json_object_get_string(item));
        }
    }

    /* Parse force proxy patterns */
    struct json_object *force_arr;
    if (json_object_object_get_ex(obj, "force_proxy", &force_arr)) {
        int len = json_object_array_length(force_arr);

        /* Free existing array */
        for (int i = 0; i < routing->force_proxy_count; i++)
            free(routing->force_proxy[i]);
        free(routing->force_proxy);

        routing->force_proxy = calloc(len, sizeof(char *));
        routing->force_proxy_count = len;

        for (int i = 0; i < len; i++) {
            struct json_object *item = json_object_array_get_idx(force_arr, i);
            routing->force_proxy[i] = safe_strdup(json_object_get_string(item));
        }
    }

    return 0;
}

static int parse_dns_config(struct dns_config *dns, struct json_object *obj)
{
    dns->proxy_dns = json_get_bool(obj, "proxy_dns", true);

    const char *server = json_get_string(obj, "dns_server", "8.8.8.8");
    free(dns->dns_server);
    dns->dns_server = safe_strdup(server);

    dns->dns_port = json_get_int(obj, "dns_port", 53);
    dns->cache_enabled = json_get_bool(obj, "cache_enabled", true);
    dns->cache_ttl = json_get_int(obj, "cache_ttl", 300);

    return 0;
}

static int parse_process_filter_config(struct process_filter_config *filter, struct json_object *obj)
{
    filter->enabled = json_get_bool(obj, "enabled", false);

    const char *mode_str = json_get_string(obj, "mode", "none");
    if (strcasecmp(mode_str, "whitelist") == 0)
        filter->mode = FILTER_MODE_WHITELIST;
    else if (strcasecmp(mode_str, "blacklist") == 0)
        filter->mode = FILTER_MODE_BLACKLIST;
    else
        filter->mode = FILTER_MODE_NONE;

    /* Parse process list */
    struct json_object *proc_arr;
    if (json_object_object_get_ex(obj, "processes", &proc_arr)) {
        int len = json_object_array_length(proc_arr);

        /* Free existing array */
        for (int i = 0; i < filter->process_count; i++)
            free(filter->processes[i]);
        free(filter->processes);

        filter->processes = calloc(len, sizeof(char *));
        filter->process_count = len;

        for (int i = 0; i < len; i++) {
            struct json_object *item = json_object_array_get_idx(proc_arr, i);
            filter->processes[i] = safe_strdup(json_object_get_string(item));
        }
    }

    return 0;
}

static int parse_performance_config(struct performance_config *perf, struct json_object *obj)
{
    perf->max_connections = json_get_int(obj, "max_connections", 10000);
    perf->connection_timeout = json_get_int(obj, "connection_timeout", 300);
    perf->buffer_size = json_get_int(obj, "buffer_size", 8192);

    return 0;
}

static int parse_monitoring_config(struct monitoring_config *mon, struct json_object *obj)
{
    mon->enabled = json_get_bool(obj, "enabled", true);
    mon->stats_interval = json_get_int(obj, "stats_interval", 60);

    const char *format = json_get_string(obj, "export_format", "json");
    free(mon->export_format);
    mon->export_format = safe_strdup(format);

    return 0;
}

int config_parse_file(struct mutex_config *config, const char *path)
{
    if (!config || !path)
        return -1;

    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON config file: %s\n", path);
        return -1;
    }

    /* Parse version */
    const char *version = json_get_string(root, "version", CONFIG_VERSION);
    free(config->version);
    config->version = safe_strdup(version);

    /* Parse each section */
    struct json_object *section;

    if (json_object_object_get_ex(root, "daemon", &section))
        parse_daemon_config(&config->daemon, section);

    if (json_object_object_get_ex(root, "proxy", &section))
        parse_proxy_config(&config->proxy, section);

    if (json_object_object_get_ex(root, "routing", &section))
        parse_routing_config(&config->routing, section);

    if (json_object_object_get_ex(root, "dns", &section))
        parse_dns_config(&config->dns, section);

    if (json_object_object_get_ex(root, "process_filtering", &section))
        parse_process_filter_config(&config->process_filtering, section);

    if (json_object_object_get_ex(root, "performance", &section))
        parse_performance_config(&config->performance, section);

    if (json_object_object_get_ex(root, "monitoring", &section))
        parse_monitoring_config(&config->monitoring, section);

    json_object_put(root);
    return 0;
}

int config_validate(const struct mutex_config *config)
{
    if (!config)
        return -1;

    /* Validate proxy configuration */
    if (config->proxy.enabled) {
        if (!config->proxy.server || strlen(config->proxy.server) == 0) {
            fprintf(stderr, "Proxy enabled but no server specified\n");
            return -1;
        }

        if (config->proxy.port == 0 || config->proxy.port > 65535) {
            fprintf(stderr, "Invalid proxy port: %u\n", config->proxy.port);
            return -1;
        }

        if (config->proxy.type == PROXY_TYPE_NONE) {
            fprintf(stderr, "Proxy enabled but type is 'none'\n");
            return -1;
        }
    }

    /* Validate DNS configuration */
    if (!config->dns.dns_server || strlen(config->dns.dns_server) == 0) {
        fprintf(stderr, "No DNS server specified\n");
        return -1;
    }

    /* Validate performance limits */
    if (config->performance.max_connections < 1) {
        fprintf(stderr, "Invalid max_connections: %d\n", config->performance.max_connections);
        return -1;
    }

    if (config->performance.buffer_size < 512) {
        fprintf(stderr, "Buffer size too small: %d\n", config->performance.buffer_size);
        return -1;
    }

    return 0;
}

void config_free(struct mutex_config *config)
{
    if (!config)
        return;

    free(config->version);
    free(config->daemon.name);
    free(config->daemon.pid_file);
    free(config->daemon.log_file);

    free(config->proxy.server);
    free(config->proxy.auth.username);
    free(config->proxy.auth.password);

    /* Free fallback servers */
    struct fallback_server *curr = config->proxy.fallback_servers;
    while (curr) {
        struct fallback_server *next = curr->next;
        free(curr->server);
        free(curr);
        curr = next;
    }

    /* Free routing arrays */
    for (int i = 0; i < config->routing.bypass_cidr_count; i++)
        free(config->routing.bypass_cidrs[i]);
    free(config->routing.bypass_cidrs);

    for (int i = 0; i < config->routing.force_proxy_count; i++)
        free(config->routing.force_proxy[i]);
    free(config->routing.force_proxy);

    free(config->dns.dns_server);

    /* Free process filter arrays */
    for (int i = 0; i < config->process_filtering.process_count; i++)
        free(config->process_filtering.processes[i]);
    free(config->process_filtering.processes);

    free(config->monitoring.export_format);

    memset(config, 0, sizeof(*config));
}

void config_print(const struct mutex_config *config)
{
    if (!config)
        return;

    printf("Configuration:\n");
    printf("  Version: %s\n", config->version);
    printf("  Daemon:\n");
    printf("    Name: %s\n", config->daemon.name);
    printf("    PID File: %s\n", config->daemon.pid_file);
    printf("    Log File: %s\n", config->daemon.log_file);
    printf("    Log Level: %s\n", config_get_log_level_str(config->daemon.log_level));

    printf("  Proxy:\n");
    printf("    Enabled: %s\n", config->proxy.enabled ? "yes" : "no");
    printf("    Type: %s\n", config_get_proxy_type_str(config->proxy.type));
    printf("    Server: %s:%u\n", config->proxy.server, config->proxy.port);
    printf("    Authentication: %s\n", config->proxy.auth.enabled ? "yes" : "no");

    printf("  Routing:\n");
    printf("    Mode: %d\n", config->routing.mode);
    printf("    Bypass Local: %s\n", config->routing.bypass_local ? "yes" : "no");
    printf("    Bypass CIDRs: %d entries\n", config->routing.bypass_cidr_count);

    printf("  DNS:\n");
    printf("    Proxy DNS: %s\n", config->dns.proxy_dns ? "yes" : "no");
    printf("    DNS Server: %s:%u\n", config->dns.dns_server, config->dns.dns_port);

    printf("  Performance:\n");
    printf("    Max Connections: %d\n", config->performance.max_connections);
    printf("    Connection Timeout: %d seconds\n", config->performance.connection_timeout);
    printf("    Buffer Size: %d bytes\n", config->performance.buffer_size);
}
