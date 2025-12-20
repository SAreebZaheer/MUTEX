/**
 * daemon.c - MUTEX daemon core functionality
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#define _GNU_SOURCE
#include "../include/daemon.h"
#include "../include/mprox.h"
#include "../include/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <time.h>
#include <syslog.h>
#include <arpa/inet.h>

/* Global daemon context for signal handlers */
static struct daemon_ctx *g_daemon_ctx = NULL;

/* Signal handler */
static void signal_handler(int signum)
{
    if (!g_daemon_ctx)
        return;

    switch (signum) {
    case SIGHUP:
        g_daemon_ctx->reload_requested = 1;
        break;
    case SIGTERM:
    case SIGINT:
        g_daemon_ctx->stop_requested = 1;
        break;
    }
}

int daemon_setup_signals(struct daemon_ctx *ctx)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        perror("sigaction(SIGHUP)");
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction(SIGTERM)");
        return -1;
    }

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction(SIGINT)");
        return -1;
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        perror("sigaction(SIGPIPE)");
        return -1;
    }

    g_daemon_ctx = ctx;
    return 0;
}

int daemon_daemonize(void)
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    /* Exit parent process */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Create new session */
    if (setsid() < 0) {
        perror("setsid");
        return -1;
    }

    /* Fork again to ensure we're not session leader */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Change working directory to root */
    if (chdir("/") < 0) {
        perror("chdir");
        return -1;
    }

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect standard fds to /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO)
            close(fd);
    }

    return 0;
}

int daemon_write_pid_file(const char *path)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "Failed to create PID file %s: %s\n", path, strerror(errno));
        return -1;
    }

    fprintf(fp, "%d\n", getpid());
    fclose(fp);

    return 0;
}

int daemon_remove_pid_file(const char *path)
{
    if (unlink(path) < 0 && errno != ENOENT) {
        fprintf(stderr, "Failed to remove PID file %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

int daemon_init(struct daemon_ctx *ctx, const char *config_path)
{
    if (!ctx || !config_path)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    ctx->config_path = strdup(config_path);
    if (!ctx->config_path)
        return -1;

    ctx->proxy_fd = -1;
    ctx->inotify_fd = -1;
    ctx->inotify_wd = -1;
    ctx->state = DAEMON_STATE_INIT;
    ctx->reload_requested = 0;
    ctx->stop_requested = 0;

    /* Initialize configuration with defaults */
    if (config_init(&ctx->config) < 0) {
        fprintf(stderr, "Failed to initialize configuration\n");
        free(ctx->config_path);
        return -1;
    }

    /* Load configuration file */
    if (config_parse_file(&ctx->config, config_path) < 0) {
        fprintf(stderr, "Failed to parse configuration file: %s\n", config_path);
        config_free(&ctx->config);
        free(ctx->config_path);
        return -1;
    }

    /* Validate configuration */
    if (config_validate(&ctx->config) < 0) {
        fprintf(stderr, "Configuration validation failed\n");
        config_free(&ctx->config);
        free(ctx->config_path);
        return -1;
    }

    return 0;
}

int daemon_apply_config(struct daemon_ctx *ctx)
{
    if (!ctx || ctx->proxy_fd < 0)
        return -1;

    struct mprox_proxy_config proxy_cfg;
    memset(&proxy_cfg, 0, sizeof(proxy_cfg));

    /* Set proxy type */
    proxy_cfg.type = ctx->config.proxy.type;
    proxy_cfg.port = htons(ctx->config.proxy.port);

    /* Parse server address */
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ctx->config.proxy.server, &addr4) == 1) {
        memcpy(proxy_cfg.server_addr, &addr4, sizeof(addr4));
    } else if (inet_pton(AF_INET6, ctx->config.proxy.server, &addr6) == 1) {
        memcpy(proxy_cfg.server_addr, &addr6, sizeof(addr6));
    } else {
        syslog(LOG_ERR, "Invalid proxy server address: %s", ctx->config.proxy.server);
        return -1;
    }

    /* Set authentication */
    if (ctx->config.proxy.auth.enabled) {
        strncpy((char *)proxy_cfg.auth_user, ctx->config.proxy.auth.username,
                sizeof(proxy_cfg.auth_user) - 1);
        strncpy((char *)proxy_cfg.auth_pass, ctx->config.proxy.auth.password,
                sizeof(proxy_cfg.auth_pass) - 1);
    }

    /* Apply configuration via ioctl */
    if (mprox_set_proxy(ctx->proxy_fd, &proxy_cfg) < 0) {
        syslog(LOG_ERR, "Failed to set proxy configuration: %s", strerror(errno));
        return -1;
    }

    /* Enable proxy if configured */
    if (ctx->config.proxy.enabled) {
        if (mprox_enable(ctx->proxy_fd) < 0) {
            syslog(LOG_ERR, "Failed to enable proxy: %s", strerror(errno));
            return -1;
        }
        syslog(LOG_INFO, "Proxy enabled: %s:%u (%s)",
               ctx->config.proxy.server,
               ctx->config.proxy.port,
               config_get_proxy_type_str(ctx->config.proxy.type));
    } else {
        if (mprox_disable(ctx->proxy_fd) < 0) {
            syslog(LOG_ERR, "Failed to disable proxy: %s", strerror(errno));
            return -1;
        }
        syslog(LOG_INFO, "Proxy disabled");
    }

    return 0;
}

int daemon_setup_file_watch(struct daemon_ctx *ctx)
{
    if (!ctx)
        return -1;

    /* Create inotify instance */
    ctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ctx->inotify_fd < 0) {
        syslog(LOG_ERR, "Failed to create inotify instance: %s", strerror(errno));
        return -1;
    }

    /* Add watch for config file */
    ctx->inotify_wd = inotify_add_watch(ctx->inotify_fd, ctx->config_path,
                                         IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
    if (ctx->inotify_wd < 0) {
        syslog(LOG_ERR, "Failed to watch config file %s: %s",
               ctx->config_path, strerror(errno));
        close(ctx->inotify_fd);
        ctx->inotify_fd = -1;
        return -1;
    }

    syslog(LOG_INFO, "Watching config file: %s", ctx->config_path);
    return 0;
}

int daemon_handle_file_event(struct daemon_ctx *ctx)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t len;

    if (!ctx || ctx->inotify_fd < 0)
        return -1;

    len = read(ctx->inotify_fd, buf, sizeof(buf));
    if (len <= 0)
        return 0;

    const struct inotify_event *event;
    for (char *ptr = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {
        event = (const struct inotify_event *)ptr;

        if (event->mask & IN_MODIFY) {
            syslog(LOG_INFO, "Config file modified, reloading...");
            ctx->reload_requested = 1;
        } else if (event->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) {
            syslog(LOG_WARNING, "Config file moved or deleted");
            /* Try to re-add watch */
            inotify_rm_watch(ctx->inotify_fd, ctx->inotify_wd);
            ctx->inotify_wd = inotify_add_watch(ctx->inotify_fd, ctx->config_path,
                                                 IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
        }
    }

    return 0;
}

int daemon_reload(struct daemon_ctx *ctx)
{
    if (!ctx)
        return -1;

    syslog(LOG_INFO, "Reloading configuration...");
    ctx->state = DAEMON_STATE_RELOADING;

    /* Create new config structure */
    struct mutex_config new_config;
    if (config_init(&new_config) < 0) {
        syslog(LOG_ERR, "Failed to initialize new configuration");
        return -1;
    }

    /* Parse configuration file */
    if (config_parse_file(&new_config, ctx->config_path) < 0) {
        syslog(LOG_ERR, "Failed to parse configuration file");
        config_free(&new_config);
        return -1;
    }

    /* Validate new configuration */
    if (config_validate(&new_config) < 0) {
        syslog(LOG_ERR, "New configuration validation failed");
        config_free(&new_config);
        return -1;
    }

    /* Free old configuration and use new one */
    config_free(&ctx->config);
    memcpy(&ctx->config, &new_config, sizeof(ctx->config));

    /* Apply new configuration */
    if (daemon_apply_config(ctx) < 0) {
        syslog(LOG_ERR, "Failed to apply new configuration");
        return -1;
    }

    syslog(LOG_INFO, "Configuration reloaded successfully");
    ctx->state = DAEMON_STATE_RUNNING;
    ctx->reload_requested = 0;

    return 0;
}

int daemon_main_loop(struct daemon_ctx *ctx)
{
    if (!ctx)
        return -1;

    ctx->state = DAEMON_STATE_RUNNING;
    syslog(LOG_INFO, "Entering main loop");

    while (!ctx->stop_requested) {
        fd_set rfds;
        struct timeval tv;
        int maxfd;

        FD_ZERO(&rfds);
        maxfd = -1;

        /* Monitor inotify fd */
        if (ctx->inotify_fd >= 0) {
            FD_SET(ctx->inotify_fd, &rfds);
            maxfd = ctx->inotify_fd;
        }

        /* Monitor proxy fd for events */
        if (ctx->proxy_fd >= 0) {
            FD_SET(ctx->proxy_fd, &rfds);
            if (ctx->proxy_fd > maxfd)
                maxfd = ctx->proxy_fd;
        }

        /* Timeout for periodic tasks */
        tv.tv_sec = ctx->config.monitoring.stats_interval;
        tv.tv_usec = 0;

        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "select() failed: %s", strerror(errno));
            break;
        }

        /* Handle inotify events */
        if (ctx->inotify_fd >= 0 && FD_ISSET(ctx->inotify_fd, &rfds)) {
            daemon_handle_file_event(ctx);
        }

        /* Handle proxy fd events (stats updates, etc.) */
        if (ctx->proxy_fd >= 0 && FD_ISSET(ctx->proxy_fd, &rfds)) {
            /* Read status/stats from proxy fd */
            struct mprox_stats stats;
            if (mprox_get_stats(ctx->proxy_fd, &stats) == 0 && ctx->config.monitoring.enabled) {
                syslog(LOG_DEBUG, "Stats: %lu packets proxied, %lu connections active",
                       stats.packets_proxied, stats.connections_active);
            }
        }

        /* Handle reload request */
        if (ctx->reload_requested) {
            daemon_reload(ctx);
        }

        /* Periodic tasks on timeout */
        if (ret == 0) {
            /* Log statistics */
            if (ctx->config.monitoring.enabled && ctx->proxy_fd >= 0) {
                struct mprox_stats stats;
                if (mprox_get_stats(ctx->proxy_fd, &stats) == 0) {
                    syslog(LOG_INFO, "Statistics: packets_proxied=%lu bytes_sent=%lu bytes_received=%lu connections=%lu",
                           stats.packets_proxied, stats.bytes_sent, stats.bytes_received, stats.connections_active);
                }
            }
        }
    }

    syslog(LOG_INFO, "Exiting main loop");
    ctx->state = DAEMON_STATE_STOPPED;

    return 0;
}

int daemon_start(struct daemon_ctx *ctx, bool foreground)
{
    if (!ctx)
        return -1;

    /* Set up logging */
    openlog(ctx->config.daemon.name, LOG_PID | (foreground ? LOG_PERROR : 0), LOG_DAEMON);

    /* Print configuration in debug mode */
    if (ctx->config.daemon.log_level == LOG_LEVEL_DEBUG) {
        config_print(&ctx->config);
    }

    /* Daemonize if not running in foreground */
    if (!foreground) {
        syslog(LOG_INFO, "Daemonizing...");
        if (daemon_daemonize() < 0) {
            syslog(LOG_ERR, "Failed to daemonize");
            return -1;
        }
    }

    /* Write PID file */
    if (daemon_write_pid_file(ctx->config.daemon.pid_file) < 0) {
        syslog(LOG_ERR, "Failed to write PID file");
        return -1;
    }

    /* Set up signal handlers */
    if (daemon_setup_signals(ctx) < 0) {
        syslog(LOG_ERR, "Failed to set up signal handlers");
        daemon_remove_pid_file(ctx->config.daemon.pid_file);
        return -1;
    }

    /* Create proxy file descriptor via syscall */
    syslog(LOG_INFO, "Creating proxy file descriptor...");
    ctx->proxy_fd = mprox_create(MPROX_CLOEXEC);
    if (ctx->proxy_fd < 0) {
        syslog(LOG_ERR, "Failed to create proxy fd: %s (syscall may not be available)",
               strerror(errno));
        daemon_remove_pid_file(ctx->config.daemon.pid_file);
        return -1;
    }

    syslog(LOG_INFO, "Proxy fd created: %d", ctx->proxy_fd);

    /* Apply initial configuration */
    if (daemon_apply_config(ctx) < 0) {
        syslog(LOG_ERR, "Failed to apply initial configuration");
        close(ctx->proxy_fd);
        daemon_remove_pid_file(ctx->config.daemon.pid_file);
        return -1;
    }

    /* Set up file watching for hot-reload */
    if (daemon_setup_file_watch(ctx) < 0) {
        syslog(LOG_WARNING, "Failed to set up file watching (hot-reload disabled)");
        /* Non-fatal, continue anyway */
    }

    syslog(LOG_INFO, "Daemon started successfully (PID %d)", getpid());

    /* Enter main event loop */
    return daemon_main_loop(ctx);
}

int daemon_stop(struct daemon_ctx *ctx)
{
    if (!ctx)
        return -1;

    syslog(LOG_INFO, "Stopping daemon...");
    ctx->state = DAEMON_STATE_STOPPING;
    ctx->stop_requested = 1;

    return 0;
}

void daemon_cleanup(struct daemon_ctx *ctx)
{
    if (!ctx)
        return;

    syslog(LOG_INFO, "Cleaning up daemon resources...");

    /* Close proxy fd */
    if (ctx->proxy_fd >= 0) {
        close(ctx->proxy_fd);
        ctx->proxy_fd = -1;
    }

    /* Close inotify */
    if (ctx->inotify_wd >= 0 && ctx->inotify_fd >= 0) {
        inotify_rm_watch(ctx->inotify_fd, ctx->inotify_wd);
        ctx->inotify_wd = -1;
    }

    if (ctx->inotify_fd >= 0) {
        close(ctx->inotify_fd);
        ctx->inotify_fd = -1;
    }

    /* Remove PID file */
    daemon_remove_pid_file(ctx->config.daemon.pid_file);

    /* Free configuration */
    config_free(&ctx->config);

    /* Free config path */
    free(ctx->config_path);
    ctx->config_path = NULL;

    closelog();
}
