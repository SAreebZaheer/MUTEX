/**
 * daemon.h - MUTEX daemon core functionality
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#ifndef MUTEX_DAEMON_H
#define MUTEX_DAEMON_H

#include "config.h"
#include <stdbool.h>
#include <signal.h>

/* Daemon state */
typedef enum {
    DAEMON_STATE_INIT = 0,
    DAEMON_STATE_RUNNING,
    DAEMON_STATE_RELOADING,
    DAEMON_STATE_STOPPING,
    DAEMON_STATE_STOPPED
} daemon_state_t;

/* Daemon context */
struct daemon_ctx {
    struct mutex_config config;
    int proxy_fd;               /* File descriptor from mprox_create() */
    int inotify_fd;             /* inotify fd for config file watching */
    int inotify_wd;             /* inotify watch descriptor */
    char *config_path;          /* Path to configuration file */
    daemon_state_t state;
    volatile sig_atomic_t reload_requested;
    volatile sig_atomic_t stop_requested;
};

/* Function prototypes */

/**
 * daemon_init - Initialize daemon context
 * @ctx: Pointer to daemon context
 * @config_path: Path to configuration file
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_init(struct daemon_ctx *ctx, const char *config_path);

/**
 * daemon_start - Start the daemon
 * @ctx: Pointer to daemon context
 * @foreground: If true, run in foreground (don't daemonize)
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_start(struct daemon_ctx *ctx, bool foreground);

/**
 * daemon_stop - Stop the daemon
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_stop(struct daemon_ctx *ctx);

/**
 * daemon_reload - Reload daemon configuration
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_reload(struct daemon_ctx *ctx);

/**
 * daemon_cleanup - Clean up daemon resources
 * @ctx: Pointer to daemon context
 */
void daemon_cleanup(struct daemon_ctx *ctx);

/**
 * daemon_daemonize - Daemonize the process
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_daemonize(void);

/**
 * daemon_write_pid_file - Write PID to file
 * @path: Path to PID file
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_write_pid_file(const char *path);

/**
 * daemon_remove_pid_file - Remove PID file
 * @path: Path to PID file
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_remove_pid_file(const char *path);

/**
 * daemon_apply_config - Apply configuration to proxy fd
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_apply_config(struct daemon_ctx *ctx);

/**
 * daemon_setup_signals - Set up signal handlers
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_setup_signals(struct daemon_ctx *ctx);

/**
 * daemon_setup_file_watch - Set up inotify watch for config file
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_setup_file_watch(struct daemon_ctx *ctx);

/**
 * daemon_handle_file_event - Handle inotify event on config file
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_handle_file_event(struct daemon_ctx *ctx);

/**
 * daemon_main_loop - Main daemon event loop
 * @ctx: Pointer to daemon context
 *
 * Returns: 0 on success, -1 on error
 */
int daemon_main_loop(struct daemon_ctx *ctx);

#endif /* MUTEX_DAEMON_H */
