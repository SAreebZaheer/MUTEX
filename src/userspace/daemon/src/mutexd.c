/**
 * mutexd.c - Main entry point for MUTEX daemon
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#define _GNU_SOURCE
#include "../include/daemon.h"
#include "../include/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#define VERSION "1.0.0"

static void print_usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("MUTEX Daemon - Kernel-level proxy service\n");
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config FILE     Configuration file path (default: %s)\n", DEFAULT_CONFIG_PATH);
    printf("  -f, --foreground      Run in foreground (don't daemonize)\n");
    printf("  -t, --test            Test configuration and exit\n");
    printf("  -v, --verbose         Verbose output (debug mode)\n");
    printf("  -V, --version         Print version and exit\n");
    printf("  -h, --help            Print this help message\n");
    printf("\n");
    printf("Signals:\n");
    printf("  SIGHUP                Reload configuration\n");
    printf("  SIGTERM, SIGINT       Graceful shutdown\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c /etc/mutex/custom.conf\n", progname);
    printf("  %s -f -v\n", progname);
    printf("  %s -t -c /etc/mutex/custom.conf\n", progname);
    printf("\n");
}

static void print_version(void)
{
    printf("mutexd version %s\n", VERSION);
    printf("Part of MUTEX (Multi-User Threaded Exchange Xfer)\n");
    printf("Kernel-level proxy module project\n");
}

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG_PATH;
    bool foreground = false;
    bool test_only = false;
    bool verbose = false;
    int ret = EXIT_FAILURE;

    struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},
        {"foreground", no_argument,       0, 'f'},
        {"test",       no_argument,       0, 't'},
        {"verbose",    no_argument,       0, 'v'},
        {"version",    no_argument,       0, 'V'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line arguments */
    int c;
    while ((c = getopt_long(argc, argv, "c:ftvVh", long_options, NULL)) != -1) {
        switch (c) {
        case 'c':
            config_path = optarg;
            break;
        case 'f':
            foreground = true;
            break;
        case 't':
            test_only = true;
            break;
        case 'v':
            verbose = true;
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Initialize daemon context */
    struct daemon_ctx ctx;
    if (daemon_init(&ctx, config_path) < 0) {
        fprintf(stderr, "Failed to initialize daemon\n");
        return EXIT_FAILURE;
    }

    /* Set verbose mode */
    if (verbose) {
        ctx.config.daemon.log_level = LOG_LEVEL_DEBUG;
    }

    /* Test mode - validate configuration and exit */
    if (test_only) {
        printf("Testing configuration: %s\n", config_path);
        printf("Configuration is valid.\n");
        config_print(&ctx.config);
        config_free(&ctx.config);
        free(ctx.config_path);
        return EXIT_SUCCESS;
    }

    /* Check if running as root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: %s must be run as root (requires CAP_NET_ADMIN)\n", argv[0]);
        daemon_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Start daemon */
    printf("Starting %s...\n", ctx.config.daemon.name);
    printf("Configuration: %s\n", config_path);
    printf("PID file: %s\n", ctx.config.daemon.pid_file);
    printf("Log file: %s\n", ctx.config.daemon.log_file);

    if (daemon_start(&ctx, foreground) < 0) {
        fprintf(stderr, "Failed to start daemon\n");
        daemon_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Daemon has stopped, clean up */
    daemon_cleanup(&ctx);

    printf("Daemon stopped\n");
    return EXIT_SUCCESS;
}
