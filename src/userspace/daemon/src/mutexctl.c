/**
 * mutexctl.c - Control utility for MUTEX daemon
 *
 * Part of MUTEX (Multi-User Threaded Exchange Xfer)
 * Kernel-level proxy module project
 */

#define _GNU_SOURCE
#include "../include/mprox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define DEFAULT_PID_FILE "/var/run/mutexd.pid"

static int read_pid_file(const char *pid_file)
{
    FILE *fp = fopen(pid_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open PID file %s: %s\n", pid_file, strerror(errno));
        return -1;
    }

    int pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        fprintf(stderr, "Failed to read PID from %s\n", pid_file);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return pid;
}

static int send_signal_to_daemon(int signum, const char *pid_file)
{
    int pid = read_pid_file(pid_file);
    if (pid < 0)
        return -1;

    if (kill(pid, signum) < 0) {
        fprintf(stderr, "Failed to send signal to daemon (PID %d): %s\n",
                pid, strerror(errno));
        return -1;
    }

    return 0;
}

static void print_usage(const char *progname)
{
    printf("Usage: %s COMMAND [OPTIONS]\n", progname);
    printf("\n");
    printf("Control utility for MUTEX daemon\n");
    printf("\n");
    printf("Commands:\n");
    printf("  start               Start the daemon\n");
    printf("  stop                Stop the daemon\n");
    printf("  restart             Restart the daemon\n");
    printf("  reload              Reload configuration (SIGHUP)\n");
    printf("  status              Show daemon status\n");
    printf("  stats               Show proxy statistics\n");
    printf("\n");
    printf("Options:\n");
    printf("  -p, --pid-file FILE   PID file path (default: %s)\n", DEFAULT_PID_FILE);
    printf("  -h, --help            Print this help message\n");
    printf("\n");
}

static int cmd_start(const char *pid_file)
{
    /* Check if already running */
    int pid = read_pid_file(pid_file);
    if (pid > 0 && kill(pid, 0) == 0) {
        printf("Daemon is already running (PID %d)\n", pid);
        return 1;
    }

    /* Start daemon */
    printf("Starting mutexd...\n");

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
        return -1;
    }

    if (child == 0) {
        /* Child process - exec daemon */
        execl("/usr/local/bin/mutexd", "mutexd", NULL);
        fprintf(stderr, "Failed to exec mutexd: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Parent process - wait a moment and check if started */
    sleep(1);

    pid = read_pid_file(pid_file);
    if (pid > 0 && kill(pid, 0) == 0) {
        printf("Daemon started successfully (PID %d)\n", pid);
        return 0;
    } else {
        fprintf(stderr, "Failed to start daemon\n");
        return -1;
    }
}

static int cmd_stop(const char *pid_file)
{
    int pid = read_pid_file(pid_file);
    if (pid < 0) {
        printf("Daemon is not running\n");
        return 1;
    }

    printf("Stopping mutexd (PID %d)...\n", pid);

    if (send_signal_to_daemon(SIGTERM, pid_file) < 0)
        return -1;

    /* Wait for daemon to stop */
    for (int i = 0; i < 10; i++) {
        sleep(1);
        if (kill(pid, 0) < 0) {
            printf("Daemon stopped\n");
            return 0;
        }
    }

    fprintf(stderr, "Daemon did not stop gracefully, sending SIGKILL\n");
    kill(pid, SIGKILL);
    sleep(1);

    if (kill(pid, 0) < 0) {
        printf("Daemon killed\n");
        return 0;
    }

    fprintf(stderr, "Failed to stop daemon\n");
    return -1;
}

static int cmd_restart(const char *pid_file)
{
    printf("Restarting mutexd...\n");

    /* Stop if running */
    int pid = read_pid_file(pid_file);
    if (pid > 0 && kill(pid, 0) == 0) {
        if (cmd_stop(pid_file) < 0)
            return -1;
    }

    /* Start */
    return cmd_start(pid_file);
}

static int cmd_reload(const char *pid_file)
{
    printf("Reloading configuration...\n");

    if (send_signal_to_daemon(SIGHUP, pid_file) < 0)
        return -1;

    printf("Reload signal sent\n");
    return 0;
}

static int cmd_status(const char *pid_file)
{
    int pid = read_pid_file(pid_file);
    if (pid < 0) {
        printf("Daemon is not running\n");
        return 1;
    }

    if (kill(pid, 0) < 0) {
        printf("Daemon is not running (stale PID file)\n");
        return 1;
    }

    printf("Daemon is running (PID %d)\n", pid);

    /* Try to get more info from /proc */
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", pid);

    FILE *fp = fopen(proc_path, "r");
    if (fp) {
        char comm[256];
        char state;
        unsigned long utime, stime;

        if (fscanf(fp, "%*d %s %c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                   comm, &state, &utime, &stime) == 4) {
            printf("Command: %s\n", comm);
            printf("State: %c\n", state);
            printf("CPU time: user=%lu system=%lu\n", utime, stime);
        }

        fclose(fp);
    }

    return 0;
}

static int cmd_stats(const char *pid_file)
{
    int pid = read_pid_file(pid_file);
    if (pid < 0) {
        fprintf(stderr, "Daemon is not running\n");
        return 1;
    }

    /* Create temporary proxy fd to query stats */
    int fd = mprox_create(0);
    if (fd < 0) {
        fprintf(stderr, "Failed to create proxy fd: %s\n", strerror(errno));
        fprintf(stderr, "Note: Syscall may not be available in current kernel\n");
        return -1;
    }

    struct mprox_stats stats;
    if (mprox_get_stats(fd, &stats) < 0) {
        fprintf(stderr, "Failed to get statistics: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Proxy Statistics:\n");
    printf("  Packets proxied:     %lu\n", stats.packets_proxied);
    printf("  Packets direct:      %lu\n", stats.packets_direct);
    printf("  Bytes sent:          %lu\n", stats.bytes_sent);
    printf("  Bytes received:      %lu\n", stats.bytes_received);
    printf("  Connections active:  %lu\n", stats.connections_active);
    printf("  Connections total:   %lu\n", stats.connections_total);
    printf("  Errors:              %lu\n", stats.errors);

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *pid_file = DEFAULT_PID_FILE;

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *command = argv[1];

    /* Parse options */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid-file") == 0) {
            if (i + 1 < argc) {
                pid_file = argv[++i];
            } else {
                fprintf(stderr, "Error: --pid-file requires an argument\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    /* Execute command */
    if (strcmp(command, "start") == 0) {
        return cmd_start(pid_file);
    } else if (strcmp(command, "stop") == 0) {
        return cmd_stop(pid_file);
    } else if (strcmp(command, "restart") == 0) {
        return cmd_restart(pid_file);
    } else if (strcmp(command, "reload") == 0) {
        return cmd_reload(pid_file);
    } else if (strcmp(command, "status") == 0) {
        return cmd_status(pid_file);
    } else if (strcmp(command, "stats") == 0) {
        return cmd_stats(pid_file);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
