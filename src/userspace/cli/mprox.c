/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mprox.c - MUTEX proxy management CLI tool
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * Command-line utility for managing MUTEX kernel-level proxy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../lib/libmutex.h"

#define PROGRAM_NAME	"mprox"
#define PROGRAM_VERSION	"0.1"

/* Command types */
enum command {
	CMD_NONE = 0,
	CMD_CREATE,
	CMD_ENABLE,
	CMD_DISABLE,
	CMD_CONFIG,
	CMD_STATUS,
	CMD_STATS,
	CMD_HELP,
	CMD_VERSION,
};

/* Global options */
static struct {
	enum command cmd;
	int fd;
	char *proxy_addr;
	uint16_t proxy_port;
	int proxy_type;
	unsigned int flags;
	int verbose;
} opts = {
	.cmd = CMD_NONE,
	.fd = -1,
	.proxy_type = PROXY_TYPE_SOCKS5,
	.flags = 0,
	.verbose = 0,
};

static void usage(void)
{
	printf("Usage: %s [OPTIONS] COMMAND\n\n", PROGRAM_NAME);
	printf("Kernel-level proxy management tool\n\n");
	printf("Commands:\n");
	printf("  create              Create a new proxy file descriptor\n");
	printf("  enable FD           Enable proxy for file descriptor FD\n");
	printf("  disable FD          Disable proxy for file descriptor FD\n");
	printf("  config FD           Configure proxy for file descriptor FD\n");
	printf("  status FD           Show proxy status for file descriptor FD\n");
	printf("  stats FD            Show statistics for file descriptor FD\n");
	printf("  help                Show this help message\n");
	printf("  version             Show version information\n\n");
	printf("Options:\n");
	printf("  -a, --address=ADDR  Proxy server address (IPv4 or IPv6)\n");
	printf("  -p, --port=PORT     Proxy server port\n");
	printf("  -t, --type=TYPE     Proxy type: socks5, http, https (default: socks5)\n");
	printf("  -g, --global        Enable global proxy (all processes)\n");
	printf("  -c, --cloexec       Set close-on-exec flag\n");
	printf("  -n, --nonblock      Set non-blocking mode\n");
	printf("  -v, --verbose       Verbose output\n");
	printf("  -h, --help          Show this help message\n\n");
	printf("Examples:\n");
	printf("  # Create a new proxy fd\n");
	printf("  %s create\n\n", PROGRAM_NAME);
	printf("  # Create with specific flags\n");
	printf("  %s create --global --cloexec\n\n", PROGRAM_NAME);
	printf("  # Configure SOCKS5 proxy\n");
	printf("  %s config 3 -a 127.0.0.1 -p 1080 -t socks5\n\n", PROGRAM_NAME);
	printf("  # Enable proxy\n");
	printf("  %s enable 3\n\n", PROGRAM_NAME);
	printf("  # Check status\n");
	printf("  %s status 3\n\n", PROGRAM_NAME);
	printf("  # View statistics\n");
	printf("  %s stats 3\n\n", PROGRAM_NAME);
}

static void version(void)
{
	int major, minor, patch;
	mprox_get_version(&major, &minor, &patch);

	printf("%s version %s\n", PROGRAM_NAME, PROGRAM_VERSION);
	printf("libmutex version %d.%d.%d\n", major, minor, patch);
}

static int parse_proxy_type(const char *type_str)
{
	if (strcasecmp(type_str, "socks5") == 0)
		return PROXY_TYPE_SOCKS5;
	else if (strcasecmp(type_str, "http") == 0)
		return PROXY_TYPE_HTTP;
	else if (strcasecmp(type_str, "https") == 0)
		return PROXY_TYPE_HTTPS;
	else
		return -1;
}

static const char *proxy_type_str(int type)
{
	switch (type) {
	case PROXY_TYPE_SOCKS5:
		return "SOCKS5";
	case PROXY_TYPE_HTTP:
		return "HTTP";
	case PROXY_TYPE_HTTPS:
		return "HTTPS";
	default:
		return "Unknown";
	}
}

static void print_config(const struct mutex_proxy_config *config)
{
	char addr_str[INET6_ADDRSTRLEN];
	unsigned int i;

	printf("Proxy Configuration:\n");
	printf("  Version:  %u\n", config->version);
	printf("  Servers:  %u\n", config->num_servers);
	printf("  Strategy: %u\n", config->selection_strategy);
	printf("  Current:  %u\n", config->current_server);

	for (i = 0; i < config->num_servers && i < MUTEX_PROXY_MAX_SERVERS; i++) {
		const struct mutex_proxy_server *srv = &config->servers[i];
		printf("\n  Server %u:\n", i);
		printf("    Type:     %s\n", proxy_type_str(srv->proxy_type));
		printf("    Port:     %u\n", srv->proxy_port);
		printf("    Priority: %u\n", srv->priority);
		printf("    Flags:    0x%x%s%s%s\n", srv->flags,
		       (srv->flags & PROXY_CONFIG_ACTIVE) ? " ACTIVE" : "",
		       (srv->flags & PROXY_CONFIG_IPV6) ? " IPV6" : "",
		       (srv->flags & PROXY_CONFIG_AUTH) ? " AUTH" : "");

		/* Try to format address */
		if (srv->flags & PROXY_CONFIG_IPV6) {
			if (inet_ntop(AF_INET6, srv->proxy_addr, addr_str, sizeof(addr_str))) {
				printf("    Address:  %s (IPv6)\n", addr_str);
			} else {
				printf("    Address:  <invalid>\n");
			}
		} else {
			if (inet_ntop(AF_INET, srv->proxy_addr, addr_str, sizeof(addr_str))) {
				printf("    Address:  %s (IPv4)\n", addr_str);
			} else {
				printf("    Address:  <invalid>\n");
			}
		}
	}
}

static void print_stats(const struct mutex_proxy_stats *stats)
{
	printf("Proxy Statistics:\n");
	printf("  Bytes sent:        %llu\n", (unsigned long long)stats->bytes_sent);
	printf("  Bytes received:    %llu\n", (unsigned long long)stats->bytes_received);
	printf("  Packets sent:      %llu\n", (unsigned long long)stats->packets_sent);
	printf("  Packets received:  %llu\n", (unsigned long long)stats->packets_received);
	printf("  Active connections:%llu\n", (unsigned long long)stats->connections_active);
	printf("  Total connections: %llu\n", (unsigned long long)stats->connections_total);
}

static int cmd_create(void)
{
	int fd;

	if (opts.verbose)
		printf("Creating proxy fd with flags: 0x%x\n", opts.flags);

	fd = mprox_create(opts.flags);
	if (fd < 0) {
		fprintf(stderr, "Error: Failed to create proxy fd: %s\n",
			strerror(errno));
		return 1;
	}

	printf("%d\n", fd);
	return 0;
}

static int cmd_enable(void)
{
	if (opts.fd < 0) {
		fprintf(stderr, "Error: File descriptor not specified\n");
		return 1;
	}

	if (opts.verbose)
		printf("Enabling proxy for fd %d\n", opts.fd);

	if (mprox_enable(opts.fd) < 0) {
		fprintf(stderr, "Error: Failed to enable proxy: %s\n",
			strerror(errno));
		return 1;
	}

	printf("Proxy enabled for fd %d\n", opts.fd);
	return 0;
}

static int cmd_disable(void)
{
	if (opts.fd < 0) {
		fprintf(stderr, "Error: File descriptor not specified\n");
		return 1;
	}

	if (opts.verbose)
		printf("Disabling proxy for fd %d\n", opts.fd);

	if (mprox_disable(opts.fd) < 0) {
		fprintf(stderr, "Error: Failed to disable proxy: %s\n",
			strerror(errno));
		return 1;
	}

	printf("Proxy disabled for fd %d\n", opts.fd);
	return 0;
}

static int cmd_config(void)
{
	if (opts.fd < 0) {
		fprintf(stderr, "Error: File descriptor not specified\n");
		return 1;
	}

	if (!opts.proxy_addr) {
		fprintf(stderr, "Error: Proxy address not specified (-a)\n");
		return 1;
	}

	if (opts.proxy_port == 0) {
		fprintf(stderr, "Error: Proxy port not specified (-p)\n");
		return 1;
	}

	if (opts.verbose) {
		printf("Configuring proxy for fd %d:\n", opts.fd);
		printf("  Type: %s\n", proxy_type_str(opts.proxy_type));
		printf("  Address: %s\n", opts.proxy_addr);
		printf("  Port: %u\n", opts.proxy_port);
	}

	if (opts.proxy_type == PROXY_TYPE_SOCKS5) {
		if (mprox_set_socks5(opts.fd, opts.proxy_addr, opts.proxy_port) < 0) {
			fprintf(stderr, "Error: Failed to configure SOCKS5 proxy: %s\n",
				strerror(errno));
			return 1;
		}
	} else {
		if (mprox_set_http(opts.fd, opts.proxy_addr, opts.proxy_port,
				   opts.proxy_type == PROXY_TYPE_HTTPS) < 0) {
			fprintf(stderr, "Error: Failed to configure HTTP proxy: %s\n",
				strerror(errno));
			return 1;
		}
	}

	printf("Proxy configured for fd %d\n", opts.fd);
	return 0;
}

static int cmd_status(void)
{
	struct mutex_proxy_config config;

	if (opts.fd < 0) {
		fprintf(stderr, "Error: File descriptor not specified\n");
		return 1;
	}

	if (mprox_get_config(opts.fd, &config) < 0) {
		fprintf(stderr, "Error: Failed to get config: %s\n",
			strerror(errno));
		return 1;
	}

	printf("Proxy Status (fd %d):\n", opts.fd);
	if (config.num_servers == 0 || config.servers[0].proxy_type == 0) {
		printf("  Status: Not configured\n");
	} else {
		printf("  Status: Configured\n");
		print_config(&config);
	}

	return 0;
}

static int cmd_stats(void)
{
	struct mutex_proxy_stats stats;

	if (opts.fd < 0) {
		fprintf(stderr, "Error: File descriptor not specified\n");
		return 1;
	}

	if (mprox_get_stats(opts.fd, &stats) < 0) {
		fprintf(stderr, "Error: Failed to get stats: %s\n",
			strerror(errno));
		return 1;
	}

	printf("Proxy Statistics (fd %d):\n", opts.fd);
	print_stats(&stats);

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int ret = 0;

	static struct option long_options[] = {
		{"address",  required_argument, 0, 'a'},
		{"port",     required_argument, 0, 'p'},
		{"type",     required_argument, 0, 't'},
		{"global",   no_argument,       0, 'g'},
		{"cloexec",  no_argument,       0, 'c'},
		{"nonblock", no_argument,       0, 'n'},
		{"verbose",  no_argument,       0, 'v'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	/* Parse options */
	while ((opt = getopt_long(argc, argv, "a:p:t:gcnvh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			opts.proxy_addr = optarg;
			break;
		case 'p':
			opts.proxy_port = atoi(optarg);
			break;
		case 't':
			opts.proxy_type = parse_proxy_type(optarg);
			if (opts.proxy_type < 0) {
				fprintf(stderr, "Error: Invalid proxy type: %s\n",
					optarg);
				return 1;
			}
			break;
		case 'g':
			opts.flags |= MUTEX_PROXY_GLOBAL;
			break;
		case 'c':
			opts.flags |= MUTEX_PROXY_CLOEXEC;
			break;
		case 'n':
			opts.flags |= MUTEX_PROXY_NONBLOCK;
			break;
		case 'v':
			opts.verbose = 1;
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	/* Parse command */
	if (optind >= argc) {
		fprintf(stderr, "Error: No command specified\n\n");
		usage();
		return 1;
	}

	const char *cmd = argv[optind];

	if (strcmp(cmd, "create") == 0) {
		opts.cmd = CMD_CREATE;
	} else if (strcmp(cmd, "enable") == 0) {
		opts.cmd = CMD_ENABLE;
		if (optind + 1 < argc)
			opts.fd = atoi(argv[optind + 1]);
	} else if (strcmp(cmd, "disable") == 0) {
		opts.cmd = CMD_DISABLE;
		if (optind + 1 < argc)
			opts.fd = atoi(argv[optind + 1]);
	} else if (strcmp(cmd, "config") == 0) {
		opts.cmd = CMD_CONFIG;
		if (optind + 1 < argc)
			opts.fd = atoi(argv[optind + 1]);
	} else if (strcmp(cmd, "status") == 0) {
		opts.cmd = CMD_STATUS;
		if (optind + 1 < argc)
			opts.fd = atoi(argv[optind + 1]);
	} else if (strcmp(cmd, "stats") == 0) {
		opts.cmd = CMD_STATS;
		if (optind + 1 < argc)
			opts.fd = atoi(argv[optind + 1]);
	} else if (strcmp(cmd, "help") == 0) {
		opts.cmd = CMD_HELP;
	} else if (strcmp(cmd, "version") == 0) {
		opts.cmd = CMD_VERSION;
	} else {
		fprintf(stderr, "Error: Unknown command: %s\n\n", cmd);
		usage();
		return 1;
	}

	/* Execute command */
	switch (opts.cmd) {
	case CMD_CREATE:
		ret = cmd_create();
		break;
	case CMD_ENABLE:
		ret = cmd_enable();
		break;
	case CMD_DISABLE:
		ret = cmd_disable();
		break;
	case CMD_CONFIG:
		ret = cmd_config();
		break;
	case CMD_STATUS:
		ret = cmd_status();
		break;
	case CMD_STATS:
		ret = cmd_stats();
		break;
	case CMD_HELP:
		usage();
		break;
	case CMD_VERSION:
		version();
		break;
	default:
		fprintf(stderr, "Error: No command specified\n\n");
		usage();
		ret = 1;
	}

	return ret;
}
