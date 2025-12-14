/*
 * Test program for KPROXY syscall
 * Part of the MUTEX Project
 *
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 * Date: December 14, 2025
 *
 * Description: This userspace program tests the custom kproxy_enable syscall.
 * It must be run with root/sudo privileges due to CAP_NET_ADMIN requirement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

/* Proxy configuration structure (must match kernel structure) */
struct kproxy_config {
	unsigned int enable;		/* 0 = disable, 1 = enable */
	unsigned int proxy_port;	/* Proxy server port */
	char proxy_addr[16];		/* Proxy server IP address */
};

/*
 * Architecture-specific syscall numbers
 * Must match the definitions in kproxy.c
 */
#if defined(__x86_64__)
	#define __NR_kproxy_enable 335
#elif defined(__i386__)
	#define __NR_kproxy_enable 358
#elif defined(__aarch64__)
	#define __NR_kproxy_enable 400
#else
	#define __NR_kproxy_enable 335
#endif

/* Wrapper function for our custom syscall */
static long kproxy_enable(struct kproxy_config *config)
{
	return syscall(__NR_kproxy_enable, config);
}

/* Print usage information */
static void print_usage(const char *progname)
{
	printf("Usage: %s <enable|disable> <proxy_ip> <proxy_port>\n", progname);
	printf("\n");
	printf("Examples:\n");
	printf("  %s enable 192.168.1.100 8080\n", progname);
	printf("  %s disable 192.168.1.100 8080\n", progname);
	printf("\n");
	printf("Note: This program requires root privileges (CAP_NET_ADMIN)\n");
}

int main(int argc, char *argv[])
{
	struct kproxy_config config;
	long ret;
	int enable_flag;

	/* Print test header */
	printf("KPROXY Syscall Test Program\n");
	printf("============================\n\n");

	/* Check if running as root */
	if (geteuid() != 0) {
		fprintf(stderr, "Error: This program must be run as root (sudo)\n");
		return EXIT_FAILURE;
	}

	/* Parse command line arguments */
	if (argc != 4) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* Parse enable/disable argument */
	if (strcmp(argv[1], "enable") == 0) {
		enable_flag = 1;
	} else if (strcmp(argv[1], "disable") == 0) {
		enable_flag = 0;
	} else {
		fprintf(stderr, "Error: First argument must be 'enable' or 'disable'\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* Parse proxy IP address */
	if (strlen(argv[2]) >= sizeof(config.proxy_addr)) {
		fprintf(stderr, "Error: Proxy IP address too long\n");
		return EXIT_FAILURE;
	}

	/* Parse proxy port */
	int port = atoi(argv[3]);
	if (port <= 0 || port > 65535) {
		fprintf(stderr, "Error: Invalid port number (must be 1-65535)\n");
		return EXIT_FAILURE;
	}

	/* Fill configuration structure */
	memset(&config, 0, sizeof(config));
	config.enable = enable_flag;
	config.proxy_port = port;
	strncpy(config.proxy_addr, argv[2], sizeof(config.proxy_addr) - 1);

	/* Display configuration */
	printf("Configuration:\n");
	printf("  Action:       %s\n", enable_flag ? "ENABLE" : "DISABLE");
	printf("  Proxy IP:     %s\n", config.proxy_addr);
	printf("  Proxy Port:   %u\n", config.proxy_port);
	printf("  Syscall Num:  %d\n", __NR_kproxy_enable);
	printf("\n");

	/* Invoke the system call */
	printf("Invoking kproxy_enable syscall...\n");
	ret = kproxy_enable(&config);

	/* Check result */
	if (ret == 0) {
		printf("Success! Syscall completed successfully.\n");
		printf("Check kernel logs with: sudo dmesg | tail -20\n");
		return EXIT_SUCCESS;
	} else {
		fprintf(stderr, "Error: Syscall failed with return value: %ld\n", ret);
		
		/* Provide helpful error messages */
		switch (-ret) {
		case EPERM:
			fprintf(stderr, "Permission denied (CAP_NET_ADMIN required)\n");
			break;
		case EINVAL:
			fprintf(stderr, "Invalid argument\n");
			break;
		case EFAULT:
			fprintf(stderr, "Bad address\n");
			break;
		case ENOSYS:
			fprintf(stderr, "System call not implemented (module loaded?)\n");
			fprintf(stderr, "Try: sudo insmod kproxy.ko\n");
			break;
		default:
			fprintf(stderr, "Error code: %ld (%s)\n", -ret, strerror(-ret));
			break;
		}
		
		return EXIT_FAILURE;
	}
}
