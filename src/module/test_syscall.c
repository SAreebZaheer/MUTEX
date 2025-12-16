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
struct mutex_proxy_config {
	unsigned int version;		/* Config version (must be 1) */
	unsigned int proxy_type;	/* Proxy type (1=SOCKS5, 2=HTTP, 3=HTTPS) */
	unsigned int proxy_port;	/* Proxy server port */
	unsigned char proxy_addr[16];	/* Proxy server address (IPv4 or IPv6) */
	unsigned int flags;		/* Configuration flags */
	unsigned char reserved[64];	/* Reserved for future use */
};

/*
 * Syscall number for mprox_create
 * Using syscall 471 as allocated in Branch 2
 */
#define __NR_mprox_create 471

/* Wrapper function for our custom syscall */
static int mprox_create(unsigned int flags)
{
	return syscall(__NR_mprox_create, flags);
}

/* Print usage information */
static void print_usage(const char *progname)
{
	printf("Usage: %s [flags]\n", progname);
	printf("\n");
	printf("Flags:\n");
	printf("  0x1 - MUTEX_PROXY_CLOEXEC (close-on-exec)\n");
	printf("  0x2 - MUTEX_PROXY_NONBLOCK (non-blocking)\n");
	printf("  0x4 - MUTEX_PROXY_GLOBAL (system-wide)\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s 0     # Create basic proxy fd\n", progname);
	printf("  %s 0x1   # Create with CLOEXEC\n", progname);
	printf("  %s 0x3   # Create with CLOEXEC | NONBLOCK\n", progname);
	printf("\n");
	printf("Note: This program requires root privileges (CAP_NET_ADMIN)\n");
}

int main(int argc, char *argv[])
{
	unsigned int flags = 0;
	int fd;

	/* Print test header */
	printf("MUTEX_PROXY mprox_create Syscall Test Program\n");
	printf("============================\n\n");

	/* Check if running as root */
	if (geteuid() != 0) {
		fprintf(stderr, "Error: This program must be run as root (sudo)\n");
		return EXIT_FAILURE;
	}

	/* Parse command line arguments */
	if (argc < 2) {
		/* No flags provided, use default */
		flags = 0;
		printf("Using default flags: 0x%x\n\n", flags);
	} else if (argc == 2) {
		/* Parse flags from command line */
		char *endptr;
		flags = strtoul(argv[1], &endptr, 0);
		if (*endptr != '\0') {
			fprintf(stderr, "Error: Invalid flags value\n");
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
		printf("Using flags: 0x%x\n\n", flags);
	} else {
		fprintf(stderr, "Error: Too many arguments\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* Display configuration */
	printf("Configuration:\n");
	printf("  Syscall Number: %d (mprox_create)\n", __NR_mprox_create);
	printf("  Flags:          0x%x\n", flags);
	if (flags & 0x1) printf("    - MUTEX_PROXY_CLOEXEC\n");
	if (flags & 0x2) printf("    - MUTEX_PROXY_NONBLOCK\n");
	if (flags & 0x4) printf("    - MUTEX_PROXY_GLOBAL\n");
	printf("\n");

	/* Invoke the system call */
	printf("Invoking mprox_create syscall...\n");
	fd = mprox_create(flags);

	/* Check result */
	if (fd >= 0) {
		printf("Success! File descriptor created: %d\n", fd);
		printf("Check kernel logs with: sudo dmesg | tail -20\n");
		printf("\nYou can now:\n");
		printf("  - Read statistics: cat /proc/self/fd/%d\n", fd);
		printf("  - Use ioctl to control the proxy\n");
		printf("  - Close the fd when done\n");

		/* Keep fd open for a moment to allow inspection */
		printf("\nPress Enter to close fd and exit...");
		getchar();
		close(fd);

		return EXIT_SUCCESS;
	} else {
		fprintf(stderr, "Error: Syscall failed with return value: %d\n", fd);

		/* Provide helpful error messages */
		switch (-fd) {
		case EPERM:
			fprintf(stderr, "Permission denied (CAP_NET_ADMIN required)\n");
			break;
		case EINVAL:
			fprintf(stderr, "Invalid flags\n");
			break;
		case ENOMEM:
			fprintf(stderr, "Out of memory\n");
			break;
		case ENOSYS:
			fprintf(stderr, "System call not implemented\n");
			fprintf(stderr, "The kernel may not have mprox_create syscall support\n");
			break;
		default:
			fprintf(stderr, "Error code: %d (%s)\n", -fd, strerror(-fd));
			break;
		}

		return EXIT_FAILURE;
	}
}
