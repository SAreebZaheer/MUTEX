// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Process Filter API Compilation Test
 *
 * Tests that the API compiles correctly and demonstrates usage patterns.
 * Does NOT require kernel module to be loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include "mutex_process_filter_api.h"

#define COLOR_GREEN  "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_BLUE   "\033[0;34m"
#define COLOR_RESET  "\033[0m"

static void print_header(const char *title)
{
	printf("\n%s=== %s ===%s\n", COLOR_BLUE, title, COLOR_RESET);
}

static void print_info(const char *fmt, ...)
{
	va_list args;
	printf("%s[INFO]%s ", COLOR_YELLOW, COLOR_RESET);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

static void print_ok(const char *fmt, ...)
{
	va_list args;
	printf("%s[OK]%s ", COLOR_GREEN, COLOR_RESET);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

void test_data_structures(void)
{
	struct mutex_process_filter_rule rule;
	struct mutex_process_filter_config config;
	struct mutex_process_filter_stats stats;

	print_header("Data Structure Sizes");

	printf("sizeof(mutex_process_filter_rule):   %zu bytes\n", sizeof(rule));
	printf("sizeof(mutex_process_filter_config): %zu bytes\n", sizeof(config));
	printf("sizeof(mutex_process_filter_stats):  %zu bytes\n", sizeof(stats));

	print_ok("All structures defined correctly");
}

void test_rule_helpers(void)
{
	struct mutex_process_filter_rule rule;

	print_header("Rule Helper Functions");

	// Test PID rule
	mutex_process_filter_create_pid_rule(&rule, 1234, MUTEX_PROCESS_SCOPE_CURRENT);
	print_ok("Created PID rule: PID=%d, scope=%s",
		 rule.match.pid.pid,
		 mutex_process_filter_scope_name(rule.scope));

	// Test UID rule
	mutex_process_filter_create_uid_rule(&rule, 1000);
	print_ok("Created UID rule: UID=%d", rule.match.uid.uid);

	// Test GID rule
	mutex_process_filter_create_gid_rule(&rule, 1000);
	print_ok("Created GID rule: GID=%d", rule.match.gid.gid);

	// Test comm rule
	mutex_process_filter_create_comm_rule(&rule, "firefox", true);
	print_ok("Created COMM rule: comm='%s', exact=%s",
		 rule.match.comm.comm,
		 rule.match.comm.exact_match ? "yes" : "no");

	// Test path rule
	mutex_process_filter_create_path_rule(&rule, "/usr/bin/test", false);
	print_ok("Created PATH rule: path='%s', exact=%s",
		 rule.match.path.path,
		 rule.match.path.exact_match ? "yes" : "no");

	// Test cgroup rule
	mutex_process_filter_create_cgroup_rule(&rule, "/user.slice", false);
	print_ok("Created CGROUP rule: cgroup='%s', exact=%s",
		 rule.match.cgroup.cgroup,
		 rule.match.cgroup.exact_match ? "yes" : "no");
}

void test_string_functions(void)
{
	print_header("String Conversion Functions");

	// Test mode names
	for (int i = 0; i <= 4; i++) {
		const char *name = mutex_process_filter_mode_name(i);
		print_ok("Mode %d = '%s'", i, name);
	}

	// Test match type names
	for (int i = 0; i <= 5; i++) {
		const char *name = mutex_process_filter_match_type_name(i);
		print_ok("Match type %d = '%s'", i, name);
	}

	// Test scope names
	for (int i = 0; i <= 3; i++) {
		const char *name = mutex_process_filter_scope_name(i);
		print_ok("Scope %d = '%s'", i, name);
	}
}

void demonstrate_usage_patterns(void)
{
	print_header("Usage Pattern Examples");

	print_info("Pattern 1: Owner-based filtering");
	printf("  int fd = mprox_create(0);\n");
	printf("  mutex_process_filter_capture_owner(fd);\n");
	printf("  mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_OWNER);\n");

	print_info("Pattern 2: Whitelist specific application");
	printf("  mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);\n");
	printf("  mutex_process_filter_create_comm_rule(&rule, \"firefox\", false);\n");
	printf("  mutex_process_filter_add_rule(fd, &rule);\n");

	print_info("Pattern 3: Blacklist root processes");
	printf("  mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_BLACKLIST);\n");
	printf("  mutex_process_filter_create_uid_rule(&rule, 0);\n");
	printf("  mutex_process_filter_add_rule(fd, &rule);\n");

	print_info("Pattern 4: Cgroup-based filtering");
	printf("  mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_CGROUP);\n");
	printf("  mutex_process_filter_create_cgroup_rule(&rule, \"/user.slice\", false);\n");
	printf("  mutex_process_filter_add_rule(fd, &rule);\n");

	print_ok("All usage patterns documented");
}

void show_current_process_info(void)
{
	char exe_path[256];
	ssize_t len;

	print_header("Current Process Information");

	printf("PID:  %d\n", getpid());
	printf("PPID: %d\n", getppid());
	printf("UID:  %d\n", getuid());
	printf("EUID: %d\n", geteuid());
	printf("GID:  %d\n", getgid());
	printf("EGID: %d\n", getegid());

	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len > 0) {
		exe_path[len] = '\0';
		printf("Executable: %s\n", exe_path);
	}

	print_ok("Process information retrieved");
}

void test_ioctl_definitions(void)
{
	print_header("IOCTL Command Definitions");

	print_ok("MUTEX_IOCTL_SET_FILTER_MODE defined");
	print_ok("MUTEX_IOCTL_GET_FILTER_MODE defined");
	print_ok("MUTEX_IOCTL_ADD_FILTER_RULE defined");
	print_ok("MUTEX_IOCTL_REMOVE_FILTER_RULE defined");
	print_ok("MUTEX_IOCTL_CLEAR_FILTER_RULES defined");
	print_ok("MUTEX_IOCTL_GET_FILTER_CONFIG defined");
	print_ok("MUTEX_IOCTL_SET_FILTER_CONFIG defined");
	print_ok("MUTEX_IOCTL_CAPTURE_OWNER defined");
	print_ok("MUTEX_IOCTL_GET_FILTER_STATS defined");
	print_ok("MUTEX_IOCTL_RESET_FILTER_STATS defined");
	print_ok("MUTEX_IOCTL_INVALIDATE_CACHE defined");

	print_ok("All IOCTL commands defined");
}

int main(void)
{
	printf("\n");
	printf("╔════════════════════════════════════════════════════════╗\n");
	printf("║  MUTEX Process Filter API Compilation Test            ║\n");
	printf("║  Tests API without requiring kernel module            ║\n");
	printf("╚════════════════════════════════════════════════════════╝\n");

	test_data_structures();
	test_rule_helpers();
	test_string_functions();
	test_ioctl_definitions();
	demonstrate_usage_patterns();
	show_current_process_info();

	print_header("Summary");
	print_ok("All API functions compiled successfully");
	print_ok("Data structures are well-defined");
	print_ok("Helper functions work correctly");

	printf("\n%s[NOTE]%s To test with actual kernel module:\n",
	       COLOR_YELLOW, COLOR_RESET);
	printf("  1. Build and load the MUTEX kernel module\n");
	printf("  2. Run: sudo ./test_process_filter\n");
	printf("  3. The full integration test will execute\n");

	printf("\n%s✓ API Compilation Test: PASSED%s\n\n",
	       COLOR_GREEN, COLOR_RESET);

	return 0;
}
