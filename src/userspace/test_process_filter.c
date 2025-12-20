// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX - Multi-User Threaded Exchange Xfer
 * Process Filter Test Utility
 *
 * Tests process filtering functionality including PID, UID, GID,
 * executable path, command name, and cgroup-based filtering.
 *
 * Copyright (C) 2025 MUTEX Development Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "mutex_process_filter_api.h"

/* Test configuration */
#define TEST_FD_PATH		"/dev/mutex0"  /* Placeholder for actual fd */
#define COLOR_RED		"\033[0;31m"
#define COLOR_GREEN		"\033[0;32m"
#define COLOR_YELLOW		"\033[0;33m"
#define COLOR_BLUE		"\033[0;34m"
#define COLOR_RESET		"\033[0m"

/* Global test counters */
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_total = 0;

/* Helper macros */
#define TEST_START(name) \
	do { \
		tests_total++; \
		printf("%s[TEST %d]%s %s\n", COLOR_BLUE, tests_total, COLOR_RESET, name); \
	} while (0)

#define TEST_PASS(fmt, ...) \
	do { \
		tests_passed++; \
		printf("  %s[PASS]%s " fmt "\n", COLOR_GREEN, COLOR_RESET, ##__VA_ARGS__); \
	} while (0)

#define TEST_FAIL(fmt, ...) \
	do { \
		tests_failed++; \
		printf("  %s[FAIL]%s " fmt "\n", COLOR_RED, COLOR_RESET, ##__VA_ARGS__); \
	} while (0)

#define TEST_INFO(fmt, ...) \
	printf("  %s[INFO]%s " fmt "\n", COLOR_YELLOW, COLOR_RESET, ##__VA_ARGS__)

/* ========== Test Functions ========== */

/**
 * test_filter_mode() - Test filter mode operations
 */
static void test_filter_mode(int fd)
{
	int ret, mode;

	TEST_START("Filter Mode Operations");

	/* Test setting to NONE */
	ret = mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_NONE);
	if (ret == 0) {
		TEST_PASS("Set mode to NONE");
	} else {
		TEST_FAIL("Failed to set mode to NONE: %s", strerror(errno));
		return;
	}

	/* Test getting mode */
	mode = mutex_process_filter_get_mode(fd);
	if (mode == MUTEX_PROCESS_FILTER_NONE) {
		TEST_PASS("Get mode returned NONE");
	} else if (mode < 0) {
		TEST_FAIL("Failed to get mode: %s", strerror(errno));
	} else {
		TEST_FAIL("Get mode returned wrong value: %d", mode);
	}

	/* Test setting to WHITELIST */
	ret = mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_WHITELIST);
	if (ret == 0) {
		TEST_PASS("Set mode to WHITELIST");
		mode = mutex_process_filter_get_mode(fd);
		if (mode == MUTEX_PROCESS_FILTER_WHITELIST)
			TEST_PASS("Mode persisted correctly");
		else
			TEST_FAIL("Mode did not persist");
	} else {
		TEST_FAIL("Failed to set mode to WHITELIST: %s", strerror(errno));
	}

	/* Test setting to BLACKLIST */
	ret = mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_BLACKLIST);
	if (ret == 0) {
		TEST_PASS("Set mode to BLACKLIST");
	} else {
		TEST_FAIL("Failed to set mode to BLACKLIST: %s", strerror(errno));
	}

	/* Test setting to OWNER */
	ret = mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_OWNER);
	if (ret == 0) {
		TEST_PASS("Set mode to OWNER");
	} else {
		TEST_FAIL("Failed to set mode to OWNER: %s", strerror(errno));
	}

	/* Reset to NONE */
	mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_NONE);
}

/**
 * test_pid_rules() - Test PID-based filtering rules
 */
static void test_pid_rules(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;
	pid_t current_pid;

	TEST_START("PID-based Filtering Rules");

	current_pid = getpid();
	TEST_INFO("Current PID: %d", current_pid);

	/* Create PID rule for current process */
	mutex_process_filter_create_pid_rule(&rule, current_pid,
					     MUTEX_PROCESS_SCOPE_CURRENT);

	/* Add rule */
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added PID rule for current process");
	} else {
		TEST_FAIL("Failed to add PID rule: %s", strerror(errno));
		return;
	}

	/* Create PID rule with tree scope */
	mutex_process_filter_create_pid_rule(&rule, current_pid,
					     MUTEX_PROCESS_SCOPE_TREE);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added PID rule with tree scope");
	} else {
		TEST_FAIL("Failed to add PID tree rule: %s", strerror(errno));
	}

	/* Clear rules */
	ret = mutex_process_filter_clear_rules(fd);
	if (ret == 0) {
		TEST_PASS("Cleared all rules");
	} else {
		TEST_FAIL("Failed to clear rules: %s", strerror(errno));
	}
}

/**
 * test_uid_gid_rules() - Test UID/GID-based filtering rules
 */
static void test_uid_gid_rules(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;
	uid_t uid;
	gid_t gid;

	TEST_START("UID/GID-based Filtering Rules");

	uid = getuid();
	gid = getgid();
	TEST_INFO("Current UID: %d, GID: %d", uid, gid);

	/* Create UID rule */
	mutex_process_filter_create_uid_rule(&rule, uid);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added UID rule");
	} else {
		TEST_FAIL("Failed to add UID rule: %s", strerror(errno));
	}

	/* Create GID rule */
	mutex_process_filter_create_gid_rule(&rule, gid);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added GID rule");
	} else {
		TEST_FAIL("Failed to add GID rule: %s", strerror(errno));
	}

	/* Clear rules */
	mutex_process_filter_clear_rules(fd);
}

/**
 * test_comm_rules() - Test command name filtering rules
 */
static void test_comm_rules(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;

	TEST_START("Command Name Filtering Rules");

	/* Create exact match rule */
	mutex_process_filter_create_comm_rule(&rule, "test_process_f",
					      true);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added exact comm name rule");
	} else {
		TEST_FAIL("Failed to add exact comm rule: %s", strerror(errno));
	}

	/* Create substring match rule */
	mutex_process_filter_create_comm_rule(&rule, "bash", false);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added substring comm name rule");
	} else {
		TEST_FAIL("Failed to add substring comm rule: %s", strerror(errno));
	}

	/* Clear rules */
	mutex_process_filter_clear_rules(fd);
}

/**
 * test_path_rules() - Test executable path filtering rules
 */
static void test_path_rules(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;
	char exe_path[256];
	ssize_t len;

	TEST_START("Executable Path Filtering Rules");

	/* Get current executable path */
	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len > 0) {
		exe_path[len] = '\0';
		TEST_INFO("Current executable: %s", exe_path);

		/* Create exact match rule */
		mutex_process_filter_create_path_rule(&rule, exe_path, true);
		ret = mutex_process_filter_add_rule(fd, &rule);
		if (ret == 0) {
			TEST_PASS("Added exact path rule");
		} else {
			TEST_FAIL("Failed to add exact path rule: %s", strerror(errno));
		}
	} else {
		TEST_FAIL("Failed to get executable path");
	}

	/* Create prefix match rule */
	mutex_process_filter_create_path_rule(&rule, "/usr/bin", false);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added prefix path rule");
	} else {
		TEST_FAIL("Failed to add prefix path rule: %s", strerror(errno));
	}

	/* Clear rules */
	mutex_process_filter_clear_rules(fd);
}

/**
 * test_cgroup_rules() - Test cgroup filtering rules
 */
static void test_cgroup_rules(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;

	TEST_START("Cgroup Filtering Rules");

	/* Create cgroup rule */
	mutex_process_filter_create_cgroup_rule(&rule, "/user.slice", false);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added cgroup rule");
	} else {
		TEST_FAIL("Failed to add cgroup rule: %s", strerror(errno));
	}

	/* Create exact cgroup rule */
	mutex_process_filter_create_cgroup_rule(&rule, "/", true);
	ret = mutex_process_filter_add_rule(fd, &rule);
	if (ret == 0) {
		TEST_PASS("Added exact cgroup rule");
	} else {
		TEST_FAIL("Failed to add exact cgroup rule: %s", strerror(errno));
	}

	/* Clear rules */
	mutex_process_filter_clear_rules(fd);
}

/**
 * test_owner_capture() - Test owner capture functionality
 */
static void test_owner_capture(int fd)
{
	int ret;

	TEST_START("Owner Capture");

	ret = mutex_process_filter_capture_owner(fd);
	if (ret == 0) {
		TEST_PASS("Captured current process as owner");
	} else {
		TEST_FAIL("Failed to capture owner: %s", strerror(errno));
	}

	/* Set mode to OWNER */
	ret = mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_OWNER);
	if (ret == 0) {
		TEST_PASS("Set mode to OWNER after capture");
	} else {
		TEST_FAIL("Failed to set OWNER mode: %s", strerror(errno));
	}
}

/**
 * test_statistics() - Test statistics functionality
 */
static void test_statistics(int fd)
{
	struct mutex_process_filter_stats stats;
	int ret;

	TEST_START("Statistics");

	/* Get statistics */
	ret = mutex_process_filter_get_stats(fd, &stats);
	if (ret == 0) {
		TEST_PASS("Retrieved statistics");
		TEST_INFO("  Packets matched: %lu", stats.packets_matched);
		TEST_INFO("  Packets filtered: %lu", stats.packets_filtered);
		TEST_INFO("  Processes checked: %lu", stats.processes_checked);
		TEST_INFO("  Cache hits: %lu", stats.cache_hits);
		TEST_INFO("  Cache misses: %lu", stats.cache_misses);
	} else {
		TEST_FAIL("Failed to get statistics: %s", strerror(errno));
	}

	/* Reset statistics */
	ret = mutex_process_filter_reset_stats(fd);
	if (ret == 0) {
		TEST_PASS("Reset statistics");

		/* Verify reset */
		ret = mutex_process_filter_get_stats(fd, &stats);
		if (ret == 0 && stats.packets_matched == 0) {
			TEST_PASS("Statistics successfully reset");
		} else {
			TEST_FAIL("Statistics not properly reset");
		}
	} else {
		TEST_FAIL("Failed to reset statistics: %s", strerror(errno));
	}
}

/**
 * test_cache_invalidation() - Test cache invalidation
 */
static void test_cache_invalidation(int fd)
{
	int ret;
	pid_t pid;

	TEST_START("Cache Invalidation");

	pid = getpid();

	/* Invalidate specific PID */
	ret = mutex_process_filter_invalidate_cache(fd, pid);
	if (ret == 0) {
		TEST_PASS("Invalidated cache for PID %d", pid);
	} else {
		TEST_FAIL("Failed to invalidate cache for PID: %s", strerror(errno));
	}

	/* Invalidate all */
	ret = mutex_process_filter_invalidate_cache(fd, 0);
	if (ret == 0) {
		TEST_PASS("Invalidated entire cache");
	} else {
		TEST_FAIL("Failed to invalidate entire cache: %s", strerror(errno));
	}
}

/**
 * test_config_operations() - Test configuration save/load
 */
static void test_config_operations(int fd)
{
	struct mutex_process_filter_config config;
	struct mutex_process_filter_rule rule;
	int ret;

	TEST_START("Configuration Operations");

	/* Create a configuration */
	memset(&config, 0, sizeof(config));
	config.mode = MUTEX_PROCESS_FILTER_WHITELIST;
	config.include_children = 1;
	config.include_threads = 1;
	config.rule_count = 2;

	/* Add PID rule */
	mutex_process_filter_create_pid_rule(&config.rules[0], getpid(),
					     MUTEX_PROCESS_SCOPE_CURRENT);

	/* Add UID rule */
	mutex_process_filter_create_uid_rule(&config.rules[1], getuid());

	/* Set configuration */
	ret = mutex_process_filter_set_config(fd, &config);
	if (ret == 0) {
		TEST_PASS("Set complete configuration");
	} else {
		TEST_FAIL("Failed to set configuration: %s", strerror(errno));
		return;
	}

	/* Get configuration */
	memset(&config, 0, sizeof(config));
	ret = mutex_process_filter_get_config(fd, &config);
	if (ret == 0) {
		TEST_PASS("Retrieved configuration");
		TEST_INFO("  Mode: %s", mutex_process_filter_mode_name(config.mode));
		TEST_INFO("  Include children: %s", config.include_children ? "yes" : "no");
		TEST_INFO("  Include threads: %s", config.include_threads ? "yes" : "no");
		TEST_INFO("  Rule count: %u", config.rule_count);
	} else {
		TEST_FAIL("Failed to get configuration: %s", strerror(errno));
	}

	/* Clear for next tests */
	mutex_process_filter_clear_rules(fd);
	mutex_process_filter_set_mode(fd, MUTEX_PROCESS_FILTER_NONE);
}

/**
 * test_rule_removal() - Test rule removal
 */
static void test_rule_removal(int fd)
{
	struct mutex_process_filter_rule rule;
	int ret;

	TEST_START("Rule Removal");

	/* Add multiple rules */
	mutex_process_filter_create_pid_rule(&rule, getpid(),
					     MUTEX_PROCESS_SCOPE_CURRENT);
	mutex_process_filter_add_rule(fd, &rule);

	mutex_process_filter_create_uid_rule(&rule, getuid());
	mutex_process_filter_add_rule(fd, &rule);

	mutex_process_filter_create_gid_rule(&rule, getgid());
	mutex_process_filter_add_rule(fd, &rule);

	TEST_INFO("Added 3 rules");

	/* Remove middle rule */
	ret = mutex_process_filter_remove_rule(fd, 1);
	if (ret == 0) {
		TEST_PASS("Removed rule at index 1");
	} else {
		TEST_FAIL("Failed to remove rule: %s", strerror(errno));
	}

	/* Try to remove invalid index */
	ret = mutex_process_filter_remove_rule(fd, 100);
	if (ret < 0 && errno == EINVAL) {
		TEST_PASS("Correctly rejected invalid rule index");
	} else {
		TEST_FAIL("Should have rejected invalid rule index");
	}

	/* Clear rules */
	mutex_process_filter_clear_rules(fd);
}

/* ========== Main Test Runner ========== */

/**
 * print_usage() - Print usage information
 */
static void print_usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("\n");
	printf("Test process filtering functionality for MUTEX kernel module\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h, --help     Show this help message\n");
	printf("  -f FD          Use specific file descriptor (default: create test fd)\n");
	printf("  -v, --verbose  Verbose output\n");
	printf("\n");
}

/**
 * create_test_fd() - Create a test file descriptor (mock)
 */
static int create_test_fd(void)
{
	int fd;

	/* For testing, we'll try to open a dummy file */
	/* In real usage, this would be the mprox_create() syscall */
	fd = open("/tmp/mutex_process_filter_test", O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to create test fd: %s\n", strerror(errno));
		fprintf(stderr, "Note: This test requires the MUTEX kernel module to be loaded\n");
		fprintf(stderr, "      and mprox_create() syscall to be available.\n");
	}

	return fd;
}

/**
 * main() - Main entry point
 */
int main(int argc, char *argv[])
{
	int fd = -1;
	int created_fd = 0;
	int opt;

	printf("\n");
	printf("========================================\n");
	printf("MUTEX Process Filter Test Suite\n");
	printf("========================================\n");
	printf("\n");

	/* Parse arguments */
	while ((opt = getopt(argc, argv, "hf:v")) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return 0;
		case 'f':
			fd = atoi(optarg);
			break;
		case 'v':
			/* Verbose mode - could expand this */
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Create test fd if not provided */
	if (fd < 0) {
		printf("Creating test file descriptor...\n");
		fd = create_test_fd();
		if (fd < 0) {
			fprintf(stderr, "Failed to create test fd\n");
			return 1;
		}
		created_fd = 1;
		printf("Test fd created: %d\n\n", fd);
	}

	/* Run tests */
	test_filter_mode(fd);
	test_pid_rules(fd);
	test_uid_gid_rules(fd);
	test_comm_rules(fd);
	test_path_rules(fd);
	test_cgroup_rules(fd);
	test_owner_capture(fd);
	test_config_operations(fd);
	test_rule_removal(fd);
	test_statistics(fd);
	test_cache_invalidation(fd);

	/* Summary */
	printf("\n");
	printf("========================================\n");
	printf("Test Summary\n");
	printf("========================================\n");
	printf("Total tests:  %d\n", tests_total);
	printf("%sPassed:%s       %d\n", COLOR_GREEN, COLOR_RESET, tests_passed);
	printf("%sFailed:%s       %d\n", COLOR_RED, COLOR_RESET, tests_failed);
	printf("Success rate: %.1f%%\n",
	       tests_total > 0 ? (100.0 * tests_passed / tests_total) : 0.0);
	printf("========================================\n");
	printf("\n");

	/* Cleanup */
	if (created_fd && fd >= 0) {
		close(fd);
		unlink("/tmp/mutex_process_filter_test");
	}

	return (tests_failed > 0) ? 1 : 0;
}
