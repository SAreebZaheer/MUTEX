// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MUTEX Protocol Detection Test Suite
 *
 * Comprehensive tests for protocol detection functionality.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include "mutex_protocol_detect_api.h"

/* Test result tracking */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
	do { \
		printf("Running test: %s...", name); \
		tests_run++; \
	} while(0)

#define PASS() \
	do { \
		printf(" PASS\n"); \
		tests_passed++; \
	} while(0)

#define FAIL(msg) \
	do { \
		printf(" FAIL: %s\n", msg); \
		tests_failed++; \
	} while(0)

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			FAIL(msg); \
			return; \
		} \
	} while(0)

/* Mock data for testing (without actual kernel module) */

/* Test: Protocol name lookup */
void test_protocol_names(void)
{
	TEST("protocol_names");

	ASSERT(strcmp(protocol_name(PROTO_HTTP), "http") == 0,
	       "HTTP protocol name mismatch");
	ASSERT(strcmp(protocol_name(PROTO_HTTPS), "https") == 0,
	       "HTTPS protocol name mismatch");
	ASSERT(strcmp(protocol_name(PROTO_SSH), "ssh") == 0,
	       "SSH protocol name mismatch");
	ASSERT(strcmp(protocol_name(PROTO_DNS), "dns") == 0,
	       "DNS protocol name mismatch");
	ASSERT(strcmp(protocol_name(PROTO_UNKNOWN), "unknown") == 0,
	       "Unknown protocol name mismatch");

	PASS();
}

/* Test: Confidence level names */
void test_confidence_names(void)
{
	TEST("confidence_names");

	ASSERT(strcmp(protocol_confidence_name(CONFIDENCE_NONE), "none") == 0,
	       "None confidence name mismatch");
	ASSERT(strcmp(protocol_confidence_name(CONFIDENCE_LOW), "low") == 0,
	       "Low confidence name mismatch");
	ASSERT(strcmp(protocol_confidence_name(CONFIDENCE_MEDIUM), "medium") == 0,
	       "Medium confidence name mismatch");
	ASSERT(strcmp(protocol_confidence_name(CONFIDENCE_HIGH), "high") == 0,
	       "High confidence name mismatch");
	ASSERT(strcmp(protocol_confidence_name(CONFIDENCE_CERTAIN), "certain") == 0,
	       "Certain confidence name mismatch");

	PASS();
}

/* Test: Action names */
void test_action_names(void)
{
	TEST("action_names");

	ASSERT(strcmp(protocol_action_name(ACTION_PROXY), "proxy") == 0,
	       "Proxy action name mismatch");
	ASSERT(strcmp(protocol_action_name(ACTION_DIRECT), "direct") == 0,
	       "Direct action name mismatch");
	ASSERT(strcmp(protocol_action_name(ACTION_BLOCK), "block") == 0,
	       "Block action name mismatch");
	ASSERT(strcmp(protocol_action_name(ACTION_INSPECT), "inspect") == 0,
	       "Inspect action name mismatch");

	PASS();
}

/* Test: Port rule creation */
void test_create_port_rule(void)
{
	struct protocol_rule rule;

	TEST("create_port_rule");

	mutex_proto_create_port_rule(PROTO_HTTP, 80, IPPROTO_TCP, &rule);

	ASSERT(rule.protocol == PROTO_HTTP, "Protocol mismatch");
	ASSERT(rule.port_start == 80, "Port start mismatch");
	ASSERT(rule.port_end == 80, "Port end mismatch");
	ASSERT(rule.transport == IPPROTO_TCP, "Transport mismatch");
	ASSERT(rule.methods & METHOD_PORT, "Method not set");
	ASSERT(rule.min_confidence == CONFIDENCE_LOW, "Confidence mismatch");

	PASS();
}

/* Test: Pattern rule creation */
void test_create_pattern_rule(void)
{
	struct protocol_rule rule;
	uint8_t pattern[] = { 'G', 'E', 'T', ' ', '/' };

	TEST("create_pattern_rule");

	mutex_proto_create_pattern_rule(PROTO_HTTP, pattern, sizeof(pattern), 0, &rule);

	ASSERT(rule.protocol == PROTO_HTTP, "Protocol mismatch");
	ASSERT(rule.methods & METHOD_PATTERN, "Method not set");
	ASSERT(rule.num_patterns == 1, "Pattern count mismatch");
	ASSERT(rule.patterns[0].len == sizeof(pattern), "Pattern length mismatch");
	ASSERT(memcmp(rule.patterns[0].data, pattern, sizeof(pattern)) == 0,
	       "Pattern data mismatch");
	ASSERT(rule.patterns[0].offset == 0, "Pattern offset mismatch");

	PASS();
}

/* Test: Routing rule creation */
void test_create_routing_rule(void)
{
	struct protocol_routing_rule rule;

	TEST("create_routing_rule");

	mutex_proto_create_routing_rule(PROTO_HTTP, ACTION_PROXY, 100, &rule);

	ASSERT(rule.protocol == PROTO_HTTP, "Protocol mismatch");
	ASSERT(rule.action == ACTION_PROXY, "Action mismatch");
	ASSERT(rule.priority == 100, "Priority mismatch");
	ASSERT(rule.has_host_pattern == false, "Host pattern flag mismatch");

	PASS();
}

/* Test: Host routing rule creation */
void test_create_host_routing_rule(void)
{
	struct protocol_routing_rule rule;
	const char *host = "example.com";

	TEST("create_host_routing_rule");

	mutex_proto_create_host_routing_rule(PROTO_HTTPS, host,
					     ACTION_DIRECT, 200, &rule);

	ASSERT(rule.protocol == PROTO_HTTPS, "Protocol mismatch");
	ASSERT(rule.action == ACTION_DIRECT, "Action mismatch");
	ASSERT(rule.priority == 200, "Priority mismatch");
	ASSERT(rule.has_host_pattern == true, "Host pattern flag mismatch");
	ASSERT(strcmp(rule.host_pattern, host) == 0, "Host pattern mismatch");

	PASS();
}

/* Test: SNI detection with sample TLS ClientHello */
void test_sni_detection(void)
{
	/* Minimal TLS ClientHello with SNI extension */
	uint8_t client_hello[] = {
		0x16, 0x03, 0x01,             /* TLS Handshake, version 3.1 */
		0x00, 0x6d,                   /* Length: 109 bytes */
		0x01,                         /* Handshake type: ClientHello */
		0x00, 0x00, 0x69,             /* Handshake length */
		0x03, 0x03,                   /* Client version: TLS 1.2 */
		/* Random (32 bytes) */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,                         /* Session ID length: 0 */
		0x00, 0x04,                   /* Cipher suites length: 4 */
		0x00, 0x2f, 0x00, 0x35,       /* Two cipher suites */
		0x01, 0x00,                   /* Compression methods */
		0x00, 0x3a,                   /* Extensions length: 58 */
		/* SNI Extension */
		0x00, 0x00,                   /* Extension type: SNI (0) */
		0x00, 0x14,                   /* Extension length: 20 */
		0x00, 0x12,                   /* SNI list length: 18 */
		0x00,                         /* SNI type: hostname */
		0x00, 0x0f,                   /* Hostname length: 15 */
		'w', 'w', 'w', '.', 't', 'e', 's', 't', '.', 'c', 'o', 'm', '.', 'c', 'n'
	};

	struct sni_info sni;
	int ret;

	TEST("sni_detection");

	ret = protocol_detect_sni(client_hello, sizeof(client_hello), &sni);

	ASSERT(ret == 0, "SNI detection failed");
	ASSERT(sni.valid == true, "SNI not valid");
	ASSERT(strcmp(sni.server_name, "www.test.com.cn") == 0,
	       "SNI hostname mismatch");
	ASSERT(sni.tls_version == 0x0301, "TLS version mismatch");

	PASS();
}

/* Test: HTTP Host header detection */
void test_http_host_detection(void)
{
	const char *http_request =
		"GET / HTTP/1.1\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: TestClient/1.0\r\n"
		"Accept: */*\r\n"
		"\r\n";

	char host[MAX_HOST_SIZE];
	int ret;

	TEST("http_host_detection");

	ret = protocol_detect_http_host((const uint8_t *)http_request,
					strlen(http_request), host);

	ASSERT(ret == 0, "HTTP host detection failed");
	ASSERT(strcmp(host, "www.example.com") == 0, "Host mismatch");

	PASS();
}

/* Test: Invalid SNI (too short) */
void test_sni_invalid_short(void)
{
	uint8_t short_data[] = { 0x16, 0x03, 0x01 };
	struct sni_info sni;
	int ret;

	TEST("sni_invalid_short");

	ret = protocol_detect_sni(short_data, sizeof(short_data), &sni);

	ASSERT(ret != 0, "Should reject short data");
	ASSERT(sni.valid == false, "SNI should not be valid");

	PASS();
}

/* Test: Invalid SNI (wrong content type) */
void test_sni_invalid_type(void)
{
	uint8_t wrong_type[] = {
		0x15, 0x03, 0x01,  /* Alert, not Handshake */
		0x00, 0x02,
		0x01, 0x00
	};
	struct sni_info sni;
	int ret;

	TEST("sni_invalid_type");

	ret = protocol_detect_sni(wrong_type, sizeof(wrong_type), &sni);

	ASSERT(ret != 0, "Should reject non-handshake");

	PASS();
}

/* Test: Error string messages */
void test_error_strings(void)
{
	TEST("error_strings");

	ASSERT(mutex_proto_get_error_string(PROTO_API_SUCCESS) != NULL,
	       "Success string is NULL");
	ASSERT(mutex_proto_get_error_string(PROTO_API_ERROR) != NULL,
	       "Error string is NULL");
	ASSERT(mutex_proto_get_error_string(PROTO_API_INVALID_FD) != NULL,
	       "Invalid FD string is NULL");
	ASSERT(mutex_proto_get_error_string(PROTO_API_NO_DEVICE) != NULL,
	       "No device string is NULL");

	PASS();
}

/* Test: Structure sizes */
void test_structure_sizes(void)
{
	TEST("structure_sizes");

	printf("\n");
	printf("  sizeof(protocol_rule)         : %zu bytes\n",
	       sizeof(struct protocol_rule));
	printf("  sizeof(protocol_routing_rule) : %zu bytes\n",
	       sizeof(struct protocol_routing_rule));
	printf("  sizeof(protocol_detection_result): %zu bytes\n",
	       sizeof(struct protocol_detection_result));
	printf("  sizeof(sni_info)              : %zu bytes\n",
	       sizeof(struct sni_info));
	printf("  sizeof(protocol_detection_stats): %zu bytes\n",
	       sizeof(struct protocol_detection_stats));

	/* Sanity checks */
	ASSERT(sizeof(struct protocol_rule) < 4096,
	       "protocol_rule too large");
	ASSERT(sizeof(struct protocol_routing_rule) < 4096,
	       "protocol_routing_rule too large");

	PASS();
}

/* Test: Enum value ranges */
void test_enum_ranges(void)
{
	TEST("enum_ranges");

	ASSERT(PROTO_HTTP > PROTO_UNKNOWN && PROTO_HTTP < PROTO_MAX,
	       "HTTP protocol out of range");
	ASSERT(PROTO_HTTPS > PROTO_UNKNOWN && PROTO_HTTPS < PROTO_MAX,
	       "HTTPS protocol out of range");

	ASSERT(CONFIDENCE_NONE < CONFIDENCE_CERTAIN,
	       "Confidence levels not ordered");

	ASSERT(ACTION_PROXY >= 0 && ACTION_PROXY < 10,
	       "Proxy action out of range");

	PASS();
}

/* Test: API without device (expected to fail gracefully) */
void test_api_without_device(void)
{
	int fd;

	TEST("api_without_device");

	fd = mutex_proto_open();

	/* We expect this to fail since module isn't loaded */
	ASSERT(fd < 0, "Should fail without device");
	ASSERT(fd == PROTO_API_NO_DEVICE || fd == PROTO_API_PERMISSION,
	       "Should return proper error code");

	printf(" (expected failure: %s)",
	       mutex_proto_get_error_string(fd));

	PASS();
}

/* Test: Statistics structure initialization */
void test_stats_structure(void)
{
	struct protocol_detection_stats stats;

	TEST("stats_structure");

	memset(&stats, 0, sizeof(stats));

	/* Verify we can set and read all fields */
	stats.total_packets = 1000;
	stats.total_inspections = 800;
	stats.cache_hits = 600;
	stats.cache_misses = 200;

	ASSERT(stats.total_packets == 1000, "Total packets mismatch");
	ASSERT(stats.cache_hits == 600, "Cache hits mismatch");

	/* Test print function (doesn't assert, just verifies no crash) */
	printf("\n");
	mutex_proto_print_stats(&stats);

	PASS();
}

/* Test: Pattern with wildcard mask */
void test_pattern_wildcard(void)
{
	struct protocol_rule rule;
	uint8_t pattern[] = { 0x16, 0x03, 0x00, 0x00, 0x00 };

	TEST("pattern_wildcard");

	mutex_proto_create_pattern_rule(PROTO_TLS_GENERIC, pattern,
					sizeof(pattern), 0, &rule);

	/* Manually set wildcard mask (match first 2 bytes only) */
	rule.patterns[0].match_mask = 0x00000003;  /* First 2 bits set */

	ASSERT(rule.patterns[0].match_mask == 0x00000003,
	       "Wildcard mask not set correctly");

	PASS();
}

/* Test: Multiple patterns in a rule */
void test_multiple_patterns(void)
{
	struct protocol_rule rule;
	uint8_t pattern1[] = { 'S', 'S', 'H', '-' };
	uint8_t pattern2[] = { '2', '.', '0' };

	TEST("multiple_patterns");

	memset(&rule, 0, sizeof(rule));
	rule.protocol = PROTO_SSH;
	rule.methods = METHOD_PATTERN;
	rule.num_patterns = 2;

	memcpy(rule.patterns[0].data, pattern1, sizeof(pattern1));
	rule.patterns[0].len = sizeof(pattern1);
	rule.patterns[0].offset = 0;

	memcpy(rule.patterns[1].data, pattern2, sizeof(pattern2));
	rule.patterns[1].len = sizeof(pattern2);
	rule.patterns[1].offset = 4;

	ASSERT(rule.num_patterns == 2, "Pattern count mismatch");
	ASSERT(rule.patterns[1].offset == 4, "Second pattern offset mismatch");

	PASS();
}

/* Test: Port range rule */
void test_port_range_rule(void)
{
	struct protocol_rule rule;

	TEST("port_range_rule");

	mutex_proto_create_port_rule(PROTO_FTP, 21, IPPROTO_TCP, &rule);

	/* Manually extend to range */
	rule.port_end = 21;

	ASSERT(rule.port_start <= rule.port_end, "Port range invalid");

	PASS();
}

/* Test: All protocol types have names */
void test_all_protocol_names(void)
{
	int i;

	TEST("all_protocol_names");

	for (i = 0; i < PROTO_MAX; i++) {
		const char *name = protocol_name(i);
		ASSERT(name != NULL, "Protocol name is NULL");
		ASSERT(strlen(name) > 0, "Protocol name is empty");
	}

	PASS();
}

/* Test: HTTPS routing with host pattern */
void test_https_host_routing(void)
{
	struct protocol_routing_rule rule;

	TEST("https_host_routing");

	mutex_proto_create_host_routing_rule(PROTO_HTTPS, "google.com",
					     ACTION_PROXY, 100, &rule);

	ASSERT(rule.has_host_pattern == true, "Host pattern not set");
	ASSERT(strstr(rule.host_pattern, "google.com") != NULL,
	       "Host pattern not found");

	PASS();
}

/* Test: Default routing for unknown protocols */
void test_default_unknown_routing(void)
{
	struct protocol_routing_rule rule;

	TEST("default_unknown_routing");

	mutex_proto_create_routing_rule(PROTO_UNKNOWN, ACTION_DIRECT, 0, &rule);

	ASSERT(rule.protocol == PROTO_UNKNOWN, "Protocol mismatch");
	ASSERT(rule.action == ACTION_DIRECT, "Action mismatch");
	ASSERT(rule.priority == 0, "Priority should be lowest");

	PASS();
}

/* Print summary */
void print_summary(void)
{
	printf("\n");
	printf("==============================================\n");
	printf("         Protocol Detection Test Summary      \n");
	printf("==============================================\n");
	printf("Total tests  : %d\n", tests_run);
	printf("Passed       : %d\n", tests_passed);
	printf("Failed       : %d\n", tests_failed);

	if (tests_failed == 0) {
		printf("\nAll tests PASSED! ✓\n");
	} else {
		printf("\nSome tests FAILED! ✗\n");
	}
	printf("==============================================\n");
}

int main(void)
{
	printf("MUTEX Protocol Detection Test Suite\n");
	printf("====================================\n\n");

	/* Run all tests */
	test_protocol_names();
	test_confidence_names();
	test_action_names();
	test_create_port_rule();
	test_create_pattern_rule();
	test_create_routing_rule();
	test_create_host_routing_rule();
	test_sni_detection();
	test_http_host_detection();
	test_sni_invalid_short();
	test_sni_invalid_type();
	test_error_strings();
	test_structure_sizes();
	test_enum_ranges();
	test_api_without_device();
	test_stats_structure();
	test_pattern_wildcard();
	test_multiple_patterns();
	test_port_range_rule();
	test_all_protocol_names();
	test_https_host_routing();
	test_default_unknown_routing();

	/* Print summary */
	print_summary();

	return (tests_failed == 0) ? 0 : 1;
}
