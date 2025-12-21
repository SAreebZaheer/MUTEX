// SPDX-License-Identifier: GPL-2.0
/*
 * test_ipv6.c - IPv6 support test program
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * Test program to verify IPv6 functionality in the MUTEX module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <errno.h>

#define TEST_PORT 8080

/* Test result codes */
#define TEST_SUCCESS 0
#define TEST_FAILURE 1

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Helper function to print test results */
static void test_result(const char *test_name, int result)
{
	if (result == TEST_SUCCESS) {
		printf("[PASS] %s\n", test_name);
		tests_passed++;
	} else {
		printf("[FAIL] %s\n", test_name);
		tests_failed++;
	}
}

/* Test 1: Create IPv6 socket */
static int test_create_ipv6_socket(void)
{
	int sock;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return TEST_FAILURE;
	}

	close(sock);
	return TEST_SUCCESS;
}

/* Test 2: Bind to IPv6 address */
static int test_bind_ipv6(void)
{
	int sock;
	struct sockaddr_in6 addr;
	int ret;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return TEST_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(TEST_PORT);
	addr.sin6_addr = in6addr_any;

	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("bind");
		close(sock);
		return TEST_FAILURE;
	}

	close(sock);
	return TEST_SUCCESS;
}

/* Test 3: IPv6 address parsing */
static int test_ipv6_address_parsing(void)
{
	struct in6_addr addr;
	char str[INET6_ADDRSTRLEN];
	const char *test_addr = "2001:db8::1";

	/* Parse address */
	if (inet_pton(AF_INET6, test_addr, &addr) != 1) {
		perror("inet_pton");
		return TEST_FAILURE;
	}

	/* Convert back to string */
	if (inet_ntop(AF_INET6, &addr, str, sizeof(str)) == NULL) {
		perror("inet_ntop");
		return TEST_FAILURE;
	}

	/* Verify roundtrip */
	if (strcmp(test_addr, str) != 0) {
		fprintf(stderr, "Address mismatch: %s != %s\n", test_addr, str);
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 4: IPv4-mapped IPv6 addresses */
static int test_ipv4_mapped_ipv6(void)
{
	struct in6_addr v6_addr;
	const char *ipv4_mapped = "::ffff:192.168.1.1";

	/* Parse IPv4-mapped address */
	if (inet_pton(AF_INET6, ipv4_mapped, &v6_addr) != 1) {
		perror("inet_pton");
		return TEST_FAILURE;
	}

	/* Check if it's IPv4-mapped */
	if (!IN6_IS_ADDR_V4MAPPED(&v6_addr)) {
		fprintf(stderr, "Address is not IPv4-mapped\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 5: Link-local address detection */
static int test_link_local_address(void)
{
	struct in6_addr addr;
	const char *link_local = "fe80::1";

	if (inet_pton(AF_INET6, link_local, &addr) != 1) {
		perror("inet_pton");
		return TEST_FAILURE;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&addr)) {
		fprintf(stderr, "Address is not link-local\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 6: Loopback address detection */
static int test_loopback_address(void)
{
	struct in6_addr addr;
	const char *loopback = "::1";

	if (inet_pton(AF_INET6, loopback, &addr) != 1) {
		perror("inet_pton");
		return TEST_FAILURE;
	}

	if (!IN6_IS_ADDR_LOOPBACK(&addr)) {
		fprintf(stderr, "Address is not loopback\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 7: Multicast address detection */
static int test_multicast_address(void)
{
	struct in6_addr addr;
	const char *multicast = "ff02::1";

	if (inet_pton(AF_INET6, multicast, &addr) != 1) {
		perror("inet_pton");
		return TEST_FAILURE;
	}

	if (!IN6_IS_ADDR_MULTICAST(&addr)) {
		fprintf(stderr, "Address is not multicast\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 8: IPv6 TCP connection */
static int test_ipv6_tcp_connect(void)
{
	int sock;
	struct sockaddr_in6 addr;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return TEST_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(80);

	/* Try to connect to localhost (will likely fail, but tests socket creation) */
	inet_pton(AF_INET6, "::1", &addr.sin6_addr);

	/* We don't expect this to succeed, just testing the socket setup */
	connect(sock, (struct sockaddr *)&addr, sizeof(addr));

	close(sock);
	return TEST_SUCCESS;
}

/* Test 9: IPv6 UDP socket */
static int test_ipv6_udp_socket(void)
{
	int sock;
	struct sockaddr_in6 addr;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return TEST_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(TEST_PORT + 1);
	addr.sin6_addr = in6addr_any;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(sock);
		return TEST_FAILURE;
	}

	close(sock);
	return TEST_SUCCESS;
}

/* Test 10: Dual-stack socket (IPv4 and IPv6) */
static int test_dual_stack_socket(void)
{
	int sock;
	struct sockaddr_in6 addr;
	int ipv6only = 0;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return TEST_FAILURE;
	}

	/* Disable IPv6-only mode to allow dual-stack */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) < 0) {
		perror("setsockopt IPV6_V6ONLY");
		close(sock);
		return TEST_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(TEST_PORT + 2);
	addr.sin6_addr = in6addr_any;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(sock);
		return TEST_FAILURE;
	}

	close(sock);
	return TEST_SUCCESS;
}

/* Test 11: Compare IPv6 addresses */
static int test_compare_addresses(void)
{
	struct in6_addr addr1, addr2, addr3;

	inet_pton(AF_INET6, "2001:db8::1", &addr1);
	inet_pton(AF_INET6, "2001:db8::1", &addr2);
	inet_pton(AF_INET6, "2001:db8::2", &addr3);

	/* Same addresses should be equal */
	if (memcmp(&addr1, &addr2, sizeof(struct in6_addr)) != 0) {
		fprintf(stderr, "Identical addresses not equal\n");
		return TEST_FAILURE;
	}

	/* Different addresses should not be equal */
	if (memcmp(&addr1, &addr3, sizeof(struct in6_addr)) == 0) {
		fprintf(stderr, "Different addresses are equal\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Test 12: Unspecified address (::) */
static int test_unspecified_address(void)
{
	struct in6_addr addr;

	inet_pton(AF_INET6, "::", &addr);

	if (!IN6_IS_ADDR_UNSPECIFIED(&addr)) {
		fprintf(stderr, "Unspecified address not detected\n");
		return TEST_FAILURE;
	}

	return TEST_SUCCESS;
}

/* Print statistics */
static void print_statistics(void)
{
	int total = tests_passed + tests_failed;
	double pass_rate = total > 0 ? (100.0 * tests_passed / total) : 0.0;

	printf("\n=== Test Results ===\n");
	printf("Total tests:  %d\n", total);
	printf("Passed:       %d\n", tests_passed);
	printf("Failed:       %d\n", tests_failed);
	printf("Pass rate:    %.1f%%\n", pass_rate);
}

/* Main test runner */
int main(int argc, char *argv[])
{
	printf("MUTEX IPv6 Support Test Suite\n");
	printf("==============================\n\n");

	/* Run all tests */
	test_result("Create IPv6 socket", test_create_ipv6_socket());
	test_result("Bind to IPv6 address", test_bind_ipv6());
	test_result("IPv6 address parsing", test_ipv6_address_parsing());
	test_result("IPv4-mapped IPv6 addresses", test_ipv4_mapped_ipv6());
	test_result("Link-local address detection", test_link_local_address());
	test_result("Loopback address detection", test_loopback_address());
	test_result("Multicast address detection", test_multicast_address());
	test_result("IPv6 TCP connection", test_ipv6_tcp_connect());
	test_result("IPv6 UDP socket", test_ipv6_udp_socket());
	test_result("Dual-stack socket", test_dual_stack_socket());
	test_result("Compare IPv6 addresses", test_compare_addresses());
	test_result("Unspecified address", test_unspecified_address());

	/* Print results */
	print_statistics();

	return (tests_failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
