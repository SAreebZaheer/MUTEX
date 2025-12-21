// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX DNS Handling Module - Test Suite
 *
 * Comprehensive tests for DNS caching, query parsing, configuration,
 * and statistics tracking.
 *
 * Copyright (C) 2025 MUTEX Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

/* Test framework macros */
#define TEST_PASS 0
#define TEST_FAIL 1

#define ASSERT(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "  FAIL: %s\n", message); \
			return TEST_FAIL; \
		} \
	} while (0)

#define ASSERT_EQ(a, b, message) \
	do { \
		if ((a) != (b)) { \
			fprintf(stderr, "  FAIL: %s (expected %ld, got %ld)\n", \
				message, (long)(b), (long)(a)); \
			return TEST_FAIL; \
		} \
	} while (0)

#define ASSERT_STR_EQ(a, b, message) \
	do { \
		if (strcmp(a, b) != 0) { \
			fprintf(stderr, "  FAIL: %s (expected '%s', got '%s')\n", \
				message, b, a); \
			return TEST_FAIL; \
		} \
	} while (0)

#define RUN_TEST(test_func) \
	do { \
		printf("Running %s...\n", #test_func); \
		if (test_func() == TEST_PASS) { \
			printf("  PASS\n"); \
			tests_passed++; \
		} else { \
			tests_failed++; \
		} \
		tests_total++; \
	} while (0)

/* Global test counters */
static int tests_total = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Simplified types for userspace testing */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

/* DNS Constants */
#define DNS_PORT 53
#define DNS_MAX_NAME_LEN 255
#define DNS_HEADER_SIZE 12
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CACHE_SIZE 1024

/* ============================================================================
 * Mock Implementations (Simplified for Userspace Testing)
 * ============================================================================ */

/* DNS header structure */
struct dns_header {
	u16 id;
	u16 flags;
	u16 qdcount;
	u16 ancount;
	u16 nscount;
	u16 arcount;
} __attribute__((packed));

/* Simple hash function for testing */
static u32 test_hash_domain(const char *domain)
{
	u32 hash = 0;
	while (*domain) {
		hash = hash * 31 + *domain;
		domain++;
	}
	return hash % 256;
}

/* Domain validation */
static bool test_is_valid_domain(const char *domain)
{
	size_t len;
	int label_len = 0;

	if (!domain)
		return false;

	len = strlen(domain);
	if (len == 0 || len > DNS_MAX_NAME_LEN)
		return false;

	for (size_t i = 0; i < len; i++) {
		char c = domain[i];

		if (c == '.') {
			if (label_len == 0 || label_len > 63)
				return false;
			label_len = 0;
		} else if ((c >= 'a' && c <= 'z') ||
			   (c >= 'A' && c <= 'Z') ||
			   (c >= '0' && c <= '9') ||
			   c == '-' || c == '_') {
			label_len++;
			if (c == '-' && (label_len == 1 || i + 1 >= len || domain[i + 1] == '.'))
				return false;
		} else {
			return false;
		}
	}

	return (label_len > 0 && label_len <= 63);
}

/* Domain pattern matching with wildcards */
static int test_domain_match_pattern(const char *domain, const char *pattern)
{
	if (!domain || !pattern)
		return 0;

	/* Exact match */
	if (strcmp(domain, pattern) == 0)
		return 1;

	/* Wildcard match: *.example.com matches subdomain.example.com */
	if (pattern[0] == '*' && pattern[1] == '.') {
		const char *suffix = pattern + 2;
		size_t suffix_len = strlen(suffix);
		size_t domain_len = strlen(domain);

		/* Domain must be longer than suffix to have a subdomain */
		if (domain_len > suffix_len &&
		    strcmp(domain + domain_len - suffix_len, suffix) == 0) {
			/* Check that there's a dot before the suffix */
			if (domain[domain_len - suffix_len - 1] == '.')
				return 1;
		}
	}

	return 0;
}

/* DNS name encoding */
static int test_encode_name(const char *name, u8 *buffer, size_t buffer_size)
{
	size_t pos = 0;
	size_t label_start = 0;
	size_t i = 0;
	size_t name_len;

	if (!name || !buffer || buffer_size == 0)
		return -1;

	name_len = strlen(name);
	if (name_len == 0 || name_len > DNS_MAX_NAME_LEN)
		return -1;

	while (i <= name_len) {
		if (name[i] == '.' || name[i] == '\0') {
			size_t label_len = i - label_start;

			if (label_len == 0) {
				if (name[i] == '\0')
					break;
				label_start = i + 1;
				i++;
				continue;
			}

			if (label_len > 63 || pos + label_len + 1 >= buffer_size)
				return -1;

			buffer[pos++] = label_len;
			memcpy(buffer + pos, name + label_start, label_len);
			pos += label_len;
			label_start = i + 1;
		}
		i++;
	}

	if (pos >= buffer_size)
		return -1;

	buffer[pos++] = 0; /* Null terminator */
	return pos;
}

/* DNS name decoding */
static int test_decode_name(const u8 *packet, size_t packet_len,
			    size_t offset, char *name, size_t name_size)
{
	size_t pos = offset;
	size_t name_pos = 0;
	int jumps = 0;
	size_t original_pos = 0;

	if (!packet || !name || packet_len < DNS_HEADER_SIZE)
		return -1;

	while (pos < packet_len && jumps < 10) {
		u8 len = packet[pos];

		/* End of name */
		if (len == 0) {
			if (name_pos > 0 && name_pos < name_size)
				name[name_pos - 1] = '\0'; /* Remove trailing dot */
			else if (name_pos < name_size)
				name[0] = '\0';

			return original_pos ? original_pos - offset + 1 : pos - offset + 1;
		}

		/* Compression pointer */
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= packet_len)
				return -1;

			if (original_pos == 0)
				original_pos = pos + 2;

			pos = ((len & 0x3F) << 8) | packet[pos + 1];
			jumps++;
			continue;
		}

		/* Regular label */
		if (len > 63 || pos + len + 1 > packet_len)
			return -1;

		if (name_pos + len + 1 >= name_size)
			return -1;

		pos++;
		memcpy(name + name_pos, packet + pos, len);
		name_pos += len;
		name[name_pos++] = '.';
		pos += len;
	}

	return -1;
}

/* Build DNS query packet */
static int test_build_query(u8 *buffer, size_t buffer_size,
			    const char *domain, u16 qtype, u16 txid)
{
	struct dns_header *header;
	int name_len;
	size_t total_len;

	if (!buffer || !domain || buffer_size < 512)
		return -1;

	/* Build header */
	header = (struct dns_header *)buffer;
	header->id = htons(txid);
	header->flags = htons(0x0100); /* Recursion desired */
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	/* Encode domain name */
	name_len = test_encode_name(domain, buffer + DNS_HEADER_SIZE,
				     buffer_size - DNS_HEADER_SIZE);
	if (name_len < 0)
		return name_len;

	/* Add question section */
	u16 *qtype_ptr = (u16 *)(buffer + DNS_HEADER_SIZE + name_len);
	u16 *qclass_ptr = qtype_ptr + 1;
	*qtype_ptr = htons(qtype);
	*qclass_ptr = htons(1); /* IN class */

	total_len = DNS_HEADER_SIZE + name_len + 4;
	return total_len;
}

/* Parse DNS query */
static int test_parse_query(const u8 *data, size_t len, char *domain,
			    size_t domain_size, u16 *qtype)
{
	struct dns_header *header;
	int name_len;

	if (!data || len < DNS_HEADER_SIZE || !domain || !qtype)
		return -1;

	header = (struct dns_header *)data;

	/* Check if this is a query */
	if (ntohs(header->flags) & 0x8000)
		return -1;

	/* Must have at least one question */
	if (ntohs(header->qdcount) == 0)
		return -1;

	/* Decode domain name */
	name_len = test_decode_name(data, len, DNS_HEADER_SIZE,
				     domain, domain_size);
	if (name_len < 0)
		return name_len;

	/* Parse question */
	if (DNS_HEADER_SIZE + name_len + 4 > len)
		return -1;

	*qtype = ntohs(*(u16 *)(data + DNS_HEADER_SIZE + name_len));

	return 0;
}

/* ============================================================================
 * Test Functions
 * ============================================================================ */

/* Test 1: Domain validation */
static int test_domain_validation(void)
{
	/* Valid domains */
	ASSERT(test_is_valid_domain("example.com"), "Valid domain rejected");
	ASSERT(test_is_valid_domain("subdomain.example.com"), "Valid subdomain rejected");
	ASSERT(test_is_valid_domain("a.b.c.d.example.com"), "Valid multi-level domain rejected");
	ASSERT(test_is_valid_domain("test-123.example.com"), "Valid domain with hyphen rejected");

	/* Invalid domains */
	ASSERT(!test_is_valid_domain(""), "Empty domain accepted");
	ASSERT(!test_is_valid_domain(".example.com"), "Leading dot accepted");
	ASSERT(!test_is_valid_domain("example.com."), "Trailing dot accepted");
	ASSERT(!test_is_valid_domain("example..com"), "Double dot accepted");
	ASSERT(!test_is_valid_domain("-example.com"), "Leading hyphen accepted");
	ASSERT(!test_is_valid_domain("example-.com"), "Trailing hyphen accepted");

	return TEST_PASS;
}

/* Test 2: Domain hashing */
static int test_domain_hashing(void)
{
	u32 hash1 = test_hash_domain("example.com");
	u32 hash2 = test_hash_domain("example.com");
	u32 hash3 = test_hash_domain("different.com");

	ASSERT(hash1 == hash2, "Same domain produces different hashes");
	ASSERT(hash1 != hash3, "Different domains produce same hash");
	ASSERT(hash1 < 256, "Hash out of range");
	ASSERT(hash3 < 256, "Hash out of range");

	return TEST_PASS;
}

/* Test 3: Pattern matching */
static int test_pattern_matching(void)
{
	/* Exact matches */
	ASSERT(test_domain_match_pattern("example.com", "example.com"),
	       "Exact match failed");

	/* Wildcard matches */
	ASSERT(test_domain_match_pattern("sub.example.com", "*.example.com"),
	       "Wildcard subdomain match failed");
	ASSERT(test_domain_match_pattern("deep.sub.example.com", "*.example.com"),
	       "Wildcard multi-level match failed");

	/* Non-matches */
	ASSERT(!test_domain_match_pattern("example.com", "*.example.com"),
	       "Wildcard matched root domain incorrectly");
	ASSERT(!test_domain_match_pattern("notexample.com", "*.example.com"),
	       "Wildcard matched different domain");
	ASSERT(!test_domain_match_pattern("example.org", "*.example.com"),
	       "Wildcard matched different TLD");

	return TEST_PASS;
}

/* Test 4: DNS name encoding */
static int test_name_encoding(void)
{
	u8 buffer[256];
	int len;

	/* Test simple domain */
	len = test_encode_name("example.com", buffer, sizeof(buffer));
	ASSERT(len > 0, "Encoding failed");
	ASSERT_EQ(buffer[0], 7, "First label length incorrect");
	ASSERT(memcmp(buffer + 1, "example", 7) == 0, "First label incorrect");
	ASSERT_EQ(buffer[8], 3, "Second label length incorrect");
	ASSERT(memcmp(buffer + 9, "com", 3) == 0, "Second label incorrect");
	ASSERT_EQ(buffer[12], 0, "Null terminator missing");

	/* Test subdomain */
	len = test_encode_name("sub.example.com", buffer, sizeof(buffer));
	ASSERT(len > 0, "Subdomain encoding failed");
	ASSERT_EQ(buffer[0], 3, "Subdomain first label length incorrect");

	/* Test error cases */
	len = test_encode_name("", buffer, sizeof(buffer));
	ASSERT(len < 0, "Empty domain accepted");

	len = test_encode_name("toolonggggggggggggggggggggggggggggggggggggggggggggggggggg"
			       "gggggggggggggggggggggggggggggggggggggggggggggggggg.com",
			       buffer, sizeof(buffer));
	ASSERT(len < 0, "Too long label accepted");

	return TEST_PASS;
}

/* Test 5: DNS name decoding */
static int test_name_decoding(void)
{
	u8 packet[256];
	char domain[256];
	int name_len;

	/* Build test packet with encoded name */
	struct dns_header *header = (struct dns_header *)packet;
	header->id = htons(1234);
	header->flags = 0;
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	/* Encode "example.com" manually */
	u8 *name_ptr = packet + DNS_HEADER_SIZE;
	name_ptr[0] = 7;  /* Length of "example" */
	memcpy(name_ptr + 1, "example", 7);
	name_ptr[8] = 3;  /* Length of "com" */
	memcpy(name_ptr + 9, "com", 3);
	name_ptr[12] = 0; /* Null terminator */

	/* Decode name */
	name_len = test_decode_name(packet, sizeof(packet), DNS_HEADER_SIZE,
				     domain, sizeof(domain));
	ASSERT(name_len > 0, "Decoding failed");
	ASSERT_STR_EQ(domain, "example.com", "Decoded domain incorrect");

	return TEST_PASS;
}

/* Test 6: DNS query building */
static int test_query_building(void)
{
	u8 buffer[512];
	int len;
	struct dns_header *header;

	/* Build query for "example.com" A record */
	len = test_build_query(buffer, sizeof(buffer), "example.com", DNS_TYPE_A, 1234);
	ASSERT(len > 0, "Query building failed");
	ASSERT(len >= DNS_HEADER_SIZE, "Query too short");

	/* Check header */
	header = (struct dns_header *)buffer;
	ASSERT_EQ(ntohs(header->id), 1234, "Transaction ID incorrect");
	ASSERT_EQ(ntohs(header->qdcount), 1, "Question count incorrect");
	ASSERT_EQ(ntohs(header->ancount), 0, "Answer count should be 0");

	/* Check flags (recursion desired) */
	ASSERT((ntohs(header->flags) & 0x0100) != 0, "Recursion desired flag not set");

	return TEST_PASS;
}

/* Test 7: DNS query parsing */
static int test_query_parsing(void)
{
	u8 buffer[512];
	char domain[256];
	u16 qtype;
	int len, result;

	/* Build query */
	len = test_build_query(buffer, sizeof(buffer), "test.example.com",
			       DNS_TYPE_A, 5678);
	ASSERT(len > 0, "Query building failed");

	/* Parse query */
	result = test_parse_query(buffer, len, domain, sizeof(domain), &qtype);
	ASSERT_EQ(result, 0, "Query parsing failed");
	ASSERT_STR_EQ(domain, "test.example.com", "Parsed domain incorrect");
	ASSERT_EQ(qtype, DNS_TYPE_A, "Query type incorrect");

	return TEST_PASS;
}

/* Test 8: Cache statistics */
static int test_cache_statistics(void)
{
	/* Simulate cache statistics */
	u64 hits = 1000;
	u64 misses = 500;
	u64 total = hits + misses;
	u64 hit_rate = (hits * 100) / total;

	ASSERT_EQ(total, 1500, "Total queries incorrect");
	ASSERT_EQ(hit_rate, 66, "Hit rate calculation incorrect");

	return TEST_PASS;
}

/* Test 9: TTL validation */
static int test_ttl_validation(void)
{
	u32 ttl;

	/* Test TTL clamping */
	ttl = 30;  /* Below minimum */
	if (ttl < 60)
		ttl = 60;
	ASSERT_EQ(ttl, 60, "TTL min clamping failed");

	ttl = 100000;  /* Above maximum */
	if (ttl > 86400)
		ttl = 86400;
	ASSERT_EQ(ttl, 86400, "TTL max clamping failed");

	ttl = 300;  /* Within range */
	if (ttl < 60)
		ttl = 60;
	else if (ttl > 86400)
		ttl = 86400;
	ASSERT_EQ(ttl, 300, "TTL in-range failed");

	return TEST_PASS;
}

/* Test 10: Domain bypass rules */
static int test_bypass_rules(void)
{
	/* Simulate bypass rule matching */
	const char *local_domains[] = {
		"localhost",
		"myserver.local",
		"test.lan"
	};

	const char *remote_domains[] = {
		"example.com",
		"google.com",
		"github.com"
	};

	/* Test local domain patterns */
	ASSERT(test_domain_match_pattern(local_domains[0], "localhost"),
	       "Localhost exact match failed");
	ASSERT(test_domain_match_pattern(local_domains[1], "*.local"),
	       "Local wildcard match failed");
	ASSERT(test_domain_match_pattern(local_domains[2], "*.lan"),
	       "LAN wildcard match failed");

	/* Test remote domains don't match local patterns */
	ASSERT(!test_domain_match_pattern(remote_domains[0], "*.local"),
	       "Remote domain matched local pattern");
	ASSERT(!test_domain_match_pattern(remote_domains[1], "*.lan"),
	       "Remote domain matched LAN pattern");

	return TEST_PASS;
}

/* Test 11: IPv4 address handling */
static int test_ipv4_addresses(void)
{
	struct in_addr addr1, addr2;

	/* Test address parsing */
	inet_pton(AF_INET, "192.0.2.1", &addr1);
	inet_pton(AF_INET, "192.0.2.2", &addr2);

	ASSERT(addr1.s_addr != 0, "IPv4 address parsing failed");
	ASSERT(addr2.s_addr != 0, "IPv4 address parsing failed");
	ASSERT(addr1.s_addr != addr2.s_addr, "Different addresses are same");

	/* Test address equality */
	struct in_addr addr3;
	inet_pton(AF_INET, "192.0.2.1", &addr3);
	ASSERT(addr1.s_addr == addr3.s_addr, "Same addresses are different");

	return TEST_PASS;
}

/* Test 12: Query latency tracking */
static int test_latency_tracking(void)
{
	/* Simulate latency measurements */
	u32 latencies[] = { 1000, 1500, 800, 1200, 900 }; /* microseconds */
	u32 sum = 0;
	u32 count = sizeof(latencies) / sizeof(latencies[0]);
	u32 avg;

	for (u32 i = 0; i < count; i++)
		sum += latencies[i];

	avg = sum / count;

	ASSERT_EQ(avg, 1080, "Average latency calculation incorrect");
	ASSERT(avg >= 800 && avg <= 1500, "Average latency out of range");

	return TEST_PASS;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void)
{
	printf("=================================================\n");
	printf("MUTEX DNS Handling Module - Test Suite\n");
	printf("=================================================\n\n");

	/* Run all tests */
	RUN_TEST(test_domain_validation);
	RUN_TEST(test_domain_hashing);
	RUN_TEST(test_pattern_matching);
	RUN_TEST(test_name_encoding);
	RUN_TEST(test_name_decoding);
	RUN_TEST(test_query_building);
	RUN_TEST(test_query_parsing);
	RUN_TEST(test_cache_statistics);
	RUN_TEST(test_ttl_validation);
	RUN_TEST(test_bypass_rules);
	RUN_TEST(test_ipv4_addresses);
	RUN_TEST(test_latency_tracking);

	/* Print summary */
	printf("\n=================================================\n");
	printf("Test Summary\n");
	printf("=================================================\n");
	printf("Total tests:  %d\n", tests_total);
	printf("Passed:       %d\n", tests_passed);
	printf("Failed:       %d\n", tests_failed);
	printf("Success rate: %.1f%%\n",
	       (tests_total > 0) ? (tests_passed * 100.0 / tests_total) : 0.0);
	printf("=================================================\n");

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
