/*
 * MUTEX Testing Framework
 *
 * Comprehensive testing infrastructure for kernel module validation,
 * including unit tests, integration tests, stress tests, and benchmarks.
 */

#ifndef MUTEX_TESTING_H
#define MUTEX_TESTING_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* Test Result Types */
#define TEST_PASS    0
#define TEST_FAIL    1
#define TEST_SKIP    2
#define TEST_ERROR   3

/* Test Categories */
#define TEST_CAT_UNIT           0x0001
#define TEST_CAT_INTEGRATION    0x0002
#define TEST_CAT_STRESS         0x0004
#define TEST_CAT_PERFORMANCE    0x0008
#define TEST_CAT_REGRESSION     0x0010
#define TEST_CAT_NETWORK        0x0020
#define TEST_CAT_SECURITY       0x0040
#define TEST_CAT_ALL            0xFFFF

/* Test Flags */
#define TEST_FLAG_DESTRUCTIVE   0x01
#define TEST_FLAG_SLOW          0x02
#define TEST_FLAG_REQUIRES_NET  0x04
#define TEST_FLAG_REQUIRES_ROOT 0x08

/* Maximum sizes */
#define TEST_MAX_NAME           128
#define TEST_MAX_DESC           256
#define TEST_MAX_ERROR_MSG      512
#define TEST_MAX_FIXTURES       16

/*
 * Test Case Structure
 */
struct test_case {
	struct list_head list;
	char name[TEST_MAX_NAME];
	char description[TEST_MAX_DESC];
	unsigned int category;
	unsigned int flags;

	/* Test functions */
	int (*setup)(void *fixture);
	int (*teardown)(void *fixture);
	int (*run)(void *fixture);

	/* Test metadata */
	unsigned int timeout_ms;
	unsigned int iterations;

	/* Results */
	int result;
	char error_msg[TEST_MAX_ERROR_MSG];
	ktime_t duration;
	unsigned long passed;
	unsigned long failed;
	unsigned long skipped;
};

/*
 * Test Suite Structure
 */
struct test_suite {
	struct list_head list;
	struct list_head test_cases;
	char name[TEST_MAX_NAME];
	char description[TEST_MAX_DESC];
	unsigned int category;

	/* Suite-wide setup/teardown */
	int (*suite_setup)(void);
	int (*suite_teardown)(void);

	/* Statistics */
	unsigned int total_tests;
	unsigned int passed;
	unsigned int failed;
	unsigned int skipped;
	unsigned int errors;
	ktime_t total_duration;
};

/*
 * Test Framework Context
 */
struct test_framework {
	struct list_head suites;
	spinlock_t lock;

	/* Configuration */
	unsigned int enabled_categories;
	bool run_destructive;
	bool run_slow;
	unsigned int default_timeout_ms;

	/* Global statistics */
	unsigned int total_suites;
	unsigned int total_tests;
	unsigned int total_passed;
	unsigned int total_failed;
	unsigned int total_skipped;
	unsigned int total_errors;
	ktime_t total_duration;

	/* Current test context */
	struct test_suite *current_suite;
	struct test_case *current_test;
};

/*
 * Test Assertion Macros
 */
#define TEST_ASSERT(condition, fmt, ...) \
	do { \
		if (!(condition)) { \
			snprintf(test_ctx->error_msg, TEST_MAX_ERROR_MSG, \
				 "Assertion failed at %s:%d: " fmt, \
				 __FILE__, __LINE__, ##__VA_ARGS__); \
			return TEST_FAIL; \
		} \
	} while (0)

#define TEST_ASSERT_EQ(a, b) \
	TEST_ASSERT((a) == (b), "Expected %lld == %lld", (long long)(a), (long long)(b))

#define TEST_ASSERT_NE(a, b) \
	TEST_ASSERT((a) != (b), "Expected %lld != %lld", (long long)(a), (long long)(b))

#define TEST_ASSERT_LT(a, b) \
	TEST_ASSERT((a) < (b), "Expected %lld < %lld", (long long)(a), (long long)(b))

#define TEST_ASSERT_GT(a, b) \
	TEST_ASSERT((a) > (b), "Expected %lld > %lld", (long long)(a), (long long)(b))

#define TEST_ASSERT_NULL(ptr) \
	TEST_ASSERT((ptr) == NULL, "Expected NULL pointer")

#define TEST_ASSERT_NOT_NULL(ptr) \
	TEST_ASSERT((ptr) != NULL, "Expected non-NULL pointer")

#define TEST_ASSERT_TRUE(condition) \
	TEST_ASSERT(condition, "Expected true")

#define TEST_ASSERT_FALSE(condition) \
	TEST_ASSERT(!(condition), "Expected false")

#define TEST_ASSERT_STR_EQ(s1, s2) \
	TEST_ASSERT(strcmp(s1, s2) == 0, "Expected strings equal: '%s' == '%s'", s1, s2)

/*
 * Performance Benchmark Macros
 */
#define BENCHMARK_START(name) \
	ktime_t __bench_start_##name = ktime_get()

#define BENCHMARK_END(name) \
	do { \
		ktime_t __bench_end_##name = ktime_get(); \
		s64 __bench_delta_##name = ktime_to_ns(ktime_sub(__bench_end_##name, __bench_start_##name)); \
		pr_info("BENCHMARK [%s]: %lld ns\n", #name, __bench_delta_##name); \
	} while (0)

/*
 * Test Registration Macros
 */
#define REGISTER_TEST(suite_name, test_name, test_func) \
	mutex_test_register(suite_name, test_name, NULL, test_func, NULL, \
			    TEST_CAT_UNIT, 0, 5000, 1)

#define REGISTER_TEST_SETUP(suite_name, test_name, setup_func, test_func, teardown_func) \
	mutex_test_register(suite_name, test_name, NULL, test_func, teardown_func, \
			    TEST_CAT_UNIT, 0, 5000, 1)

/*
 * Framework Management
 */
int mutex_test_framework_init(void);
void mutex_test_framework_destroy(void);

/*
 * Test Suite Management
 */
struct test_suite *mutex_test_suite_create(const char *name, const char *description,
					    unsigned int category);
void mutex_test_suite_destroy(struct test_suite *suite);
int mutex_test_suite_register(struct test_suite *suite);
int mutex_test_suite_run(struct test_suite *suite);

/*
 * Test Case Management
 */
struct test_case *mutex_test_case_create(const char *name, const char *description,
					  int (*run)(void *), unsigned int category);
void mutex_test_case_destroy(struct test_case *test);
int mutex_test_case_add_to_suite(struct test_suite *suite, struct test_case *test);
int mutex_test_case_run(struct test_case *test, void *fixture);

/*
 * Test Registration Helper
 */
int mutex_test_register(const char *suite_name, const char *test_name,
			const char *description,
			int (*run)(void *),
			int (*teardown)(void *),
			unsigned int category, unsigned int flags,
			unsigned int timeout_ms, unsigned int iterations);

/*
 * Test Execution
 */
int mutex_test_run_all(void);
int mutex_test_run_category(unsigned int category);
int mutex_test_run_suite(const char *suite_name);
int mutex_test_run_single(const char *suite_name, const char *test_name);

/*
 * Configuration
 */
void mutex_test_enable_category(unsigned int category);
void mutex_test_disable_category(unsigned int category);
void mutex_test_set_timeout(unsigned int timeout_ms);
void mutex_test_enable_destructive(bool enable);
void mutex_test_enable_slow(bool enable);

/*
 * Results and Reporting
 */
void mutex_test_print_results(void);
void mutex_test_print_summary(void);
int mutex_test_export_results(char *buffer, size_t size);

/*
 * Statistics
 */
struct test_statistics {
	unsigned int total_suites;
	unsigned int total_tests;
	unsigned int passed;
	unsigned int failed;
	unsigned int skipped;
	unsigned int errors;
	ktime_t total_duration;
	unsigned int pass_rate;
};

void mutex_test_get_statistics(struct test_statistics *stats);

/*
 * Specific Test Suites
 */

/* Connection Tracking Tests */
int mutex_test_conn_track_init(void);
int test_conn_track_create(void *fixture);
int test_conn_track_lookup(void *fixture);
int test_conn_track_update(void *fixture);
int test_conn_track_timeout(void *fixture);

/* Packet Rewrite Tests */
int mutex_test_packet_rewrite_init(void);
int test_ipv4_addr_rewrite(void *fixture);
int test_ipv6_addr_rewrite(void *fixture);
int test_tcp_port_rewrite(void *fixture);
int test_udp_port_rewrite(void *fixture);
int test_checksum_update(void *fixture);

/* Protocol Detection Tests */
int mutex_test_protocol_detect_init(void);
int test_http_detection(void *fixture);
int test_https_detection(void *fixture);
int test_ssh_detection(void *fixture);
int test_dns_detection(void *fixture);

/* Process Filter Tests */
int mutex_test_process_filter_init(void);
int test_process_match(void *fixture);
int test_process_hierarchy(void *fixture);
int test_cgroup_filter(void *fixture);

/* DNS Tests */
int mutex_test_dns_init(void);
int test_dns_cache_add(void *fixture);
int test_dns_cache_lookup(void *fixture);
int test_dns_cache_eviction(void *fixture);

/* Performance Tests */
int mutex_test_performance_init(void);
int test_conn_track_performance(void *fixture);
int test_hash_table_performance(void *fixture);
int test_packet_processing_rate(void *fixture);

/* Stress Tests */
int mutex_test_stress_init(void);
int test_concurrent_connections(void *fixture);
int test_memory_pressure(void *fixture);
int test_high_packet_rate(void *fixture);

/* Integration Tests */
int mutex_test_integration_init(void);
int test_end_to_end_proxy(void *fixture);
int test_transparent_proxy_flow(void *fixture);
int test_dns_proxy_integration(void *fixture);

/* Security Tests */
int mutex_test_security_init(void);
int test_capability_checks(void *fixture);
int test_input_validation(void *fixture);
int test_buffer_overflow_protection(void *fixture);
int test_rate_limiting(void *fixture);

/*
 * Mock and Fixture Helpers
 */
struct sk_buff *test_create_mock_skb(int protocol, __be32 saddr, __be32 daddr,
				     __be16 sport, __be16 dport, size_t data_len);
void test_free_mock_skb(struct sk_buff *skb);

struct mutex_connection *test_create_mock_connection(__be32 saddr, __be32 daddr,
						     __be16 sport, __be16 dport,
						     u8 protocol);
void test_free_mock_connection(struct mutex_connection *conn);

/*
 * Test Utilities
 */
void test_sleep_ms(unsigned int ms);
unsigned long test_get_random(unsigned long max);
void test_generate_random_data(void *buffer, size_t size);

#endif /* MUTEX_TESTING_H */
