/*
 * MUTEX Testing Framework Implementation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "mutex_testing.h"

/* Global test framework context */
static struct test_framework *g_test_framework = NULL;

/* Module parameters */
static unsigned int test_categories = TEST_CAT_UNIT;
module_param(test_categories, uint, 0644);
MODULE_PARM_DESC(test_categories, "Enabled test categories bitmask");

static bool run_on_load = false;
module_param(run_on_load, bool, 0644);
MODULE_PARM_DESC(run_on_load, "Run tests automatically on module load");

static unsigned int default_timeout = 5000;
module_param(default_timeout, uint, 0644);
MODULE_PARM_DESC(default_timeout, "Default test timeout in milliseconds");

/*
 * Framework Initialization
 */
int mutex_test_framework_init(void)
{
	if (g_test_framework) {
		pr_warn("MUTEX test framework already initialized\n");
		return -EEXIST;
	}

	g_test_framework = kzalloc(sizeof(*g_test_framework), GFP_KERNEL);
	if (!g_test_framework)
		return -ENOMEM;

	INIT_LIST_HEAD(&g_test_framework->suites);
	spin_lock_init(&g_test_framework->lock);

	g_test_framework->enabled_categories = test_categories;
	g_test_framework->run_destructive = false;
	g_test_framework->run_slow = false;
	g_test_framework->default_timeout_ms = default_timeout;

	pr_info("MUTEX test framework initialized (categories=0x%04x)\n",
		test_categories);

	return 0;
}

/*
 * Framework Cleanup
 */
void mutex_test_framework_destroy(void)
{
	struct test_suite *suite, *suite_tmp;
	unsigned long flags;

	if (!g_test_framework)
		return;

	spin_lock_irqsave(&g_test_framework->lock, flags);

	list_for_each_entry_safe(suite, suite_tmp, &g_test_framework->suites, list) {
		list_del(&suite->list);
		spin_unlock_irqrestore(&g_test_framework->lock, flags);
		mutex_test_suite_destroy(suite);
		spin_lock_irqsave(&g_test_framework->lock, flags);
	}

	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	kfree(g_test_framework);
	g_test_framework = NULL;

	pr_info("MUTEX test framework destroyed\n");
}

/*
 * Test Suite Management
 */
struct test_suite *mutex_test_suite_create(const char *name, const char *description,
					    unsigned int category)
{
	struct test_suite *suite;

	suite = kzalloc(sizeof(*suite), GFP_KERNEL);
	if (!suite)
		return NULL;

	INIT_LIST_HEAD(&suite->list);
	INIT_LIST_HEAD(&suite->test_cases);
	strscpy(suite->name, name, sizeof(suite->name));
	if (description)
		strscpy(suite->description, description, sizeof(suite->description));
	suite->category = category;

	return suite;
}

void mutex_test_suite_destroy(struct test_suite *suite)
{
	struct test_case *test, *test_tmp;

	if (!suite)
		return;

	list_for_each_entry_safe(test, test_tmp, &suite->test_cases, list) {
		list_del(&test->list);
		mutex_test_case_destroy(test);
	}

	kfree(suite);
}

int mutex_test_suite_register(struct test_suite *suite)
{
	unsigned long flags;

	if (!g_test_framework || !suite)
		return -EINVAL;

	spin_lock_irqsave(&g_test_framework->lock, flags);
	list_add_tail(&suite->list, &g_test_framework->suites);
	g_test_framework->total_suites++;
	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	pr_debug("MUTEX: Registered test suite '%s' (%u tests)\n",
		 suite->name, suite->total_tests);

	return 0;
}

int mutex_test_suite_run(struct test_suite *suite)
{
	struct test_case *test;
	ktime_t suite_start;
	int ret = 0;

	if (!suite)
		return -EINVAL;

	/* Run suite setup if defined */
	if (suite->suite_setup) {
		ret = suite->suite_setup();
		if (ret < 0) {
			pr_err("MUTEX: Suite '%s' setup failed: %d\n", suite->name, ret);
			return ret;
		}
	}

	suite_start = ktime_get();
	suite->passed = 0;
	suite->failed = 0;
	suite->skipped = 0;
	suite->errors = 0;

	pr_info("MUTEX: Running test suite '%s' (%u tests)\n",
		suite->name, suite->total_tests);

	list_for_each_entry(test, &suite->test_cases, list) {
		ret = mutex_test_case_run(test, NULL);

		if (ret == TEST_PASS) {
			suite->passed++;
		} else if (ret == TEST_FAIL) {
			suite->failed++;
			pr_err("MUTEX: TEST FAILED: %s - %s\n", test->name, test->error_msg);
		} else if (ret == TEST_SKIP) {
			suite->skipped++;
		} else {
			suite->errors++;
		}
	}

	suite->total_duration = ktime_sub(ktime_get(), suite_start);

	/* Run suite teardown if defined */
	if (suite->suite_teardown) {
		ret = suite->suite_teardown();
		if (ret < 0)
			pr_warn("MUTEX: Suite '%s' teardown failed: %d\n", suite->name, ret);
	}

	pr_info("MUTEX: Suite '%s' complete: %u passed, %u failed, %u skipped (%lld ms)\n",
		suite->name, suite->passed, suite->failed, suite->skipped,
		ktime_to_ms(suite->total_duration));

	return 0;
}

/*
 * Test Case Management
 */
struct test_case *mutex_test_case_create(const char *name, const char *description,
					  int (*run)(void *), unsigned int category)
{
	struct test_case *test;

	test = kzalloc(sizeof(*test), GFP_KERNEL);
	if (!test)
		return NULL;

	INIT_LIST_HEAD(&test->list);
	strscpy(test->name, name, sizeof(test->name));
	if (description)
		strscpy(test->description, description, sizeof(test->description));
	test->run = run;
	test->category = category;
	test->timeout_ms = 5000;
	test->iterations = 1;

	return test;
}

void mutex_test_case_destroy(struct test_case *test)
{
	if (test)
		kfree(test);
}

int mutex_test_case_add_to_suite(struct test_suite *suite, struct test_case *test)
{
	if (!suite || !test)
		return -EINVAL;

	list_add_tail(&test->list, &suite->test_cases);
	suite->total_tests++;

	return 0;
}

int mutex_test_case_run(struct test_case *test, void *fixture)
{
	ktime_t start;
	int ret;

	if (!test || !test->run)
		return TEST_ERROR;

	/* Check if test should be skipped */
	if (!g_test_framework)
		return TEST_SKIP;

	if (!(test->category & g_test_framework->enabled_categories))
		return TEST_SKIP;

	if ((test->flags & TEST_FLAG_DESTRUCTIVE) && !g_test_framework->run_destructive)
		return TEST_SKIP;

	if ((test->flags & TEST_FLAG_SLOW) && !g_test_framework->run_slow)
		return TEST_SKIP;

	/* Run setup if defined */
	if (test->setup) {
		ret = test->setup(fixture);
		if (ret < 0)
			return TEST_ERROR;
	}

	/* Run the test */
	start = ktime_get();
	ret = test->run(fixture);
	test->duration = ktime_sub(ktime_get(), start);
	test->result = ret;

	/* Update iteration counters */
	if (ret == TEST_PASS)
		test->passed++;
	else if (ret == TEST_FAIL)
		test->failed++;
	else if (ret == TEST_SKIP)
		test->skipped++;

	/* Run teardown if defined */
	if (test->teardown)
		test->teardown(fixture);

	return ret;
}

/*
 * Test Registration Helper
 */
int mutex_test_register(const char *suite_name, const char *test_name,
			const char *description,
			int (*run)(void *),
			int (*teardown)(void *),
			unsigned int category, unsigned int flags,
			unsigned int timeout_ms, unsigned int iterations)
{
	struct test_suite *suite = NULL;
	struct test_case *test;
	unsigned long lock_flags;

	if (!g_test_framework || !suite_name || !test_name || !run)
		return -EINVAL;

	/* Find or create suite */
	spin_lock_irqsave(&g_test_framework->lock, lock_flags);
	list_for_each_entry(suite, &g_test_framework->suites, list) {
		if (strcmp(suite->name, suite_name) == 0)
			break;
	}
	spin_unlock_irqrestore(&g_test_framework->lock, lock_flags);

	if (!suite || strcmp(suite->name, suite_name) != 0) {
		suite = mutex_test_suite_create(suite_name, NULL, category);
		if (!suite)
			return -ENOMEM;
		mutex_test_suite_register(suite);
	}

	/* Create test case */
	test = mutex_test_case_create(test_name, description, run, category);
	if (!test)
		return -ENOMEM;

	test->teardown = teardown;
	test->flags = flags;
	test->timeout_ms = timeout_ms;
	test->iterations = iterations;

	return mutex_test_case_add_to_suite(suite, test);
}

/*
 * Test Execution
 */
int mutex_test_run_all(void)
{
	struct test_suite *suite;
	ktime_t start;
	unsigned long flags;

	if (!g_test_framework)
		return -EINVAL;

	pr_info("MUTEX: Running all test suites\n");
	pr_info("=====================================================\n");

	start = ktime_get();

	g_test_framework->total_tests = 0;
	g_test_framework->total_passed = 0;
	g_test_framework->total_failed = 0;
	g_test_framework->total_skipped = 0;
	g_test_framework->total_errors = 0;

	spin_lock_irqsave(&g_test_framework->lock, flags);
	list_for_each_entry(suite, &g_test_framework->suites, list) {
		g_test_framework->total_tests += suite->total_tests;
	}
	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	spin_lock_irqsave(&g_test_framework->lock, flags);
	list_for_each_entry(suite, &g_test_framework->suites, list) {
		spin_unlock_irqrestore(&g_test_framework->lock, flags);
		mutex_test_suite_run(suite);
		spin_lock_irqsave(&g_test_framework->lock, flags);

		g_test_framework->total_passed += suite->passed;
		g_test_framework->total_failed += suite->failed;
		g_test_framework->total_skipped += suite->skipped;
		g_test_framework->total_errors += suite->errors;
	}
	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	g_test_framework->total_duration = ktime_sub(ktime_get(), start);

	mutex_test_print_summary();

	return 0;
}

int mutex_test_run_category(unsigned int category)
{
	struct test_suite *suite;
	unsigned long flags;

	if (!g_test_framework)
		return -EINVAL;

	pr_info("MUTEX: Running tests for category 0x%04x\n", category);

	spin_lock_irqsave(&g_test_framework->lock, flags);
	list_for_each_entry(suite, &g_test_framework->suites, list) {
		if (suite->category & category) {
			spin_unlock_irqrestore(&g_test_framework->lock, flags);
			mutex_test_suite_run(suite);
			spin_lock_irqsave(&g_test_framework->lock, flags);
		}
	}
	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	return 0;
}

int mutex_test_run_suite(const char *suite_name)
{
	struct test_suite *suite;
	unsigned long flags;
	int ret = -ENOENT;

	if (!g_test_framework || !suite_name)
		return -EINVAL;

	spin_lock_irqsave(&g_test_framework->lock, flags);
	list_for_each_entry(suite, &g_test_framework->suites, list) {
		if (strcmp(suite->name, suite_name) == 0) {
			spin_unlock_irqrestore(&g_test_framework->lock, flags);
			ret = mutex_test_suite_run(suite);
			return ret;
		}
	}
	spin_unlock_irqrestore(&g_test_framework->lock, flags);

	pr_err("MUTEX: Test suite '%s' not found\n", suite_name);
	return ret;
}

/*
 * Configuration
 */
void mutex_test_enable_category(unsigned int category)
{
	if (g_test_framework)
		g_test_framework->enabled_categories |= category;
}

void mutex_test_disable_category(unsigned int category)
{
	if (g_test_framework)
		g_test_framework->enabled_categories &= ~category;
}

void mutex_test_set_timeout(unsigned int timeout_ms)
{
	if (g_test_framework)
		g_test_framework->default_timeout_ms = timeout_ms;
}

void mutex_test_enable_destructive(bool enable)
{
	if (g_test_framework)
		g_test_framework->run_destructive = enable;
}

void mutex_test_enable_slow(bool enable)
{
	if (g_test_framework)
		g_test_framework->run_slow = enable;
}

/*
 * Results and Reporting
 */
void mutex_test_print_summary(void)
{
	unsigned int pass_rate = 0;

	if (!g_test_framework)
		return;

	if (g_test_framework->total_tests > 0)
		pass_rate = (g_test_framework->total_passed * 100) /
			    g_test_framework->total_tests;

	pr_info("=====================================================\n");
	pr_info("MUTEX Test Summary:\n");
	pr_info("  Total Suites:  %u\n", g_test_framework->total_suites);
	pr_info("  Total Tests:   %u\n", g_test_framework->total_tests);
	pr_info("  Passed:        %u\n", g_test_framework->total_passed);
	pr_info("  Failed:        %u\n", g_test_framework->total_failed);
	pr_info("  Skipped:       %u\n", g_test_framework->total_skipped);
	pr_info("  Errors:        %u\n", g_test_framework->total_errors);
	pr_info("  Pass Rate:     %u%%\n", pass_rate);
	pr_info("  Duration:      %lld ms\n",
		ktime_to_ms(g_test_framework->total_duration));
	pr_info("=====================================================\n");
}

void mutex_test_get_statistics(struct test_statistics *stats)
{
	if (!g_test_framework || !stats)
		return;

	memset(stats, 0, sizeof(*stats));

	stats->total_suites = g_test_framework->total_suites;
	stats->total_tests = g_test_framework->total_tests;
	stats->passed = g_test_framework->total_passed;
	stats->failed = g_test_framework->total_failed;
	stats->skipped = g_test_framework->total_skipped;
	stats->errors = g_test_framework->total_errors;
	stats->total_duration = g_test_framework->total_duration;

	if (stats->total_tests > 0)
		stats->pass_rate = (stats->passed * 100) / stats->total_tests;
}

/*
 * Mock and Fixture Helpers
 */
struct sk_buff *test_create_mock_skb(int protocol, __be32 saddr, __be32 daddr,
				     __be16 sport, __be16 dport, size_t data_len)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	size_t total_len;

	/* Calculate total length */
	total_len = sizeof(struct iphdr) + data_len;
	if (protocol == IPPROTO_TCP)
		total_len += sizeof(struct tcphdr);
	else if (protocol == IPPROTO_UDP)
		total_len += sizeof(struct udphdr);

	skb = alloc_skb(total_len + 128, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb_reserve(skb, 64);
	skb_put(skb, total_len);
	skb_reset_network_header(skb);

	/* Fill IP header */
	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(total_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;

	skb_set_transport_header(skb, sizeof(struct iphdr));

	/* Fill transport header */
	if (protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr *)(skb->data + sizeof(struct iphdr));
		tcph->source = sport;
		tcph->dest = dport;
		tcph->seq = 0;
		tcph->ack_seq = 0;
		tcph->doff = 5;
		tcph->window = htons(65535);
		tcph->check = 0;
	} else if (protocol == IPPROTO_UDP) {
		udph = (struct udphdr *)(skb->data + sizeof(struct iphdr));
		udph->source = sport;
		udph->dest = dport;
		udph->len = htons(sizeof(struct udphdr) + data_len);
		udph->check = 0;
	}

	return skb;
}

void test_free_mock_skb(struct sk_buff *skb)
{
	if (skb)
		kfree_skb(skb);
}

/*
 * Test Utilities
 */
void test_sleep_ms(unsigned int ms)
{
	msleep(ms);
}

unsigned long test_get_random(unsigned long max)
{
	unsigned long val;
	get_random_bytes(&val, sizeof(val));
	return val % max;
}

void test_generate_random_data(void *buffer, size_t size)
{
	get_random_bytes(buffer, size);
}

/*
 * Example Test Cases
 */
static int test_basic_pass(void *fixture)
{
	pr_info("MUTEX: Running basic pass test\n");
	return TEST_PASS;
}

static int test_basic_assertion(void *fixture)
{
	struct test_case *test_ctx = (struct test_case *)fixture;
	int value = 42;

	TEST_ASSERT_EQ(value, 42);
	TEST_ASSERT_NE(value, 0);
	TEST_ASSERT_GT(value, 0);
	TEST_ASSERT_LT(value, 100);

	return TEST_PASS;
}

static int test_mock_skb_creation(void *fixture)
{
	struct sk_buff *skb;
	struct iphdr *iph;

	skb = test_create_mock_skb(IPPROTO_TCP, htonl(0x7f000001),
				   htonl(0x7f000002), htons(8080), htons(80), 100);

	if (!skb)
		return TEST_FAIL;

	iph = ip_hdr(skb);
	if (!iph) {
		test_free_mock_skb(skb);
		return TEST_FAIL;
	}

	test_free_mock_skb(skb);
	return TEST_PASS;
}

/*
 * Initialization Function (to be called by main module)
 */
int mutex_testing_module_init(void)
{
	int ret;

	pr_info("MUTEX Testing Framework loading...\n");

	ret = mutex_test_framework_init();
	if (ret < 0)
		return ret;

	/* Register basic tests */
	mutex_test_register("basic", "pass", "Basic passing test",
			    test_basic_pass, NULL, TEST_CAT_UNIT, 0, 1000, 1);

	mutex_test_register("basic", "assertion", "Basic assertion test",
			    test_basic_assertion, NULL, TEST_CAT_UNIT, 0, 1000, 1);

	mutex_test_register("basic", "mock_skb", "Mock SKB creation test",
			    test_mock_skb_creation, NULL, TEST_CAT_UNIT, 0, 1000, 1);

	if (run_on_load) {
		pr_info("MUTEX: Running tests automatically\n");
		mutex_test_run_all();
	}

	return 0;
}

void mutex_testing_module_exit(void)
{
	mutex_test_framework_destroy();
	pr_info("MUTEX Testing Framework unloaded\n");
}

EXPORT_SYMBOL(mutex_testing_module_init);
EXPORT_SYMBOL(mutex_testing_module_exit);

EXPORT_SYMBOL(mutex_test_framework_init);
EXPORT_SYMBOL(mutex_test_framework_destroy);
EXPORT_SYMBOL(mutex_test_suite_create);
EXPORT_SYMBOL(mutex_test_suite_register);
EXPORT_SYMBOL(mutex_test_suite_run);
EXPORT_SYMBOL(mutex_test_case_create);
EXPORT_SYMBOL(mutex_test_case_add_to_suite);
EXPORT_SYMBOL(mutex_test_register);
EXPORT_SYMBOL(mutex_test_run_all);
EXPORT_SYMBOL(mutex_test_run_category);
EXPORT_SYMBOL(test_create_mock_skb);
EXPORT_SYMBOL(test_free_mock_skb);
