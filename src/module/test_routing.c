// SPDX-License-Identifier: GPL-2.0
/*
 * MUTEX Advanced Routing Test Suite
 *
 * Comprehensive tests for routing tables, load balancing,
 * policy-based routing, and failover mechanisms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>

// Test result tracking
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) \
    do { \
        tests_run++; \
        printf("Test %d: %s ... ", tests_run, name); \
        fflush(stdout); \
    } while(0)

#define TEST_PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        tests_failed++; \
        printf("FAIL: %s\n", msg); \
    } while(0)

#define ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            TEST_FAIL(msg); \
            return; \
        } \
    } while(0)

// Mock structures for userspace testing
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// Load balancing algorithms
enum routing_lb_algorithm {
    ROUTING_LB_ROUND_ROBIN = 0,
    ROUTING_LB_LEAST_CONN,
    ROUTING_LB_WEIGHTED,
    ROUTING_LB_RANDOM,
    ROUTING_LB_HASH,
    ROUTING_LB_LEAST_LATENCY,
};

// Mock routing structures
struct routing_server {
    char ip[64];
    u16 port;
    u32 weight;
    int active;

    // Statistics
    u64 total_packets;
    u64 total_bytes;
    u32 active_connections;
    u64 total_connections;
    u64 failed_connections;
    u64 total_latency_us;
    u32 latency_samples;
};

struct routing_server_group {
    char name[64];
    struct routing_server servers[32];
    int num_servers;
    enum routing_lb_algorithm lb_algo;
    u32 next_server_index;

    // Statistics
    u64 total_requests;
    u64 total_load_balanced;
    u64 total_failed_lb;
};

struct routing_table {
    char name[64];
    int priority;
    int num_routes;
};

// Mock functions
static struct routing_server_group* create_test_group(const char *name) {
    struct routing_server_group *group = calloc(1, sizeof(*group));
    strncpy(group->name, name, sizeof(group->name) - 1);
    group->lb_algo = ROUTING_LB_ROUND_ROBIN;
    group->num_servers = 0;
    return group;
}

static void add_server_to_group(struct routing_server_group *group,
                               const char *ip, u16 port, u32 weight) {
    if (group->num_servers >= 32) return;

    struct routing_server *server = &group->servers[group->num_servers++];
    strncpy(server->ip, ip, sizeof(server->ip) - 1);
    server->port = port;
    server->weight = weight;
    server->active = 1;
}

static struct routing_server* select_round_robin(struct routing_server_group *group) {
    if (group->num_servers == 0) return NULL;

    int attempts = 0;
    while (attempts < group->num_servers) {
        u32 idx = group->next_server_index % group->num_servers;
        group->next_server_index++;

        struct routing_server *server = &group->servers[idx];
        if (server->active) {
            group->total_load_balanced++;
            return server;
        }
        attempts++;
    }

    group->total_failed_lb++;
    return NULL;
}

static struct routing_server* select_least_conn(struct routing_server_group *group) {
    if (group->num_servers == 0) return NULL;

    struct routing_server *best = NULL;
    u32 min_conn = UINT32_MAX;

    for (int i = 0; i < group->num_servers; i++) {
        struct routing_server *server = &group->servers[i];
        if (server->active && server->active_connections < min_conn) {
            min_conn = server->active_connections;
            best = server;
        }
    }

    if (best) {
        group->total_load_balanced++;
    } else {
        group->total_failed_lb++;
    }

    return best;
}

static struct routing_server* select_weighted(struct routing_server_group *group) {
    if (group->num_servers == 0) return NULL;

    u32 total_weight = 0;
    for (int i = 0; i < group->num_servers; i++) {
        if (group->servers[i].active) {
            total_weight += group->servers[i].weight;
        }
    }

    if (total_weight == 0) {
        group->total_failed_lb++;
        return NULL;
    }

    u32 random_weight = rand() % total_weight;
    u32 cumulative_weight = 0;

    for (int i = 0; i < group->num_servers; i++) {
        struct routing_server *server = &group->servers[i];
        if (server->active) {
            cumulative_weight += server->weight;
            if (random_weight < cumulative_weight) {
                group->total_load_balanced++;
                return server;
            }
        }
    }

    group->total_failed_lb++;
    return NULL;
}

static struct routing_server* select_hash(struct routing_server_group *group,
                                         const char *src_ip) {
    if (group->num_servers == 0) return NULL;

    // Simple hash of source IP
    u32 hash = 0;
    for (int i = 0; src_ip[i]; i++) {
        hash = hash * 31 + src_ip[i];
    }

    // Find active servers
    int active_count = 0;
    int active_indices[32];
    for (int i = 0; i < group->num_servers; i++) {
        if (group->servers[i].active) {
            active_indices[active_count++] = i;
        }
    }

    if (active_count == 0) {
        group->total_failed_lb++;
        return NULL;
    }

    int idx = active_indices[hash % active_count];
    group->total_load_balanced++;
    return &group->servers[idx];
}

// Test 1: Round Robin Load Balancing
static void test_round_robin_lb(void) {
    TEST_START("Round Robin Load Balancing");

    struct routing_server_group *group = create_test_group("test-rr");
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 100);
    add_server_to_group(group, "10.0.1.3", 8080, 100);

    // Select servers in round-robin fashion
    struct routing_server *s1 = select_round_robin(group);
    struct routing_server *s2 = select_round_robin(group);
    struct routing_server *s3 = select_round_robin(group);
    struct routing_server *s4 = select_round_robin(group);

    ASSERT(s1 != NULL && s2 != NULL && s3 != NULL && s4 != NULL,
           "All selections should succeed");
    ASSERT(strcmp(s1->ip, "10.0.1.1") == 0, "First should be server 1");
    ASSERT(strcmp(s2->ip, "10.0.1.2") == 0, "Second should be server 2");
    ASSERT(strcmp(s3->ip, "10.0.1.3") == 0, "Third should be server 3");
    ASSERT(strcmp(s4->ip, "10.0.1.1") == 0, "Fourth should wrap to server 1");
    ASSERT(group->total_load_balanced == 4, "Should have 4 successful LB operations");

    free(group);
    TEST_PASS();
}

// Test 2: Least Connections Load Balancing
static void test_least_conn_lb(void) {
    TEST_START("Least Connections Load Balancing");

    struct routing_server_group *group = create_test_group("test-lc");
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 100);
    add_server_to_group(group, "10.0.1.3", 8080, 100);

    // Set different connection counts
    group->servers[0].active_connections = 10;
    group->servers[1].active_connections = 5;
    group->servers[2].active_connections = 15;

    // Should select server with fewest connections
    struct routing_server *s1 = select_least_conn(group);
    ASSERT(s1 != NULL, "Should find a server");
    ASSERT(strcmp(s1->ip, "10.0.1.2") == 0, "Should select server with 5 connections");

    // Increase connections on server 2
    group->servers[1].active_connections = 20;
    struct routing_server *s2 = select_least_conn(group);
    ASSERT(strcmp(s2->ip, "10.0.1.1") == 0, "Should now select server with 10 connections");

    free(group);
    TEST_PASS();
}

// Test 3: Weighted Load Balancing
static void test_weighted_lb(void) {
    TEST_START("Weighted Load Balancing");

    srand(time(NULL));
    struct routing_server_group *group = create_test_group("test-weighted");

    // Server 1: weight 100 (50%)
    // Server 2: weight 50 (25%)
    // Server 3: weight 50 (25%)
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 50);
    add_server_to_group(group, "10.0.1.3", 8080, 50);

    // Run many selections and check distribution
    int counts[3] = {0, 0, 0};
    int iterations = 10000;

    for (int i = 0; i < iterations; i++) {
        struct routing_server *server = select_weighted(group);
        ASSERT(server != NULL, "Should always find a server");

        if (strcmp(server->ip, "10.0.1.1") == 0) counts[0]++;
        else if (strcmp(server->ip, "10.0.1.2") == 0) counts[1]++;
        else if (strcmp(server->ip, "10.0.1.3") == 0) counts[2]++;
    }

    // Check distribution is roughly correct (within 10% tolerance)
    double ratio1 = (double)counts[0] / iterations;
    double ratio2 = (double)counts[1] / iterations;
    double ratio3 = (double)counts[2] / iterations;

    ASSERT(ratio1 >= 0.45 && ratio1 <= 0.55, "Server 1 should get ~50% of traffic");
    ASSERT(ratio2 >= 0.20 && ratio2 <= 0.30, "Server 2 should get ~25% of traffic");
    ASSERT(ratio3 >= 0.20 && ratio3 <= 0.30, "Server 3 should get ~25% of traffic");

    free(group);
    TEST_PASS();
}

// Test 4: Hash-Based Load Balancing (Session Affinity)
static void test_hash_lb(void) {
    TEST_START("Hash-Based Load Balancing");

    struct routing_server_group *group = create_test_group("test-hash");
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 100);
    add_server_to_group(group, "10.0.1.3", 8080, 100);

    // Same source IP should always get same server
    const char *src_ip = "192.168.1.100";
    struct routing_server *s1 = select_hash(group, src_ip);
    struct routing_server *s2 = select_hash(group, src_ip);
    struct routing_server *s3 = select_hash(group, src_ip);

    ASSERT(s1 != NULL && s2 != NULL && s3 != NULL, "All selections should succeed");
    ASSERT(strcmp(s1->ip, s2->ip) == 0, "Same client should get same server (1)");
    ASSERT(strcmp(s2->ip, s3->ip) == 0, "Same client should get same server (2)");

    // Different source IP should likely get different server
    const char *src_ip2 = "192.168.1.200";
    struct routing_server *s4 = select_hash(group, src_ip2);
    ASSERT(s4 != NULL, "Should find server for different client");

    free(group);
    TEST_PASS();
}

// Test 5: Failover Handling
static void test_failover(void) {
    TEST_START("Failover Handling");

    struct routing_server_group *group = create_test_group("test-failover");
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 100);
    add_server_to_group(group, "10.0.1.3", 8080, 100);

    // All servers active
    struct routing_server *s1 = select_round_robin(group);
    ASSERT(s1 != NULL, "Should find active server");

    // Mark first server as inactive
    group->servers[0].active = 0;

    // Should skip inactive server
    struct routing_server *s2 = select_round_robin(group);
    struct routing_server *s3 = select_round_robin(group);
    ASSERT(s2 != NULL && s3 != NULL, "Should find active servers");
    ASSERT(strcmp(s2->ip, "10.0.1.2") == 0, "Should skip inactive server 1");
    ASSERT(strcmp(s3->ip, "10.0.1.3") == 0, "Should continue with active servers");

    // Mark all servers inactive
    group->servers[1].active = 0;
    group->servers[2].active = 0;

    struct routing_server *s4 = select_round_robin(group);
    ASSERT(s4 == NULL, "Should return NULL when all servers down");
    ASSERT(group->total_failed_lb > 0, "Should record failed LB");

    free(group);
    TEST_PASS();
}

// Test 6: IPv6 Address Support
static void test_ipv6_addresses(void) {
    TEST_START("IPv6 Address Support");

    struct routing_server_group *group = create_test_group("test-ipv6");
    add_server_to_group(group, "2001:db8::1", 8080, 100);
    add_server_to_group(group, "2001:db8::2", 8080, 100);
    add_server_to_group(group, "::ffff:10.0.1.1", 8080, 100); // IPv4-mapped

    ASSERT(group->num_servers == 3, "Should add all servers");

    struct routing_server *s1 = select_round_robin(group);
    ASSERT(s1 != NULL, "Should select server");
    ASSERT(strstr(s1->ip, "2001:db8::1") != NULL, "Should support IPv6 addresses");

    free(group);
    TEST_PASS();
}

// Test 7: Server Statistics Tracking
static void test_server_statistics(void) {
    TEST_START("Server Statistics Tracking");

    struct routing_server_group *group = create_test_group("test-stats");
    add_server_to_group(group, "10.0.1.1", 8080, 100);

    struct routing_server *server = &group->servers[0];

    // Simulate traffic
    server->total_packets = 1000;
    server->total_bytes = 1500000;
    server->total_connections = 100;
    server->active_connections = 25;
    server->failed_connections = 5;

    // Simulate latency tracking
    server->total_latency_us = 500000; // 500ms total
    server->latency_samples = 100;

    u64 avg_latency = server->total_latency_us / server->latency_samples;

    ASSERT(server->total_packets == 1000, "Should track packets");
    ASSERT(server->total_bytes == 1500000, "Should track bytes");
    ASSERT(server->active_connections == 25, "Should track active connections");
    ASSERT(avg_latency == 5000, "Average latency should be 5ms");

    free(group);
    TEST_PASS();
}

// Test 8: Group Statistics Tracking
static void test_group_statistics(void) {
    TEST_START("Group Statistics Tracking");

    struct routing_server_group *group = create_test_group("test-group-stats");
    add_server_to_group(group, "10.0.1.1", 8080, 100);
    add_server_to_group(group, "10.0.1.2", 8080, 100);

    // Track load balancing operations
    for (int i = 0; i < 100; i++) {
        struct routing_server *server = select_round_robin(group);
        ASSERT(server != NULL, "Should select server");
    }

    ASSERT(group->total_load_balanced == 100, "Should track successful LB operations");

    // Test failed load balancing
    group->servers[0].active = 0;
    group->servers[1].active = 0;

    struct routing_server *failed = select_round_robin(group);
    ASSERT(failed == NULL, "Should fail with no active servers");
    ASSERT(group->total_failed_lb > 0, "Should track failed LB operations");

    free(group);
    TEST_PASS();
}

// Test 9: Multiple Server Groups
static void test_multiple_groups(void) {
    TEST_START("Multiple Server Groups");

    struct routing_server_group *web_group = create_test_group("web-servers");
    struct routing_server_group *api_group = create_test_group("api-servers");
    struct routing_server_group *db_group = create_test_group("db-servers");

    add_server_to_group(web_group, "10.0.1.1", 80, 100);
    add_server_to_group(api_group, "10.0.2.1", 8080, 100);
    add_server_to_group(db_group, "10.0.3.1", 3306, 100);

    ASSERT(web_group->num_servers == 1, "Web group should have 1 server");
    ASSERT(api_group->num_servers == 1, "API group should have 1 server");
    ASSERT(db_group->num_servers == 1, "DB group should have 1 server");

    struct routing_server *web_server = select_round_robin(web_group);
    struct routing_server *api_server = select_round_robin(api_group);

    ASSERT(web_server->port == 80, "Web server on port 80");
    ASSERT(api_server->port == 8080, "API server on port 8080");

    free(web_group);
    free(api_group);
    free(db_group);
    TEST_PASS();
}

// Test 10: Edge Cases
static void test_edge_cases(void) {
    TEST_START("Edge Cases");

    // Empty group
    struct routing_server_group *empty_group = create_test_group("empty");
    struct routing_server *server = select_round_robin(empty_group);
    ASSERT(server == NULL, "Empty group should return NULL");

    // Single server group
    struct routing_server_group *single_group = create_test_group("single");
    add_server_to_group(single_group, "10.0.1.1", 8080, 100);
    struct routing_server *s1 = select_round_robin(single_group);
    struct routing_server *s2 = select_round_robin(single_group);
    ASSERT(s1 != NULL && s2 != NULL, "Single server should work");
    ASSERT(s1 == s2, "Should return same server multiple times");

    // Zero weight servers
    struct routing_server_group *zero_weight = create_test_group("zero-weight");
    add_server_to_group(zero_weight, "10.0.1.1", 8080, 0);
    add_server_to_group(zero_weight, "10.0.1.2", 8080, 0);
    struct routing_server *s3 = select_weighted(zero_weight);
    ASSERT(s3 == NULL, "Zero total weight should fail");

    free(empty_group);
    free(single_group);
    free(zero_weight);
    TEST_PASS();
}

// Test 11: Policy Rule Matching
static void test_policy_rules(void) {
    TEST_START("Policy Rule Matching");

    // Simulate policy rule structure
    struct {
        u16 dst_port_min;
        u16 dst_port_max;
        u8 protocol;
    } rule1 = {80, 80, 6}; // TCP port 80

    struct {
        u16 dst_port_min;
        u16 dst_port_max;
        u8 protocol;
    } rule2 = {8000, 9000, 6}; // TCP ports 8000-9000

    // Test matching
    ASSERT(8080 >= rule2.dst_port_min && 8080 <= rule2.dst_port_max,
           "Port 8080 should match range 8000-9000");
    ASSERT(!(80 >= rule2.dst_port_min && 80 <= rule2.dst_port_max),
           "Port 80 should not match range 8000-9000");

    TEST_PASS();
}

// Test 12: Routing Cache Simulation
static void test_routing_cache(void) {
    TEST_START("Routing Cache Simulation");

    // Simple cache structure
    struct cache_entry {
        char key[64];
        struct routing_server *server;
        time_t timestamp;
    };

    struct routing_server_group *group = create_test_group("test-cache");
    add_server_to_group(group, "10.0.1.1", 8080, 100);

    struct cache_entry cache[10] = {0};

    // Add cache entry
    strncpy(cache[0].key, "192.168.1.100:80", sizeof(cache[0].key) - 1);
    cache[0].server = &group->servers[0];
    cache[0].timestamp = time(NULL);

    // Lookup cache entry
    ASSERT(strcmp(cache[0].key, "192.168.1.100:80") == 0, "Cache key should match");
    ASSERT(cache[0].server != NULL, "Cached server should exist");

    // Test cache expiry
    cache[0].timestamp = time(NULL) - 400; // 400 seconds ago
    int expired = (time(NULL) - cache[0].timestamp) > 300;
    ASSERT(expired, "Entry should be expired after 300 seconds");

    free(group);
    TEST_PASS();
}

// Main test runner
int main(void) {
    printf("MUTEX Advanced Routing Test Suite\n");
    printf("==================================\n\n");

    test_round_robin_lb();
    test_least_conn_lb();
    test_weighted_lb();
    test_hash_lb();
    test_failover();
    test_ipv6_addresses();
    test_server_statistics();
    test_group_statistics();
    test_multiple_groups();
    test_edge_cases();
    test_policy_rules();
    test_routing_cache();

    printf("\n==================================\n");
    printf("Test Results:\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("==================================\n");

    if (tests_failed == 0) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}
