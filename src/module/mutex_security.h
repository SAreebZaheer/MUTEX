/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MUTEX Security Hardening Header
 *
 * Security features including input validation, rate limiting,
 * capability checks, audit logging, and secure memory handling.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#ifndef MUTEX_SECURITY_H
#define MUTEX_SECURITY_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/ratelimit.h>
#include <net/sock.h>

/* Security configuration limits */
#define SECURITY_MAX_PROXY_SERVERS     16
#define SECURITY_MAX_HOSTNAME_LEN      256
#define SECURITY_MAX_USERNAME_LEN      64
#define SECURITY_MAX_PASSWORD_LEN      128
#define SECURITY_MAX_RULE_COUNT        1024
#define SECURITY_MAX_PACKET_SIZE       65535
#define SECURITY_MIN_PACKET_SIZE       20

/* Rate limiting parameters */
#define SECURITY_RATELIMIT_BURST       10
#define SECURITY_RATELIMIT_INTERVAL    (1 * HZ)  /* 1 second */

/* Audit event types */
enum security_audit_event {
	AUDIT_PROXY_CREATE = 0,
	AUDIT_PROXY_DESTROY,
	AUDIT_PROXY_ENABLE,
	AUDIT_PROXY_DISABLE,
	AUDIT_PROXY_CONFIG_CHANGE,
	AUDIT_SUSPICIOUS_PACKET,
	AUDIT_RATE_LIMIT_EXCEEDED,
	AUDIT_CAPABILITY_DENIED,
	AUDIT_INVALID_INPUT,
	AUDIT_CONNECTION_BLOCKED,
	AUDIT_MAX
};

/* Security violation types */
enum security_violation {
	VIOLATION_NONE = 0,
	VIOLATION_INVALID_SIZE,
	VIOLATION_INVALID_POINTER,
	VIOLATION_BUFFER_OVERFLOW,
	VIOLATION_RATE_LIMIT,
	VIOLATION_CAPABILITY,
	VIOLATION_MALFORMED_PACKET,
	VIOLATION_SUSPICIOUS_ACTIVITY,
	VIOLATION_MAX
};

/* Rate limiter structure */
struct security_rate_limiter {
	spinlock_t lock;
	unsigned long window_start;
	unsigned int count;
	unsigned int burst;
	unsigned int interval;  /* in jiffies */
	atomic64_t total_allowed;
	atomic64_t total_dropped;
};

/* Per-connection security context */
struct security_conn_context {
	atomic_t packet_count;
	atomic_t violation_count;
	ktime_t first_seen;
	ktime_t last_activity;
	u32 flags;
	struct security_rate_limiter rate_limiter;
};

/* Global security statistics */
struct security_statistics {
	atomic64_t audit_events[AUDIT_MAX];
	atomic64_t violations[VIOLATION_MAX];
	atomic64_t capability_checks;
	atomic64_t capability_denials;
	atomic64_t rate_limit_hits;
	atomic64_t validated_inputs;
	atomic64_t sanitized_data;
	atomic64_t secure_wipes;
};

/* Security context for the module */
struct security_context {
	struct security_statistics stats;
	struct security_rate_limiter global_limiter;
	spinlock_t audit_lock;
	bool audit_enabled;
	bool strict_validation;
	bool memory_wipe_enabled;
};

/* Core security functions */
int mutex_security_init(void);
void mutex_security_exit(void);

/* Capability checks */
bool mutex_security_check_capability(int cap);
bool mutex_security_check_net_admin(void);
bool mutex_security_check_net_raw(void);

/* Input validation */
int mutex_security_validate_pointer(const void __user *ptr, size_t size);
int mutex_security_validate_string(const char __user *str, size_t max_len);
int mutex_security_validate_address(const void *addr, size_t size);
int mutex_security_validate_packet_size(size_t size);
int mutex_security_validate_proxy_config(const void *config, size_t size);

/* Buffer operations with overflow protection */
int mutex_security_safe_copy_from_user(void *to, const void __user *from,
					size_t size, size_t max_size);
int mutex_security_safe_copy_to_user(void __user *to, const void *from,
				      size_t size, size_t max_size);
int mutex_security_safe_string_copy(char *dest, const char *src,
				     size_t dest_size);

/* Rate limiting */
bool mutex_security_rate_limit_check(struct security_rate_limiter *limiter);
void mutex_security_rate_limiter_init(struct security_rate_limiter *limiter,
				       unsigned int burst, unsigned int interval);
void mutex_security_rate_limiter_reset(struct security_rate_limiter *limiter);

/* Audit logging */
void mutex_security_audit_log(enum security_audit_event event, uid_t uid,
			       pid_t pid, const char *msg);
void mutex_security_log_violation(enum security_violation violation,
				   const char *details);
void mutex_security_log_capability_denial(int cap, uid_t uid, pid_t pid);

/* Secure memory operations */
void mutex_security_wipe_memory(void *ptr, size_t size);
void *mutex_security_alloc_sensitive(size_t size, gfp_t flags);
void mutex_security_free_sensitive(void *ptr, size_t size);

/* Packet validation */
int mutex_security_validate_packet(struct sk_buff *skb);
int mutex_security_validate_tcp_packet(struct sk_buff *skb);
int mutex_security_validate_udp_packet(struct sk_buff *skb);
bool mutex_security_is_suspicious_packet(struct sk_buff *skb);

/* Connection security context */
struct security_conn_context *mutex_security_conn_context_alloc(void);
void mutex_security_conn_context_free(struct security_conn_context *ctx);
int mutex_security_check_connection(struct security_conn_context *ctx);

/* Statistics */
void mutex_security_get_statistics(struct security_statistics *stats);
void mutex_security_reset_statistics(void);

/* SELinux/AppArmor integration helpers */
int mutex_security_check_lsm_permission(void);
const char *mutex_security_get_context_string(void);

/* Utility functions */
const char *mutex_security_audit_event_name(enum security_audit_event event);
const char *mutex_security_violation_name(enum security_violation violation);

/* Export global security context */
extern struct security_context *global_security_ctx;

#endif /* MUTEX_SECURITY_H */
