// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MUTEX Security Hardening Implementation
 *
 * Comprehensive security features including input validation, rate limiting,
 * capability checks, audit logging, and secure memory handling.
 *
 * Copyright (C) 2025 MUTEX Project
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/audit.h>
#include <linux/ratelimit.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "mutex_security.h"

/* Global security context */
struct security_context *global_security_ctx;
EXPORT_SYMBOL_GPL(global_security_ctx);

/* Audit event names */
static const char * const audit_event_names[] = {
	[AUDIT_PROXY_CREATE] = "proxy_create",
	[AUDIT_PROXY_DESTROY] = "proxy_destroy",
	[AUDIT_PROXY_ENABLE] = "proxy_enable",
	[AUDIT_PROXY_DISABLE] = "proxy_disable",
	[AUDIT_PROXY_CONFIG_CHANGE] = "proxy_config_change",
	[AUDIT_SUSPICIOUS_PACKET] = "suspicious_packet",
	[AUDIT_RATE_LIMIT_EXCEEDED] = "rate_limit_exceeded",
	[AUDIT_CAPABILITY_DENIED] = "capability_denied",
	[AUDIT_INVALID_INPUT] = "invalid_input",
	[AUDIT_CONNECTION_BLOCKED] = "connection_blocked",
};

/* Violation names */
static const char * const violation_names[] = {
	[VIOLATION_NONE] = "none",
	[VIOLATION_INVALID_SIZE] = "invalid_size",
	[VIOLATION_INVALID_POINTER] = "invalid_pointer",
	[VIOLATION_BUFFER_OVERFLOW] = "buffer_overflow",
	[VIOLATION_RATE_LIMIT] = "rate_limit",
	[VIOLATION_CAPABILITY] = "capability",
	[VIOLATION_MALFORMED_PACKET] = "malformed_packet",
	[VIOLATION_SUSPICIOUS_ACTIVITY] = "suspicious_activity",
};

/* ========== Initialization and Cleanup ========== */

/**
 * mutex_security_init() - Initialize security subsystem
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_security_init(void)
{
	global_security_ctx = kzalloc(sizeof(*global_security_ctx), GFP_KERNEL);
	if (!global_security_ctx)
		return -ENOMEM;

	/* Initialize global rate limiter */
	mutex_security_rate_limiter_init(&global_security_ctx->global_limiter,
					 SECURITY_RATELIMIT_BURST,
					 SECURITY_RATELIMIT_INTERVAL);

	spin_lock_init(&global_security_ctx->audit_lock);
	global_security_ctx->audit_enabled = true;
	global_security_ctx->strict_validation = true;
	global_security_ctx->memory_wipe_enabled = true;

	pr_info("MUTEX security subsystem initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_init);

/**
 * mutex_security_exit() - Cleanup security subsystem
 */
void mutex_security_exit(void)
{
	if (!global_security_ctx)
		return;

	/* Wipe sensitive data before freeing */
	mutex_security_wipe_memory(global_security_ctx,
				    sizeof(*global_security_ctx));
	kfree(global_security_ctx);
	global_security_ctx = NULL;

	pr_info("MUTEX security subsystem exited\n");
}
EXPORT_SYMBOL_GPL(mutex_security_exit);

/* ========== Capability Checks ========== */

/**
 * mutex_security_check_capability() - Check if current task has capability
 * @cap: Capability to check (e.g., CAP_NET_ADMIN)
 *
 * Return: true if capability is present, false otherwise
 */
bool mutex_security_check_capability(int cap)
{
	bool has_cap;

	if (!global_security_ctx)
		return false;

	atomic64_inc(&global_security_ctx->stats.capability_checks);

	has_cap = capable(cap);
	if (!has_cap) {
		atomic64_inc(&global_security_ctx->stats.capability_denials);
		mutex_security_log_capability_denial(cap,
						     current_uid().val,
						     task_pid_nr(current));
	}

	return has_cap;
}
EXPORT_SYMBOL_GPL(mutex_security_check_capability);

/**
 * mutex_security_check_net_admin() - Check CAP_NET_ADMIN capability
 *
 * Return: true if capability is present
 */
bool mutex_security_check_net_admin(void)
{
	return mutex_security_check_capability(CAP_NET_ADMIN);
}
EXPORT_SYMBOL_GPL(mutex_security_check_net_admin);

/**
 * mutex_security_check_net_raw() - Check CAP_NET_RAW capability
 *
 * Return: true if capability is present
 */
bool mutex_security_check_net_raw(void)
{
	return mutex_security_check_capability(CAP_NET_RAW);
}
EXPORT_SYMBOL_GPL(mutex_security_check_net_raw);

/* ========== Input Validation ========== */

/**
 * mutex_security_validate_pointer() - Validate user-space pointer
 * @ptr: User-space pointer to validate
 * @size: Size of data to be accessed
 *
 * Return: 0 if valid, -EFAULT if invalid
 */
int mutex_security_validate_pointer(const void __user *ptr, size_t size)
{
	if (!global_security_ctx)
		return -EINVAL;

	if (!ptr || size == 0 || size > SECURITY_MAX_PACKET_SIZE) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		mutex_security_log_violation(VIOLATION_INVALID_POINTER,
					      "Invalid user pointer or size");
		return -EFAULT;
	}

	if (!access_ok(ptr, size)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		mutex_security_log_violation(VIOLATION_INVALID_POINTER,
					      "User pointer not accessible");
		return -EFAULT;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_pointer);

/**
 * mutex_security_validate_string() - Validate user-space string
 * @str: User-space string pointer
 * @max_len: Maximum allowed length
 *
 * Return: 0 if valid, negative error code otherwise
 */
int mutex_security_validate_string(const char __user *str, size_t max_len)
{
	long len;

	if (!global_security_ctx)
		return -EINVAL;

	if (!str || max_len == 0) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EFAULT;
	}

	len = strnlen_user(str, max_len + 1);
	if (len < 0) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EFAULT;
	}

	if (len > max_len) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_SIZE]);
		mutex_security_log_violation(VIOLATION_INVALID_SIZE,
					      "String exceeds maximum length");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_string);

/**
 * mutex_security_validate_address() - Validate kernel address
 * @addr: Kernel address to validate
 * @size: Size of data at address
 *
 * Return: 0 if valid, -EFAULT if invalid
 */
int mutex_security_validate_address(const void *addr, size_t size)
{
	if (!global_security_ctx)
		return -EINVAL;

	if (!addr || size == 0) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EFAULT;
	}

	if (!virt_addr_valid((unsigned long)addr)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		mutex_security_log_violation(VIOLATION_INVALID_POINTER,
					      "Invalid kernel address");
		return -EFAULT;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_address);

/**
 * mutex_security_validate_packet_size() - Validate packet size
 * @size: Packet size to validate
 *
 * Return: 0 if valid, -EINVAL if invalid
 */
int mutex_security_validate_packet_size(size_t size)
{
	if (!global_security_ctx)
		return -EINVAL;

	if (size < SECURITY_MIN_PACKET_SIZE || size > SECURITY_MAX_PACKET_SIZE) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_SIZE]);
		mutex_security_log_violation(VIOLATION_INVALID_SIZE,
					      "Packet size out of range");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_packet_size);

/**
 * mutex_security_validate_proxy_config() - Validate proxy configuration
 * @config: Configuration data to validate
 * @size: Size of configuration data
 *
 * Return: 0 if valid, negative error code otherwise
 */
int mutex_security_validate_proxy_config(const void *config, size_t size)
{
	int ret;

	if (!global_security_ctx)
		return -EINVAL;

	ret = mutex_security_validate_address(config, size);
	if (ret)
		return ret;

	/* Add more specific validation as needed */
	if (size > PAGE_SIZE) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_SIZE]);
		mutex_security_log_violation(VIOLATION_INVALID_SIZE,
					      "Configuration too large");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_proxy_config);

/* ========== Buffer Operations ========== */

/**
 * mutex_security_safe_copy_from_user() - Safe copy from user space
 * @to: Kernel destination buffer
 * @from: User source buffer
 * @size: Size to copy
 * @max_size: Maximum allowed size
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_security_safe_copy_from_user(void *to, const void __user *from,
					size_t size, size_t max_size)
{
	int ret;

	if (!global_security_ctx)
		return -EINVAL;

	if (size > max_size) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_BUFFER_OVERFLOW]);
		mutex_security_log_violation(VIOLATION_BUFFER_OVERFLOW,
					      "Copy size exceeds maximum");
		return -EINVAL;
	}

	ret = mutex_security_validate_pointer(from, size);
	if (ret)
		return ret;

	ret = mutex_security_validate_address(to, size);
	if (ret)
		return ret;

	if (copy_from_user(to, from, size)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EFAULT;
	}

	atomic64_inc(&global_security_ctx->stats.sanitized_data);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_safe_copy_from_user);

/**
 * mutex_security_safe_copy_to_user() - Safe copy to user space
 * @to: User destination buffer
 * @from: Kernel source buffer
 * @size: Size to copy
 * @max_size: Maximum allowed size
 *
 * Return: 0 on success, negative error code on failure
 */
int mutex_security_safe_copy_to_user(void __user *to, const void *from,
				      size_t size, size_t max_size)
{
	int ret;

	if (!global_security_ctx)
		return -EINVAL;

	if (size > max_size) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_BUFFER_OVERFLOW]);
		mutex_security_log_violation(VIOLATION_BUFFER_OVERFLOW,
					      "Copy size exceeds maximum");
		return -EINVAL;
	}

	ret = mutex_security_validate_pointer(to, size);
	if (ret)
		return ret;

	ret = mutex_security_validate_address(from, size);
	if (ret)
		return ret;

	if (copy_to_user(to, from, size)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EFAULT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_safe_copy_to_user);

/**
 * mutex_security_safe_string_copy() - Safe string copy with size check
 * @dest: Destination buffer
 * @src: Source string
 * @dest_size: Size of destination buffer
 *
 * Return: 0 on success, -EINVAL on overflow
 */
int mutex_security_safe_string_copy(char *dest, const char *src,
				     size_t dest_size)
{
	size_t len;

	if (!global_security_ctx)
		return -EINVAL;

	if (!dest || !src || dest_size == 0) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EINVAL;
	}

	len = strnlen(src, dest_size);
	if (len >= dest_size) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_BUFFER_OVERFLOW]);
		mutex_security_log_violation(VIOLATION_BUFFER_OVERFLOW,
					      "String copy would overflow");
		return -EINVAL;
	}

	strscpy(dest, src, dest_size);
	atomic64_inc(&global_security_ctx->stats.sanitized_data);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_safe_string_copy);

/* ========== Rate Limiting ========== */

/**
 * mutex_security_rate_limiter_init() - Initialize rate limiter
 * @limiter: Rate limiter structure
 * @burst: Maximum burst size
 * @interval: Time interval in jiffies
 */
void mutex_security_rate_limiter_init(struct security_rate_limiter *limiter,
				       unsigned int burst, unsigned int interval)
{
	if (!limiter)
		return;

	spin_lock_init(&limiter->lock);
	limiter->window_start = jiffies;
	limiter->count = 0;
	limiter->burst = burst;
	limiter->interval = interval;
	atomic64_set(&limiter->total_allowed, 0);
	atomic64_set(&limiter->total_dropped, 0);
}
EXPORT_SYMBOL_GPL(mutex_security_rate_limiter_init);

/**
 * mutex_security_rate_limit_check() - Check if rate limit allows action
 * @limiter: Rate limiter to check
 *
 * Return: true if action is allowed, false if rate limited
 */
bool mutex_security_rate_limit_check(struct security_rate_limiter *limiter)
{
	unsigned long now = jiffies;
	bool allowed = false;

	if (!limiter || !global_security_ctx)
		return true;  /* Fail open if not initialized */

	spin_lock(&limiter->lock);

	/* Check if we need to reset the window */
	if (time_after(now, limiter->window_start + limiter->interval)) {
		limiter->window_start = now;
		limiter->count = 0;
	}

	/* Check if we're within burst limit */
	if (limiter->count < limiter->burst) {
		limiter->count++;
		atomic64_inc(&limiter->total_allowed);
		allowed = true;
	} else {
		atomic64_inc(&limiter->total_dropped);
		atomic64_inc(&global_security_ctx->stats.rate_limit_hits);
		mutex_security_log_violation(VIOLATION_RATE_LIMIT,
					      "Rate limit exceeded");
	}

	spin_unlock(&limiter->lock);
	return allowed;
}
EXPORT_SYMBOL_GPL(mutex_security_rate_limit_check);

/**
 * mutex_security_rate_limiter_reset() - Reset rate limiter
 * @limiter: Rate limiter to reset
 */
void mutex_security_rate_limiter_reset(struct security_rate_limiter *limiter)
{
	if (!limiter)
		return;

	spin_lock(&limiter->lock);
	limiter->window_start = jiffies;
	limiter->count = 0;
	spin_unlock(&limiter->lock);
}
EXPORT_SYMBOL_GPL(mutex_security_rate_limiter_reset);

/* ========== Audit Logging ========== */

/**
 * mutex_security_audit_log() - Log audit event
 * @event: Audit event type
 * @uid: User ID
 * @pid: Process ID
 * @msg: Additional message
 */
void mutex_security_audit_log(enum security_audit_event event, uid_t uid,
			       pid_t pid, const char *msg)
{
	if (!global_security_ctx || !global_security_ctx->audit_enabled)
		return;

	if (event >= AUDIT_MAX)
		return;

	atomic64_inc(&global_security_ctx->stats.audit_events[event]);

	spin_lock(&global_security_ctx->audit_lock);
	pr_info("MUTEX AUDIT [%s]: uid=%u pid=%d msg='%s'\n",
		audit_event_names[event], uid, pid, msg ? msg : "");
	spin_unlock(&global_security_ctx->audit_lock);
}
EXPORT_SYMBOL_GPL(mutex_security_audit_log);

/**
 * mutex_security_log_violation() - Log security violation
 * @violation: Violation type
 * @details: Violation details
 */
void mutex_security_log_violation(enum security_violation violation,
				   const char *details)
{
	if (!global_security_ctx)
		return;

	if (violation >= VIOLATION_MAX)
		return;

	atomic64_inc(&global_security_ctx->stats.violations[violation]);

	pr_warn("MUTEX SECURITY VIOLATION [%s]: %s\n",
		violation_names[violation], details ? details : "");
}
EXPORT_SYMBOL_GPL(mutex_security_log_violation);

/**
 * mutex_security_log_capability_denial() - Log capability denial
 * @cap: Capability that was denied
 * @uid: User ID
 * @pid: Process ID
 */
void mutex_security_log_capability_denial(int cap, uid_t uid, pid_t pid)
{
	if (!global_security_ctx)
		return;

	pr_warn("MUTEX CAPABILITY DENIED: cap=%d uid=%u pid=%d\n", cap, uid, pid);
	mutex_security_audit_log(AUDIT_CAPABILITY_DENIED, uid, pid,
				 "Capability check failed");
}
EXPORT_SYMBOL_GPL(mutex_security_log_capability_denial);

/* ========== Secure Memory Operations ========== */

/**
 * mutex_security_wipe_memory() - Securely wipe memory
 * @ptr: Pointer to memory to wipe
 * @size: Size of memory to wipe
 */
void mutex_security_wipe_memory(void *ptr, size_t size)
{
	if (!ptr || size == 0 || !global_security_ctx)
		return;

	if (!global_security_ctx->memory_wipe_enabled)
		return;

	/* Use memzero_explicit to prevent compiler optimization */
	memzero_explicit(ptr, size);
	atomic64_inc(&global_security_ctx->stats.secure_wipes);
}
EXPORT_SYMBOL_GPL(mutex_security_wipe_memory);

/**
 * mutex_security_alloc_sensitive() - Allocate memory for sensitive data
 * @size: Size to allocate
 * @flags: GFP flags
 *
 * Return: Pointer to allocated memory, or NULL on failure
 */
void *mutex_security_alloc_sensitive(size_t size, gfp_t flags)
{
	void *ptr;

	if (!global_security_ctx)
		return NULL;

	ptr = kzalloc(size, flags);
	if (!ptr)
		return NULL;

	/* Memory is already zeroed by kzalloc */
	return ptr;
}
EXPORT_SYMBOL_GPL(mutex_security_alloc_sensitive);

/**
 * mutex_security_free_sensitive() - Free sensitive memory
 * @ptr: Pointer to memory to free
 * @size: Size of memory
 */
void mutex_security_free_sensitive(void *ptr, size_t size)
{
	if (!ptr || !global_security_ctx)
		return;

	/* Wipe before freeing */
	mutex_security_wipe_memory(ptr, size);
	kfree(ptr);
}
EXPORT_SYMBOL_GPL(mutex_security_free_sensitive);

/* ========== Packet Validation ========== */

/**
 * mutex_security_validate_packet() - Validate packet structure
 * @skb: Socket buffer to validate
 *
 * Return: 0 if valid, negative error code otherwise
 */
int mutex_security_validate_packet(struct sk_buff *skb)
{
	if (!global_security_ctx)
		return -EINVAL;

	if (!skb) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_POINTER]);
		return -EINVAL;
	}

	if (skb->len < SECURITY_MIN_PACKET_SIZE ||
	    skb->len > SECURITY_MAX_PACKET_SIZE) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_INVALID_SIZE]);
		mutex_security_log_violation(VIOLATION_INVALID_SIZE,
					      "Packet size out of range");
		return -EINVAL;
	}

	/* Check if packet is suspicious */
	if (mutex_security_is_suspicious_packet(skb)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_SUSPICIOUS_ACTIVITY]);
		mutex_security_audit_log(AUDIT_SUSPICIOUS_PACKET,
					 current_uid().val,
					 task_pid_nr(current),
					 "Suspicious packet detected");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_packet);

/**
 * mutex_security_validate_tcp_packet() - Validate TCP packet
 * @skb: Socket buffer containing TCP packet
 *
 * Return: 0 if valid, negative error code otherwise
 */
int mutex_security_validate_tcp_packet(struct sk_buff *skb)
{
	struct tcphdr *th;
	unsigned int tcp_hdr_len;

	if (!global_security_ctx)
		return -EINVAL;

	if (!skb || !tcp_hdr(skb)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_MALFORMED_PACKET]);
		return -EINVAL;
	}

	th = tcp_hdr(skb);
	tcp_hdr_len = th->doff * 4;

	if (tcp_hdr_len < sizeof(struct tcphdr)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_MALFORMED_PACKET]);
		mutex_security_log_violation(VIOLATION_MALFORMED_PACKET,
					      "TCP header too small");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_tcp_packet);

/**
 * mutex_security_validate_udp_packet() - Validate UDP packet
 * @skb: Socket buffer containing UDP packet
 *
 * Return: 0 if valid, negative error code otherwise
 */
int mutex_security_validate_udp_packet(struct sk_buff *skb)
{
	struct udphdr *uh;

	if (!global_security_ctx)
		return -EINVAL;

	if (!skb || !udp_hdr(skb)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_MALFORMED_PACKET]);
		return -EINVAL;
	}

	uh = udp_hdr(skb);

	if (ntohs(uh->len) < sizeof(struct udphdr)) {
		atomic64_inc(&global_security_ctx->stats.violations[VIOLATION_MALFORMED_PACKET]);
		mutex_security_log_violation(VIOLATION_MALFORMED_PACKET,
					      "UDP header length invalid");
		return -EINVAL;
	}

	atomic64_inc(&global_security_ctx->stats.validated_inputs);
	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_validate_udp_packet);

/**
 * mutex_security_is_suspicious_packet() - Check if packet is suspicious
 * @skb: Socket buffer to check
 *
 * Return: true if suspicious, false otherwise
 */
bool mutex_security_is_suspicious_packet(struct sk_buff *skb)
{
	if (!skb)
		return true;

	/* Check for extremely small packets (likely malformed) */
	if (skb->len < 20)
		return true;

	/* Check for packets with invalid IP version */
	if (ip_hdr(skb)->version != 4 && ip_hdr(skb)->version != 6)
		return true;

	/* Add more heuristics as needed */

	return false;
}
EXPORT_SYMBOL_GPL(mutex_security_is_suspicious_packet);

/* ========== Connection Security Context ========== */

/**
 * mutex_security_conn_context_alloc() - Allocate connection security context
 *
 * Return: Pointer to allocated context, or NULL on failure
 */
struct security_conn_context *mutex_security_conn_context_alloc(void)
{
	struct security_conn_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return NULL;

	atomic_set(&ctx->packet_count, 0);
	atomic_set(&ctx->violation_count, 0);
	ctx->first_seen = ktime_get();
	ctx->last_activity = ctx->first_seen;
	ctx->flags = 0;

	mutex_security_rate_limiter_init(&ctx->rate_limiter,
					 SECURITY_RATELIMIT_BURST,
					 SECURITY_RATELIMIT_INTERVAL);

	return ctx;
}
EXPORT_SYMBOL_GPL(mutex_security_conn_context_alloc);

/**
 * mutex_security_conn_context_free() - Free connection security context
 * @ctx: Context to free
 */
void mutex_security_conn_context_free(struct security_conn_context *ctx)
{
	if (!ctx)
		return;

	/* Wipe sensitive data */
	mutex_security_wipe_memory(ctx, sizeof(*ctx));
	kfree(ctx);
}
EXPORT_SYMBOL_GPL(mutex_security_conn_context_free);

/**
 * mutex_security_check_connection() - Check connection security
 * @ctx: Connection security context
 *
 * Return: 0 if allowed, negative error code if blocked
 */
int mutex_security_check_connection(struct security_conn_context *ctx)
{
	if (!ctx || !global_security_ctx)
		return -EINVAL;

	/* Check rate limit for this connection */
	if (!mutex_security_rate_limit_check(&ctx->rate_limiter)) {
		atomic_inc(&ctx->violation_count);
		return -EBUSY;
	}

	/* Check if too many violations */
	if (atomic_read(&ctx->violation_count) > 10) {
		mutex_security_audit_log(AUDIT_CONNECTION_BLOCKED,
					 current_uid().val,
					 task_pid_nr(current),
					 "Too many violations");
		return -EPERM;
	}

	atomic_inc(&ctx->packet_count);
	ctx->last_activity = ktime_get();

	return 0;
}
EXPORT_SYMBOL_GPL(mutex_security_check_connection);

/* ========== Statistics ========== */

/**
 * mutex_security_get_statistics() - Get security statistics
 * @stats: Buffer to store statistics
 */
void mutex_security_get_statistics(struct security_statistics *stats)
{
	int i;

	if (!stats || !global_security_ctx)
		return;

	for (i = 0; i < AUDIT_MAX; i++)
		stats->audit_events[i] = global_security_ctx->stats.audit_events[i];

	for (i = 0; i < VIOLATION_MAX; i++)
		stats->violations[i] = global_security_ctx->stats.violations[i];

	stats->capability_checks = global_security_ctx->stats.capability_checks;
	stats->capability_denials = global_security_ctx->stats.capability_denials;
	stats->rate_limit_hits = global_security_ctx->stats.rate_limit_hits;
	stats->validated_inputs = global_security_ctx->stats.validated_inputs;
	stats->sanitized_data = global_security_ctx->stats.sanitized_data;
	stats->secure_wipes = global_security_ctx->stats.secure_wipes;
}
EXPORT_SYMBOL_GPL(mutex_security_get_statistics);

/**
 * mutex_security_reset_statistics() - Reset security statistics
 */
void mutex_security_reset_statistics(void)
{
	int i;

	if (!global_security_ctx)
		return;

	for (i = 0; i < AUDIT_MAX; i++)
		atomic64_set(&global_security_ctx->stats.audit_events[i], 0);

	for (i = 0; i < VIOLATION_MAX; i++)
		atomic64_set(&global_security_ctx->stats.violations[i], 0);

	atomic64_set(&global_security_ctx->stats.capability_checks, 0);
	atomic64_set(&global_security_ctx->stats.capability_denials, 0);
	atomic64_set(&global_security_ctx->stats.rate_limit_hits, 0);
	atomic64_set(&global_security_ctx->stats.validated_inputs, 0);
	atomic64_set(&global_security_ctx->stats.sanitized_data, 0);
	atomic64_set(&global_security_ctx->stats.secure_wipes, 0);
}
EXPORT_SYMBOL_GPL(mutex_security_reset_statistics);

/* ========== LSM Integration Helpers ========== */

/**
 * mutex_security_check_lsm_permission() - Check LSM permissions
 *
 * Return: 0 if allowed, negative error code otherwise
 */
int mutex_security_check_lsm_permission(void)
{
	/* This would integrate with SELinux/AppArmor */
	/* For now, just check capabilities */
	return mutex_security_check_net_admin() ? 0 : -EPERM;
}
EXPORT_SYMBOL_GPL(mutex_security_check_lsm_permission);

/**
 * mutex_security_get_context_string() - Get security context string
 *
 * Return: String describing current security context
 */
const char *mutex_security_get_context_string(void)
{
	/* This would return SELinux/AppArmor context */
	/* For now, return a placeholder */
	return "unconfined";
}
EXPORT_SYMBOL_GPL(mutex_security_get_context_string);

/* ========== Utility Functions ========== */

/**
 * mutex_security_audit_event_name() - Get audit event name
 * @event: Audit event type
 *
 * Return: Name string for the event
 */
const char *mutex_security_audit_event_name(enum security_audit_event event)
{
	if (event >= AUDIT_MAX)
		return "unknown";
	return audit_event_names[event];
}
EXPORT_SYMBOL_GPL(mutex_security_audit_event_name);

/**
 * mutex_security_violation_name() - Get violation name
 * @violation: Violation type
 *
 * Return: Name string for the violation
 */
const char *mutex_security_violation_name(enum security_violation violation)
{
	if (violation >= VIOLATION_MAX)
		return "unknown";
	return violation_names[violation];
}
EXPORT_SYMBOL_GPL(mutex_security_violation_name);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MUTEX Development Team");
MODULE_DESCRIPTION("MUTEX Security Hardening Implementation");
