/*
 * KPROXY - Kernel-level Proxy Module
 * Part of the MUTEX (Multi-User Threaded Exchange Xfer) Project
 *
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 * Date: December 14, 2025
 *
 * Description: This module provides a loadable kernel module (LKM) that
 * creates a kernel-level proxy service. It hooks into the network stack
 * to route packets through a proxy server.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>
#include <asm/unistd.h>

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Syed Areeb Zaheer, Azeem, Hamza Bin Aamir");
MODULE_DESCRIPTION("KPROXY - Kernel-level proxy service module for MUTEX project");
MODULE_VERSION("0.2.0");

/*
 * System call number allocation strategy:
 * We use a custom syscall number in the architecture-specific range.
 * For x86_64, we use a number in the range 335-424 (user-defined range).
 */
#if defined(__x86_64__)
	#define __NR_kproxy_enable 335
#elif defined(__i386__)
	#define __NR_kproxy_enable 358
#elif defined(__aarch64__)
	#define __NR_kproxy_enable 400
#else
	#warning "Architecture not explicitly supported, using default syscall number"
	#define __NR_kproxy_enable 335
#endif

/* Proxy configuration structure passed from userspace */
struct kproxy_config {
	unsigned int enable;		/* 0 = disable, 1 = enable */
	unsigned int proxy_port;	/* Proxy server port */
	char proxy_addr[16];		/* Proxy server IP address (IPv4) */
};

/* System call table pointer */
static unsigned long **sys_call_table_ptr = NULL;

/* Original syscall function pointer (for restoration) */
static void *original_syscall = NULL;

/* Write protection control for CR0 register */
static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order)
	);
}

/* Disable write protection on syscall table */
static inline void disable_write_protection(void)
{
	write_cr0_forced(read_cr0() & (~0x10000));
}

/* Enable write protection on syscall table */
static inline void enable_write_protection(void)
{
	write_cr0_forced(read_cr0() | 0x10000);
}

/*
 * kproxy_enable_syscall - Custom system call implementation
 * @config: Pointer to proxy configuration structure in userspace
 *
 * This system call enables or disables the kernel proxy service.
 * It validates user permissions and configuration parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
asmlinkage long kproxy_enable_syscall(struct kproxy_config __user *config)
{
	struct kproxy_config kconfig;
	int ret;

	/* Check if caller has CAP_NET_ADMIN capability */
	if (!capable(CAP_NET_ADMIN)) {
		pr_warn("KPROXY: syscall denied - CAP_NET_ADMIN required\n");
		return -EPERM;
	}

	/* Validate userspace pointer */
	if (!config) {
		pr_err("KPROXY: syscall called with NULL config\n");
		return -EINVAL;
	}

	/* Copy configuration from userspace */
	ret = copy_from_user(&kconfig, config, sizeof(struct kproxy_config));
	if (ret != 0) {
		pr_err("KPROXY: failed to copy config from userspace\n");
		return -EFAULT;
	}

	/* Validate configuration parameters */
	if (kconfig.enable > 1) {
		pr_err("KPROXY: invalid enable value: %u\n", kconfig.enable);
		return -EINVAL;
	}

	if (kconfig.proxy_port == 0 || kconfig.proxy_port > 65535) {
		pr_err("KPROXY: invalid proxy port: %u\n", kconfig.proxy_port);
		return -EINVAL;
	}

	/* Log the syscall invocation */
	pr_info("KPROXY: syscall invoked by PID %d (UID %d)\n",
		current->pid, current_uid().val);
	pr_info("KPROXY: proxy %s requested\n",
		kconfig.enable ? "enable" : "disable");
	pr_info("KPROXY: proxy address: %s, port: %u\n",
		kconfig.proxy_addr, kconfig.proxy_port);

	/*
	 * TODO: Actual proxy enable/disable logic will be implemented
	 * in later branches (netfilter-hooks, packet-rewriting, etc.)
	 */
	if (kconfig.enable) {
		pr_info("KPROXY: proxy service enabled\n");
	} else {
		pr_info("KPROXY: proxy service disabled\n");
	}

	return 0;
}

/*
 * find_syscall_table - Locate the system call table
 *
 * Uses kallsyms to find the address of the syscall table.
 * This is necessary because the table is not exported by the kernel.
 * For kernels >= 5.7, we use kprobes to find kallsyms_lookup_name first.
 *
 * Return: Pointer to syscall table on success, NULL on failure
 */
static unsigned long **find_syscall_table(void)
{
	unsigned long **table = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	/* For kernels >= 5.7, kallsyms_lookup_name is not exported */
	/* We use kprobes to find it */
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name_func;
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};
	
	/* Register kprobe to get kallsyms_lookup_name address */
	if (register_kprobe(&kp) < 0) {
		pr_err("KPROXY: failed to register kprobe\n");
		return NULL;
	}
	
	kallsyms_lookup_name_func = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	
	if (!kallsyms_lookup_name_func) {
		pr_err("KPROXY: kallsyms_lookup_name not found\n");
		return NULL;
	}
	
	table = (unsigned long **)kallsyms_lookup_name_func("sys_call_table");
#else
	/* For older kernels, kallsyms_lookup_name is exported */
	table = (unsigned long **)kallsyms_lookup_name("sys_call_table");
#endif

	if (!table) {
		pr_err("KPROXY: sys_call_table not found\n");
		return NULL;
	}

	pr_info("KPROXY: sys_call_table found at address: %p\n", table);
	return table;
}

/*
 * register_kproxy_syscall - Register custom system call
 *
 * Hooks our custom syscall into the system call table.
 * This requires temporarily disabling write protection.
 *
 * Return: 0 on success, negative error code on failure
 */
static int register_kproxy_syscall(void)
{
	/* Find the syscall table */
	sys_call_table_ptr = find_syscall_table();
	if (!sys_call_table_ptr) {
		pr_err("KPROXY: failed to locate syscall table\n");
		return -EFAULT;
	}

	/* Save original syscall (if any) at our chosen number */
	original_syscall = (void *)sys_call_table_ptr[__NR_kproxy_enable];
	
	pr_info("KPROXY: registering syscall at number %d\n",
		__NR_kproxy_enable);

	/* Disable write protection temporarily */
	disable_write_protection();

	/* Install our syscall */
	sys_call_table_ptr[__NR_kproxy_enable] =
		(unsigned long *)kproxy_enable_syscall;

	/* Re-enable write protection */
	enable_write_protection();

	pr_info("KPROXY: syscall registered successfully\n");
	return 0;
}

/*
 * unregister_kproxy_syscall - Unregister custom system call
 *
 * Restores the original syscall table entry and cleans up.
 * Must be called during module unload.
 */
static void unregister_kproxy_syscall(void)
{
	if (!sys_call_table_ptr) {
		pr_warn("KPROXY: syscall table pointer is NULL, nothing to unregister\n");
		return;
	}

	pr_info("KPROXY: unregistering syscall at number %d\n",
		__NR_kproxy_enable);

	/* Disable write protection */
	disable_write_protection();

	/* Restore original syscall */
	sys_call_table_ptr[__NR_kproxy_enable] = (unsigned long *)original_syscall;

	/* Re-enable write protection */
	enable_write_protection();

	pr_info("KPROXY: syscall unregistered successfully\n");
}

/*
 * kproxy_module_init - Module initialization function
 *
 * This function is called when the module is loaded into the kernel.
 * It performs initial setup and resource allocation.
 *
 * Return: 0 on success, negative error code on failure
 */
static int __init kproxy_module_init(void)
{
	int ret;

	pr_info("KPROXY: Initializing kernel module\n");
	pr_info("KPROXY: Version %s\n", "0.2.0");
	pr_info("KPROXY: Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir\n");
	
	/* Print architecture information */
#if defined(__x86_64__)
	pr_info("KPROXY: Architecture: x86_64\n");
#elif defined(__i386__)
	pr_info("KPROXY: Architecture: i386\n");
#elif defined(__aarch64__)
	pr_info("KPROXY: Architecture: aarch64 (ARM64)\n");
#else
	pr_info("KPROXY: Architecture: Unknown\n");
#endif

	/* Register custom system call */
	ret = register_kproxy_syscall();
	if (ret != 0) {
		pr_err("KPROXY: failed to register syscall, error: %d\n", ret);
		return ret;
	}

	/* Basic initialization successful */
	pr_info("KPROXY: Module loaded successfully\n");

	return 0;
}

/*
 * kproxy_module_exit - Module cleanup function
 *
 * This function is called when the module is unloaded from the kernel.
 * It performs cleanup and releases resources.
 */
static void __exit kproxy_module_exit(void)
{
	pr_info("KPROXY: Cleaning up module\n");

	/* Unregister system call */
	unregister_kproxy_syscall();

	/* Perform additional cleanup operations */
	pr_info("KPROXY: Module unloaded successfully\n");
}

/* Register init and exit functions */
module_init(kproxy_module_init);
module_exit(kproxy_module_exit);
