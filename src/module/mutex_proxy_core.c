// SPDX-License-Identifier: GPL-2.0
/*
 * mutex_proxy_core.c - MUTEX kernel-level proxy syscall implementation
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 *
 * This file implements the mutex_proxy_create() syscall that returns
 * a file descriptor for proxy control, following the "everything is a file"
 * paradigm similar to eventfd(), timerfd(), and signalfd().
 */

#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include "mutex_proxy.h"

/**
 * sys_mutex_proxy_create - Create a new proxy control file descriptor
 * @flags: Creation flags (MUTEX_PROXY_CLOEXEC, MUTEX_PROXY_NONBLOCK, etc.)
 *
 * This syscall creates a file descriptor that can be used to control
 * kernel-level proxy behavior. It requires CAP_NET_ADMIN capability.
 *
 * Return: File descriptor on success, negative error code on failure
 */
SYSCALL_DEFINE1(mutex_proxy_create, unsigned int, flags)
{
	/* Check for CAP_NET_ADMIN capability */
	if (!capable(CAP_NET_ADMIN)) {
		pr_warn("mutex_proxy: Process %d (%s) lacks CAP_NET_ADMIN\n",
			current->pid, current->comm);
		return -EPERM;
	}

	/* Validate flags */
	if (flags & ~MUTEX_PROXY_ALL_FLAGS) {
		pr_warn("mutex_proxy: Invalid flags 0x%x from process %d\n",
			flags, current->pid);
		return -EINVAL;
	}

	/* TODO: Implement fd creation */
	pr_info("mutex_proxy: syscall invoked by process %d (%s) with flags 0x%x\n",
		current->pid, current->comm, flags);

	return -ENOSYS;
}
