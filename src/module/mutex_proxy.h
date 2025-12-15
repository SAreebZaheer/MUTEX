/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mutex_proxy.h - MUTEX kernel-level proxy module header
 *
 * Copyright (C) 2025 MUTEX Team
 * Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
 */

#ifndef _MUTEX_PROXY_H
#define _MUTEX_PROXY_H

#include <linux/types.h>

/* Flags for mutex_proxy_create() syscall */
#define MUTEX_PROXY_CLOEXEC	(1 << 0)  /* Set close-on-exec */
#define MUTEX_PROXY_NONBLOCK	(1 << 1)  /* Set O_NONBLOCK */
#define MUTEX_PROXY_GLOBAL	(1 << 2)  /* Global proxy (all processes) */

#define MUTEX_PROXY_ALL_FLAGS	(MUTEX_PROXY_CLOEXEC | \
				 MUTEX_PROXY_NONBLOCK | \
				 MUTEX_PROXY_GLOBAL)

/* Function prototypes */
asmlinkage long sys_mutex_proxy_create(unsigned int flags);

#endif /* _MUTEX_PROXY_H */
