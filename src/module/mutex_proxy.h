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
#include <uapi/linux/mutex_proxy.h>

/* Function prototypes */
asmlinkage long sys_mutex_proxy_create(unsigned int flags);

#endif /* _MUTEX_PROXY_H */
