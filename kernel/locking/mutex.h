/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * This file contains mutex debugging related internal prototypes, for the
 * !CONFIG_DEBUG_MUTEXES case. Most of them are NOPs:
 */

#define debug_mutex_wake_waiter(lock, waiter)		((void)0)
#define debug_mutex_free_waiter(waiter)			((void)0)
#define debug_mutex_add_waiter(lock, waiter, ti)	((void)0)
#define debug_mutex_remove_waiter(lock, waiter, ti)     ((void)0)
#define debug_mutex_unlock(lock)			((void)0)
#define debug_mutex_init(lock, name, key)		((void)0)

static inline void
debug_mutex_lock_common(struct mutex *lock, struct mutex_waiter *waiter)
{
}
