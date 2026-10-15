/*
 * Shared declarations of the oracle frontend.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef ORACLE_INTERNAL_H
#define ORACLE_INTERNAL_H

extern __thread CPUState *thread_cpu;

void oracle_mmap_lock_init(void);

#endif
