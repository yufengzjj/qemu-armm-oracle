/*
 * Pieces that QEMU's user-mode core (accel/tcg/user-exec.c and friends)
 * expects from linux-user / common-user, re-done for the oracle: no
 * syscalls, no ELF loader, no guest signals.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "hw/core/cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/cpu-common.h"
#include "exec/mmap-lock.h"
#include "user/cpu_loop.h"
#include "user/guest-base.h"
#include "oracle-internal.h"

uintptr_t guest_base;
bool have_guest_base;
unsigned long reserved_va;
unsigned long guest_addr_max;

__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

static QemuMutex mmap_mutex;
static __thread int mmap_lock_count;

void oracle_mmap_lock_init(void)
{
    qemu_mutex_init(&mmap_mutex);
}

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        qemu_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    assert(mmap_lock_count > 0);
    if (--mmap_lock_count == 0) {
        qemu_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

/*
 * As linux-user/signal.c, minus queueing a guest signal: for Arm,
 * record_sigsegv/record_sigbus raise the abort and do not return.
 */
void cpu_loop_exit_sigsegv(CPUState *cpu, vaddr addr,
                           MMUAccessType access_type, bool maperr, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigsegv) {
        tcg_ops->record_sigsegv(cpu, addr, access_type, maperr, ra);
    }
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

void cpu_loop_exit_sigbus(CPUState *cpu, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigbus) {
        tcg_ops->record_sigbus(cpu, addr, access_type, ra);
    }
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}
