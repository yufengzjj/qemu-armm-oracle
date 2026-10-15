/*
 * Host layer of the oracle frontend: the guest address window and the
 * catching of host memory faults raised by guest accesses. Each host OS
 * provides one implementation (host-win32.c; Linux will use signals).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef ORACLE_HOST_H
#define ORACLE_HOST_H

/* Host protection, using QEMU's PAGE_READ / PAGE_WRITE / PAGE_EXEC bits. */

void *oracle_host_reserve(size_t size);
bool oracle_host_commit(void *addr, size_t len, int page_prot);
bool oracle_host_decommit(void *addr, size_t len);
bool oracle_host_protect(void *addr, size_t len, int page_prot);

/* Install the fault handler; called once before any guest code runs. */
bool oracle_host_fault_init(void);

typedef enum OracleFaultAction {
    ORACLE_FAULT_NOT_GUEST, /* not caused by the guest: let the host handle it */
    ORACLE_FAULT_RETRY,     /* fixed up: resume the faulting instruction */
    ORACLE_FAULT_EXIT,      /* resume in oracle_fault_exit() instead */
} OracleFaultAction;

/*
 * Called by the host layer from its fault handler with the faulting host
 * address, whether it was a write, and the host pc of the faulting
 * instruction.
 */
OracleFaultAction oracle_fault_decide(uintptr_t host_addr, bool is_write,
                                      uintptr_t host_pc);

/*
 * Leave the current cpu_exec() for the fault recorded by
 * oracle_fault_decide(). Must run outside the host fault handler.
 */
G_NORETURN void oracle_fault_exit(void);

#endif
