/*
 * Windows host layer: guest window with VirtualAlloc, faults with a
 * vectored exception handler (VEH).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "exec/page-protection.h"
#include "host.h"

static DWORD win32_protect(int page_prot)
{
    if (page_prot & PAGE_WRITE) {
        return PAGE_READWRITE;
    }
    if (page_prot & (PAGE_READ | PAGE_EXEC)) {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
}

void *oracle_host_reserve(size_t size)
{
    return VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS);
}

bool oracle_host_commit(void *addr, size_t len, int page_prot)
{
    DWORD old;

    if (!VirtualAlloc(addr, len, MEM_COMMIT, PAGE_READWRITE)) {
        return false;
    }
    /* On a remap the pages are already committed; set the protection anyway. */
    return VirtualProtect(addr, len, win32_protect(page_prot), &old);
}

bool oracle_host_decommit(void *addr, size_t len)
{
    return VirtualFree(addr, len, MEM_DECOMMIT);
}

bool oracle_host_protect(void *addr, size_t len, int page_prot)
{
    DWORD old;

    return VirtualProtect(addr, len, win32_protect(page_prot), &old);
}

/* Called by user-exec.c (tb_lock_page0, page_unprotect) with PROT_* bits. */
int mprotect(void *addr, size_t len, int prot)
{
    int page_prot = (prot & PROT_READ ? PAGE_READ : 0)
                  | (prot & PROT_WRITE ? PAGE_WRITE : 0)
                  | (prot & PROT_EXEC ? PAGE_EXEC : 0);

    if (!oracle_host_protect(addr, len, page_prot)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static LONG CALLBACK oracle_veh(EXCEPTION_POINTERS *info)
{
    EXCEPTION_RECORD *rec = info->ExceptionRecord;
    CONTEXT *ctx = info->ContextRecord;
    bool is_write;

    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION
        || rec->NumberParameters < 2) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* ExceptionInformation[0]: 0 read, 1 write, 8 DEP. */
    is_write = rec->ExceptionInformation[0] == 1;

    switch (oracle_fault_decide(rec->ExceptionInformation[1], is_write,
                                ctx->Rip)) {
    case ORACLE_FAULT_RETRY:
        return EXCEPTION_CONTINUE_EXECUTION;
    case ORACLE_FAULT_EXIT:
        /*
         * longjmp from inside a VEH handler is not safe, so resume in
         * oracle_fault_exit() as if the faulting instruction had called it.
         * The new frame lies below the faulting frame, which is abandoned;
         * nothing is written to the stack here because the exception
         * dispatcher's own frames (with this CONTEXT) live there.
         */
        ctx->Rsp = ((ctx->Rsp - 256) & ~(DWORD64)15) - 8;
        ctx->Rip = (DWORD64)(uintptr_t)oracle_fault_exit;
        return EXCEPTION_CONTINUE_EXECUTION;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

bool oracle_host_fault_init(void)
{
    return AddVectoredExceptionHandler(1, oracle_veh) != NULL;
}

/*
 * The constructor rcu_init() registers the thread that loads the DLL as an
 * RCU reader and never unregisters it; once that thread exits, the RCU
 * registry points at its freed TLS. The MinGW CRT runs constructors before
 * DllMain, so undo the registration here; API calls register per call.
 */
BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        rcu_unregister_thread();
    }
    return TRUE;
}
