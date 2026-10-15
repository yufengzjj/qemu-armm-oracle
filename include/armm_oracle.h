/*
 * qemu-armm-oracle: in-process Armv8.1-M instruction oracle built from QEMU.
 *
 * One oracle per process (QEMU keeps global state). Calls may come from
 * different threads, but never at the same time.
 *
 * The guest runs as QEMU user mode runs it: non-secure, unprivileged
 * Thread mode, FPU and MVE enabled.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef ARMM_ORACLE_H
#define ARMM_ORACLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(ARMM_ORACLE_BUILD)
#    define ARMM_API __declspec(dllexport)
#  else
#    define ARMM_API __declspec(dllimport)
#  endif
#else
#  define ARMM_API __attribute__((visibility("default")))
#endif

#define ARMM_ORACLE_API_VERSION 2

typedef struct armm_oracle armm_oracle;

/* Return codes of the functions that return int. */
enum {
    ARMM_OK = 0,
    ARMM_ERR_ARG = -1,      /* bad argument (register number, range, ...) */
    ARMM_ERR_STATE = -2,    /* oracle not usable (create failed, destroyed) */
    ARMM_ERR_UNMAPPED = -3, /* memory range not (fully) mapped */
    ARMM_ERR_HOST = -4,     /* host call failed (out of memory, ...) */
};

/* Page protection for armm_map; pages are 4 KiB. */
enum {
    ARMM_PROT_READ = 1,
    ARMM_PROT_WRITE = 2,
    ARMM_PROT_EXEC = 4,
};

/* armm_step_result.kind */
enum {
    ARMM_STEP_RETIRED = 0,        /* one instruction completed (YIELD too) */
    ARMM_STEP_UNDEFINED = 1,      /* EXCP_UDEF */
    ARMM_STEP_NO_COPROCESSOR = 2, /* EXCP_NOCP */
    ARMM_STEP_INVALID_STATE = 3,  /* EXCP_INVSTATE */
    ARMM_STEP_DATA_ABORT = 4,     /* fault_addr is the data address */
    ARMM_STEP_PREFETCH_ABORT = 5, /* fault_addr is the fetch address */
    ARMM_STEP_SVC = 6,
    ARMM_STEP_BKPT = 7,
    ARMM_STEP_OTHER = 8,          /* any other QEMU exception, see excp */
};

typedef struct armm_step_result {
    uint32_t kind;       /* ARMM_STEP_* */
    int32_t excp;        /* raw QEMU exception number (EXCP_*) */
    uint32_t pc;         /* pc after the step; for faults, the faulting insn */
    uint32_t fault_addr; /* aborts only */
    uint32_t fsr;        /* aborts only: QEMU's short-format FSR */
    uint32_t reserved;
} armm_step_result;

ARMM_API int armm_api_version(void);

/* Text of the last error on this thread, or "" if none. */
ARMM_API const char *armm_last_error(void);

/*
 * Create the oracle for a CPU model such as "cortex-m55". The first call
 * initializes QEMU; later calls must use the same model. Returns NULL on
 * failure (see armm_last_error). After create the CPU is reset and no
 * memory is mapped.
 */
ARMM_API armm_oracle *armm_create(const char *cpu_model);

/* Unmap all memory and release the handle. */
ARMM_API void armm_destroy(armm_oracle *o);

/* Reset the CPU (registers only; memory is kept). xPSR.T is set. */
ARMM_API int armm_reset(armm_oracle *o);

/* r0-r15; r13 is the current SP, r15 the PC (bit 0 is ignored on write). */
ARMM_API uint32_t armm_get_r(armm_oracle *o, unsigned n);
ARMM_API int armm_set_r(armm_oracle *o, unsigned n, uint32_t v);

/* Full xPSR: NZCVQ, GE, IT/ICI, T. IPSR reads 0 and is ignored on write. */
ARMM_API uint32_t armm_get_xpsr(armm_oracle *o);
ARMM_API int armm_set_xpsr(armm_oracle *o, uint32_t v);

/* q0-q7 as two 64-bit halves (lo = d[2n], hi = d[2n+1]). */
ARMM_API int armm_get_q(armm_oracle *o, unsigned n, uint64_t *lo, uint64_t *hi);
ARMM_API int armm_set_q(armm_oracle *o, unsigned n, uint64_t lo, uint64_t hi);
/* d0-d15 */
ARMM_API uint64_t armm_get_d(armm_oracle *o, unsigned n);
ARMM_API int armm_set_d(armm_oracle *o, unsigned n, uint64_t v);
/* s0-s31 */
ARMM_API uint32_t armm_get_s(armm_oracle *o, unsigned n);
ARMM_API int armm_set_s(armm_oracle *o, unsigned n, uint32_t v);

/* FPSCR including LTPSIZE (bits 18:16). */
ARMM_API uint32_t armm_get_fpscr(armm_oracle *o);
ARMM_API int armm_set_fpscr(armm_oracle *o, uint32_t v);

/* VPR (P0 in bits 15:0, MASK01/MASK23 in bits 23:16). */
ARMM_API uint32_t armm_get_vpr(armm_oracle *o);
ARMM_API int armm_set_vpr(armm_oracle *o, uint32_t v);

/*
 * CONTROL as seen from non-secure state: nPRIV (bit 0), SPSEL (bit 1),
 * FPCA (bit 2). nPRIV always reads 1 and ignores writes, because the
 * guest always runs unprivileged. Writing SPSEL does not swap stack
 * pointers; r13 is always the current SP.
 */
ARMM_API uint32_t armm_get_control(armm_oracle *o);
ARMM_API int armm_set_control(armm_oracle *o, uint32_t v);

/*
 * Local exclusive monitor. armm_get_exclusive returns 1 and stores the
 * marked address if the monitor is open, 0 if it is closed.
 * armm_set_exclusive with size 0 closes it; size 1, 2 or 4 opens it for
 * addr as LDREXB/LDREXH/LDREX would, taking the current memory contents
 * (QEMU's STREX succeeds only if memory still holds that value).
 */
ARMM_API int armm_get_exclusive(armm_oracle *o, uint32_t *addr);
ARMM_API int armm_set_exclusive(armm_oracle *o, uint32_t addr, unsigned size);

/*
 * Map [addr, addr + len) with ARMM_PROT_* flags, rounded out to 4 KiB
 * pages. New pages read as zero; remapping keeps the contents and only
 * changes the protection.
 */
ARMM_API int armm_map(armm_oracle *o, uint32_t addr, uint32_t len, uint32_t prot);
ARMM_API int armm_unmap(armm_oracle *o, uint32_t addr, uint32_t len);

/*
 * Debug access to mapped memory; ignores the page protection. Writing
 * invalidates translated code for the range.
 */
ARMM_API int armm_write_mem(armm_oracle *o, uint32_t addr, const void *buf, size_t len);
ARMM_API int armm_read_mem(armm_oracle *o, uint32_t addr, void *buf, size_t len);

/* Execute the instruction at pc. Returns ARMM_OK and fills *out. */
ARMM_API int armm_step(armm_oracle *o, armm_step_result *out);

/* Drop all translated code. */
ARMM_API int armm_flush_tb(armm_oracle *o);

#ifdef __cplusplus
}
#endif

#endif /* ARMM_ORACLE_H */
