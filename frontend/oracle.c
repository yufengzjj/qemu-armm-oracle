/*
 * qemu-armm-oracle frontend: the C API of include/armm_oracle.h on top of
 * QEMU's user-mode TCG execution of an M-profile CPU.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/rcu.h"
#include "qemu/accel.h"
#include "qapi/error.h"
#include "accel/accel-ops.h"
#include "accel/tcg/cpu-loop.h"
#include "hw/core/cpu.h"
#include "hw/core/qdev.h"
#include "exec/cpu-common.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "exec/page-vary.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include "tcg/startup.h"
#include "tcg/tcg.h"
#include "tcg/tcg-internal.h"
#include "user/cpu_loop.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "cpu.h"
#include "internals.h"
#include "host.h"
#include "oracle-internal.h"
#include "armm_oracle.h"

/* 4 GiB guest window plus a guard for accesses that run past its end. */
#define ORACLE_WINDOW_SIZE ((size_t)1 << 32)
#define ORACLE_GUARD_SIZE  ((size_t)64 << 10)
/*
 * Host bookkeeping of dead TBs (about 50 bytes each) is only freed when the
 * code buffer fills and is flushed, so the buffer size bounds that growth.
 */
#define ORACLE_TB_SIZE_MIB 16

struct armm_oracle {
    CPUState *cpu;
};

static armm_oracle the_oracle;
static TCGContext *oracle_tcg_ctxs[1];
static bool oracle_live;
static bool qemu_started;
static char *oracle_cpu_model;

static __thread char last_error[256];
static __thread int call_depth;
static __thread bool in_guest_exec;

typedef struct PendingFault {
    vaddr addr;
    uintptr_t pc;
    MMUAccessType access;
    bool maperr;
    bool exit_noexc;
} PendingFault;

static __thread PendingFault pending_fault;

static void set_error(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

static void set_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(last_error, sizeof(last_error), fmt, ap);
    va_end(ap);
}

/*
 * Every API call that touches RCU-protected state runs between
 * call_begin/call_end: the calling thread is registered with RCU only for
 * the call, because callers may use short-lived threads and RCU keeps a
 * pointer to each registered thread's TLS.
 */
static void call_begin(void)
{
    if (call_depth++ == 0) {
        rcu_register_thread();
        tcg_register_thread();
        thread_cpu = the_oracle.cpu;
        current_cpu = the_oracle.cpu;
    }
}

static void call_end(void)
{
    if (--call_depth == 0) {
        rcu_unregister_thread();
    }
}

static CPUARMState *oracle_env(armm_oracle *o)
{
    if (o != &the_oracle || !oracle_live) {
        set_error("invalid oracle handle");
        return NULL;
    }
    return cpu_env(o->cpu);
}

static int to_page_prot(uint32_t prot)
{
    return (prot & ARMM_PROT_READ ? PAGE_READ : 0)
         | (prot & ARMM_PROT_WRITE ? PAGE_WRITE : 0)
         | (prot & ARMM_PROT_EXEC ? PAGE_EXEC : 0);
}

int armm_api_version(void)
{
    return ARMM_ORACLE_API_VERSION;
}

const char *armm_last_error(void)
{
    return last_error;
}

static void oracle_reset_cpu(CPUState *cs)
{
    CPUARMState *env = cpu_env(cs);

    cpu_reset(cs);
    /* Reset leaves env->ZF = 0, which reads as Z = 1. */
    xpsr_write(env, 0, XPSR_NZCV | XPSR_Q | XPSR_GE);
    env->thumb = true;
    /* User-mode translation is always unprivileged (IS_USER is 1). */
    env->v7m.control[M_REG_NS] |= R_V7M_CONTROL_NPRIV_MASK;
    arm_rebuild_hflags(env);
}

static bool oracle_start_qemu(const char *cpu_model)
{
    Error *err = NULL;
    AccelState *accel;
    AccelClass *ac;
    ObjectClass *oc;
    CPUState *cs;
    void *window;

    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);
    oracle_mmap_lock_init();

    window = oracle_host_reserve(ORACLE_WINDOW_SIZE + ORACLE_GUARD_SIZE);
    if (!window) {
        set_error("cannot reserve the 4 GiB guest address window");
        return false;
    }
    guest_base = (uintptr_t)window;
    have_guest_base = true;
    reserved_va = UINT32_MAX;
    guest_addr_max = UINT32_MAX;

    if (!oracle_host_fault_init()) {
        set_error("cannot install the host fault handler");
        return false;
    }

    accel = current_accel();
    ac = ACCEL_GET_CLASS(accel);
    accel_init_interfaces(ac);
    object_property_set_int(OBJECT(accel), "tb-size", ORACLE_TB_SIZE_MIB,
                            &error_abort);
    if (ac->init_machine(accel, NULL) < 0) {
        set_error("TCG initialization failed");
        return false;
    }
    /*
     * User-mode tcg_context_init sets tcg_ctxs = &tcg_ctx, the TLS slot of
     * this thread; later calls may come from other threads after this one
     * has exited.
     */
    oracle_tcg_ctxs[0] = tcg_ctx;
    tcg_ctxs = oracle_tcg_ctxs;

    /* Common (not per-target) code reads the page size from target_page. */
    set_preferred_target_page_bits(ctz32(qemu_real_host_page_size()));
    finalize_target_page_bits();

    oc = cpu_class_by_name(CPU_RESOLVING_TYPE, cpu_model);
    if (!oc) {
        set_error("unknown CPU model '%s'", cpu_model);
        return false;
    }
    cs = CPU(object_new(object_class_get_name(oc)));
    if (!arm_feature(cpu_env(cs), ARM_FEATURE_M)) {
        set_error("CPU model '%s' is not M-profile", cpu_model);
        object_unref(OBJECT(cs));
        return false;
    }
    if (!qdev_realize(DEVICE(cs), NULL, &err)) {
        set_error("cannot realize CPU '%s': %s", cpu_model,
                  error_get_pretty(err));
        error_free(err);
        object_unref(OBJECT(cs));
        return false;
    }

    /* The prologue bakes in guest_base, so this comes after it is fixed. */
    tcg_prologue_init();

    the_oracle.cpu = cs;
    thread_cpu = cs;
    current_cpu = cs;
    cpu_single_step(cs, SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER);
    oracle_cpu_model = g_strdup(cpu_model);
    qemu_started = true;
    return true;
}

armm_oracle *armm_create(const char *cpu_model)
{
    last_error[0] = '\0';
    if (!cpu_model) {
        set_error("cpu_model is NULL");
        return NULL;
    }
    if (oracle_live) {
        set_error("an oracle already exists in this process");
        return NULL;
    }
    if (!qemu_started) {
        bool ok;

        call_begin();
        ok = oracle_start_qemu(cpu_model);
        call_end();
        if (!ok) {
            return NULL;
        }
    } else if (strcmp(cpu_model, oracle_cpu_model) != 0) {
        set_error("this process already uses CPU model '%s'", oracle_cpu_model);
        return NULL;
    }

    call_begin();
    oracle_reset_cpu(the_oracle.cpu);
    tb_flush__exclusive_or_serial();
    call_end();
    oracle_live = true;
    return &the_oracle;
}

void armm_destroy(armm_oracle *o)
{
    if (!oracle_env(o)) {
        return;
    }
    call_begin();
    mmap_lock();
    page_set_flags(0, UINT32_MAX, 0, PAGE_VALID);
    mmap_unlock();
    oracle_host_decommit((void *)guest_base, ORACLE_WINDOW_SIZE);
    tb_flush__exclusive_or_serial();
    call_end();
    oracle_live = false;
}

int armm_reset(armm_oracle *o)
{
    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    call_begin();
    oracle_reset_cpu(o->cpu);
    call_end();
    return ARMM_OK;
}

uint32_t armm_get_r(armm_oracle *o, unsigned n)
{
    CPUARMState *env = oracle_env(o);

    return env && n < 16 ? env->regs[n] : 0;
}

int armm_set_r(armm_oracle *o, unsigned n, uint32_t v)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (n >= 16) {
        return ARMM_ERR_ARG;
    }
    env->regs[n] = n == 15 ? v & ~1u : v;
    return ARMM_OK;
}

uint32_t armm_get_xpsr(armm_oracle *o)
{
    CPUARMState *env = oracle_env(o);

    return env ? xpsr_read(env) : 0;
}

int armm_set_xpsr(armm_oracle *o, uint32_t v)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    xpsr_write(env, v, XPSR_NZCV | XPSR_Q | XPSR_GE);
    /* xpsr_write ignores T and IT/ICI under CONFIG_USER_ONLY. */
    env->thumb = (v & XPSR_T) != 0;
    env->condexec_bits = ((v >> 25) & 3) | ((v >> 8) & 0xfc);
    arm_rebuild_hflags(env);
    return ARMM_OK;
}

int armm_get_q(armm_oracle *o, unsigned n, uint64_t *lo, uint64_t *hi)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (n >= 8 || !lo || !hi) {
        return ARMM_ERR_ARG;
    }
    *lo = aa32_vfp_qreg(env, n)[0];
    *hi = aa32_vfp_qreg(env, n)[1];
    return ARMM_OK;
}

int armm_set_q(armm_oracle *o, unsigned n, uint64_t lo, uint64_t hi)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (n >= 8) {
        return ARMM_ERR_ARG;
    }
    aa32_vfp_qreg(env, n)[0] = lo;
    aa32_vfp_qreg(env, n)[1] = hi;
    return ARMM_OK;
}

uint64_t armm_get_d(armm_oracle *o, unsigned n)
{
    CPUARMState *env = oracle_env(o);

    return env && n < 16 ? *aa32_vfp_dreg(env, n) : 0;
}

int armm_set_d(armm_oracle *o, unsigned n, uint64_t v)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (n >= 16) {
        return ARMM_ERR_ARG;
    }
    *aa32_vfp_dreg(env, n) = v;
    return ARMM_OK;
}

uint32_t armm_get_s(armm_oracle *o, unsigned n)
{
    CPUARMState *env = oracle_env(o);

    if (!env || n >= 32) {
        return 0;
    }
    return *aa32_vfp_dreg(env, n >> 1) >> (32 * (n & 1));
}

int armm_set_s(armm_oracle *o, unsigned n, uint32_t v)
{
    CPUARMState *env = oracle_env(o);
    uint64_t *d;
    unsigned shift = 32 * (n & 1);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (n >= 32) {
        return ARMM_ERR_ARG;
    }
    d = aa32_vfp_dreg(env, n >> 1);
    *d = (*d & ~(0xffffffffull << shift)) | ((uint64_t)v << shift);
    return ARMM_OK;
}

uint32_t armm_get_fpscr(armm_oracle *o)
{
    CPUARMState *env = oracle_env(o);

    return env ? vfp_get_fpscr(env) : 0;
}

int armm_set_fpscr(armm_oracle *o, uint32_t v)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    vfp_set_fpscr(env, v);
    arm_rebuild_hflags(env);
    return ARMM_OK;
}

uint32_t armm_get_vpr(armm_oracle *o)
{
    CPUARMState *env = oracle_env(o);

    return env ? env->v7m.vpr : 0;
}

int armm_set_vpr(armm_oracle *o, uint32_t v)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    env->v7m.vpr = v & (R_V7M_VPR_P0_MASK | R_V7M_VPR_MASK01_MASK |
                        R_V7M_VPR_MASK23_MASK);
    arm_rebuild_hflags(env);
    return ARMM_OK;
}

uint32_t armm_get_control(armm_oracle *o)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return 0;
    }
    /* QEMU keeps FPCA in the secure copy of CONTROL. */
    return (env->v7m.control[M_REG_NS] &
            (R_V7M_CONTROL_NPRIV_MASK | R_V7M_CONTROL_SPSEL_MASK)) |
           (env->v7m.control[M_REG_S] & R_V7M_CONTROL_FPCA_MASK);
}

int armm_set_control(armm_oracle *o, uint32_t v)
{
    CPUARMState *env = oracle_env(o);
    uint32_t ns_mask = R_V7M_CONTROL_NPRIV_MASK | R_V7M_CONTROL_SPSEL_MASK;

    if (!env) {
        return ARMM_ERR_STATE;
    }
    env->v7m.control[M_REG_NS] = (env->v7m.control[M_REG_NS] & ~ns_mask) |
                                 (v & ns_mask) | R_V7M_CONTROL_NPRIV_MASK;
    env->v7m.control[M_REG_S] =
        (env->v7m.control[M_REG_S] & ~R_V7M_CONTROL_FPCA_MASK) |
        (v & R_V7M_CONTROL_FPCA_MASK);
    arm_rebuild_hflags(env);
    return ARMM_OK;
}

static bool page_range(uint32_t addr, uint64_t len, vaddr *start, vaddr *last)
{
    uint64_t end = (uint64_t)addr + len;

    if (len == 0 || end > ORACLE_WINDOW_SIZE) {
        set_error("bad guest range 0x%08x + 0x%" PRIx64, addr, len);
        return false;
    }
    *start = addr & TARGET_PAGE_MASK;
    *last = (end - 1) | ~TARGET_PAGE_MASK;
    *last &= UINT32_MAX;
    return true;
}

int armm_map(armm_oracle *o, uint32_t addr, uint32_t len, uint32_t prot)
{
    vaddr start, last;
    int page_prot = to_page_prot(prot);

    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    if ((prot & ~(ARMM_PROT_READ | ARMM_PROT_WRITE | ARMM_PROT_EXEC)) ||
        !page_range(addr, len, &start, &last)) {
        return ARMM_ERR_ARG;
    }
    if (!oracle_host_commit(g2h_untagged_vaddr(start), last - start + 1,
                            page_prot)) {
        set_error("cannot commit host memory for 0x%08" PRIx64, start);
        return ARMM_ERR_HOST;
    }
    call_begin();
    mmap_lock();
    page_set_flags(start, last, PAGE_VALID | page_prot, PAGE_VALID);
    mmap_unlock();
    call_end();
    return ARMM_OK;
}

int armm_unmap(armm_oracle *o, uint32_t addr, uint32_t len)
{
    vaddr start, last;

    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    if (!page_range(addr, len, &start, &last)) {
        return ARMM_ERR_ARG;
    }
    call_begin();
    mmap_lock();
    page_set_flags(start, last, 0, PAGE_VALID);
    mmap_unlock();
    call_end();
    if (!oracle_host_decommit(g2h_untagged_vaddr(start), last - start + 1)) {
        set_error("cannot decommit host memory for 0x%08" PRIx64, start);
        return ARMM_ERR_HOST;
    }
    return ARMM_OK;
}

/*
 * Host protection follows the guest protection and tb_lock_page0's lock on
 * translated code, so it is lifted around each debug copy that it blocks.
 */
static int debug_access(uint32_t addr, void *buf, size_t len, bool is_write)
{
    uint64_t pos = addr;
    uint64_t end = (uint64_t)addr + len;
    uint8_t *p = buf;

    if (len == 0) {
        return ARMM_OK;
    }
    if (end > ORACLE_WINDOW_SIZE || !page_check_range(addr, len, PAGE_VALID)) {
        set_error("guest range 0x%08x + 0x%zx is not mapped", addr, len);
        return ARMM_ERR_UNMAPPED;
    }
    while (pos < end) {
        vaddr page = pos & TARGET_PAGE_MASK;
        size_t n = MIN(end, page + TARGET_PAGE_SIZE) - pos;
        void *host = g2h_untagged_vaddr(pos);
        void *host_page = g2h_untagged_vaddr(page);
        int flags = page_get_flags(page);
        bool lifted = false;

        if (is_write) {
            if (!(flags & PAGE_WRITE) && (flags & PAGE_WRITE_ORG)) {
                page_unprotect(NULL, page, 0);
                flags = page_get_flags(page);
            }
            if (!(flags & PAGE_WRITE)) {
                oracle_host_protect(host_page, TARGET_PAGE_SIZE,
                                    PAGE_READ | PAGE_WRITE);
                lifted = true;
            }
            memcpy(host, p, n);
        } else {
            if (!(flags & PAGE_RWX)) {
                oracle_host_protect(host_page, TARGET_PAGE_SIZE, PAGE_READ);
                lifted = true;
            }
            memcpy(p, host, n);
        }
        if (lifted) {
            oracle_host_protect(host_page, TARGET_PAGE_SIZE, flags & PAGE_RWX);
        }
        pos += n;
        p += n;
    }
    if (is_write) {
        mmap_lock();
        tb_invalidate_phys_range(NULL, addr, end - 1);
        mmap_unlock();
    }
    return ARMM_OK;
}

int armm_write_mem(armm_oracle *o, uint32_t addr, const void *buf, size_t len)
{
    int ret;

    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    if (!buf && len) {
        return ARMM_ERR_ARG;
    }
    call_begin();
    ret = debug_access(addr, (void *)buf, len, true);
    call_end();
    return ret;
}

int armm_read_mem(armm_oracle *o, uint32_t addr, void *buf, size_t len)
{
    int ret;

    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    if (!buf && len) {
        return ARMM_ERR_ARG;
    }
    call_begin();
    ret = debug_access(addr, buf, len, false);
    call_end();
    return ret;
}

int armm_get_exclusive(armm_oracle *o, uint32_t *addr)
{
    CPUARMState *env = oracle_env(o);

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (env->exclusive_addr == -1) {
        return 0;
    }
    if (addr) {
        *addr = env->exclusive_addr;
    }
    return 1;
}

int armm_set_exclusive(armm_oracle *o, uint32_t addr, unsigned size)
{
    CPUARMState *env = oracle_env(o);
    uint8_t bytes[4] = { 0 };
    int ret;

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (size == 0) {
        arm_clear_exclusive(env);
        return ARMM_OK;
    }
    if (size != 1 && size != 2 && size != 4) {
        return ARMM_ERR_ARG;
    }
    call_begin();
    ret = debug_access(addr, bytes, size, false);
    call_end();
    if (ret != ARMM_OK) {
        return ret;
    }
    /* gen_store_exclusive compares memory with the zero-extended loaded value. */
    env->exclusive_addr = addr;
    env->exclusive_val = ldl_le_p(bytes);
    return ARMM_OK;
}

int armm_flush_tb(armm_oracle *o)
{
    if (!oracle_env(o)) {
        return ARMM_ERR_STATE;
    }
    call_begin();
    tb_flush__exclusive_or_serial();
    call_end();
    return ARMM_OK;
}

static uint32_t step_kind(int excp)
{
    switch (excp) {
    case EXCP_DEBUG:
    case EXCP_YIELD: /* YIELD completed; QEMU only gives up the time slice */
        return ARMM_STEP_RETIRED;
    case EXCP_UDEF:
        return ARMM_STEP_UNDEFINED;
    case EXCP_NOCP:
        return ARMM_STEP_NO_COPROCESSOR;
    case EXCP_INVSTATE:
        return ARMM_STEP_INVALID_STATE;
    case EXCP_DATA_ABORT:
        return ARMM_STEP_DATA_ABORT;
    case EXCP_PREFETCH_ABORT:
        return ARMM_STEP_PREFETCH_ABORT;
    case EXCP_SWI:
        return ARMM_STEP_SVC;
    case EXCP_BKPT:
        return ARMM_STEP_BKPT;
    default:
        return ARMM_STEP_OTHER;
    }
}

int armm_step(armm_oracle *o, armm_step_result *out)
{
    CPUARMState *env = oracle_env(o);
    CPUState *cs;
    int excp;

    if (!env) {
        return ARMM_ERR_STATE;
    }
    if (!out) {
        return ARMM_ERR_ARG;
    }
    cs = o->cpu;
    call_begin();
    cs->exception_index = -1;
    in_guest_exec = true;
    cpu_exec_start(cs);
    excp = cpu_exec(cs);
    cpu_exec_end(cs);
    in_guest_exec = false;
    qemu_process_cpu_events(cs);
    call_end();

    memset(out, 0, sizeof(*out));
    out->kind = step_kind(excp);
    out->excp = excp;
    out->pc = env->regs[15];
    if (excp == EXCP_DATA_ABORT || excp == EXCP_PREFETCH_ABORT) {
        out->fault_addr = env->exception.vaddress;
        out->fsr = env->exception.fsr;
    }
    return ARMM_OK;
}

OracleFaultAction oracle_fault_decide(uintptr_t host_addr, bool is_write,
                                      uintptr_t host_pc)
{
    CPUState *cpu = thread_cpu;
    uintptr_t offset = host_addr - guest_base;
    uintptr_t pc = host_pc;
    MMUAccessType access;
    vaddr guest_addr;

    if (!in_guest_exec || !cpu ||
        offset >= ORACLE_WINDOW_SIZE + ORACLE_GUARD_SIZE) {
        return ORACLE_FAULT_NOT_GUEST;
    }
    access = adjust_signal_pc(&pc, is_write);
    if (access != MMU_INST_FETCH &&
        !in_code_gen_buffer((void *)(pc - tcg_splitwx_diff))) {
        return ORACLE_FAULT_NOT_GUEST;
    }
    guest_addr = (uint32_t)offset;

    /* A write to a page locked by tb_lock_page0, as handle_sigsegv_accerr_write. */
    if (is_write && offset < ORACLE_WINDOW_SIZE) {
        switch (page_unprotect(cpu, guest_addr, pc)) {
        case 1:
            return ORACLE_FAULT_RETRY;
        case 2:
            pending_fault.exit_noexc = true;
            return ORACLE_FAULT_EXIT;
        default:
            break;
        }
    }

    pending_fault.addr = guest_addr;
    pending_fault.pc = pc;
    pending_fault.access = access;
    pending_fault.maperr = !(page_get_flags(guest_addr) & PAGE_VALID);
    pending_fault.exit_noexc = false;
    return ORACLE_FAULT_EXIT;
}

void oracle_fault_exit(void)
{
    CPUState *cpu = thread_cpu;

    if (pending_fault.exit_noexc) {
        cpu_loop_exit_noexc(cpu);
    }
    cpu_loop_exit_sigsegv(cpu, pending_fault.addr, pending_fault.access,
                          pending_fault.maperr, pending_fault.pc);
}
