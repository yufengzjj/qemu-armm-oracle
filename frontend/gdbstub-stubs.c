/*
 * The oracle runs no gdbstub server. gdbstub/gdbstub.c and gdbstub/user.c
 * are still linked (CPU realize registers gdb features through them);
 * these replace what linux-user and gdbstub/user-target.c provide.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "user/signal.h"
#include "gdbstub/internals.h"

int host_interrupt_signal;

int target_to_host_signal(int sig)
{
    return sig;
}

int qemu_kill_thread(int tid, int sig)
{
    return -ENOSYS;
}

int gdb_get_cpu_index(CPUState *cpu)
{
    return cpu->cpu_index + 1;
}

int gdb_target_sigtrap(void)
{
    return 5;
}

int gdb_signal_to_target(int sig)
{
    return sig;
}

int gdb_target_signal_to_gdb(int sig)
{
    return sig;
}

void gdb_handle_query_offsets(GArray *params, void *user_ctx)
{
}

void gdb_handle_v_file_open(GArray *params, void *user_ctx)
{
}

void gdb_handle_v_file_close(GArray *params, void *user_ctx)
{
}

void gdb_handle_v_file_pread(GArray *params, void *user_ctx)
{
}

void gdb_handle_v_file_readlink(GArray *params, void *user_ctx)
{
}

void gdb_handle_query_xfer_exec_file(GArray *params, void *user_ctx)
{
}
