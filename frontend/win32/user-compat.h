/*
 * POSIX declarations that QEMU's user-mode core uses unguarded and that
 * MinGW lacks. Force-included (-include) before every frontend-built
 * source on Windows.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef ORACLE_WIN32_USER_COMPAT_H
#define ORACLE_WIN32_USER_COMPAT_H

#include "qemu/osdep.h"

typedef _sigset_t sigset_t;

#define SIG_SETMASK 2

struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
};

/* The oracle never blocks or delivers host signals. */
static inline int sigfillset(sigset_t *set)
{
    *set = (sigset_t)-1;
    return 0;
}

static inline int sigaction(int sig, const struct sigaction *act,
                            struct sigaction *old)
{
    return 0;
}

static inline int sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
    return 0;
}

#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

/* Implemented in host-win32.c on top of VirtualProtect. */
int mprotect(void *addr, size_t len, int prot);

/* Only reached by cpu_memory_rw_debug on non-writable pages (gdbstub). */
static inline ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    errno = ENOSYS;
    return -1;
}

static inline ssize_t pwrite(int fd, const void *buf, size_t count,
                             off_t offset)
{
    errno = ENOSYS;
    return -1;
}

#endif
