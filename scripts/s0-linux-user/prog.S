@ S0 test for linux-user qemu-arm -cpu cortex-m55. No libc.
@ Path is chosen by argc:
@   1 arg  : write 32 bytes to stdout: q0 after vadd.i32 (16 bytes),
@            then CONTROL, FPSCR, VPR, P0 as read at start; exit 0.
@            VMRS VPR is a NOP when unprivileged, so its slot is preset
@            to 0x5e5e5e5e to show whether the read happened.
@   2 args : udf #0
@   3 args : load from unmapped address 0xdead0000

    .syntax unified
    .thumb
    .text

    .global _start
    .type _start, %function
    .thumb_func
_start:
    ldr     r0, [sp]
    cmp     r0, #2
    beq     do_udf
    cmp     r0, #3
    beq     do_segv

    sub     sp, sp, #32
    mov     r4, sp

    @ Read the initial state before any guest code touches FP/MVE.
    mrs     r1, control
    str     r1, [r4, #16]
    vmrs    r1, fpscr
    str     r1, [r4, #20]
    ldr     r1, =0x5e5e5e5e
    vmrs    r1, vpr
    str     r1, [r4, #24]
    vmrs    r1, p0
    str     r1, [r4, #28]

    ldr     r1, =vals_a
    vldrw.u32 q1, [r1]
    ldr     r1, =vals_b
    vldrw.u32 q2, [r1]
    vadd.i32 q0, q1, q2
    vstrw.32 q0, [r4]

    movs    r0, #1
    mov     r1, r4
    movs    r2, #32
    movs    r7, #4          @ __NR_write
    svc     #0

    movs    r0, #0
    movs    r7, #1          @ __NR_exit
    svc     #0

do_udf:
    udf     #0
    b       do_udf

do_segv:
    ldr     r0, =0xdead0000
    ldr     r1, [r0]
    movs    r0, #0
    movs    r7, #1
    svc     #0

    .ltorg

    .section .rodata
    .balign 16
vals_a:
    .word   1, 2, 0x7fffffff, 0xffffffff
vals_b:
    .word   10, 20, 1, 1
