//! S4: CLRM, VSCCLRM, MRS/MSR and VMRS/VMSR, LDREX/STREX, the Security and
//! PACBTI instructions, hints, and how each kind of fault maps to FaultKind.
//! The oracle runs as Non-secure unprivileged Thread mode; expected values
//! follow DDI0553B.z for that state.

mod common;
use common::*;
use qemu_armm_oracle::*;

fn setup(f: &mut Fixture) -> &mut Oracle {
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    o
}

fn fault_kind(o: &mut Oracle) -> FaultKind {
    match o.step() {
        StepOutcome::Fault { kind, .. } => kind,
        StepOutcome::Retired => panic!("expected a fault"),
    }
}

const GE: u32 = 0b1010 << 16;

#[test]
fn clrm() {
    let mut f = fixture();
    let o = setup(&mut f);
    o.set_r(0, 1);
    o.set_r(1, 2);
    o.set_r(12, 3);
    o.set_xpsr(XPSR_T | FLAG_N | FLAG_Q | GE);
    run1(o, &[0xe89f, 0x8003]); // clrm {r0, r1, apsr}
    assert_eq!((o.get_r(0), o.get_r(1), o.get_r(12)), (0, 0, 3));
    assert_eq!(o.get_xpsr(), XPSR_T, "APSR (NZCVQ, GE) cleared");
}

#[test]
fn mrs_msr_psr() {
    let mut f = fixture();
    let o = setup(&mut f);
    let apsr = FLAG_N | FLAG_C | FLAG_Q | GE;
    for (code, what, value) in [
        ([0xf3efu16, 0x8000], "apsr", apsr),
        ([0xf3ef, 0x8005], "ipsr", 0),
        ([0xf3ef, 0x8006], "epsr", 0), // EPSR reads as zero
        ([0xf3ef, 0x8003], "xpsr", apsr),
    ] {
        o.set_xpsr(XPSR_T | apsr | it_bits(0xe8)); // inside "it al"
        o.set_r(0, 0xdead);
        run1(o, &code);
        assert_eq!(o.get_r(0), value, "mrs r0, {what}");
    }

    for (code, what, xpsr) in [
        ([0xf380u16, 0x8800], "apsr_nzcvq", XPSR_T | FLAG_Z | FLAG_V | FLAG_Q),
        ([0xf380, 0x8400], "apsr_g", XPSR_T | (0b0101 << 16)),
        ([0xf380, 0x8c00], "apsr_nzcvqg", XPSR_T | FLAG_Z | FLAG_V | FLAG_Q | (0b0101 << 16)),
    ] {
        o.set_xpsr(XPSR_T);
        o.set_r(0, FLAG_Z | FLAG_V | FLAG_Q | (0b0101 << 16) | 0x0700_fc00);
        run1(o, &code);
        assert_eq!(o.get_xpsr(), xpsr, "msr {what}, r0");
    }
}

#[test]
fn special_registers_unprivileged() {
    let mut f = fixture();
    let o = setup(&mut f);
    assert_eq!(o.get_control(), 5, "nPRIV = 1, FPCA = 1");
    o.set_r(0, 0xdead);
    run1(o, &[0xf3ef, 0x8014]); // mrs r0, control
    assert_eq!(o.get_r(0), 5);

    // Unprivileged MRS of these reads zero; MSR to them is ignored.
    o.set_r(13, DATA + 0x800);
    for (code, what) in [
        ([0xf3efu16, 0x8008], "msp"),
        ([0xf3ef, 0x8009], "psp"),
        ([0xf3ef, 0x8010], "primask"),
        ([0xf3ef, 0x8011], "basepri"),
        ([0xf3ef, 0x800a], "msplim"),
    ] {
        o.set_r(0, 0xdead);
        run1(o, &code);
        assert_eq!(o.get_r(0), 0, "mrs r0, {what}");
    }
    o.set_r(0, 0);
    for code in [[0xf380u16, 0x8814], [0xf380, 0x8810], [0xf380, 0x8809]] {
        run1(o, &code); // msr control / primask / psp, r0
    }
    assert_eq!(o.get_control(), 5);
    assert_eq!(o.get_r(13), DATA + 0x800);
    o.set_control(0);
    assert_eq!(o.get_control(), 1, "nPRIV cannot be cleared through the API");
    o.set_control(4);

    run1(o, &[0xb672]); // cpsid i: no effect when unprivileged
    assert_eq!(o.get_r(15), CODE + 2);
}

#[test]
fn fp_and_mve_system_registers() {
    let mut f = fixture();
    let o = setup(&mut f);
    o.set_vpr(0x0088_00ff);
    o.set_r(0, 0xdead);
    run1(o, &[0xeefd, 0x0a10]); // vmrs r0, p0
    assert_eq!(o.get_r(0), 0xff);
    o.set_r(0, 0x1234_0f0f);
    run1(o, &[0xeeed, 0x0a10]); // vmsr p0, r0
    assert_eq!(o.get_vpr(), 0x0088_0f0f, "only P0 is written");

    // VPR itself is privileged: QEMU takes the IMPDEF choice of a NOP.
    o.set_r(0, 0xdead);
    run1(o, &[0xeefc, 0x0a10]); // vmrs r0, vpr
    assert_eq!(o.get_r(0), 0xdead);
    o.set_r(0, 0);
    run1(o, &[0xeeec, 0x0a10]); // vmsr vpr, r0
    assert_eq!(o.get_vpr(), 0x0088_0f0f);
    o.set_r(1, DATA);
    write32s(o, DATA, &[0x9999_9999]);
    run1(o, &[0xedc1, 0x8f80]); // vstr vpr, [r1]
    assert_eq!(read32(o, DATA), 0x9999_9999);

    o.set_fpscr((4 << 16) | 0x1f);
    o.set_r(0, 0xdead);
    run1(o, &[0xeef2, 0x0a10]); // vmrs r0, fpscr_nzcvqc
    assert_eq!(o.get_r(0), 0);
    o.set_r(0, 0xffff_ffff);
    run1(o, &[0xeee2, 0x0a10]); // vmsr fpscr_nzcvqc, r0
    assert_eq!(o.get_fpscr(), 0xf804_001f, "only NZCV and QC change");

    run1(o, &[0xed81, 0x2f80]); // vstr fpscr, [r1]
    assert_eq!(read32(o, DATA), 0xf804_001f);
    write32s(o, DATA, &[0x9999_9999]);
    run1(o, &[0xed91, 0x2f80]); // vldr fpscr, [r1]
    assert_eq!(o.get_fpscr(), 0x9989_0099, "RES0 bits dropped, LTPSIZE = 1 loaded");
}

#[test]
fn fpca_zero_means_no_fp_context() {
    let mut f = fixture();
    let o = setup(&mut f);
    // CONTROL.FPCA = 0 with FPCCR.ASPEN = 1: the first FP instruction creates
    // a new context, FPSCR = FPDSCR_NS (reset value: RN, LTPSIZE = 4).
    o.set_control(0);
    o.set_fpscr((4 << 16) | (3 << 22));
    o.set_s(1, 0x3f80_0000);
    o.set_s(2, 0x33c0_0000);
    run1(o, &[0xee30, 0x0a81]); // vadd.f32 s0, s1, s2
    assert_eq!(o.get_s(0), 0x3f80_0001, "rounded to nearest, not toward zero");
    assert_eq!(o.get_fpscr(), (4 << 16) | (1 << 4));
    assert_eq!(o.get_control(), 5, "FPCA set again");

    // Without an FP context LTPSIZE() reads 4, so LE does not fault.
    o.set_control(1);
    o.set_fpscr(2 << 16);
    o.set_r(14, 3);
    o.write_mem(CODE, &thumb(&[0x3101, 0xf00f, 0xc803])).unwrap(); // adds r1, #1; le lr, -4
    o.set_r(15, CODE + 2);
    retire(o);
    assert_eq!((o.get_r(15), o.get_r(14)), (CODE, 2));
}

#[test]
fn exclusive_monitor() {
    let mut f = fixture();
    let o = setup(&mut f);
    let a = DATA + 0x10;
    let ldrex = [0xe851, 0x0f00]; // ldrex r0, [r1]
    let strex = [0xe841, 0x3200]; // strex r2, r3, [r1]
    let strex_once = |o: &mut Oracle| {
        o.set_r(2, 0xdead);
        run1(o, &strex);
        o.get_r(2)
    };
    write32s(o, a, &[0x1111_1111]);
    o.set_r(1, a);
    o.set_r(3, 0x2222_2222);

    run1(o, &ldrex);
    assert_eq!(o.get_r(0), 0x1111_1111);
    assert_eq!(o.get_exclusive(), Some(a));
    assert_eq!(strex_once(o), 0, "monitor open: store done");
    assert_eq!(read32(o, a), 0x2222_2222);
    assert_eq!(o.get_exclusive(), None, "STREX closes the monitor");
    o.set_r(3, 0x3333_3333);
    assert_eq!(strex_once(o), 1, "monitor closed: no store");
    assert_eq!(read32(o, a), 0x2222_2222);

    run1(o, &ldrex);
    run1(o, &[0xf3bf, 0x8f2f]); // clrex
    assert_eq!(o.get_exclusive(), None);
    assert_eq!(strex_once(o), 1);

    // The monitor is part of the case state: open it through the API.
    o.set_exclusive(Some((a, 4))).unwrap();
    assert_eq!(o.get_exclusive(), Some(a));
    assert_eq!(strex_once(o), 0);
    assert_eq!(read32(o, a), 0x3333_3333);
    o.set_exclusive(Some((a, 4))).unwrap();
    o.set_exclusive(None).unwrap();
    assert_eq!(strex_once(o), 1);

    // Byte and halfword forms
    o.set_exclusive(Some((a, 1))).unwrap();
    o.set_r(3, 0xab);
    run1(o, &[0xe8c1, 0x3f42]); // strexb r2, r3, [r1]
    assert_eq!(o.get_r(2), 0);
    assert_eq!(read32(o, a), 0x3333_33ab);
    run1(o, &[0xe8d1, 0x0f5f]); // ldrexh r0, [r1]
    assert_eq!(o.get_r(0), 0x33ab);
    o.set_r(3, 0xcdef);
    run1(o, &[0xe8c1, 0x3f52]); // strexh r2, r3, [r1]
    assert_eq!(o.get_r(2), 0);
    assert_eq!(read32(o, a), 0x3333_cdef);

    // Acquire/release forms
    run1(o, &[0xe8d1, 0x0fef]); // ldaex r0, [r1]
    assert_eq!(o.get_r(0), 0x3333_cdef);
    o.set_r(3, 7);
    run1(o, &[0xe8c1, 0x3fe2]); // stlex r2, r3, [r1]
    assert_eq!((o.get_r(2), read32(o, a)), (0, 7));
}

#[test]
fn exclusive_monitor_plain_store_and_alignment() {
    let mut f = fixture();
    let o = setup(&mut f);
    let a = DATA + 0x10;
    let strex = [0xe841, 0x3200]; // strex r2, r3, [r1]
    o.set_r(1, a);
    o.set_r(3, 0x2222_2222);

    // A plain store by the same core leaves the local monitor as it is
    // (IMPLEMENTATION DEFINED, B9.2; Cortex-M55 does the same), whatever
    // value it writes; more cases in s4_exclusive.rs.
    for stored in [0x5555_5555u32, 0x1111_1111] {
        write32s(o, a, &[0x1111_1111]);
        run1(o, &[0xe851, 0x0f00]); // ldrex r0, [r1]
        o.set_r(4, stored);
        run1(o, &[0x600c]); // str r4, [r1]
        run1(o, &strex);
        assert_eq!(o.get_r(2), 0, "plain store of {stored:#x} in between");
        assert_eq!(read32(o, a), 0x2222_2222, "plain store of {stored:#x} in between");
    }

    // An unaligned STREX is an UNALIGNED UsageFault whatever the monitor
    // state (ExclusiveMonitorsPass); more cases in s4_exclusive.rs.
    o.set_r(1, DATA + 0x12);
    o.set_r(2, 0xdead);
    o.write_mem(CODE, &thumb(&strex)).unwrap();
    o.set_r(15, CODE);
    assert_eq!(fault_kind(o), FaultKind::Unaligned { addr: DATA + 0x12 }, "monitor closed: fault");
    assert_eq!((o.get_r(2), o.get_r(15)), (0xdead, CODE));
    o.set_exclusive(Some((DATA + 0x12, 4))).unwrap();
    assert_eq!(fault_kind(o), FaultKind::Unaligned { addr: DATA + 0x12 }, "marked address matches: fault");
}

#[test]
fn security_extension_in_non_secure_state() {
    let mut f = fixture();
    let o = setup(&mut f);
    // TT/TTT from Non-secure unprivileged code return 0 (TTResp: no MPU
    // information unless privileged or alt, no SAU information unless Secure).
    for code in [[0xe841u16, 0xf000], [0xe841, 0xf040]] {
        o.set_r(0, 0xdead);
        o.set_r(1, CODE);
        run1(o, &code);
        assert_eq!(o.get_r(0), 0, "{code:x?}");
    }
    // SG in Non-secure state is a NOP.
    o.set_r(0, 0xdead);
    run1(o, &[0xe97f, 0xe97f]);
    assert_eq!((o.get_r(0), o.get_r(15)), (0xdead, CODE + 4));
    // UNDEFINED in Non-secure state
    for i in 0..16 {
        o.set_d(i, 0x0101_0101_0101_0101 * (i as u64 + 1));
    }
    o.set_vpr(0x00f0_1234);
    for (code, what) in [
        (&[0xe841u16, 0xf080][..], "tta r0, r1"),
        (&[0xe841, 0xf0c0], "ttat r0, r1"),
        (&[0x4774], "bxns lr"),
        (&[0x4794], "blxns r2"),
        (&[0xec9f, 0x0a04], "vscclrm {s0-s3, vpr}"),
        (&[0xec9f, 0x0a00], "vscclrm {vpr}"),
        (&[0xec9f, 0x0b08], "vscclrm {d0-d3, vpr}"),
        (&[0xec9f, 0xeb08], "vscclrm {d14-d17, vpr}"),
        (&[0xecdf, 0x0b02], "vscclrm {d16, vpr}"),
        (&[0xecdf, 0x1b02], "vscclrm {d17, vpr}"),
        (&[0xecdf, 0x6b08], "vscclrm {d22-d25, vpr}"),
        (&[0xecdf, 0x4b00], "vscclrm, D list from d20 with no registers"),
        (&[0xec20, 0x0a00], "vlstm r0"),
        (&[0xec30, 0x0a00], "vlldm r0"),
    ] {
        o.write_mem(CODE, &thumb(code)).unwrap();
        o.set_r(15, CODE);
        assert_eq!(fault_kind(o), FaultKind::Undefined, "{what}");
        assert_eq!(o.get_r(15), CODE);
        for i in 0..16 {
            assert_eq!(o.get_d(i), 0x0101_0101_0101_0101 * (i as u64 + 1), "{what}: d{i}");
        }
        assert_eq!(o.get_vpr(), 0x00f0_1234, "{what}: vpr");
    }
}

#[test]
fn pacbti() {
    let mut f = fixture();
    let o = setup(&mut f);
    // QEMU has no PACBTI (cpu-v7m.c sets ID_ISAR5 = 0, even for cortex-m85),
    // so the hint-space forms are NOPs.
    for (code, what) in [
        ([0xf3afu16, 0x801d], "pac r12, lr, sp"),
        ([0xf3af, 0x802d], "aut r12, lr, sp"),
        ([0xf3af, 0x800f], "bti"),
        ([0xf3af, 0x800d], "pacbti r12, lr, sp"),
    ] {
        o.set_r(12, 0x1234);
        o.set_r(14, CODE + 0x201);
        run1(o, &code);
        assert_eq!((o.get_r(12), o.get_r(14), o.get_r(15)), (0x1234, CODE + 0x201, CODE + 4), "{what}");
    }

    // PACG/AUTG/BXAUT are UNPREDICTABLE without PACBTI on a PE with DSP;
    // QEMU decodes them as SMMUL/SMMLA/SMMLAR with Ra or Rd = 15.
    o.set_r(0, 0x1000_0000);
    o.set_r(1, 0x2_0010);
    o.set_r(2, 0x8101);
    run1(o, &[0xfb61, 0xf002]); // pacg r0, r1, r2 = smmul r0, r1, r2
    assert_eq!(o.get_r(0), 1);
    for code in [[0xfb51u16, 0x0f02], [0xfb51, 0x0f12]] {
        // autg / bxaut r0, r1, r2 = smmla(r) pc, r1, r2, r0
        o.set_r(0, 0x1000_0000);
        run1(o, &code);
        assert_eq!(o.get_r(15), 0x1000_0000, "{code:x?} writes the pc");
    }
}

#[test]
fn hints() {
    let mut f = fixture();
    let o = setup(&mut f);
    for (code, what) in [(0xbf30u16, "wfi"), (0xbf20, "wfe"), (0xbf10, "yield"), (0xbf40, "sev")] {
        run1(o, &[code]);
        assert_eq!(o.get_r(15), CODE + 2, "{what}");
    }
    // yield as the first instruction of an IT block advances ITSTATE.
    o.write_mem(CODE, &thumb(&[0xbf10, 0xbf00])).unwrap();
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T | it_bits(0x04));
    retire(o);
    assert_eq!(o.get_xpsr(), XPSR_T | it_bits(it_advance(0x04)));
}

#[test]
fn fault_kinds() {
    let mut f = fixture();
    let o = setup(&mut f);
    let unmapped = 0x0010_0000;
    o.map(DATA + PAGE, PAGE, PROT_READ).unwrap();
    let run = |o: &mut Oracle, code: &[u16]| {
        o.write_mem(CODE, &thumb(code)).unwrap();
        o.set_r(15, CODE);
        o.set_xpsr(XPSR_T);
        fault_kind(o)
    };

    assert_eq!(run(o, &[0xde00]), FaultKind::Undefined); // udf #0
    assert_eq!(run(o, &[0xee00, 0x0010]), FaultKind::NoCoprocessor); // mcr p0, ...
    assert_eq!(run(o, &[0xee10, 0x0710]), FaultKind::NoCoprocessor); // mrc p7, ...
    o.set_xpsr(0);
    o.write_mem(CODE, &thumb(&[0xbf00])).unwrap();
    o.set_r(15, CODE);
    assert_eq!(fault_kind(o), FaultKind::InvalidState);

    o.set_r(1, unmapped + 4);
    assert_eq!(run(o, &[0x6808]), FaultKind::DataAbort { addr: unmapped + 4 }); // ldr r0, [r1]
    o.set_r(1, DATA + PAGE + 8);
    assert_eq!(run(o, &[0x6008]), FaultKind::DataAbort { addr: DATA + PAGE + 8 }); // str to read-only
    o.set_r(1, DATA + 2);
    assert_eq!(run(o, &[0xe9d1, 0x2300]), FaultKind::Unaligned { addr: DATA + 2 }); // ldrd r2, r3, [r1]
    o.set_r(1, DATA + 1);
    assert_eq!(run(o, &[0xe851, 0x0f00]), FaultKind::Unaligned { addr: DATA + 1 }); // ldrex r0, [r1]

    o.set_r(15, unmapped);
    assert_eq!(fault_kind(o), FaultKind::PrefetchAbort { addr: unmapped });
    o.set_r(15, DATA);
    assert_eq!(fault_kind(o), FaultKind::PrefetchAbort { addr: DATA }, "data page is not executable");

    assert_eq!(run(o, &[0xdf05]), FaultKind::Svc);
    assert_eq!(o.get_r(15), CODE + 2, "SVC: pc is the return address");
    assert_eq!(run(o, &[0xbe03]), FaultKind::Bkpt);
    assert_eq!(o.get_r(15), CODE, "BKPT: pc stays");

    // pc >= 0xffff0000 hits the Linux kernel-helper trap of QEMU user mode
    // (translate.c arm_check_kernelpage), even with the page mapped.
    o.map(0xffff_0000, PAGE, PROT_READ | PROT_EXEC).unwrap();
    o.write_mem(0xffff_0000, &thumb(&[0xbf00])).unwrap();
    o.set_r(15, 0xffff_0000);
    let r = o.step_raw();
    assert_eq!((r.kind, r.excp), (STEP_OTHER, 9), "EXCP_KERNEL_TRAP");
    assert_eq!(outcome(&r), StepOutcome::Fault { kind: FaultKind::Unimplemented, msg: format!("QEMU exception 9 at pc {:#010x}, fsr 0x0", 0xffff_0000u32) });
}
