//! S4: low-overhead loops (DLS/WLS/LE, DLSTP/WLSTP/LETP, LCTP) and tail
//! predication through LR and FPSCR.LTPSIZE. Expected values follow the
//! DDI0553B.z pseudocode (LE/LETP, WLS/DLS, GetCurInstrBeat,
//! IsLastLowOverheadLoop).

mod common;
use common::*;
use qemu_armm_oracle::*;

const LTP4: u32 = 4 << 16;

fn ltpsize(o: &Oracle) -> u32 {
    (o.get_fpscr() >> 16) & 7
}

#[test]
fn dls_and_wls() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));

    o.set_r(0, 7);
    o.set_fpscr(2 << 16);
    run1(o, &[0xf040, 0xe001]); // dls lr, r0
    assert_eq!(o.get_r(14), 7);
    assert_eq!(o.get_r(15), CODE + 4);
    assert_eq!(ltpsize(o), 2, "DLS leaves LTPSIZE alone");

    // wls lr, r0, +8; nop; nop; after: nop
    let wls = [0xf040, 0xc003, 0xbf00, 0xbf00, 0xbf00];
    o.set_fpscr(LTP4);
    for (count, pc, lr) in [(0u32, CODE + 8, 0xdead), (3, CODE + 4, 3)] {
        o.set_r(0, count);
        o.set_r(14, 0xdead);
        run1(o, &wls);
        assert_eq!((o.get_r(15), o.get_r(14)), (pc, lr), "wls with count {count}");
    }
}

#[test]
fn le_branches_back_and_decrements() {
    let mut f = fixture();
    let o = &mut f.o;
    // loop: adds r1, #1; le lr, loop; nop
    let code = [0x3101, 0xf00f, 0xc803, 0xbf00];
    load(o, &thumb(&code));
    for (lr, pc, lr_after) in [(3u32, CODE, 2u32), (2, CODE, 1), (1, CODE + 6, 1), (0, CODE + 6, 0)] {
        o.set_r(14, lr);
        o.set_r(15, CODE + 2);
        retire(o);
        assert_eq!((o.get_r(15), o.get_r(14)), (pc, lr_after), "le with LR = {lr}");
    }

    // le loop (no counter): always branches, LR untouched
    o.write_mem(CODE, &thumb(&[0x3101, 0xf02f, 0xc803])).unwrap();
    o.set_r(14, 0);
    o.set_r(15, CODE + 2);
    retire(o);
    assert_eq!((o.get_r(15), o.get_r(14)), (CODE, 0));
}

#[test]
fn whole_dls_loop() {
    let mut f = fixture();
    let o = &mut f.o;
    // dls lr, r0; loop: adds r1, #1; le lr, loop
    load(o, &thumb(&[0xf040, 0xe001, 0x3101, 0xf00f, 0xc803]));
    o.set_r(0, 5);
    o.set_r(1, 0);
    let mut steps = 0;
    while o.get_r(15) != CODE + 10 {
        retire(o);
        steps += 1;
        assert!(steps < 100);
    }
    assert_eq!(o.get_r(1), 5, "five iterations");
    assert_eq!(o.get_r(14), 1, "the last LE does not decrement");
    assert_eq!(steps, 1 + 2 * 5);
}

#[test]
fn le_faults() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0x3101, 0xf00f, 0xc803, 0xf02f, 0xc803]));

    // LE (counted or forever) with LTPSIZE != 4 is an INVSTATE UsageFault.
    for pc in [CODE + 2, CODE + 6] {
        o.set_fpscr(2 << 16);
        o.set_r(14, 3);
        o.set_r(15, pc);
        let r = o.step_raw();
        assert_eq!((r.kind, r.pc), (STEP_INVALID_STATE, pc));
        assert_eq!(o.get_r(14), 3);
    }

    // LE inside an IT block is CONSTRAINED UNPREDICTABLE; QEMU chose UNDEFINED.
    o.set_fpscr(LTP4);
    o.set_xpsr(XPSR_T | FLAG_Z | it_bits(0x08));
    o.set_r(15, CODE + 2);
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_UNDEFINED, CODE + 2));
}

#[test]
fn tail_predicated_loop() {
    let mut f = fixture();
    let o = &mut f.o;
    // dlstp.32 lr, r0
    // loop: vldrw.u32 q0, [r1], #16; vadd.i32 q0, q0, q2; vstrw.32 q0, [r2], #16
    //       letp lr, loop
    // nop
    let code = [0xf020, 0xe001, 0xecb1, 0x1f04, 0xef20, 0x0844, 0xeca2, 0x1f04, 0xf01f, 0xc009, 0xbf00];
    load(o, &thumb(&code));
    write32s(o, DATA, &[1, 2, 3, 4, 5, 6, 7, 8]);
    write32s(o, DATA + 0x40, &[0xeeee_eeee; 8]);
    o.set_r(0, 6);
    o.set_r(1, DATA);
    o.set_r(2, DATA + 0x40);
    o.set_q(2, q32([100; 4]));

    retire(o);
    assert_eq!(o.get_r(14), 6);
    assert_eq!(o.get_fpscr(), 2 << 16, "DLSTP.32 sets LTPSIZE = 2");

    let mut lr_seen = vec![];
    let mut steps = 1;
    while o.get_r(15) != CODE + 20 {
        if o.get_r(15) == CODE + 16 {
            lr_seen.push(o.get_r(14));
        }
        retire(o);
        steps += 1;
        assert!(steps < 100);
    }
    assert_eq!(lr_seen, [6, 2], "LETP subtracts 4 elements per iteration");
    assert_eq!(steps, 1 + 2 * 4);
    assert_eq!(o.get_r(14), 2, "the last LETP does not decrement");
    assert_eq!(o.get_fpscr(), LTP4, "the last LETP resets LTPSIZE");
    assert_eq!((o.get_r(1), o.get_r(2)), (DATA + 32, DATA + 0x60), "write-back is not predicated");
    let out: Vec<u32> = (0..8).map(|i| read32(o, DATA + 0x40 + 4 * i)).collect();
    assert_eq!(out, [101, 102, 103, 104, 105, 106, 0xeeee_eeee, 0xeeee_eeee]);
    assert_eq!(w32(o.get_q(0)), [105, 106, 0, 0], "masked load lanes zeroed, masked add lanes kept");
}

#[test]
fn letp_wlstp_lctp() {
    let mut f = fixture();
    let o = &mut f.o;
    // letp at CODE + 16 targeting CODE + 4, from the loop above
    let code = [0xf020, 0xe001, 0xecb1, 0x1f04, 0xef20, 0x0844, 0xeca2, 0x1f04, 0xf01f, 0xc009, 0xbf00];
    load(o, &thumb(&code));
    o.set_fpscr(0);
    o.set_r(14, 20);
    o.set_r(15, CODE + 16);
    retire(o);
    assert_eq!((o.get_r(15), o.get_r(14), ltpsize(o)), (CODE + 4, 4, 0), "8-bit elements: LR -= 16");
    o.set_r(15, CODE + 16);
    retire(o);
    assert_eq!((o.get_r(15), o.get_r(14), ltpsize(o)), (CODE + 20, 4, 4));

    // wlstp.8 lr, r0, +6; nop; after: nop
    let wlstp = [0xf000, 0xc801, 0xbf00, 0xbf00];
    for (count, pc, lr, ltp) in [(0u32, CODE + 6, 0xdead, 4), (20, CODE + 4, 20, 0)] {
        o.set_fpscr(LTP4);
        o.set_r(0, count);
        o.set_r(14, 0xdead);
        run1(o, &wlstp);
        assert_eq!((o.get_r(15), o.get_r(14), ltpsize(o)), (pc, lr, ltp), "wlstp with count {count}");
    }

    o.set_fpscr(2 << 16);
    run1(o, &[0xf00f, 0xe001]); // lctp
    assert_eq!(o.get_fpscr(), LTP4);
}

#[test]
fn tail_predication_outside_a_loop() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    let vadd = [0xef22, 0x0844]; // vadd.i32 q0, q1, q2
    o.set_q(1, q32([1, 2, 3, 4]));
    o.set_q(2, q32([10, 20, 30, 40]));
    // Only LR and LTPSIZE decide; no loop instruction has run.
    for (lr, lanes) in [(3u32, [11, 22, 33, 0]), (5, [11, 22, 33, 44]), (0, [0, 0, 0, 0]), (4, [11, 22, 33, 44])] {
        o.set_fpscr(2 << 16);
        o.set_r(14, lr);
        o.set_q(0, 0);
        run1(o, &vadd);
        assert_eq!(w32(o.get_q(0)), lanes, "LR = {lr}");
    }

    // ANDed with VPR.P0 under a VPT mask
    o.set_r(14, 3);
    o.set_vpr(0x0088_00ff);
    o.set_q(0, 0);
    run1(o, &vadd);
    assert_eq!(w32(o.get_q(0)), [11, 22, 0, 0]);

    // VPT itself: P0 = compare AND tail mask
    o.set_vpr(0);
    o.set_q(0, q32([5; 4]));
    o.set_q(1, q32([5; 4]));
    run1(o, &[0xfe61, 0x0f02]); // vpt.i32 eq, q0, q1
    assert_eq!(o.get_vpr(), 0x0088_0fff);

    // 16-bit elements: LR = 5 enables halfword lanes 0..4
    o.set_fpscr(1 << 16);
    o.set_r(14, 5);
    o.set_vpr(0);
    o.set_q(0, 0);
    o.set_q(1, q16([1; 8]));
    o.set_q(2, q16([2; 8]));
    run1(o, &[0xef12, 0x0844]); // vadd.i16 q0, q1, q2
    assert_eq!(w16(o.get_q(0)), [3, 3, 3, 3, 3, 0, 0, 0]);
}
