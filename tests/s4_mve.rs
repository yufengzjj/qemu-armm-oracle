//! S4: MVE integer and floating point, VPT predication (VPR.P0 and the
//! MASK fields), beat-wise loads and stores, EPSR.ECI, and the MVE scalar
//! shifts. Expected values follow DDI0553B.z.

mod common;
use common::*;
use qemu_armm_oracle::*;

const QC: u32 = 1 << 27;
const IOC: u32 = 1 << 0;
const OFC: u32 = 1 << 2;
const IXC: u32 = 1 << 4;
const IDC: u32 = 1 << 7;
const FZ16: u32 = 1 << 19;
const RZ: u32 = 3 << 22;
const BASE: u32 = 4 << 16;
const MASK_1000: u32 = 0x0088_0000; // MASK01 = MASK23 = 0b1000

fn setup(f: &mut Fixture) -> &mut Oracle {
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    o
}

/// Run a Qd = op(Q1, Q2) instruction and return Q0.
fn qop(o: &mut Oracle, code: &[u16], q0: u128, q1: u128, q2: u128) -> u128 {
    o.set_q(0, q0);
    o.set_q(1, q1);
    o.set_q(2, q2);
    run1(o, code);
    o.get_q(0)
}

#[test]
fn integer_arithmetic() {
    let mut f = fixture();
    let o = setup(&mut f);

    let a: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
    let r = qop(o, &[0xef02, 0x0844], 0, q8(a), q8([0xf0; 16])); // vadd.i8 q0, q1, q2
    assert_eq!(w8(r), std::array::from_fn(|i| a[i].wrapping_add(0xf0)));

    o.set_fpscr(BASE);
    let mut x = [0u8; 16];
    let mut y = [0u8; 16];
    (x[0], y[0]) = (0x7f, 1);
    (x[1], y[1]) = (0x80, 0xff);
    (x[2], y[2]) = (5, 3);
    let r = qop(o, &[0xef02, 0x0054], 0, q8(x), q8(y)); // vqadd.s8 q0, q1, q2
    assert_eq!(&w8(r)[..3], &[0x7f, 0x80, 8]);
    assert_eq!(o.get_fpscr(), BASE | QC, "MVE saturation sets FPSCR.QC");

    o.set_fpscr(BASE);
    let r = qop(o, &[0xff12, 0x0054], 0, q16([0xffff, 1, 0, 0, 0, 0, 0, 0]), q16([1, 2, 0, 0, 0, 0, 0, 0])); // vqadd.u16
    assert_eq!(&w16(r)[..2], &[0xffff, 3]);
    assert_eq!(o.get_fpscr(), BASE | QC);

    o.set_fpscr(BASE);
    let r = qop(o, &[0xef12, 0x0b44], 0, q16([0x8000, 0x4000, 0, 0, 0, 0, 0, 0]), q16([0x8000, 0x4000, 0, 0, 0, 0, 0, 0])); // vqdmulh.s16
    assert_eq!(&w16(r)[..2], &[0x7fff, 0x2000]);
    assert_eq!(o.get_fpscr(), BASE | QC);

    let r = qop(o, &[0xee23, 0x0e05], 0, q32([0x4000_0000, 0xffff_ffff, 3, 0]), q32([4, 1, 5, 0])); // vmulh.s32
    assert_eq!(w32(r), [1, 0xffff_ffff, 0, 0]);

    let r = qop(o, &[0xef02, 0x0744], 0, q8([0x80, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), q8([0x7f, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])); // vabd.s8
    assert_eq!(&w8(r)[..2], &[0xff, 2]);

    let r = qop(o, &[0xff02, 0x0144], 0, q8([255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), q8([254, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])); // vrhadd.u8
    assert_eq!(&w8(r)[..2], &[255, 2]);

    // vshl.s32 q0, q1, q2: signed shift by the bottom byte of each Q2 element
    let r = qop(o, &[0xef24, 0x0442], 0, q32([0xffff_fff0, 1, 1, 0xffff_ffff]), q32([0xffff_fffe, 31, 32, 0xffff_ffd8]));
    assert_eq!(w32(r), [0xffff_fffc, 0x8000_0000, 0, 0xffff_ffff]);

    let r = qop(o, &[0xff9d, 0x0052], 0, q16([0xffff; 8]), 0); // vshr.u16 q0, q1, #3
    assert_eq!(w16(r), [0x1fff; 8]);

    let r = qop(o, &[0xefbc, 0x0252], 0, q32([24, -24i32 as u32, 0x7fff_fff8, 7]), 0); // vrshr.s32 q0, q1, #4
    assert_eq!(w32(r), [2, 0xffff_ffff, 0x0800_0000, 0]);
}

#[test]
fn integer_moves_and_narrowing() {
    let mut f = fixture();
    let o = setup(&mut f);
    let src: [u8; 16] = [0x80, 0x11, 0x7f, 0x22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    let r = qop(o, &[0xeea8, 0x0f42], 0, q8(src), 0); // vmovlb.s8 q0, q1
    assert_eq!(w16(r), [0xff80, 0x007f, 1, 3, 5, 7, 9, 11]);

    // vmovnb.i16 q0, q1: bottom bytes of Q0 from Q1 halfwords, top bytes kept
    let r = qop(o, &[0xfe31, 0x0e83], q8([0xaa; 16]), q16([0x1234, 0x5678, 0x9abc, 0xdef0, 1, 2, 3, 4]), 0);
    assert_eq!(w8(r), [0x34, 0xaa, 0x78, 0xaa, 0xbc, 0xaa, 0xf0, 0xaa, 1, 0xaa, 2, 0xaa, 3, 0xaa, 4, 0xaa]);

    let r = qop(o, &[0xffb0, 0x0042], 0, q8(src), 0); // vrev64.8 q0, q1
    let mut rev = src;
    rev[..8].reverse();
    rev[8..].reverse();
    assert_eq!(w8(r), rev);

    o.set_r(0, 0xcafe_f00d);
    run1(o, &[0xeea0, 0x0b10]); // vdup.32 q0, r0
    assert_eq!(w32(o.get_q(0)), [0xcafe_f00d; 4]);

    o.set_q(1, q32([10, 11, 12, 13]));
    run1(o, &[0xee13, 0x0b10]); // vmov.32 r0, q1[2]
    assert_eq!(o.get_r(0), 12);

    o.set_q(0, 0);
    o.set_r(1, 0x55);
    run1(o, &[0xee20, 0x1b10]); // vmov.32 q0[1], r1
    assert_eq!(w32(o.get_q(0)), [0, 0x55, 0, 0]);
}

#[test]
fn across_lane_reductions() {
    let mut f = fixture();
    let o = setup(&mut f);
    let reduce = |o: &mut Oracle, code: &[u16], r0: u32, r1: u32, q1: u128, q2: u128| {
        o.set_r(0, r0);
        o.set_r(1, r1);
        o.set_q(1, q1);
        o.set_q(2, q2);
        run1(o, code);
        (o.get_r(0), o.get_r(1))
    };
    let vmlav = [0xeef3, 0x0e04]; // vmlav.s32 r0, q1, q2
    assert_eq!(reduce(o, &vmlav, 99, 0, q32([1, 2, 3, 4]), q32([5, 6, 7, 8])).0, 70);
    assert_eq!(reduce(o, &vmlav, 99, 0, q32([0x4000_0000; 4]), q32([4; 4])).0, 0, "wraps to 32 bits");
    assert_eq!(reduce(o, &[0xeef3, 0x0e24], 100, 0, q32([1, 2, 3, 4]), q32([5, 6, 7, 8])).0, 170); // vmlava.s32
    assert_eq!(reduce(o, &[0xfef1, 0x0f02], 7, 0, q8([0xff; 16]), 0).0, 0xff0); // vaddv.u8 r0, q1
    // vmaxv.s8 r0, q1 starts from SInt(R0[7:0]) and writes the 32-bit result
    let neg = q8([0xfb, 0xfd, 0x9c, 0x80, 0xfb, 0xfd, 0x9c, 0x80, 0xfb, 0xfd, 0x9c, 0x80, 0xfb, 0xfd, 0x9c, 0x80]);
    assert_eq!(reduce(o, &[0xeee2, 0x0f02], 0x1234_5680, 0, neg, 0).0, 0xffff_fffd);
    assert_eq!(reduce(o, &[0xeee2, 0x0f02], 0x0000_0005, 0, neg, 0).0, 5);
    // vmlalv.s32 r0, r1, q1, q2: 64-bit accumulate in r1:r0
    assert_eq!(reduce(o, &[0xee83, 0x0e04], 1, 1, q32([0x7fff_ffff; 4]), q32([0x7fff_ffff; 4])), (4, 0xffff_fffc));
    assert_eq!(reduce(o, &[0xfe82, 0x0f05], 5, 0, q8([10; 16]), q8([3; 16])).0, 117); // vabav.u8 r0, q1, q2
}

#[test]
fn compares_vctp_and_vpsel() {
    let mut f = fixture();
    let o = setup(&mut f);
    o.set_q(0, q32([1, 2, 3, 4]));
    o.set_q(1, q32([1, 0, 3, 0]));
    o.set_vpr(0xffff);
    run1(o, &[0xfe21, 0x0f02]); // vcmp.i32 eq, q0, q1
    assert_eq!(o.get_vpr(), 0x0f0f);

    o.set_r(0, 2);
    run1(o, &[0xfe21, 0x1f60]); // vcmp.s32 gt, q0, r0
    assert_eq!(o.get_vpr(), 0xff00);

    o.set_vpr(0x0ff0);
    let r = qop(o, &[0xfe33, 0x0f05], 0, q32([1, 1, 1, 1]), q32([2, 2, 2, 2])); // vpsel q0, q1, q2
    assert_eq!(w32(r), [2, 1, 1, 2]);

    for (code, n, p0) in [
        ([0xf020u16, 0xe801], 3u32, 0x0fffu32), // vctp.32 r0
        ([0xf020, 0xe801], 0, 0),
        ([0xf020, 0xe801], 100, 0xffff),
        ([0xf000, 0xe801], 5, 0x001f), // vctp.8 r0
    ] {
        o.set_vpr(0);
        o.set_r(0, n);
        run1(o, &code);
        assert_eq!(o.get_vpr(), p0, "{code:x?} r0 = {n}");
    }
}

#[test]
fn vpt_block() {
    let mut f = fixture();
    let o = &mut f.o;
    let (a, b) = (q32([10, 20, 30, 40]), q32([1, 2, 3, 4]));

    // vpt.i32 eq, q0, q1; vaddt.i32 q3, q1, q2
    load(o, &thumb(&[0xfe61, 0x0f02, 0xef22, 0x6844]));
    o.set_q(0, q32([1, 2, 3, 4]));
    o.set_q(2, b);
    o.set_q(3, 0);
    o.set_q(1, q32([1, 0, 3, 0]));
    retire(o);
    assert_eq!(o.get_vpr(), MASK_1000 | 0x0f0f, "P0 from the compare, both MASK fields = 1000");
    o.set_q(1, a);
    retire(o);
    assert_eq!(w32(o.get_q(3)), [11, 0, 33, 0]);
    assert_eq!(o.get_vpr(), 0x0f0f, "mask advanced to 0000, P0 kept");

    // vpte.i32 eq, q0, q1; vaddt.i32 q3, q1, q2; vsube.i32 q3, q1, q2
    load(o, &thumb(&[0xfe61, 0x8f02, 0xef22, 0x6844, 0xff22, 0x6844]));
    o.set_q(0, q32([1, 2, 3, 4]));
    o.set_q(1, q32([1, 0, 3, 0]));
    o.set_q(2, b);
    o.set_q(3, 0);
    retire(o);
    assert_eq!(o.get_vpr(), 0x00cc_0f0f);
    o.set_q(1, a);
    retire(o);
    assert_eq!(o.get_vpr(), MASK_1000 | 0xf0f0, "shifting out a 1 inverts P0");
    retire(o);
    assert_eq!(o.get_vpr(), 0xf0f0);
    assert_eq!(w32(o.get_q(3)), [11, 18, 33, 36]);
}

#[test]
fn vpr_mask_set_through_api() {
    let mut f = fixture();
    let o = setup(&mut f);
    let vmlav = [0xeef3, 0x0e04]; // vmlav.s32 r0, q1, q2 (predicated when VPR.MASK != 0)
    o.set_q(1, q32([1, 2, 3, 4]));
    o.set_q(2, q32([5, 6, 7, 8]));

    // vpst; vmlavt.s32 r0, q1, q2
    o.write_mem(CODE, &thumb(&[0xfe71, 0x0f4d, 0xeef3, 0x0e04])).unwrap();
    o.set_r(15, CODE);
    o.set_vpr(0x0f0f);
    retire(o);
    assert_eq!(o.get_vpr(), MASK_1000 | 0x0f0f);
    retire(o);
    assert_eq!(o.get_r(0), 1 * 5 + 3 * 7);
    assert_eq!(o.get_vpr(), 0x0f0f);

    // Same state without the VPST: the MASK fields alone predicate the instruction.
    o.set_vpr(MASK_1000 | 0x0f0f);
    run1(o, &vmlav);
    assert_eq!(o.get_r(0), 26);
    assert_eq!(o.get_vpr(), 0x0f0f);
}

#[test]
fn predicated_loads_and_stores() {
    let mut f = fixture();
    let o = setup(&mut f);
    write32s(o, DATA, &[0x11, 0x22, 0x33, 0x44]);
    write32s(o, DATA + 0x40, &[0xa, 0xb, 0xc, 0xd]);
    // vpstt; vldrwt.u32 q0, [r1]; vstrwt.32 q0, [r2]
    o.write_mem(CODE, &thumb(&[0xfe31, 0x8f4d, 0xed91, 0x1f00, 0xed82, 0x1f00])).unwrap();
    o.set_r(15, CODE);
    o.set_r(1, DATA);
    o.set_r(2, DATA + 0x40);
    o.set_q(0, u128::MAX);
    o.set_vpr(0x0f0f);
    retire(o);
    retire(o);
    assert_eq!(w32(o.get_q(0)), [0x11, 0, 0x33, 0], "inactive load lanes are zeroed");
    retire(o);
    assert_eq!(
        [read32(o, DATA + 0x40), read32(o, DATA + 0x44), read32(o, DATA + 0x48), read32(o, DATA + 0x4c)],
        [0x11, 0xb, 0x33, 0xd],
        "inactive store lanes are not written"
    );
}

#[test]
fn beatwise_loads_and_stores() {
    let mut f = fixture();
    let o = setup(&mut f);
    let bytes: Vec<u8> = (0x80u8..0xc0).collect();
    o.write_mem(DATA, &bytes).unwrap();
    o.set_r(1, DATA);

    run1(o, &[0xfd91, 0x0e80]); // vldrb.u16 q0, [r1]
    assert_eq!(w16(o.get_q(0)), std::array::from_fn(|i| bytes[i] as u16));

    run1(o, &[0xed99, 0x0f00]); // vldrh.s32 q0, [r1]
    assert_eq!(w32(o.get_q(0)), [0xffff_8180, 0xffff_8382, 0xffff_8584, 0xffff_8786]);

    o.set_q(0, q16([0x1101, 0x2202, 0x3303, 0x4404, 0x5505, 0x6606, 0x7707, 0x8808]));
    o.set_r(1, DATA + 0x80);
    run1(o, &[0xed81, 0x0e80]); // vstrb.16 q0, [r1]
    assert_eq!(o.read_mem(DATA + 0x80, 9).unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8, 0]);

    o.set_r(1, DATA);
    run1(o, &[0xecb1, 0x1f04]); // vldrw.u32 q0, [r1], #16
    assert_eq!(o.get_r(1), DATA + 16);
    assert_eq!(w32(o.get_q(0))[0], 0x8382_8180);
    run1(o, &[0xedb1, 0x1f04]); // vldrw.u32 q0, [r1, #16]!
    assert_eq!(o.get_r(1), DATA + 32);
    assert_eq!(w32(o.get_q(0))[0], 0xa3a2_a1a0);

    // gather: vldrw.u32 q0, [q1]; scatter: vstrw.32 q0, [q1, #8]
    write32s(o, DATA + 0x100, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let addrs = q32([DATA + 0x100 + 4 * 9, DATA + 0x100 + 4 * 2, DATA + 0x100 + 4 * 15, DATA + 0x100]);
    o.set_q(1, addrs);
    run1(o, &[0xfd92, 0x1e00]);
    assert_eq!(w32(o.get_q(0)), [9, 2, 15, 0]);
    o.set_q(0, q32([0xa0, 0xa1, 0xa2, 0xa3]));
    o.set_q(1, q32([DATA + 0x200, DATA + 0x210, DATA + 0x220, DATA + 0x230]));
    run1(o, &[0xfd82, 0x1e02]);
    assert_eq!([read32(o, DATA + 0x208), read32(o, DATA + 0x218), read32(o, DATA + 0x228), read32(o, DATA + 0x238)], [0xa0, 0xa1, 0xa2, 0xa3]);

    // vld20.32 then vld21.32 de-interleave eight words into q0 (even) and q1 (odd)
    write32s(o, DATA + 0x300, &[0, 1, 2, 3, 4, 5, 6, 7]);
    o.set_r(1, DATA + 0x300);
    o.set_q(0, 0);
    o.set_q(1, 0);
    run1(o, &[0xfc91, 0x1f00]);
    run1(o, &[0xfc91, 0x1f20]);
    assert_eq!(w32(o.get_q(0)), [0, 2, 4, 6]);
    assert_eq!(w32(o.get_q(1)), [1, 3, 5, 7]);

    // MVE accesses must be element aligned (MemA_MVE): UNALIGNED, not a translation fault
    o.set_r(1, DATA + 2);
    o.write_mem(CODE, &thumb(&[0xed91, 0x1f00])).unwrap();
    o.set_r(15, CODE);
    let r = o.step_raw();
    assert_eq!((r.kind, r.fault_addr, r.fsr), (STEP_DATA_ABORT, DATA + 2, 0x1));
    assert!(matches!(outcome(&r), StepOutcome::Fault { kind: FaultKind::Unaligned { addr }, .. } if addr == DATA + 2));
    o.set_r(1, DATA + 1);
    run1(o, &[0xfd91, 0x0e80]); // vldrb.u16 at an odd address is fine
}

#[test]
fn eci_skips_completed_beats() {
    let mut f = fixture();
    let o = setup(&mut f);
    let vadd_q0 = [0xef22, 0x0844]; // vadd.i32 q0, q1, q2
    o.set_q(1, q32([1, 2, 3, 4]));
    o.set_q(2, q32([10, 20, 30, 40]));
    for (eci, lanes) in [(0u8, [11, 22, 33, 44]), (1, [0, 22, 33, 44]), (2, [0, 0, 33, 44]), (4, [0, 0, 0, 44])] {
        o.set_q(0, 0);
        o.set_xpsr(XPSR_T | eci_bits(eci));
        run1(o, &vadd_q0);
        assert_eq!(w32(o.get_q(0)), lanes, "ECI {eci}");
        assert_eq!(o.get_xpsr(), XPSR_T, "ECI cleared");
    }

    // ECI 5 = A0 A1 A2 B0: the next instruction starts with ECI = 1.
    // vadd.i32 q0, q1, q2; vadd.i32 q3, q1, q2
    o.write_mem(CODE, &thumb(&[0xef22, 0x0844, 0xef22, 0x6844])).unwrap();
    o.set_r(15, CODE);
    o.set_q(0, 0);
    o.set_q(3, 0);
    o.set_xpsr(XPSR_T | eci_bits(5));
    retire(o);
    assert_eq!(w32(o.get_q(0)), [0, 0, 0, 44]);
    assert_eq!(o.get_xpsr(), XPSR_T | eci_bits(1));
    retire(o);
    assert_eq!(w32(o.get_q(3)), [0, 22, 33, 44]);
    assert_eq!(o.get_xpsr(), XPSR_T);

    // A non-beat-wise instruction with nonzero ECI is INVSTATE (B3.27.7).
    o.write_mem(CODE, &thumb(&[0x2005])).unwrap();
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T | eci_bits(1));
    assert_eq!(o.step_raw().kind, STEP_INVALID_STATE);
}

#[test]
fn float_uses_standard_fpscr() {
    let mut f = fixture();
    let o = setup(&mut f);
    // StandardFPSCRValue: DN = 1, FZ = 1, RN; FZ16 and AHP come from FPSCR.
    // Flags still accumulate in FPSCR.
    o.set_fpscr(BASE | RZ);
    let r = qop(
        o,
        &[0xef02, 0x0d44], // vadd.f32 q0, q1, q2
        0,
        q32([0x0000_0001, 0x7f80_0001, 0x3f80_0000, 0x4000_0000]),
        q32([0, 0x3f80_0000, 0x33c0_0000, 0x4000_0000]),
    );
    assert_eq!(w32(r), [0, 0x7fc0_0000, 0x3f80_0001, 0x4080_0000]);
    assert_eq!(o.get_fpscr(), BASE | RZ | IDC | IOC | IXC);

    // Inactive lanes raise no exceptions.
    // vpst; vaddt.f32 q0, q1, q2
    o.write_mem(CODE, &thumb(&[0xfe71, 0x0f4d, 0xef02, 0x0d44])).unwrap();
    o.set_r(15, CODE);
    o.set_fpscr(BASE);
    o.set_vpr(0x00ff);
    o.set_q(0, 0);
    o.set_q(1, q32([0x3f80_0000, 0x3f80_0000, 0x3f80_0000, 0x7f80_0001]));
    o.set_q(2, q32([0x3f80_0000, 0x3f80_0000, 0x3f80_0000, 0x3f80_0000]));
    retire(o);
    retire(o);
    assert_eq!(w32(o.get_q(0)), [0x4000_0000, 0x4000_0000, 0, 0]);
    assert_eq!(o.get_fpscr(), BASE, "no IOC from the inactive sNaN lane");

    // Half precision follows FPSCR.FZ16 even under the standard value.
    let vadd_f16 = [0xef12, 0x0d44]; // vadd.f16 q0, q1, q2
    for (ctl, out, flags) in [(0, 0x0001u16, 0), (FZ16, 0, 0)] {
        o.set_fpscr(BASE | ctl);
        let r = qop(o, &vadd_f16, 0, q16([0x0001, 0x3c00, 0, 0, 0, 0, 0, 0]), q16([0, 0x3c00, 0, 0, 0, 0, 0, 0]));
        assert_eq!(&w16(r)[..2], &[out, 0x4000], "FZ16 = {}", ctl != 0);
        assert_eq!(o.get_fpscr(), BASE | ctl | flags);
    }
    o.set_fpscr(BASE);
    let r = qop(o, &[0xff12, 0x0d54], 0, q16([0x7bff, 0x3c00, 0, 0, 0, 0, 0, 0]), q16([0x4000, 0x4200, 0, 0, 0, 0, 0, 0])); // vmul.f16
    assert_eq!(&w16(r)[..2], &[0x7c00, 0x4200]);
    assert_eq!(o.get_fpscr(), BASE | OFC | IXC);
}

#[test]
fn float_operations() {
    let mut f = fixture();
    let o = setup(&mut f);
    o.set_fpscr(BASE);
    // vfma.f32 q0, q1, q2: q0 += q1 * q2
    let r = qop(o, &[0xef02, 0x0c54], q32([0x3f80_0000; 4]), q32([0x4000_0000; 4]), q32([0x4040_0000; 4]));
    assert_eq!(w32(r), [0x40e0_0000; 4]);

    // vcvtb.f16.f32 q0, q1: even halfwords of Q0, odd ones kept
    let r = qop(o, &[0xee3f, 0x0e03], q16([0xaaaa; 8]), q32([0x3f80_0000, 0x4000_0000, 0xbf80_0000, 0x7f80_0000]), 0);
    assert_eq!(w16(r), [0x3c00, 0xaaaa, 0x4000, 0xaaaa, 0xbc00, 0xaaaa, 0x7c00, 0xaaaa]);

    o.set_fpscr(BASE);
    let r = qop(o, &[0xffbb, 0x0742], 0, q32([0x402c_cccd, 0xc02c_cccd, 0x7fc0_0000, 0x5015_02f9]), 0); // vcvt.s32.f32
    assert_eq!(w32(r), [2, -2i32 as u32, 0, 0x7fff_ffff]);
    assert_eq!(o.get_fpscr(), BASE | IXC | IOC);

    o.set_q(0, q32([0x3f80_0000, 0x7fc0_0000, 0x4000_0000, 0]));
    o.set_q(1, q32([0x3f80_0000, 0x7fc0_0000, 0x4040_0000, 0x8000_0000]));
    run1(o, &[0xee31, 0x0f02]); // vcmp.f32 eq, q0, q1
    assert_eq!(o.get_vpr(), 0xf00f, "NaN != NaN, +0 == -0");

    let r = qop(o, &[0xff02, 0x0f54], 0, q32([0x7fc0_0000, 0x3f80_0000, 0, 0]), q32([0x3f80_0000, 0x7fc0_0000, 0, 0])); // vmaxnm.f32
    assert_eq!(&w32(r)[..2], &[0x3f80_0000, 0x3f80_0000]);

    o.set_r(0, 0x4000_0000);
    o.set_q(1, q32([0x4040_0000, 0x7fc0_0000, 0x3f80_0000, 0x40a0_0000]));
    run1(o, &[0xeeee, 0x0f82]); // vminnmv.f32 r0, q1
    assert_eq!(o.get_r(0), 0x3f80_0000);

    // vcadd.f32 q0, q1, q2, #90: re = a.re - b.im, im = a.im + b.re
    let r = qop(o, &[0xfc92, 0x0844], 0, q32([0x3f80_0000, 0x4000_0000, 0x4040_0000, 0x4080_0000]), q32([0x40a0_0000, 0x40c0_0000, 0x40e0_0000, 0x4100_0000]));
    assert_eq!(w32(r), [0xc0a0_0000, 0x40e0_0000, 0xc0a0_0000, 0x4130_0000]);
    let r = qop(o, &[0xfe22, 0x0f04], 0, q32([1, 2, 3, 4]), q32([5, 6, 7, 8])); // vcadd.i32 #90
    assert_eq!(w32(r), [-5i32 as u32, 7, -5i32 as u32, 11]);
}

#[test]
fn scalar_long_shifts() {
    let mut f = fixture();
    let o = setup(&mut f);
    o.set_r(0, 0x8000_0001);
    o.set_r(1, 1);
    run1(o, &[0xea50, 0x210f]); // lsll r0, r1, #8
    assert_eq!((o.get_r(0), o.get_r(1)), (0x100, 0x180));

    // asrl r0, r1, r2: a negative amount shifts left
    for (hi_in, amount, lo, hi) in [(0x8000_0000u32, 4u32, 1u32, 0xf800_0000u32), (1, -4i32 as u32, 0x100, 0x10)] {
        o.set_r(0, 0x10);
        o.set_r(1, hi_in);
        o.set_r(2, amount);
        run1(o, &[0xea50, 0x212d]);
        assert_eq!((o.get_r(0), o.get_r(1)), (lo, hi), "asrl by {amount:#x}");
    }

    o.set_xpsr(XPSR_T);
    o.set_r(0, 0x7fff_ffff);
    o.set_r(2, -1i32 as u32);
    run1(o, &[0xea50, 0x2f2d]); // sqrshr r0, r2
    assert_eq!(o.get_r(0), 0x7fff_ffff);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_Q);
    o.set_xpsr(XPSR_T);
    o.set_r(0, 5);
    o.set_r(2, 1);
    run1(o, &[0xea50, 0x2f2d]);
    assert_eq!(o.get_r(0), 3, "rounding right shift");
    assert_eq!(o.get_xpsr(), XPSR_T);

    o.set_r(0, 0x1000_0000);
    run1(o, &[0xea50, 0x1f0f]); // uqshl r0, #4
    assert_eq!(o.get_r(0), 0xffff_ffff);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_Q);
}
