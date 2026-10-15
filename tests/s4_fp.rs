//! S4: scalar floating point (single, double, half precision): FPSCR
//! rounding modes, flush-to-zero, default NaN, cumulative exception flags.
//! Expected values follow the DDI0553B.z pseudocode (FPRoundBase, FPUnpack,
//! FPProcessNaNs, FPMulAdd, StandardFPSCRValue).

mod common;
use common::*;
use qemu_armm_oracle::*;

const IOC: u32 = 1 << 0;
const DZC: u32 = 1 << 1;
const OFC: u32 = 1 << 2;
const UFC: u32 = 1 << 3;
const IXC: u32 = 1 << 4;
const IDC: u32 = 1 << 7;
const FZ16: u32 = 1 << 19;
const RN: u32 = 0 << 22;
const RP: u32 = 1 << 22;
const RM: u32 = 2 << 22;
const RZ: u32 = 3 << 22;
const FZ: u32 = 1 << 24;
const DN: u32 = 1 << 25;
const AHP: u32 = 1 << 26;
/// LTPSIZE = 4 (no tail predication), the reset value.
const BASE: u32 = 4 << 16;

const VADD_F32: [u16; 2] = [0xee30, 0x0a81]; // vadd.f32 s0, s1, s2
const VMUL_F32: [u16; 2] = [0xee20, 0x0a81]; // vmul.f32 s0, s1, s2
const VDIV_F32: [u16; 2] = [0xee80, 0x0a81]; // vdiv.f32 s0, s1, s2
const VSQRT_F32: [u16; 2] = [0xeeb1, 0x0ae0]; // vsqrt.f32 s0, s1
const VFMA_F32: [u16; 2] = [0xeea0, 0x0a81]; // vfma.f32 s0, s1, s2
const VADD_F16: [u16; 2] = [0xee30, 0x0981]; // vadd.f16 s0, s1, s2
const VMUL_F16: [u16; 2] = [0xee20, 0x0981]; // vmul.f16 s0, s1, s2

/// Run `code` with s1, s2 (and s0) set, FPSCR = BASE | `ctl`; check s0 and FPSCR.
fn s_case(o: &mut Oracle, what: &str, code: [u16; 2], s0: u32, s1: u32, s2: u32, ctl: u32, out: u32, flags: u32) {
    o.set_s(0, s0);
    o.set_s(1, s1);
    o.set_s(2, s2);
    o.set_fpscr(BASE | ctl);
    run1(o, &code);
    assert_eq!(o.get_s(0), out, "{what}: s0");
    assert_eq!(o.get_fpscr(), BASE | ctl | flags, "{what}: FPSCR");
}

fn setup(f: &mut Fixture) -> &mut Oracle {
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    o
}

#[test]
fn f32_rounding_modes() {
    let mut f = fixture();
    let o = setup(&mut f);
    // 1.0 + 0.75 ulp and -1.0 - 0.75 ulp
    for (rmode, pos, neg) in [
        (RN, 0x3f80_0001, 0xbf80_0001),
        (RP, 0x3f80_0001, 0xbf80_0000),
        (RM, 0x3f80_0000, 0xbf80_0001),
        (RZ, 0x3f80_0000, 0xbf80_0000),
    ] {
        s_case(o, "1 + 0.75ulp", VADD_F32, 0, 0x3f80_0000, 0x33c0_0000, rmode, pos, IXC);
        s_case(o, "-1 - 0.75ulp", VADD_F32, 0, 0xbf80_0000, 0xb3c0_0000, rmode, neg, IXC);
    }
    s_case(o, "1 + 0.5ulp ties to even", VADD_F32, 0, 0x3f80_0000, 0x3380_0000, RN, 0x3f80_0000, IXC);
    s_case(o, "exact", VADD_F32, 0, 0x3f80_0000, 0x3f80_0000, RN, 0x4000_0000, 0);
}

#[test]
fn f32_exceptions_and_cumulative_flags() {
    let mut f = fixture();
    let o = setup(&mut f);
    s_case(o, "1/0", VDIV_F32, 0, 0x3f80_0000, 0, RN, 0x7f80_0000, DZC);
    s_case(o, "max*2 RN", VMUL_F32, 0, 0x7f7f_ffff, 0x4000_0000, RN, 0x7f80_0000, OFC | IXC);
    s_case(o, "max*2 RZ", VMUL_F32, 0, 0x7f7f_ffff, 0x4000_0000, RZ, 0x7f7f_ffff, OFC | IXC);
    s_case(o, "sqrt(-1)", VSQRT_F32, 0, 0xbf80_0000, 0, RN, 0x7fc0_0000, IOC);
    s_case(o, "0*inf", VMUL_F32, 0, 0, 0x7f80_0000, RN, 0x7fc0_0000, IOC);
    s_case(o, "exact denormal result", VMUL_F32, 0, 0x0080_0000, 0x3f00_0000, RN, 0x0040_0000, 0);
    s_case(o, "inexact denormal result", VMUL_F32, 0, 0x0080_0001, 0x3f00_0000, RN, 0x0040_0000, UFC | IXC);

    // Flags are sticky: an exact operation keeps earlier flags.
    o.set_fpscr(BASE);
    o.set_s(1, 0x3f80_0000);
    o.set_s(2, 0);
    run1(o, &VDIV_F32);
    o.set_s(2, 0x3f80_0000);
    run1(o, &VADD_F32);
    assert_eq!(o.get_s(0), 0x4000_0000);
    assert_eq!(o.get_fpscr(), BASE | DZC);
}

#[test]
fn f32_flush_to_zero() {
    let mut f = fixture();
    let o = setup(&mut f);
    s_case(o, "denormal input, FZ=0", VADD_F32, 0, 0x0000_0001, 0, RN, 0x0000_0001, 0);
    s_case(o, "denormal input, FZ=1", VADD_F32, 0, 0x0000_0001, 0, FZ, 0, IDC);
    s_case(o, "negative denormal input, FZ=1", VADD_F32, 0, 0x8000_0001, 0x8000_0000, FZ, 0x8000_0000, IDC);
    s_case(o, "denormal output, FZ=1", VMUL_F32, 0, 0x0080_0000, 0x3f00_0000, FZ, 0, UFC);
}

#[test]
fn f32_nan_handling() {
    let mut f = fixture();
    let o = setup(&mut f);
    s_case(o, "sNaN + 1, DN=0", VADD_F32, 0, 0x7f80_0001, 0x3f80_0000, RN, 0x7fc0_0001, IOC);
    s_case(o, "sNaN + 1, DN=1", VADD_F32, 0, 0x7f80_0001, 0x3f80_0000, DN, 0x7fc0_0000, IOC);
    s_case(o, "qNaN + 1, DN=0", VADD_F32, 0, 0x7fc0_0005, 0x3f80_0000, RN, 0x7fc0_0005, 0);
    s_case(o, "qNaN + 1, DN=1", VADD_F32, 0, 0x7fc0_0005, 0x3f80_0000, DN, 0x7fc0_0000, 0);
    s_case(o, "qNaN + sNaN: sNaN wins", VADD_F32, 0, 0x7fc0_0011, 0x7f80_0022, RN, 0x7fc0_0022, IOC);
    // FPMulAdd: qNaN addend with 0 * inf gives the default NaN and IOC.
    s_case(o, "vfma qNaN + 0*inf", VFMA_F32, 0x7fc0_0003, 0, 0x7f80_0000, RN, 0x7fc0_0000, IOC);
    s_case(o, "vfma 1 + 2*3", VFMA_F32, 0x3f80_0000, 0x4000_0000, 0x4040_0000, RN, 0x40e0_0000, 0);
}

#[test]
fn f32_conversions_and_v8_ops() {
    let mut f = fixture();
    let o = setup(&mut f);
    let vcvt = [0xeebd, 0x0ae0]; // vcvt.s32.f32 s0, s1 (round toward zero)
    let vcvtr = [0xeebd, 0x0a60]; // vcvtr.s32.f32 s0, s1 (FPSCR rounding)
    let vcvta = [0xfebc, 0x0ae0]; // vcvta.s32.f32 s0, s1
    let vcvtm = [0xfebf, 0x0ae0]; // vcvtm.s32.f32 s0, s1
    let vrintx = [0xeeb7, 0x0a60]; // vrintx.f32 s0, s1
    let vmaxnm = [0xfe80, 0x0a81]; // vmaxnm.f32 s0, s1, s2
    s_case(o, "vcvt 2.7", vcvt, 0, 0x402c_cccd, 0, RN, 2, IXC);
    s_case(o, "vcvt -2.7", vcvt, 0, 0xc02c_cccd, 0, RN, -2i32 as u32, IXC);
    s_case(o, "vcvt 1e10", vcvt, 0, 0x5015_02f9, 0, RN, 0x7fff_ffff, IOC);
    s_case(o, "vcvt NaN", vcvt, 0, 0x7fc0_0000, 0, RN, 0, IOC);
    s_case(o, "vcvtr 2.5 RN", vcvtr, 0, 0x4020_0000, 0, RN, 2, IXC);
    s_case(o, "vcvtr 2.5 RP", vcvtr, 0, 0x4020_0000, 0, RP, 3, IXC);
    s_case(o, "vcvta 2.5", vcvta, 0, 0x4020_0000, 0, RZ, 3, IXC);
    s_case(o, "vcvta -2.5", vcvta, 0, 0xc020_0000, 0, RZ, -3i32 as u32, IXC);
    s_case(o, "vcvtm 2.5", vcvtm, 0, 0x4020_0000, 0, RP, 2, IXC);
    s_case(o, "vrintx 2.5", vrintx, 0, 0x4020_0000, 0, RN, 0x4000_0000, IXC);
    s_case(o, "vrintx 3.0", vrintx, 0, 0x4040_0000, 0, RN, 0x4040_0000, 0);
    s_case(o, "vmaxnm qNaN, 1", vmaxnm, 0, 0x7fc0_0000, 0x3f80_0000, RN, 0x3f80_0000, 0);
    s_case(o, "vmaxnm sNaN, 1", vmaxnm, 0, 0x7f80_0001, 0x3f80_0000, RN, 0x7fc0_0001, IOC);
    s_case(o, "vmaxnm -0, +0", vmaxnm, 0, 0x8000_0000, 0, RN, 0, 0);
}

#[test]
fn compare_and_flag_transfer() {
    let mut f = fixture();
    let o = setup(&mut f);
    let vcmp = [0xeef4, 0x0a41]; // vcmp.f32 s1, s2
    let vcmpe = [0xeef4, 0x0ac1]; // vcmpe.f32 s1, s2
    let vmrs_apsr = [0xeef1, 0xfa10]; // vmrs APSR_nzcv, fpscr
    let vselgt = [0xfe30, 0x0a81]; // vselgt.f32 s0, s1, s2
    for (code, s1, s2, nzcv, flags) in [
        (vcmp, 0x3f80_0000, 0x4000_0000, 0b1000, 0),
        (vcmp, 0x4000_0000, 0x4000_0000, 0b0110, 0),
        (vcmp, 0x4040_0000, 0x4000_0000, 0b0010, 0),
        (vcmp, 0x7fc0_0000, 0x4000_0000, 0b0011, 0),
        (vcmpe, 0x7fc0_0000, 0x4000_0000, 0b0011, IOC),
        (vcmp, 0x7f80_0001, 0x4000_0000, 0b0011, IOC),
    ] {
        o.set_s(1, s1);
        o.set_s(2, s2);
        o.set_fpscr(BASE);
        run1(o, &code);
        assert_eq!(o.get_fpscr(), BASE | nzcv << 28 | flags, "{code:x?} {s1:#x} {s2:#x}");
        o.set_xpsr(XPSR_T);
        run1(o, &vmrs_apsr);
        assert_eq!(o.get_xpsr(), XPSR_T | nzcv << 28);
    }
    // vselgt reads APSR, not FPSCR
    o.set_s(1, 0x1111_1111);
    o.set_s(2, 0x2222_2222);
    o.set_xpsr(XPSR_T);
    run1(o, &vselgt);
    assert_eq!(o.get_s(0), 0x1111_1111);
    o.set_xpsr(XPSR_T | FLAG_Z);
    run1(o, &vselgt);
    assert_eq!(o.get_s(0), 0x2222_2222);
}

#[test]
fn f64_arithmetic() {
    let mut f = fixture();
    let o = setup(&mut f);
    let d_case = |o: &mut Oracle, what: &str, code: [u16; 2], d0: u64, d1: u64, d2: u64, ctl: u32, out: u64, flags: u32| {
        o.set_d(0, d0);
        o.set_d(1, d1);
        o.set_d(2, d2);
        o.set_fpscr(BASE | ctl);
        run1(o, &code);
        assert_eq!(o.get_d(0), out, "{what}: d0");
        assert_eq!(o.get_fpscr(), BASE | ctl | flags, "{what}: FPSCR");
    };
    let vadd = [0xee31, 0x0b02]; // vadd.f64 d0, d1, d2
    let vfma = [0xeea1, 0x0b02]; // vfma.f64 d0, d1, d2
    let vsqrt = [0xeeb1, 0x0bc1]; // vsqrt.f64 d0, d1
    d_case(o, "1 + 0.75ulp RN", vadd, 0, 0x3ff0_0000_0000_0000, 0x3ca8_0000_0000_0000, RN, 0x3ff0_0000_0000_0001, IXC);
    d_case(o, "1 + 0.75ulp RZ", vadd, 0, 0x3ff0_0000_0000_0000, 0x3ca8_0000_0000_0000, RZ, 0x3ff0_0000_0000_0000, IXC);
    // (1+2^-52)(1-2^-53) - 1 is exact when fused; unfused it would be 0.
    d_case(o, "fused multiply-add", vfma, 0xbff0_0000_0000_0000, 0x3ff0_0000_0000_0001, 0x3fef_ffff_ffff_ffff, RN, 0x3c9f_ffff_ffff_fffe, 0);
    d_case(o, "sqrt 2", vsqrt, 0, 0x4000_0000_0000_0000, 0, RN, 0x3ff6_a09e_667f_3bcd, IXC);
    d_case(o, "denormal input, FZ=1", vadd, 0, 1, 0, FZ, 0, IDC);

    // Conversions out of double write an S register.
    let vcvt_f32 = [0xeeb7, 0x0bc1]; // vcvt.f32.f64 s0, d1
    let vcvt_s32 = [0xeebd, 0x0bc1]; // vcvt.s32.f64 s0, d1
    for (code, d1, ctl, s0, flags) in [
        (vcvt_f32, 0x3ff0_0000_0400_0000u64, RN, 0x3f80_0000u32, IXC),
        (vcvt_f32, 0x3ff0_0000_0400_0000, RP, 0x3f80_0001, IXC),
        (vcvt_s32, 0x7ff8_0000_0000_0000, RN, 0, IOC),
        (vcvt_s32, 0x41e6_5a0b_c000_0000, RN, 0x7fff_ffff, IOC),
        (vcvt_s32, 0xc004_0000_0000_0000, RN, -2i32 as u32, IXC),
    ] {
        o.set_d(1, d1);
        o.set_s(0, 0xdead_beef);
        o.set_fpscr(BASE | ctl);
        run1(o, &code);
        assert_eq!(o.get_s(0), s0, "{code:x?} {d1:#x}");
        assert_eq!(o.get_fpscr(), BASE | ctl | flags, "{code:x?} {d1:#x}");
    }
}

#[test]
fn f16_arithmetic() {
    let mut f = fixture();
    let o = setup(&mut f);
    // Half-precision results are written as Zeros(16):result.
    s_case(o, "1 + 2", VADD_F16, 0xffff_ffff, 0xdead_3c00, 0xbeef_4000, RN, 0x0000_4200, 0);
    for (rmode, out) in [(RN, 0x3c01), (RP, 0x3c01), (RM, 0x3c00), (RZ, 0x3c00)] {
        s_case(o, "1 + 0.75ulp", VADD_F16, 0, 0x3c00, 0x1200, rmode, out, IXC);
    }
    s_case(o, "65504 * 2", VMUL_F16, 0, 0x7bff, 0x4000, RN, 0x7c00, OFC | IXC);
    s_case(o, "sNaN + 1, DN=0", VADD_F16, 0, 0x7c01, 0x3c00, RN, 0x7e01, IOC);
    s_case(o, "sNaN + 1, DN=1", VADD_F16, 0, 0x7c01, 0x3c00, DN, 0x7e00, IOC);
    // FZ16 controls half precision; FZ does not.
    s_case(o, "denormal, FZ16=0", VADD_F16, 0, 0x0001, 0, RN, 0x0001, 0);
    s_case(o, "denormal, FZ=1 FZ16=0", VADD_F16, 0, 0x0001, 0, FZ, 0x0001, 0);
    // FPUnpackBase flushes a half-precision denormal input without setting IDC.
    s_case(o, "denormal, FZ16=1", VADD_F16, 0, 0x0001, 0, FZ16, 0, 0);
    s_case(o, "denormal output, FZ16=1", VMUL_F16, 0, 0x0400, 0x3800, FZ16, 0, UFC);
    s_case(o, "denormal output, FZ16=0", VMUL_F16, 0, 0x0400, 0x3800, RN, 0x0200, 0);
    s_case(o, "vfma.f16 1 + 2*3", [0xeea0, 0x0981], 0x3c00, 0x4000, 0x4200, RN, 0x4700, 0);
    s_case(o, "vsqrt.f16 4", [0xeeb1, 0x09e0], 0, 0x4400, 0, RN, 0x4000, 0);
    s_case(o, "vmaxnm.f16 qNaN, 1", [0xfe80, 0x0981], 0, 0x7e00, 0x3c00, RN, 0x3c00, 0);
    s_case(o, "vrinta.f16 2.5 (no IXC)", [0xfeb8, 0x0960], 0, 0x4100, 0, RN, 0x4200, 0);
    s_case(o, "vcvt.f16.s32 3", [0xeeb8, 0x09e0], 0xffff_ffff, 3, 0, RN, 0x4200, 0);

    o.set_s(1, 0x3c00);
    o.set_s(2, 0x4000);
    o.set_fpscr(BASE);
    run1(o, &[0xeef4, 0x0941]); // vcmp.f16 s1, s2
    assert_eq!(o.get_fpscr(), BASE | 0b1000 << 28);
}

#[test]
fn f16_conversions_and_moves() {
    let mut f = fixture();
    let o = setup(&mut f);
    let vcvtb_f16_f32 = [0xeeb3, 0x0a60]; // vcvtb.f16.f32 s0, s1
    let vcvtt_f16_f32 = [0xeeb3, 0x0ae0]; // vcvtt.f16.f32 s0, s1
    // VCVTB/VCVTT keep the other half of the destination.
    s_case(o, "vcvtb 1.0", vcvtb_f16_f32, 0xaaaa_bbbb, 0x3f80_0000, 0, RN, 0xaaaa_3c00, 0);
    s_case(o, "vcvtt 1.0", vcvtt_f16_f32, 0xaaaa_bbbb, 0x3f80_0000, 0, RN, 0x3c00_bbbb, 0);
    s_case(o, "vcvtb 65520", vcvtb_f16_f32, 0, 0x477f_f000, 0, RN, 0x7c00, OFC | IXC);
    s_case(o, "vcvtb inf, AHP=1", vcvtb_f16_f32, 0, 0x7f80_0000, 0, AHP, 0x7fff, IOC);
    s_case(o, "vcvtb 65536, AHP=1", vcvtb_f16_f32, 0, 0x4780_0000, 0, AHP, 0x7c00, 0);
    s_case(o, "vcvtb.f32.f16", [0xeeb2, 0x0a60], 0, 0x1234_3c00, 0, RN, 0x3f80_0000, 0);
    s_case(o, "vmovx.f16", [0xfeb0, 0x0a60], 0xffff_ffff, 0x1234_5678, 0, RN, 0x0000_1234, 0);
    s_case(o, "vins.f16", [0xfeb0, 0x0ae0], 0xaaaa_bbbb, 0x1234_5678, 0, RN, 0x5678_bbbb, 0);

    o.set_d(1, 0x3ff0_0000_0000_0000);
    o.set_s(0, 0xaaaa_bbbb);
    run1(o, &[0xeeb3, 0x0b41]); // vcvtb.f16.f64 s0, d1
    assert_eq!(o.get_s(0), 0xaaaa_3c00);

    o.set_s(1, 0x1234_5678);
    o.set_r(0, 0xffff_ffff);
    run1(o, &[0xee10, 0x0990]); // vmov.f16 r0, s1
    assert_eq!(o.get_r(0), 0x5678);
    o.set_r(1, 0x1234_5678);
    o.set_s(0, 0xffff_ffff);
    run1(o, &[0xee00, 0x1910]); // vmov.f16 s0, r1
    assert_eq!(o.get_s(0), 0x5678);
}

#[test]
fn fpscr_through_vmsr_vmrs() {
    let mut f = fixture();
    let o = setup(&mut f);
    // Every defined bit: NZCV, QC, AHP, DN, FZ, RMode, FZ16, LTPSIZE = 2, IDC, IXC..IOC
    let v = 0xffca_009f;
    o.set_r(0, v | 0x0030_ff60); // RES0 bits are dropped
    run1(o, &[0xeee1, 0x0a10]); // vmsr fpscr, r0
    assert_eq!(o.get_fpscr(), v);
    o.set_r(0, 0);
    run1(o, &[0xeef1, 0x0a10]); // vmrs r0, fpscr
    assert_eq!(o.get_r(0), v);
    for ltpsize in 0..=4 {
        o.set_fpscr(ltpsize << 16);
        assert_eq!(o.get_fpscr(), ltpsize << 16, "LTPSIZE {ltpsize} through the API");
    }
}
