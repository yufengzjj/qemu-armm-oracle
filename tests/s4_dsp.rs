//! S4: DSP extension (saturating arithmetic, Q flag, SIMD with GE bits, SEL,
//! dual multiplies). Expected values follow DDI0553B.z.

mod common;
use common::*;

const GE_SHIFT: u32 = 16;

struct Case {
    asm: &'static str,
    code: [u16; 2],
    regs: &'static [(u32, u32)],
    xpsr: u32,
    expect: &'static [(u32, u32)],
    expect_xpsr: u32,
}

fn run_cases(cases: &[Case]) {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for c in cases {
        for &(r, v) in c.regs {
            o.set_r(r, v);
        }
        o.set_xpsr(XPSR_T | c.xpsr);
        run1(o, &c.code);
        for &(r, v) in c.expect {
            assert_eq!(o.get_r(r), v, "{}: r{r}", c.asm);
        }
        assert_eq!(o.get_xpsr(), XPSR_T | c.expect_xpsr, "{}: xPSR", c.asm);
    }
}

#[test]
fn saturating_arithmetic_sets_q() {
    run_cases(&[
        Case { asm: "qadd r0, r1, r2", code: [0xfa82, 0xf081], regs: &[(1, 0x7fff_ffff), (2, 1)], xpsr: 0, expect: &[(0, 0x7fff_ffff)], expect_xpsr: FLAG_Q },
        Case { asm: "qadd r0, r1, r2", code: [0xfa82, 0xf081], regs: &[(1, -5i32 as u32), (2, 3)], xpsr: FLAG_Q, expect: &[(0, -2i32 as u32)], expect_xpsr: FLAG_Q },
        Case { asm: "qadd r0, r1, r2", code: [0xfa82, 0xf081], regs: &[(1, -5i32 as u32), (2, 3)], xpsr: 0, expect: &[(0, -2i32 as u32)], expect_xpsr: 0 },
        Case { asm: "qsub r0, r1, r2", code: [0xfa82, 0xf0a1], regs: &[(1, 0x8000_0000), (2, 1)], xpsr: 0, expect: &[(0, 0x8000_0000)], expect_xpsr: FLAG_Q },
        Case { asm: "qdadd r0, r1, r2", code: [0xfa82, 0xf091], regs: &[(1, 0), (2, 0x4000_0000)], xpsr: 0, expect: &[(0, 0x7fff_ffff)], expect_xpsr: FLAG_Q },
        Case { asm: "qdsub r0, r1, r2", code: [0xfa82, 0xf0b1], regs: &[(1, 0), (2, 0xc000_0000)], xpsr: 0, expect: &[(0, 0x7fff_ffff)], expect_xpsr: FLAG_Q },
        Case { asm: "ssat r0, #8, r1", code: [0xf301, 0x0007], regs: &[(1, 300)], xpsr: 0, expect: &[(0, 127)], expect_xpsr: FLAG_Q },
        Case { asm: "ssat r0, #8, r1", code: [0xf301, 0x0007], regs: &[(1, -5i32 as u32)], xpsr: 0, expect: &[(0, -5i32 as u32)], expect_xpsr: 0 },
        Case { asm: "usat r0, #8, r1", code: [0xf381, 0x0008], regs: &[(1, -5i32 as u32)], xpsr: 0, expect: &[(0, 0)], expect_xpsr: FLAG_Q },
        Case { asm: "usat r0, #8, r1", code: [0xf381, 0x0008], regs: &[(1, 200)], xpsr: 0, expect: &[(0, 200)], expect_xpsr: 0 },
        Case { asm: "ssat16 r0, #4, r1", code: [0xf321, 0x0003], regs: &[(1, 0x0009_fff0)], xpsr: 0, expect: &[(0, 0x0007_fff8)], expect_xpsr: FLAG_Q },
        // Parallel saturating forms never touch Q or GE.
        Case { asm: "uqadd8 r0, r1, r2", code: [0xfa81, 0xf052], regs: &[(1, 0xff10_8001), (2, 0x0110_8001)], xpsr: 0, expect: &[(0, 0xff20_ff02)], expect_xpsr: 0 },
        Case { asm: "qasx r0, r1, r2", code: [0xfaa1, 0xf012], regs: &[(1, 0x7fff_8000), (2, 0x0001_0001)], xpsr: 0, expect: &[(0, 0x7fff_8000)], expect_xpsr: 0 },
    ]);
}

#[test]
fn simd_ge_bits_and_sel() {
    run_cases(&[
        Case { asm: "uadd8 r0, r1, r2", code: [0xfa81, 0xf042], regs: &[(1, 0xff01_807f), (2, 0x01ff_8001)], xpsr: 0, expect: &[(0, 0x0000_0080)], expect_xpsr: 0b1110 << GE_SHIFT },
        Case { asm: "sel r0, r1, r2", code: [0xfaa1, 0xf082], regs: &[(1, 0x1122_3344), (2, 0xaabb_ccdd)], xpsr: 0b1110 << GE_SHIFT, expect: &[(0, 0x1122_33dd)], expect_xpsr: 0b1110 << GE_SHIFT },
        Case { asm: "sel r0, r1, r2", code: [0xfaa1, 0xf082], regs: &[(1, 0x1122_3344), (2, 0xaabb_ccdd)], xpsr: 0b0101 << GE_SHIFT, expect: &[(0, 0xaa22_cc44)], expect_xpsr: 0b0101 << GE_SHIFT },
        Case { asm: "ssub16 r0, r1, r2", code: [0xfad1, 0xf002], regs: &[(1, 0x0005_0003), (2, 0x0003_0005)], xpsr: 0, expect: &[(0, 0x0002_fffe)], expect_xpsr: 0b1100 << GE_SHIFT },
        Case { asm: "sasx r0, r1, r2", code: [0xfaa1, 0xf002], regs: &[(1, 0x0001_0001), (2, 0x0002_0003)], xpsr: 0b0011 << GE_SHIFT, expect: &[(0, 0x0004_ffff)], expect_xpsr: 0b1100 << GE_SHIFT },
        Case { asm: "shadd16 r0, r1, r2", code: [0xfa91, 0xf022], regs: &[(1, 0x7fff_0001), (2, 0x7fff_0002)], xpsr: 0, expect: &[(0, 0x7fff_0001)], expect_xpsr: 0 },
        Case { asm: "usad8 r0, r1, r2", code: [0xfb71, 0xf002], regs: &[(1, 0x0102_0304), (2, 0x0403_0201)], xpsr: 0, expect: &[(0, 8)], expect_xpsr: 0 },
        Case { asm: "usada8 r0, r1, r2, r3", code: [0xfb71, 0x3002], regs: &[(1, 0x0102_0304), (2, 0x0403_0201), (3, 100)], xpsr: 0, expect: &[(0, 108)], expect_xpsr: 0 },
        Case { asm: "pkhtb r0, r1, r2, asr #16", code: [0xeac1, 0x4022], regs: &[(1, 0x1234_5678), (2, 0xabcd_ef01)], xpsr: 0, expect: &[(0, 0x1234_abcd)], expect_xpsr: 0 },
        Case { asm: "sxtab16 r0, r1, r2, ror #8", code: [0xfa21, 0xf092], regs: &[(1, 0x0010_0010), (2, 0x8000_ff00)], xpsr: 0, expect: &[(0, 0xff90_000f)], expect_xpsr: 0 },
    ]);
}

#[test]
fn dual_and_halfword_multiplies() {
    run_cases(&[
        Case { asm: "smlad r0, r1, r2, r3", code: [0xfb21, 0x3002], regs: &[(1, 0x8000_8000), (2, 0x8000_8000), (3, 0)], xpsr: 0, expect: &[(0, 0x8000_0000)], expect_xpsr: FLAG_Q },
        Case { asm: "smlad r0, r1, r2, r3", code: [0xfb21, 0x3002], regs: &[(1, 0x0002_0003), (2, 0x0004_0005), (3, 10)], xpsr: 0, expect: &[(0, 33)], expect_xpsr: 0 },
        Case { asm: "smlsd r0, r1, r2, r3", code: [0xfb41, 0x3002], regs: &[(1, 0x0002_0003), (2, 0x0004_0005), (3, 10)], xpsr: 0, expect: &[(0, 17)], expect_xpsr: 0 },
        Case { asm: "smuad r0, r1, r2", code: [0xfb21, 0xf002], regs: &[(1, 0x8000_8000), (2, 0x8000_8000)], xpsr: 0, expect: &[(0, 0x8000_0000)], expect_xpsr: FLAG_Q },
        Case { asm: "smlald r0, r1, r2, r3", code: [0xfbc2, 0x01c3], regs: &[(0, 0xffff_ffff), (1, 0), (2, 0x8000_8000), (3, 0x8000_8000)], xpsr: 0, expect: &[(0, 0x7fff_ffff), (1, 1)], expect_xpsr: 0 },
        Case { asm: "smlabb r0, r1, r2, r3", code: [0xfb11, 0x3002], regs: &[(1, 0x8000), (2, 0x8000), (3, 0x4000_0000)], xpsr: 0, expect: &[(0, 0x8000_0000)], expect_xpsr: FLAG_Q },
        Case { asm: "smulbt r0, r1, r2", code: [0xfb11, 0xf012], regs: &[(1, 0x0000_fffe), (2, 0x0003_0000)], xpsr: 0, expect: &[(0, 0xffff_fffa)], expect_xpsr: 0 },
        Case { asm: "smmulr r0, r1, r2", code: [0xfb51, 0xf012], regs: &[(1, 0x4000_0000), (2, 3)], xpsr: 0, expect: &[(0, 1)], expect_xpsr: 0 },
        Case { asm: "smlawb r0, r1, r2, r3", code: [0xfb31, 0x3002], regs: &[(1, 0x7fff_ffff), (2, 0x7fff), (3, 0x7fff_ffff)], xpsr: 0, expect: &[(0, 0xbfff_7ffe)], expect_xpsr: FLAG_Q },
        Case { asm: "umaal r0, r1, r2, r3", code: [0xfbe2, 0x0163], regs: &[(0, 0xffff_ffff), (1, 0xffff_ffff), (2, 0xffff_ffff), (3, 0xffff_ffff)], xpsr: 0, expect: &[(0, 0xffff_ffff), (1, 0xffff_ffff)], expect_xpsr: 0 },
    ]);
}
