//! S2: single instructions execute, faults are classified, 10k cases run
//! without leaking.

mod common;
use common::*;
use qemu_armm_oracle::*;
use std::time::Instant;

const N: u32 = 1 << 31;
const Z: u32 = 1 << 30;
const C: u32 = 1 << 29;
const V: u32 = 1 << 28;

#[test]
fn movs_sets_flags() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0x2005])); // movs r0, #5
    o.set_r(0, 0xffff_ffff);
    o.set_xpsr(N | Z | C | V | XPSR_T);
    assert_eq!(o.step(), StepOutcome::Retired);
    assert_eq!(o.get_r(0), 5);
    assert_eq!(o.get_xpsr(), C | V | XPSR_T, "N=0 Z=0, C and V unchanged");
    assert_eq!(o.get_r(15), CODE + 2);

    load(o, &thumb(&[0x2005]));
    o.set_xpsr(N | XPSR_T);
    o.step();
    assert_eq!(o.get_xpsr(), XPSR_T, "C stays 0");
}

#[test]
fn vadd_i32() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xef22, 0x0844])); // vadd.i32 q0, q1, q2
    let q = |w: [u32; 4]| w.iter().rev().fold(0u128, |acc, &x| acc << 32 | x as u128);
    o.set_q(0, u128::MAX);
    o.set_q(1, q([1, 2, 0x7fff_ffff, 0xffff_ffff]));
    o.set_q(2, q([10, 20, 1, 1]));
    assert_eq!(o.step(), StepOutcome::Retired);
    assert_eq!(o.get_q(0), q([11, 22, 0x8000_0000, 0]));
    assert_eq!(o.get_d(0), 0x0000_0016_0000_000b);
    assert_eq!(o.get_r(15), CODE + 4);
}

#[test]
fn vadd_i32_predicated_by_vpr() {
    let mut f = fixture();
    let o = &mut f.o;
    // vpst; vaddt.i32 q0, q1, q2 -- lanes 1 and 3 disabled by P0
    load(o, &thumb(&[0xfe71, 0x0f4d, 0xef22, 0x0844]));
    o.set_q(0, 0);
    o.set_q(1, 0x0000_0001_0000_0001_0000_0001_0000_0001);
    o.set_q(2, 0x0000_0002_0000_0002_0000_0002_0000_0002);
    o.set_vpr(0x0f0f);
    assert_eq!(o.step(), StepOutcome::Retired, "vpst");
    assert_eq!(o.get_r(15), CODE + 4);
    assert_eq!(o.step(), StepOutcome::Retired, "vaddt");
    assert_eq!(o.get_q(0), 0x0000_0000_0000_0003_0000_0000_0000_0003);
}

#[test]
fn udf_is_undefined() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xde00]));
    let r = o.step_raw();
    assert_eq!(r.kind, STEP_UNDEFINED);
    assert_eq!(r.excp, 1, "EXCP_UDEF");
    assert_eq!(r.pc, CODE, "pc stays on the faulting instruction");
}

#[test]
fn svc_bkpt_and_branch() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xdf01, 0xbe00, 0xe7fe, 0xf100, 0x0001]));
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_SVC, CODE + 2));
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_BKPT, CODE + 2));
    o.set_r(15, CODE + 4);
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_RETIRED, CODE + 4), "b . loops");
    o.set_r(15, CODE + 6);
    o.set_r(0, 41);
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_RETIRED, CODE + 10));
    assert_eq!(o.get_r(0), 42);
}

#[test]
fn thumb_bit_clear_is_invalid_state() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    o.set_xpsr(0);
    let r = o.step_raw();
    assert_eq!(r.kind, STEP_INVALID_STATE);
}

/// Instructions that do not fault with the register setup of `run_case`.
pub const S2_POOL: &[&[u16]] = &[
    &[0x2005],         // movs r0, #5
    &[0x1888],         // adds r0, r1, r2
    &[0xf100, 0x0001], // add.w r0, r0, #1
    &[0xef22, 0x0844], // vadd.i32 q0, q1, q2
    &[0xee30, 0x0a81], // vadd.f32 s0, s1, s2
    &[0xbf00],         // nop
    &[0xe7fe],         // b .
    &[0x6808],         // ldr r0, [r1]
    &[0x6008],         // str r0, [r1]
    &[0xed91, 0x1f00], // vldrw.u32 q0, [r1]
    &[0xde00],         // udf #0
];

pub struct State {
    pub r: [u32; 16],
    pub xpsr: u32,
    pub q: [u128; 8],
    pub fpscr: u32,
    pub vpr: u32,
}

pub fn run_case(o: &mut Oracle, rng: &mut Rng, code: &[u8], flush: bool) -> (RawStep, State) {
    if flush {
        o.flush_tb();
    }
    o.write_mem(CODE, code).unwrap();
    for n in 0..13 {
        o.set_r(n, rng.u32());
    }
    o.set_r(1, DATA + (rng.u32() & 0xff0));
    o.set_r(13, DATA + 0x800);
    o.set_r(14, rng.u32());
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T | (rng.u32() & 0xf000_0000));
    for n in 0..8 {
        o.set_q(n, (rng.next() as u128) << 64 | rng.next() as u128);
    }
    o.set_fpscr(0x0004_0000);
    o.set_vpr(0);
    let step = o.step_raw();
    let mut st = State { r: [0; 16], xpsr: o.get_xpsr(), q: [0; 8], fpscr: o.get_fpscr(), vpr: o.get_vpr() };
    for n in 0..16 {
        st.r[n] = o.get_r(n as u32);
    }
    for n in 0..8 {
        st.q[n] = o.get_q(n as u32);
    }
    (step, st)
}

fn run_many(o: &mut Oracle, rng: &mut Rng, count: u32, flush: bool) -> [u32; 9] {
    let mut kinds = [0u32; 9];
    for _ in 0..count {
        let insn = S2_POOL[rng.below(S2_POOL.len() as u32) as usize];
        let (step, st) = run_case(o, rng, &thumb(insn), flush);
        kinds[step.kind as usize] += 1;
        assert!(step.kind == STEP_RETIRED || step.kind == STEP_UNDEFINED, "{step:?}");
        if step.kind == STEP_RETIRED && insn != [0xe7fe] {
            assert_eq!(st.r[15], CODE + 2 * insn.len() as u32);
        }
    }
    kinds
}

#[test]
fn ten_thousand_cases() {
    let mut f = fixture();
    let o = &mut f.o;
    o.map(CODE, PAGE, PROT_READ | PROT_EXEC).unwrap();
    o.map(DATA, PAGE, PROT_READ | PROT_WRITE).unwrap();
    let mut rng = Rng(0x1234_5678_9abc_def1);

    run_many(o, &mut rng, 2000, true);
    let before = mem_usage();
    let t = Instant::now();
    let kinds = run_many(o, &mut rng, 10_000, true);
    let dt = t.elapsed();
    let after = mem_usage();
    let t2 = Instant::now();
    run_many(o, &mut rng, 10_000, false);
    let dt_noflush = t2.elapsed();

    // only the step itself: same instruction, nothing else changes
    o.write_mem(CODE, &thumb(&[0xbf00])).unwrap();
    let t3 = Instant::now();
    for _ in 0..10_000 {
        o.set_r(15, CODE);
        o.step_raw();
    }
    let dt_step = t3.elapsed();

    println!(
        "S2 10k cases: {:.2} us/case with flush, {:.2} us/case without flush, {:.2} us/step (nop, cached TB)",
        dt.as_secs_f64() * 1e6 / 10_000.0,
        dt_noflush.as_secs_f64() * 1e6 / 10_000.0,
        dt_step.as_secs_f64() * 1e6 / 10_000.0
    );
    println!("S2 kinds (retired, udef): {} {}", kinds[0], kinds[1]);
    println!(
        "S2 memory: working set {} -> {} KiB, private {} -> {} KiB",
        before.working_set / 1024,
        after.working_set / 1024,
        before.private / 1024,
        after.private / 1024
    );
    assert!(after.private <= before.private + (1 << 20), "private bytes grew by more than 1 MiB");
}
