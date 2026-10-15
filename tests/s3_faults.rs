//! S3: guest memory faults become aborts with the right address and a
//! consistent guest state; the next case runs normally.

mod common;
use common::*;
use qemu_armm_oracle::*;
use std::time::Instant;

const UNMAPPED: u32 = 0x0010_0000;
const DATA_END: u32 = DATA + PAGE; // first byte of the unmapped page after DATA

fn movs_still_works(o: &mut Oracle) {
    o.write_mem(CODE, &thumb(&[0x2005])).unwrap();
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T);
    assert_eq!(o.step(), StepOutcome::Retired, "case after the fault");
    assert_eq!(o.get_r(0), 5);
    assert_eq!(o.get_r(15), CODE + 2);
}

fn expect_abort(r: RawStep, kind: u32, addr: u32, pc: u32) {
    assert_eq!(r.kind, kind, "{r:?}");
    assert_eq!(r.fault_addr, addr, "fault address {r:?}");
    assert_eq!(r.pc, pc, "pc of the faulting instruction {r:?}");
}

#[test]
fn load_store_unmapped() {
    let mut f = fixture();
    let o = &mut f.o;
    for (name, code) in [("ldr", 0x6808u16), ("str", 0x6008)] {
        load(o, &thumb(&[code]));
        o.set_r(0, 0xaaaa_aaaa);
        o.set_r(1, UNMAPPED + 0x10);
        let r = o.step_raw();
        println!("{name} unmapped: {r:x?}");
        expect_abort(r, STEP_DATA_ABORT, UNMAPPED + 0x10, CODE);
        assert_eq!(o.get_r(0), 0xaaaa_aaaa);
        assert_eq!(o.get_r(1), UNMAPPED + 0x10);
        movs_still_works(o);
    }
}

#[test]
fn store_to_read_only_page() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0x6008])); // str r0, [r1]
    o.map(DATA, PAGE, PROT_READ).unwrap();
    o.set_r(0, 0x1234_5678);
    o.set_r(1, DATA + 8);
    let r = o.step_raw();
    println!("str to read-only page: {r:x?}");
    expect_abort(r, STEP_DATA_ABORT, DATA + 8, CODE);
    let unmapped_fsr = {
        load(o, &thumb(&[0x6008]));
        o.set_r(1, UNMAPPED);
        o.step_raw().fsr
    };
    assert_ne!(r.fsr, unmapped_fsr, "permission and translation faults differ");
    assert_eq!(o.read_mem(DATA + 8, 4).unwrap(), vec![0; 4]);
    movs_still_works(o);
}

#[test]
fn writeback_is_not_done_on_fault() {
    let mut f = fixture();
    let o = &mut f.o;
    // ldr r0, [r1], #4 ; str r0, [r1, #4]!
    for code in [[0xf851u16, 0x0b04], [0xf841, 0x0f04]] {
        load(o, &thumb(&code));
        o.set_r(0, 0xaaaa_aaaa);
        o.set_r(1, UNMAPPED);
        let r = o.step_raw();
        expect_abort(r, STEP_DATA_ABORT, UNMAPPED + if code[0] == 0xf841 { 4 } else { 0 }, CODE);
        assert_eq!(o.get_r(1), UNMAPPED, "base register not written back");
        assert_eq!(o.get_r(0), 0xaaaa_aaaa);
        movs_still_works(o);
    }
}

#[test]
fn fault_inside_it_block_keeps_xpsr() {
    let mut f = fixture();
    let o = &mut f.o;
    let z = 1 << 30;
    let it_eq_one_insn = 0x08 >> 2 << 10; // ITSTATE 0x08: "it eq", last insn
    load(o, &thumb(&[0x6808])); // ldreq r0, [r1]
    o.set_xpsr(XPSR_T | z | it_eq_one_insn);
    o.set_r(1, UNMAPPED);
    let r = o.step_raw();
    expect_abort(r, STEP_DATA_ABORT, UNMAPPED, CODE);
    assert_eq!(o.get_xpsr(), XPSR_T | z | it_eq_one_insn, "IT state not advanced");

    o.set_r(1, DATA);
    assert_eq!(o.step(), StepOutcome::Retired);
    assert_eq!(o.get_xpsr(), XPSR_T | z, "IT block finished");
    movs_still_works(o);
}

#[test]
fn access_across_page_end() {
    let mut f = fixture();
    let o = &mut f.o;

    load(o, &thumb(&[0x6808])); // ldr r0, [r1]
    o.set_r(0, 0xaaaa_aaaa);
    o.set_r(1, DATA_END - 2);
    let r = o.step_raw();
    println!("ldr across page end: {r:x?}");
    assert_eq!(r.kind, STEP_DATA_ABORT);
    assert_eq!(o.get_r(0), 0xaaaa_aaaa);
    movs_still_works(o);

    load(o, &thumb(&[0x6008])); // str r0, [r1]
    o.write_mem(DATA_END - 4, &[0x11; 4]).unwrap();
    o.set_r(0, 0x4433_2211);
    o.set_r(1, DATA_END - 2);
    let r = o.step_raw();
    let left = o.read_mem(DATA_END - 4, 4).unwrap();
    println!("str across page end: {r:x?}, bytes before the boundary now {left:x?}");
    assert_eq!(r.kind, STEP_DATA_ABORT);
    movs_still_works(o);

    load(o, &thumb(&[0xc905])); // ldm r1!, {r0, r2}
    o.write_mem(DATA_END - 4, &0x5555_5555u32.to_le_bytes()).unwrap();
    o.set_r(0, 0xaaaa_aaaa);
    o.set_r(2, 0xbbbb_bbbb);
    o.set_r(1, DATA_END - 4);
    let r = o.step_raw();
    println!(
        "ldm across page end: {r:x?}, r0 {:#x} r1 {:#x} r2 {:#x}",
        o.get_r(0),
        o.get_r(1),
        o.get_r(2)
    );
    expect_abort(r, STEP_DATA_ABORT, DATA_END, CODE);
    assert_eq!(o.get_r(1), DATA_END - 4, "no base writeback");
    assert_eq!(o.get_r(2), 0xbbbb_bbbb);
    movs_still_works(o);
}

#[test]
fn mve_beats_across_page_end() {
    let mut f = fixture();
    let o = &mut f.o;
    let q0 = 0x4444_4444_3333_3333_2222_2222_1111_1111u128;

    load(o, &thumb(&[0xed91, 0x1f00])); // vldrw.u32 q0, [r1]
    o.write_mem(DATA_END - 8, &[0x77; 8]).unwrap();
    o.set_q(0, q0);
    o.set_r(1, DATA_END - 8);
    let r = o.step_raw();
    println!("vldrw across page end: {r:x?}, q0 now {:#034x}", o.get_q(0));
    expect_abort(r, STEP_DATA_ABORT, DATA_END, CODE);
    movs_still_works(o);

    load(o, &thumb(&[0xed81, 0x1f00])); // vstrw.32 q0, [r1]
    o.write_mem(DATA_END - 8, &[0; 8]).unwrap();
    o.set_q(0, q0);
    o.set_r(1, DATA_END - 8);
    let r = o.step_raw();
    let mem = o.read_mem(DATA_END - 8, 8).unwrap();
    println!("vstrw across page end: {r:x?}, mapped bytes now {mem:x?}");
    expect_abort(r, STEP_DATA_ABORT, DATA_END, CODE);
    movs_still_works(o);

    load(o, &thumb(&[0xed91, 0x1f00]));
    o.set_r(1, UNMAPPED);
    let r = o.step_raw();
    expect_abort(r, STEP_DATA_ABORT, UNMAPPED, CODE);
    movs_still_works(o);
}

#[test]
fn unaligned_ldrd() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xe9d1, 0x2300])); // ldrd r2, r3, [r1]
    o.set_r(1, DATA + 2);
    let r = o.step_raw();
    println!("unaligned ldrd: {r:x?}");
    expect_abort(r, STEP_DATA_ABORT, DATA + 2, CODE);
    movs_still_works(o);
}

#[test]
fn fetch_faults() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));

    o.set_r(15, UNMAPPED + 0x20);
    let r = o.step_raw();
    println!("fetch from unmapped: {r:x?}");
    expect_abort(r, STEP_PREFETCH_ABORT, UNMAPPED + 0x20, UNMAPPED + 0x20);
    movs_still_works(o);

    o.write_mem(DATA, &thumb(&[0xbf00])).unwrap();
    o.set_r(15, DATA);
    let r = o.step_raw();
    println!("fetch from non-executable page: {r:x?}");
    expect_abort(r, STEP_PREFETCH_ABORT, DATA, DATA);
    movs_still_works(o);

    // T32 instruction whose second halfword is on the next, unmapped page
    o.write_mem(CODE + PAGE - 2, &thumb(&[0xf100])).unwrap();
    o.set_r(15, CODE + PAGE - 2);
    let r = o.step_raw();
    println!("T32 across page end: {r:x?}");
    assert_eq!(r.kind, STEP_PREFETCH_ABORT);
    movs_still_works(o);
}

#[test]
fn store_into_translated_code_page() {
    let mut f = fixture();
    let o = &mut f.o;
    o.map(CODE, PAGE, PROT_RWX).unwrap();
    // str r0, [r1]; movs r0, #5 -- the store overwrites the movs with movs r0, #7
    o.write_mem(CODE, &thumb(&[0x6008, 0x2005])).unwrap();
    o.set_xpsr(XPSR_T);
    o.set_r(15, CODE + 2);
    assert_eq!(o.step(), StepOutcome::Retired, "translate movs #5 first");
    assert_eq!(o.get_r(0), 5);
    o.set_r(15, CODE);
    o.set_r(0, 0x2007_2007);
    o.set_r(1, CODE + 2);
    assert_eq!(o.step(), StepOutcome::Retired, "store into the code page");
    assert_eq!(o.read_mem(CODE + 2, 2).unwrap(), vec![0x07, 0x20]);
    assert_eq!(o.step(), StepOutcome::Retired);
    assert_eq!(o.get_r(0), 7, "new code runs");
}

#[test]
fn ten_thousand_mixed_cases() {
    let mut f = fixture();
    let o = &mut f.o;
    o.map(CODE, PAGE, PROT_READ | PROT_EXEC).unwrap();
    o.map(DATA, PAGE, PROT_READ | PROT_WRITE).unwrap();
    o.map(DATA + 2 * PAGE, PAGE, PROT_READ).unwrap();
    let mut rng = Rng(0x0dd_ba11_cafe_f00d);
    let pool: &[&[u16]] = &[
        &[0x2005],
        &[0x1888],
        &[0xef22, 0x0844],
        &[0x6808],
        &[0x6008],
        &[0xc905],
        &[0xed91, 0x1f00],
        &[0xed81, 0x1f00],
        &[0xf851, 0x0b04],
        &[0xe9d1, 0x2300],
        &[0xde00],
    ];
    let addrs = [DATA + 0x100, DATA_END - 2, DATA_END - 8, UNMAPPED, DATA + 2 * PAGE + 0x10, 0xffff_fff0];

    let run = |o: &mut Oracle, rng: &mut Rng, n: u32| {
        let mut kinds = [0u32; 9];
        for _ in 0..n {
            let insn = pool[rng.below(pool.len() as u32) as usize];
            let pc = if rng.below(50) == 0 { UNMAPPED } else { CODE };
            o.write_mem(CODE, &thumb(insn)).unwrap();
            for r in 0..13 {
                o.set_r(r, rng.u32());
            }
            o.set_r(1, addrs[rng.below(addrs.len() as u32) as usize]);
            o.set_r(15, pc);
            o.set_xpsr(XPSR_T);
            o.set_q(0, rng.next() as u128);
            let r = o.step_raw();
            kinds[r.kind as usize] += 1;
            if r.kind == STEP_DATA_ABORT || r.kind == STEP_PREFETCH_ABORT {
                assert_eq!(r.pc, pc);
            }
            let _ = (o.get_r(0), o.get_xpsr(), o.get_q(0));
        }
        kinds
    };

    run(o, &mut rng, 2000);
    let before = mem_usage();
    let t = Instant::now();
    let kinds = run(o, &mut rng, 10_000);
    let dt = t.elapsed();
    let after = mem_usage();
    println!(
        "S3 10k mixed: {:.2} us/case; retired {} udef {} data abort {} prefetch abort {}",
        dt.as_secs_f64() * 1e6 / 10_000.0,
        kinds[STEP_RETIRED as usize],
        kinds[STEP_UNDEFINED as usize],
        kinds[STEP_DATA_ABORT as usize],
        kinds[STEP_PREFETCH_ABORT as usize]
    );
    println!(
        "S3 memory: working set {} -> {} KiB, private {} -> {} KiB",
        before.working_set / 1024,
        after.working_set / 1024,
        before.private / 1024,
        after.private / 1024
    );
    assert!(kinds[STEP_DATA_ABORT as usize] > 1000);

    // Every case retranslates; dead-TB bookkeeping is freed when the code
    // buffer fills, so private memory must go up and down within a bound.
    let mut privs = vec![];
    for _ in 0..40 {
        run(o, &mut rng, 10_000);
        privs.push(mem_usage().private / 1024);
    }
    let (min, max) = (*privs.iter().min().unwrap(), *privs.iter().max().unwrap());
    println!("S3 private KiB after each further 10k (400k cases): min {min} max {max} {privs:?}");
    assert!(max <= before.private / 1024 + 8 * 1024, "private memory grew by more than 8 MiB");
    assert!(privs.windows(2).any(|w| w[1] < w[0]), "memory was never given back");
    movs_still_works(o);
}
