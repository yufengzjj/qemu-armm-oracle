//! S4: T16/T32 base instructions and IT blocks. Expected values follow the
//! Armv8-M pseudocode (DDI0553B.z), not QEMU output.

mod common;
use common::*;
use qemu_armm_oracle::*;

fn setup(o: &mut Oracle) {
    load(o, &thumb(&[0xbf00]));
}

#[test]
fn add_sub_flags() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);

    o.set_r(1, 0x7fff_ffff);
    o.set_r(2, 1);
    run1(o, &[0x1888]); // adds r0, r1, r2
    assert_eq!(o.get_r(0), 0x8000_0000);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_N | FLAG_V);

    o.set_r(1, 5);
    o.set_r(2, 5);
    run1(o, &[0x1a88]); // subs r0, r1, r2
    assert_eq!(o.get_r(0), 0);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_Z | FLAG_C, "no borrow: C = 1");

    o.set_r(1, 0);
    o.set_r(2, 1);
    run1(o, &[0x1a88]);
    assert_eq!(o.get_r(0), 0xffff_ffff);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_N, "borrow: C = 0");

    o.set_xpsr(XPSR_T | FLAG_C);
    o.set_r(1, 0xffff_ffff);
    o.set_r(2, 0);
    run1(o, &[0xeb51, 0x0002]); // adcs.w r0, r1, r2
    assert_eq!(o.get_r(0), 0);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_Z | FLAG_C);
}

#[test]
fn shifts_and_carry() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);

    o.set_xpsr(XPSR_T | FLAG_V);
    o.set_r(1, 0x8000_0001);
    run1(o, &[0x0048]); // lsls r0, r1, #1
    assert_eq!(o.get_r(0), 2);
    assert_eq!(o.get_xpsr(), XPSR_T | FLAG_C | FLAG_V, "carry out of bit 31, V unchanged");

    // lsrs r0, r2: shift amount is R[2]<7:0>
    for (amount, result, flags) in [
        (32u32, 0u32, FLAG_Z | FLAG_C),
        (33, 0, FLAG_Z),
        (0x101, 0x4000_0000, 0),
        (0, 0x8000_0000, FLAG_N | FLAG_C),
    ] {
        o.set_xpsr(XPSR_T | FLAG_C);
        o.set_r(0, 0x8000_0000);
        o.set_r(2, amount);
        run1(o, &[0x40d0]);
        assert_eq!(o.get_r(0), result, "lsrs by {amount:#x}");
        assert_eq!(o.get_xpsr(), XPSR_T | flags, "lsrs by {amount:#x}");
    }
}

#[test]
fn bitfield_and_bit_ops() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);

    o.set_r(1, 0x1234_5678);
    run1(o, &[0xf3c1, 0x1007]); // ubfx r0, r1, #4, #8
    assert_eq!(o.get_r(0), 0x67);

    o.set_r(1, 0x0000_0f80);
    run1(o, &[0xf341, 0x1007]); // sbfx r0, r1, #4, #8
    assert_eq!(o.get_r(0), 0xffff_fff8);

    o.set_r(0, 0xffff_ffff);
    o.set_r(1, 5);
    run1(o, &[0xf361, 0x200b]); // bfi r0, r1, #8, #4
    assert_eq!(o.get_r(0), 0xffff_f5ff);

    o.set_r(1, 1);
    run1(o, &[0xfa91, 0xf0a1]); // rbit r0, r1
    assert_eq!(o.get_r(0), 0x8000_0000);

    o.set_r(1, 0x0001_0000);
    run1(o, &[0xfab1, 0xf081]); // clz r0, r1
    assert_eq!(o.get_r(0), 15);

    o.set_r(1, 0x1122_3344);
    run1(o, &[0xba48]); // rev16 r0, r1
    assert_eq!(o.get_r(0), 0x2211_4433);
    assert_eq!(o.get_xpsr(), XPSR_T, "none of these set flags");
}

#[test]
fn multiply_and_divide() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);

    // udiv r0, r1, r2; sdiv r0, r1, r2
    for (code, n, m, q) in [
        ([0xfbb1u16, 0xf0f2], 100u32, 7u32, 14u32),
        ([0xfbb1, 0xf0f2], 7, 0, 0),
        ([0xfb91, 0xf0f2], 0x8000_0000, 0xffff_ffff, 0x8000_0000),
        ([0xfb91, 0xf0f2], -7i32 as u32, 2, -3i32 as u32),
        ([0xfb91, 0xf0f2], 7, 0, 0),
    ] {
        o.set_r(1, n);
        o.set_r(2, m);
        run1(o, &code);
        assert_eq!(o.get_r(0), q, "{code:x?} {n:#x} / {m:#x}");
    }

    o.set_r(2, 0xffff_ffff);
    o.set_r(3, 0xffff_ffff);
    run1(o, &[0xfba2, 0x0103]); // umull r0, r1, r2, r3
    assert_eq!((o.get_r(0), o.get_r(1)), (1, 0xffff_fffe));

    o.set_r(0, 0xffff_ffff);
    o.set_r(1, 0);
    o.set_r(2, -1i32 as u32);
    o.set_r(3, 2);
    run1(o, &[0xfbc2, 0x0103]); // smlal r0, r1, r2, r3
    assert_eq!((o.get_r(0), o.get_r(1)), (0xffff_fffd, 0));

    o.set_r(1, 3);
    o.set_r(2, 4);
    o.set_r(3, 100);
    run1(o, &[0xfb01, 0x3012]); // mls r0, r1, r2, r3
    assert_eq!(o.get_r(0), 88);
}

#[test]
fn loads_stores_and_stack() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);
    o.write_mem(DATA, &(0u8..64).collect::<Vec<u8>>()).unwrap();
    o.write_mem(DATA + 2, &[0x01, 0x80]).unwrap();
    write32s(o, DATA + 8, &[0x1111_1111, 0x2222_2222]);

    o.set_r(1, DATA);
    run1(o, &[0xf9b1, 0x0002]); // ldrsh.w r0, [r1, #2]
    assert_eq!(o.get_r(0), 0xffff_8001);

    run1(o, &[0xe9d1, 0x2302]); // ldrd r2, r3, [r1, #8]
    assert_eq!((o.get_r(2), o.get_r(3)), (0x1111_1111, 0x2222_2222));

    o.set_r(1, DATA + 0x20);
    o.set_r(2, 0xaaaa_aaaa);
    o.set_r(3, 0xbbbb_bbbb);
    run1(o, &[0xe961, 0x2302]); // strd r2, r3, [r1, #-8]!
    assert_eq!(o.get_r(1), DATA + 0x18);
    assert_eq!((read32(o, DATA + 0x18), read32(o, DATA + 0x1c)), (0xaaaa_aaaa, 0xbbbb_bbbb));

    // Unaligned LDR is allowed (CCR.UNALIGN_TRP = 0); LDRD would fault (S3).
    o.set_r(1, DATA + 0x21);
    run1(o, &[0x6808]); // ldr r0, [r1]
    assert_eq!(o.get_r(0), 0x2423_2221);

    // push {r4, r5, lr}; pop {r4, r5, pc}
    o.write_mem(CODE, &thumb(&[0xb530, 0xbd30])).unwrap();
    o.set_r(13, DATA + 0x100);
    o.set_r(4, 4);
    o.set_r(5, 5);
    o.set_r(14, CODE + 0x41);
    o.set_r(15, CODE);
    retire(o);
    assert_eq!(o.get_r(13), DATA + 0xf4);
    assert_eq!(read32(o, DATA + 0xfc), CODE + 0x41);
    o.set_r(4, 0);
    o.set_r(5, 0);
    retire(o);
    assert_eq!((o.get_r(4), o.get_r(5), o.get_r(13)), (4, 5, DATA + 0x100));
    assert_eq!(o.get_r(15), CODE + 0x40, "pop pc interworks, bit 0 selects Thumb");
    assert_eq!(o.get_xpsr() & XPSR_T, XPSR_T);
}

#[test]
fn branches() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);

    run1(o, &[0xf000, 0xf802]); // bl +8
    assert_eq!(o.get_r(15), CODE + 8);
    assert_eq!(o.get_r(14), CODE + 5);

    o.set_r(2, CODE + 0x101);
    run1(o, &[0x4790]); // blx r2
    assert_eq!(o.get_r(15), CODE + 0x100);
    assert_eq!(o.get_r(14), CODE + 3);

    for (r0, pc) in [(0, CODE + 6), (1, CODE + 2)] {
        o.set_r(0, r0);
        run1(o, &[0xb108]); // cbz r0, +6
        assert_eq!(o.get_r(15), pc, "cbz with r0 = {r0}");
    }

    // tbb [pc, r0] with table {2, 3} right after it
    for (r0, pc) in [(0, CODE + 8), (1, CODE + 10)] {
        o.set_r(0, r0);
        run1(o, &[0xe8df, 0xf000, 0x0302]);
        assert_eq!(o.get_r(15), pc, "tbb index {r0}");
    }

    // bx to an even address clears EPSR.T; the next instruction is INVSTATE.
    o.set_r(2, CODE + 0x100);
    run1(o, &[0x4710]); // bx r2
    assert_eq!(o.get_r(15), CODE + 0x100);
    assert_eq!(o.get_xpsr() & XPSR_T, 0);
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_INVALID_STATE, CODE + 0x100));
}

#[test]
fn it_instruction_sets_itstate() {
    let mut f = fixture();
    let o = &mut f.o;
    // ite eq; moveq r0, #1; movne r0, #2
    let code = [0xbf0c, 0x2001, 0x2002];
    for z in [true, false] {
        load(o, &thumb(&code));
        let flags = if z { FLAG_Z } else { 0 };
        o.set_xpsr(XPSR_T | flags);
        o.set_r(0, 0xdead);
        retire(o);
        assert_eq!(o.get_xpsr(), XPSR_T | flags | it_bits(0x0c), "ITSTATE = firstcond:mask");
        retire(o);
        assert_eq!(o.get_xpsr(), XPSR_T | flags | it_bits(it_advance(0x0c)));
        retire(o);
        assert_eq!(o.get_xpsr(), XPSR_T | flags, "IT block finished, MOV in IT sets no flags");
        assert_eq!(o.get_r(0), if z { 1 } else { 2 });
        assert_eq!(o.get_r(15), CODE + 6);
    }
}

#[test]
fn it_state_from_xpsr() {
    let mut f = fixture();
    let o = &mut f.o;
    // itete gt (0xcb) without the IT instruction: addgt r0, #1; addle r1, #1;
    // addgt.w r2, r2, #1; ldrle r3, [r4]
    let body = [0x3001, 0x3101, 0xf102, 0x0201, 0x6823];
    for gt in [true, false] {
        load(o, &thumb(&body));
        let flags = if gt { 0 } else { FLAG_Z };
        o.set_xpsr(XPSR_T | flags | it_bits(0xcb));
        for r in 0..4 {
            o.set_r(r, 0);
        }
        o.set_r(4, if gt { 0x0010_0000 } else { DATA }); // unmapped when the load is skipped
        write32s(o, DATA, &[0x5555_5555]);
        let mut it = 0xcbu8;
        for _ in 0..4 {
            retire(o);
            it = it_advance(it);
            assert_eq!(o.get_xpsr(), XPSR_T | flags | it_bits(it));
        }
        assert_eq!(it, 0);
        assert_eq!(o.get_r(15), CODE + 10);
        let expect = if gt { [1, 0, 1, 0] } else { [0, 1, 0, 0x5555_5555] };
        assert_eq!([o.get_r(0), o.get_r(1), o.get_r(2), o.get_r(3)], expect, "gt = {gt}");
    }
}

#[test]
fn branch_at_end_of_it_block() {
    let mut f = fixture();
    let o = &mut f.o;
    // it ne; bne +8 (the branch is the T2 unconditional encoding)
    for (z, pc) in [(true, CODE + 4), (false, CODE + 8)] {
        load(o, &thumb(&[0xbf18, 0xe001]));
        let flags = if z { FLAG_Z } else { 0 };
        o.set_xpsr(XPSR_T | flags);
        retire(o);
        retire(o);
        assert_eq!(o.get_r(15), pc);
        assert_eq!(o.get_xpsr(), XPSR_T | flags);
    }
}

#[test]
fn epsr_bits_round_trip() {
    let mut f = fixture();
    let o = &mut f.o;
    setup(o);
    let mut rng = Rng(0x5eed);
    // NZCVQ, IT/ICI/ECI, T, GE; IPSR reads 0 in Thread mode.
    let defined = 0xff0f_fc00u32;
    for _ in 0..1000 {
        let v = rng.u32() & defined | XPSR_T;
        o.set_xpsr(v);
        assert_eq!(o.get_xpsr(), v);
    }
    o.set_xpsr(XPSR_T | 0x1ff);
    assert_eq!(o.get_xpsr(), XPSR_T, "IPSR is ignored on write");
}

#[test]
fn ici_on_ldm_restarts() {
    let mut f = fixture();
    let o = &mut f.o;
    // ldm r1!, {r0, r2} with EPSR.ICI naming r2 (ICI[7:4] = 2): QEMU takes the
    // IMPDEF "instruction restart" choice, runs the whole LDM and clears ICI.
    load(o, &thumb(&[0xc905]));
    write32s(o, DATA, &[0x1111_1111, 0x2222_2222]);
    o.set_r(1, DATA);
    o.set_xpsr(XPSR_T | it_bits(0x20));
    retire(o);
    assert_eq!((o.get_r(0), o.get_r(1), o.get_r(2)), (0x1111_1111, DATA + 8, 0x2222_2222));
    assert_eq!(o.get_xpsr(), XPSR_T);

    // A non-continuable instruction with nonzero ICI/ECI is INVSTATE (B3.27.7).
    load(o, &thumb(&[0x2005])); // movs r0, #5
    o.set_xpsr(XPSR_T | it_bits(0x20));
    let r = o.step_raw();
    assert_eq!((r.kind, r.pc), (STEP_INVALID_STATE, CODE));
}
