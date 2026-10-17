//! S4: the local exclusive monitor and the exclusive stores.
//!
//! Alignment: ExclusiveMonitorsPass (DDI0553B.z E2.1.125) checks alignment
//! before the local monitor, so an unaligned STREX, STREXH, STLEX or STLEXH
//! is an UNALIGNED UsageFault whatever the monitor state; STREXB and STLEXB
//! never are. QEMU needs patches/0002-unaligned-strex-fault.patch for the
//! closed and mismatched monitor cases.
//!
//! Plain stores: whether a store by the same PE that is not a
//! Store-Exclusive changes the local monitor is IMPLEMENTATION DEFINED
//! (B9.2). The Cortex-M55 monitor keeps its state (TRM 101051, 9.11), and
//! the pseudocode store path only clears the global monitor of other PEs.
//! QEMU needs patches/0003-plain-store-keeps-exclusive-monitor.patch:
//! without it STREX compares memory with the value LDREX read.
//!
//! Doubleword exclusives: Armv8-M has no LDREXD, STREXD, LDAEXD or STLEXD
//! (sz = 11 is missing from the T32 encoding tables). QEMU needs
//! patches/0006-m-profile-no-doubleword-exclusives.patch to make them
//! UNDEFINED; without it they run as on A-profile.

mod common;
use common::*;
use qemu_armm_oracle::*;

const STREX: [u16; 2] = [0xe841, 0x3200]; // strex r2, r3, [r1]
const STREXH: [u16; 2] = [0xe8c1, 0x3f52]; // strexh r2, r3, [r1]
const STREXB: [u16; 2] = [0xe8c1, 0x3f42]; // strexb r2, r3, [r1]
const STLEX: [u16; 2] = [0xe8c1, 0x3fe2]; // stlex r2, r3, [r1]
const STLEXH: [u16; 2] = [0xe8c1, 0x3fd2]; // stlexh r2, r3, [r1]
const STLEXB: [u16; 2] = [0xe8c1, 0x3fc2]; // stlexb r2, r3, [r1]

const LDREX: [u16; 2] = [0xe851, 0x0f00]; // ldrex r0, [r1]
const LDREXH: [u16; 2] = [0xe8d1, 0x0f5f]; // ldrexh r0, [r1]
const LDREXB: [u16; 2] = [0xe8d1, 0x0f4f]; // ldrexb r0, [r1]
const LDAEX: [u16; 2] = [0xe8d1, 0x0fef]; // ldaex r0, [r1]
const LDAEXH: [u16; 2] = [0xe8d1, 0x0fdf]; // ldaexh r0, [r1]
const LDAEXB: [u16; 2] = [0xe8d1, 0x0fcf]; // ldaexb r0, [r1]
const CLREX: [u16; 2] = [0xf3bf, 0x8f2f]; // clrex

/// Load-exclusive and store-exclusive pairs with their access size.
const PAIRS: [([u16; 2], [u16; 2], &str, u32); 6] = [
    (LDREX, STREX, "ldrex/strex", 4),
    (LDREXH, STREXH, "ldrexh/strexh", 2),
    (LDREXB, STREXB, "ldrexb/strexb", 1),
    (LDAEX, STLEX, "ldaex/stlex", 4),
    (LDAEXH, STLEXH, "ldaexh/stlexh", 2),
    (LDAEXB, STLEXB, "ldaexb/stlexb", 1),
];

/// Plain stores to [r1] and how many bytes each writes: r4 (or s0), then r5.
const PLAIN_STORES: [(&[u16], &str, usize); 7] = [
    (&[0x600c], "str r4, [r1]", 4),
    (&[0x800c], "strh r4, [r1]", 2),
    (&[0x700c], "strb r4, [r1]", 1),
    (&[0xe9c1, 0x4500], "strd r4, r5, [r1]", 8),
    (&[0xe881, 0x0030], "stm r1, {r4, r5}", 8),
    (&[0xe8c1, 0x4faf], "stl r4, [r1]", 4),
    (&[0xed81, 0x0a00], "vstr s0, [r1]", 4),
];

const BASE: u32 = DATA + 0x100;
const OTHER: u32 = DATA + 0x200;
const FILL: [u8; 16] = *b"\x10\x21\x32\x43\x54\x65\x76\x87\x98\xa9\xba\xcb\xdc\xed\xfe\x0f";
const FSR_WRITE: u32 = 0x800;

#[derive(Clone, Copy, Debug)]
enum Monitor {
    Closed,
    Other,
    Same,
}

/// Fill memory around BASE, set the monitor, point r1 at `addr` and step
/// `code` once. Rd = r2 starts as 0xdead, Rt = r3 holds the value to store.
fn step_strex(o: &mut Oracle, code: [u16; 2], addr: u32, size: u32, monitor: Monitor) -> RawStep {
    o.write_mem(BASE, &FILL).unwrap();
    o.write_mem(OTHER, &FILL).unwrap();
    o.set_exclusive(match monitor {
        Monitor::Closed => None,
        Monitor::Other => Some((OTHER, size)),
        Monitor::Same => Some((addr, size)),
    })
    .unwrap();
    o.set_r(1, addr);
    o.set_r(2, 0xdead);
    o.set_r(3, 0x5a5a_5a5a);
    o.write_mem(CODE, &thumb(&code)).unwrap();
    o.set_r(15, CODE);
    o.step_raw()
}

fn retires(o: &mut Oracle, code: [u16; 2], addr: u32, size: u32, monitor: Monitor) -> bool {
    outcome(&step_strex(o, code, addr, size, monitor)) == StepOutcome::Retired
}

fn memory_unchanged(o: &Oracle) -> bool {
    o.read_mem(BASE, FILL.len()).unwrap() == FILL
}

#[test]
fn unaligned_strex_faults_in_every_monitor_state() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (code, what, size) in [
        (STREX, "strex", 4),
        (STLEX, "stlex", 4),
        (STREXH, "strexh", 2),
        (STLEXH, "stlexh", 2),
    ] {
        for offset in (1..4).filter(|off| off % size != 0) {
            let addr = BASE + offset;
            for monitor in [Monitor::Closed, Monitor::Other, Monitor::Same] {
                let case = format!("{what} at {addr:#x}, monitor {monitor:?}");
                let r = step_strex(o, code, addr, size, monitor);
                match outcome(&r) {
                    StepOutcome::Fault { kind, .. } => {
                        assert_eq!(kind, FaultKind::Unaligned { addr }, "{case}")
                    }
                    StepOutcome::Retired => panic!("{case}: retired with r2 = {:#x}", o.get_r(2)),
                }
                assert_ne!(r.fsr & FSR_WRITE, 0, "{case}: reported as a store, fsr {:#x}", r.fsr);
                assert_eq!((r.pc, o.get_r(15)), (CODE, CODE), "{case}: pc stays on the instruction");
                assert_eq!(o.get_r(2), 0xdead, "{case}: Rd unchanged");
                assert!(memory_unchanged(o), "{case}: memory unchanged");
            }
        }
    }
}

#[test]
fn strexb_never_faults_on_alignment() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (code, what) in [(STREXB, "strexb"), (STLEXB, "stlexb")] {
        for offset in 0..4 {
            let addr = BASE + offset;
            for monitor in [Monitor::Closed, Monitor::Other] {
                let case = format!("{what} at {addr:#x}, monitor {monitor:?}");
                assert!(retires(o, code, addr, 1, monitor), "{case}");
                assert_eq!(o.get_r(2), 1, "{case}: store fails");
                assert!(memory_unchanged(o), "{case}: memory unchanged");
            }
            let case = format!("{what} at {addr:#x}, monitor marks it");
            assert!(retires(o, code, addr, 1, Monitor::Same), "{case}");
            assert_eq!(o.get_r(2), 0, "{case}: store done");
            let mut want = FILL;
            want[offset as usize] = 0x5a;
            assert_eq!(o.read_mem(BASE, FILL.len()).unwrap(), want, "{case}");
        }
    }
}

#[test]
fn aligned_strex_follows_the_monitor() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (code, what, size, addr) in [
        (STREX, "strex", 4, BASE + 4),
        (STLEX, "stlex", 4, BASE + 4),
        (STREXH, "strexh", 2, BASE + 2),
        (STLEXH, "stlexh", 2, BASE + 6),
    ] {
        for monitor in [Monitor::Closed, Monitor::Other] {
            let case = format!("{what} at {addr:#x}, monitor {monitor:?}");
            assert!(retires(o, code, addr, size, monitor), "{case}");
            assert_eq!(o.get_r(15), CODE + 4, "{case}");
            assert_eq!(o.get_r(2), 1, "{case}: store fails");
            assert!(memory_unchanged(o), "{case}: memory unchanged");
        }

        let case = format!("{what} at {addr:#x}, monitor marks it");
        assert!(retires(o, code, addr, size, Monitor::Same), "{case}");
        assert_eq!(o.get_r(2), 0, "{case}: store done");
        let mut want = FILL;
        let at = (addr - BASE) as usize;
        want[at..at + size as usize].copy_from_slice(&0x5a5a_5a5au32.to_le_bytes()[..size as usize]);
        assert_eq!(o.read_mem(BASE, FILL.len()).unwrap(), want, "{case}");
        assert_eq!(o.get_exclusive(), None, "{case}: monitor closed after the store");
    }
}

/// The marked address in the sequences below: aligned for every size.
const MARKED: u32 = BASE + 4;
const STREX_VALUE: u32 = 0x5a5a_5a5a;

/// Fill memory around BASE and OTHER, close the monitor, point r1 at
/// MARKED and put the store-exclusive value in r3.
fn start(o: &mut Oracle) {
    o.write_mem(BASE, &FILL).unwrap();
    o.write_mem(OTHER, &FILL).unwrap();
    o.set_exclusive(None).unwrap();
    o.set_r(1, MARKED);
    o.set_r(3, STREX_VALUE);
}

/// Run one store-exclusive and return Rd (r2, which starts as 0xdead).
fn strex(o: &mut Oracle, code: [u16; 2]) -> u32 {
    o.set_r(2, 0xdead);
    run1(o, &code);
    o.get_r(2)
}

/// FILL with `bytes` written at `addr` (inside BASE..BASE + 16).
fn with(mut mem: [u8; 16], addr: u32, bytes: &[u8]) -> [u8; 16] {
    let at = (addr - BASE) as usize;
    mem[at..at + bytes.len()].copy_from_slice(bytes);
    mem
}

fn base_mem(o: &Oracle) -> Vec<u8> {
    o.read_mem(BASE, FILL.len()).unwrap()
}

#[test]
fn plain_store_to_the_marked_address_keeps_the_monitor() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (ldrex, strex_code, pair, size) in PAIRS {
        for (store, what, len) in PLAIN_STORES {
            for same in [false, true] {
                let case = format!("{pair}, {what} of the {} value", if same { "same" } else { "other" });
                start(o);
                let (r4, r5) = if same {
                    (read32(o, MARKED), read32(o, MARKED + 4))
                } else {
                    (0x8899_aabb, 0xccdd_eeff)
                };
                o.set_r(4, r4);
                o.set_r(5, r5);
                o.set_s(0, r4);
                run1(o, &ldrex);
                assert_eq!(o.get_exclusive(), Some(MARKED), "{case}");
                run1(o, store);
                assert_eq!(o.get_exclusive(), Some(MARKED), "{case}: still open after the plain store");

                let stored = [r4.to_le_bytes(), r5.to_le_bytes()].concat();
                let after_plain = with(FILL, MARKED, &stored[..len]);
                assert_eq!(base_mem(o), after_plain, "{case}: plain store done");
                assert_eq!(strex(o, strex_code), 0, "{case}: store-exclusive succeeds");
                let want = with(after_plain, MARKED, &STREX_VALUE.to_le_bytes()[..size as usize]);
                assert_eq!(base_mem(o), want, "{case}: memory holds the store-exclusive value");
                assert_eq!(o.get_exclusive(), None, "{case}: monitor closed");
            }
        }
    }
}

#[test]
fn plain_store_to_another_address_keeps_the_monitor() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (ldrex, strex_code, pair, size) in PAIRS {
        start(o);
        o.set_r(4, 0x8899_aabb);
        o.set_r(5, OTHER);
        run1(o, &ldrex);
        run1(o, &[0x602c]); // str r4, [r5]
        assert_eq!(read32(o, OTHER), 0x8899_aabb, "{pair}");
        assert_eq!(strex(o, strex_code), 0, "{pair}: store-exclusive succeeds");
        assert_eq!(base_mem(o), with(FILL, MARKED, &STREX_VALUE.to_le_bytes()[..size as usize]), "{pair}");
    }
}

#[test]
fn clrex_closes_the_monitor() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (ldrex, strex_code, pair, _) in PAIRS {
        start(o);
        run1(o, &ldrex);
        run1(o, &CLREX);
        assert_eq!(o.get_exclusive(), None, "{pair}");
        assert_eq!(strex(o, strex_code), 1, "{pair}: store-exclusive fails");
        assert_eq!(base_mem(o), FILL, "{pair}: memory unchanged");
    }
}

#[test]
fn strex_to_another_address_fails() {
    // QEMU compares the marked address. That is one of the IMPLEMENTATION
    // DEFINED choices of B9.4; the Cortex-M55 monitor holds no address and
    // would store.
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (ldrex, strex_code, pair, _) in PAIRS {
        start(o);
        run1(o, &ldrex);
        o.set_r(1, MARKED + 4);
        assert_eq!(strex(o, strex_code), 1, "{pair}: store-exclusive fails");
        assert_eq!(base_mem(o), FILL, "{pair}: memory unchanged");
        assert_eq!(o.get_exclusive(), None, "{pair}: monitor closed");
    }
}

#[test]
fn second_strex_fails() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (ldrex, strex_code, pair, size) in PAIRS {
        start(o);
        run1(o, &ldrex);
        assert_eq!(strex(o, strex_code), 0, "{pair}: first store-exclusive");
        let want = with(FILL, MARKED, &STREX_VALUE.to_le_bytes()[..size as usize]);
        o.set_r(3, 0x1234_5678);
        assert_eq!(strex(o, strex_code), 1, "{pair}: second store-exclusive fails");
        assert_eq!(base_mem(o), want, "{pair}: memory keeps the first value");
    }
}

#[test]
fn set_exclusive_does_not_depend_on_memory() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (_, strex_code, pair, size) in PAIRS {
        let after_plain = with(FILL, MARKED, &0x8899_aabbu32.to_le_bytes());
        let want = with(after_plain, MARKED, &STREX_VALUE.to_le_bytes()[..size as usize]);

        // A guest store after the monitor was set
        start(o);
        o.set_exclusive(Some((MARKED, size))).unwrap();
        o.set_r(4, 0x8899_aabb);
        run1(o, &[0x600c]); // str r4, [r1]
        assert_eq!(strex(o, strex_code), 0, "{pair}: str after set_exclusive");
        assert_eq!(base_mem(o), want, "{pair}: str after set_exclusive");

        // A debug write after the monitor was set
        start(o);
        o.set_exclusive(Some((MARKED, size))).unwrap();
        o.write_mem(MARKED, &0x8899_aabbu32.to_le_bytes()).unwrap();
        assert_eq!(strex(o, strex_code), 0, "{pair}: write_mem after set_exclusive");
        assert_eq!(base_mem(o), want, "{pair}: write_mem after set_exclusive");
    }
}

#[test]
fn strex_memory_fault_is_a_store() {
    // ExclusiveMonitorsPass validates the address as a write.
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    let read_only = DATA + PAGE;
    let unmapped = DATA + 2 * PAGE;
    o.map(read_only, PAGE, PROT_READ).unwrap();
    for (code, what, size) in [(STREX, "strex", 4), (STREXH, "strexh", 2), (STREXB, "strexb", 1)] {
        for (addr, page) in [(read_only, "read-only"), (unmapped, "unmapped")] {
            let case = format!("{what} to the {page} page");
            o.map(unmapped, PAGE, PROT_READ | PROT_WRITE).unwrap();
            o.set_exclusive(Some((addr, size))).unwrap();
            o.unmap(unmapped, PAGE).unwrap();
            o.set_r(1, addr);
            o.set_r(2, 0xdead);
            o.write_mem(CODE, &thumb(&code)).unwrap();
            o.set_r(15, CODE);
            let r = o.step_raw();
            match outcome(&r) {
                StepOutcome::Fault { kind, .. } => assert_eq!(kind, FaultKind::DataAbort { addr }, "{case}"),
                StepOutcome::Retired => panic!("{case}: retired with r2 = {:#x}", o.get_r(2)),
            }
            assert_ne!(r.fsr & FSR_WRITE, 0, "{case}: reported as a store, fsr {:#x}", r.fsr);
            assert_eq!((o.get_r(2), o.get_r(15)), (0xdead, CODE), "{case}");
        }
    }
    assert_eq!(o.read_mem(read_only, 4).unwrap(), [0; 4], "read-only page unchanged");
}

#[test]
fn doubleword_exclusives_are_undefined() {
    let mut f = fixture();
    let o = &mut f.o;
    load(o, &thumb(&[0xbf00]));
    for (code, what) in [
        ([0xe8d1, 0x237f], "ldrexd r2, r3, [r1]"),
        ([0xe8d1, 0x23ff], "ldaexd r2, r3, [r1]"),
        ([0xe8c1, 0x2374], "strexd r4, r2, r3, [r1]"),
        ([0xe8c1, 0x23f4], "stlexd r4, r2, r3, [r1]"),
    ] {
        o.write_mem(BASE, &FILL).unwrap();
        o.set_exclusive(Some((BASE, 4))).unwrap();
        o.set_r(1, BASE);
        o.set_r(2, 0x2222_2222);
        o.set_r(3, 0x3333_3333);
        o.set_r(4, 0x4444_4444);
        o.write_mem(CODE, &thumb(&code)).unwrap();
        o.set_r(15, CODE);
        match outcome(&o.step_raw()) {
            StepOutcome::Fault { kind, .. } => assert_eq!(kind, FaultKind::Undefined, "{what}"),
            StepOutcome::Retired => panic!("{what}: retired"),
        }
        assert_eq!(
            [o.get_r(2), o.get_r(3), o.get_r(4), o.get_r(15)],
            [0x2222_2222, 0x3333_3333, 0x4444_4444, CODE],
            "{what}"
        );
        assert_eq!(o.read_mem(BASE, 16).unwrap(), FILL, "{what}: memory unchanged");
    }
}
