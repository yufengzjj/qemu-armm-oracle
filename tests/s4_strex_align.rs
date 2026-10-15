//! S4: alignment of the exclusive stores. ExclusiveMonitorsPass (DDI0553B.z
//! E2.1.125) checks alignment before the local monitor, so an unaligned
//! STREX, STREXH, STLEX or STLEXH is an UNALIGNED UsageFault whatever the
//! monitor state; STREXB and STLEXB never are. QEMU needs
//! patches/0002-unaligned-strex-fault.patch for the closed and mismatched
//! monitor cases.

mod common;
use common::*;
use qemu_armm_oracle::*;

const STREX: [u16; 2] = [0xe841, 0x3200]; // strex r2, r3, [r1]
const STREXH: [u16; 2] = [0xe8c1, 0x3f52]; // strexh r2, r3, [r1]
const STREXB: [u16; 2] = [0xe8c1, 0x3f42]; // strexb r2, r3, [r1]
const STLEX: [u16; 2] = [0xe8c1, 0x3fe2]; // stlex r2, r3, [r1]
const STLEXH: [u16; 2] = [0xe8c1, 0x3fd2]; // stlexh r2, r3, [r1]
const STLEXB: [u16; 2] = [0xe8c1, 0x3fc2]; // stlexb r2, r3, [r1]

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
