//! S1: the DLL loads without PATH and every API function can be called.

mod common;
use common::*;
use qemu_armm_oracle::{Oracle, PROT_READ, PROT_WRITE};

#[test]
fn second_oracle_and_other_model_are_refused() {
    let _guard = lock();
    let o = Oracle::new("cortex-m55").unwrap();
    let err = Oracle::new("cortex-m55").err().unwrap();
    assert!(err.contains("already exists"), "{err}");
    drop(o);
    let err = Oracle::new("cortex-m4").err().unwrap();
    assert!(err.contains("already uses"), "{err}");
    let o = Oracle::new("cortex-m55").unwrap();
    drop(o);
}

#[test]
fn register_round_trip() {
    let mut f = fixture();
    let o = &mut f.o;
    for n in 0..15 {
        o.set_r(n, 0x1111_0000 + n);
        assert_eq!(o.get_r(n), 0x1111_0000 + n);
    }
    o.set_r(15, 0x2001);
    assert_eq!(o.get_r(15), 0x2000);

    o.set_xpsr(0xf80f_0000 | XPSR_T);
    assert_eq!(o.get_xpsr(), 0xf80f_0000 | XPSR_T);
    // IT bits: ITSTATE = 0x18 split as IT[1:0] at 26:25, IT[7:2] at 15:10.
    let it = (0x0 << 25) | (0x18 >> 2 << 10);
    o.set_xpsr(XPSR_T | it);
    assert_eq!(o.get_xpsr(), XPSR_T | it);

    o.set_q(3, 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
    assert_eq!(o.get_q(3), 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
    assert_eq!(o.get_d(6), 0xfedc_ba98_7654_3210);
    assert_eq!(o.get_d(7), 0x0123_4567_89ab_cdef);
    assert_eq!(o.get_s(12), 0x7654_3210);
    assert_eq!(o.get_s(13), 0xfedc_ba98);
    o.set_s(15, 0xdead_beef);
    assert_eq!(o.get_d(7), 0xdead_beef_89ab_cdef);

    o.set_fpscr(0x0004_0000 | (1 << 22));
    assert_eq!(o.get_fpscr(), 0x0004_0000 | (1 << 22));
    o.set_vpr(0x00ff_00ff);
    assert_eq!(o.get_vpr(), 0x00ff_00ff);
    assert_eq!(o.get_control() & 4, 4, "FPCA set at reset");
}

#[test]
fn reset_state() {
    let mut f = fixture();
    let o = &mut f.o;
    o.set_r(3, 7);
    o.reset();
    assert_eq!(o.get_r(3), 0);
    assert_eq!(o.get_xpsr(), XPSR_T);
    assert_eq!(o.get_fpscr(), 0x0004_0000, "LTPSIZE = 4");
    assert_eq!(o.get_vpr(), 0);
    assert_eq!(o.get_control(), 5, "FPCA, and nPRIV because the guest is unprivileged");
    assert_eq!(o.get_exclusive(), None);
}

#[test]
fn memory_map_write_read() {
    let mut f = fixture();
    let o = &mut f.o;
    assert!(o.read_mem(DATA, 4).is_err(), "unmapped");
    o.map(DATA, 2 * PAGE, PROT_READ | PROT_WRITE).unwrap();
    assert_eq!(o.read_mem(DATA, 8).unwrap(), vec![0; 8], "new pages are zero");
    let data: Vec<u8> = (0..=255).collect();
    o.write_mem(DATA + PAGE - 100, &data).unwrap();
    assert_eq!(o.read_mem(DATA + PAGE - 100, 256).unwrap(), data);
    // read-only pages can still be written through the debug interface
    o.map(DATA, PAGE, PROT_READ).unwrap();
    o.write_mem(DATA, &[1, 2, 3, 4]).unwrap();
    assert_eq!(o.read_mem(DATA, 4).unwrap(), vec![1, 2, 3, 4]);
    o.unmap(DATA, 2 * PAGE).unwrap();
    assert!(o.read_mem(DATA, 4).is_err());
    o.map(DATA, PAGE, PROT_READ).unwrap();
    assert_eq!(o.read_mem(DATA, 4).unwrap(), vec![0; 4], "remapped after unmap is zero");
}
