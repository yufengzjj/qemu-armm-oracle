//! S8: the backend-independent ArmMOracle interface, snapshots and diffs.

mod common;
use common::{fixture, thumb, CODE, DATA, PAGE, XPSR_T};
use qemu_armm_oracle::{
    diff_results, dll_path, ArmMOracle, CpuState, FaultKind, StepOutcome, PROT_EXEC, PROT_READ,
    PROT_WRITE,
};

/// Written against the trait only, as a diff harness would be.
fn movs_and_udf<O: ArmMOracle>(o: &mut O) {
    o.map(CODE, PAGE, PROT_READ | PROT_EXEC);
    o.write_mem(CODE, &thumb(&[0x2005, 0xde00])); // movs r0, #5; udf #0
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T);
    assert!(o.step().is_retired());
    assert_eq!(o.get_r(0), 5);
    assert_eq!(o.get_r(15), CODE + 2);
    let out = o.step();
    assert_eq!(out.fault_kind(), Some(FaultKind::Undefined), "{out:?}");
    assert!(out.is_comparable());
}

#[test]
fn generic_harness() {
    let mut f = fixture();
    assert_eq!(ArmMOracle::backend_name(&f.o), "qemu");
    movs_and_udf(&mut f.o);
}

#[test]
fn snapshot_restore_round_trip() {
    let mut f = fixture();
    let o = &mut f.o;
    let s = CpuState {
        r: std::array::from_fn(|i| 0x1000_0000 + i as u32 * 0x111),
        xpsr: 0xf80f_0000 | XPSR_T,
        q: std::array::from_fn(|i| 0x0123_4567_89ab_cdef_0011_2233_4455_6600 + i as u128),
        fpscr: 0x0002_0000 | (1 << 22),
        vpr: 0x0088_0f0f,
        control: 5,
        exclusive: None,
    };
    let mut want = s.clone();
    want.r[15] &= !1;
    ArmMOracle::restore(o, &s);
    let got = ArmMOracle::snapshot(o);
    assert_eq!(got, want, "{:?}", got.diff(&want));

    ArmMOracle::reset(o);
    let reset = ArmMOracle::snapshot(o);
    assert_eq!(reset.xpsr, XPSR_T);
    assert_eq!(reset.control, 5);
    assert_eq!(reset.fpscr, 0x0004_0000);

    ArmMOracle::map(o, DATA, PAGE, PROT_READ | PROT_WRITE);
    ArmMOracle::set_exclusive(o, Some((DATA + 8, 4)));
    assert_eq!(ArmMOracle::snapshot(o).exclusive, Some(DATA + 8));
    ArmMOracle::restore(o, &reset);
    assert_eq!(ArmMOracle::get_exclusive(o), Some(DATA + 8), "restore leaves the monitor");
    ArmMOracle::set_exclusive(o, None);
    assert_eq!(ArmMOracle::snapshot(o), reset);
}

#[test]
fn diff_names_fields() {
    let a = CpuState::default();
    assert!(a.diff(&a).is_empty());
    let mut b = a.clone();
    b.r[3] = 1;
    b.r[13] = 0x2000;
    b.q[7] = 1 << 100;
    b.fpscr = 1;
    b.exclusive = Some(0x20);
    let d = a.diff(&b);
    let fields: Vec<&str> = d.iter().map(|l| l.split(':').next().unwrap()).collect();
    assert_eq!(fields, ["r3", "sp", "fpscr", "q7", "exclusive"], "{d:?}");
}

#[test]
fn unimplemented_is_never_a_difference() {
    let s = CpuState::default();
    let mut t = s.clone();
    t.r[0] = 1;
    let fault = |kind| StepOutcome::Fault { kind, msg: String::new() };
    let unimpl = fault(FaultKind::Unimplemented);
    assert!(!unimpl.is_comparable());
    assert!(diff_results(&unimpl, &s, &StepOutcome::Retired, &t).is_empty());
    assert!(diff_results(&StepOutcome::Retired, &s, &unimpl, &t).is_empty());

    let d = diff_results(&StepOutcome::Retired, &s, &fault(FaultKind::Undefined), &t);
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d[0].starts_with("outcome:"));
    assert!(d[1].starts_with("r0:"));

    let other_msg = StepOutcome::Fault { kind: FaultKind::Undefined, msg: "x".into() };
    assert!(diff_results(&fault(FaultKind::Undefined), &s, &other_msg, &s).is_empty());
    let d = diff_results(
        &fault(FaultKind::DataAbort { addr: 4 }),
        &s,
        &fault(FaultKind::DataAbort { addr: 8 }),
        &s,
    );
    assert_eq!(d.len(), 1, "fault address is compared: {d:?}");
}

#[test]
fn dll_comes_from_build_script() {
    if std::env::var_os("ARMM_ORACLE_DLL").is_some() {
        return;
    }
    let p = dll_path().unwrap();
    assert!(p.is_file(), "{}", p.display());
    assert_eq!(p.parent().unwrap().file_name().unwrap(), "dist");
    for dep in ["libglib-2.0-0.dll", "libiconv-2.dll", "libintl-8.dll", "libpcre2-8-0.dll", "zlib1.dll"]
    {
        assert!(p.with_file_name(dep).is_file(), "{dep} next to the DLL");
    }
}
