//! Rust side of qemu-armm-oracle (spike): loads `armm_oracle.dll` at run
//! time and wraps the C API of `include/armm_oracle.h`.
//!
//! [`ArmMOracle`] is the backend-independent interface; [`Oracle`] is the
//! QEMU backend and also keeps the full low-level API (s/d registers, page
//! permissions, raw step results).
//!
//! build.rs builds the DLL into its OUT_DIR; `$ARMM_ORACLE_DLL` overrides the
//! path at run time. The runtime DLLs (glib etc.) must sit in the same
//! directory as the DLL; PATH is not searched.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::PathBuf;
use std::sync::OnceLock;

pub const API_VERSION: i32 = 2;

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
pub const PROT_RWX: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// `armm_step_result` of the C API.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawStep {
    pub kind: u32,
    pub excp: i32,
    pub pc: u32,
    pub fault_addr: u32,
    pub fsr: u32,
    reserved: u32,
}

pub const STEP_RETIRED: u32 = 0;
pub const STEP_UNDEFINED: u32 = 1;
pub const STEP_NO_COPROCESSOR: u32 = 2;
pub const STEP_INVALID_STATE: u32 = 3;
pub const STEP_DATA_ABORT: u32 = 4;
pub const STEP_PREFETCH_ABORT: u32 = 5;
pub const STEP_SVC: u32 = 6;
pub const STEP_BKPT: u32 = 7;
pub const STEP_OTHER: u32 = 8;

/// Why a step did not retire. The comments give the exception a real
/// M-profile PE would take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultKind {
    /// UsageFault UNDEFINSTR.
    Undefined,
    /// UsageFault NOCP.
    NoCoprocessor,
    /// UsageFault INVSTATE (EPSR.T = 0, bad ICI/ECI, LE with LTPSIZE != 4).
    InvalidState,
    /// UsageFault UNALIGNED: the instruction requires an aligned address.
    Unaligned { addr: u32 },
    /// Data access to an unmapped page or one without the needed
    /// permission: MemManage (DACCVIOL) or BusFault on real hardware.
    DataAbort { addr: u32 },
    /// Instruction fetch from an unmapped or non-executable page:
    /// MemManage (IACCVIOL) or BusFault (IBUSERR) on real hardware.
    PrefetchAbort { addr: u32 },
    /// SVCall; pc is already past the SVC.
    Svc,
    /// DebugMonitor or HardFault; pc is still on the BKPT.
    Bkpt,
    /// Any other QEMU exception: not a usable reference result.
    Unimplemented,
}

/// QEMU short-format FSR status for an alignment fault (FS = 0b00001).
const FSR_STATUS_MASK: u32 = 0x40f;
const FSR_ALIGNMENT: u32 = 0x001;

/// Classify a raw step result.
pub fn outcome(r: &RawStep) -> StepOutcome {
    let kind = match r.kind {
        STEP_RETIRED => return StepOutcome::Retired,
        STEP_UNDEFINED => FaultKind::Undefined,
        STEP_NO_COPROCESSOR => FaultKind::NoCoprocessor,
        STEP_INVALID_STATE => FaultKind::InvalidState,
        STEP_DATA_ABORT if r.fsr & FSR_STATUS_MASK == FSR_ALIGNMENT => {
            FaultKind::Unaligned { addr: r.fault_addr }
        }
        STEP_DATA_ABORT => FaultKind::DataAbort { addr: r.fault_addr },
        STEP_PREFETCH_ABORT => FaultKind::PrefetchAbort { addr: r.fault_addr },
        STEP_SVC => FaultKind::Svc,
        STEP_BKPT => FaultKind::Bkpt,
        _ => FaultKind::Unimplemented,
    };
    StepOutcome::Fault {
        kind,
        msg: format!("QEMU exception {} at pc {:#010x}, fsr {:#x}", r.excp, r.pc, r.fsr),
    }
}

impl FaultKind {
    /// False for [`FaultKind::Unimplemented`], which says nothing about the
    /// instruction's semantics.
    pub fn is_architectural(self) -> bool {
        self != FaultKind::Unimplemented
    }
}

/// What one [`ArmMOracle::step`] did. `msg` is backend-specific free text;
/// compare `kind`, not `msg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Retired,
    Fault { kind: FaultKind, msg: String },
}

impl StepOutcome {
    pub fn is_retired(&self) -> bool {
        matches!(self, StepOutcome::Retired)
    }

    pub fn fault_kind(&self) -> Option<FaultKind> {
        match self {
            StepOutcome::Retired => None,
            StepOutcome::Fault { kind, .. } => Some(*kind),
        }
    }

    /// False when the backend could not run the case (`Unimplemented`);
    /// such a result is never counted as a difference.
    pub fn is_comparable(&self) -> bool {
        self.fault_kind().is_none_or(FaultKind::is_architectural)
    }
}

const R_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr",
    "pc",
];

/// The architectural state a diff normally checks. Memory is not included;
/// compare the addresses a case writes explicitly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuState {
    /// r0–r15; r13 is the current stack pointer, r15 the pc.
    pub r: [u32; 16],
    pub xpsr: u32,
    /// q0–q7, which are also d0–d15 and s0–s31.
    pub q: [u128; 8],
    pub fpscr: u32,
    pub vpr: u32,
    pub control: u32,
    /// Address marked by the local exclusive monitor; `None` when it is closed.
    pub exclusive: Option<u32>,
}

impl CpuState {
    /// One line per field that differs ("r3: 0x1 vs 0x2"); empty iff equal.
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        for (i, name) in R_NAMES.iter().enumerate() {
            if self.r[i] != other.r[i] {
                out.push(format!("{name}: {:#x} vs {:#x}", self.r[i], other.r[i]));
            }
        }
        let words = [
            ("xpsr", self.xpsr, other.xpsr),
            ("fpscr", self.fpscr, other.fpscr),
            ("vpr", self.vpr, other.vpr),
            ("control", self.control, other.control),
        ];
        for (name, a, b) in words {
            if a != b {
                out.push(format!("{name}: {a:#x} vs {b:#x}"));
            }
        }
        for i in 0..8 {
            if self.q[i] != other.q[i] {
                out.push(format!("q{i}: {:#034x} vs {:#034x}", self.q[i], other.q[i]));
            }
        }
        if self.exclusive != other.exclusive {
            out.push(format!("exclusive: {:x?} vs {:x?}", self.exclusive, other.exclusive));
        }
        out
    }
}

/// Differences between two backends' results for the same case: the step
/// outcome first, then the state. Empty when either outcome is not
/// comparable ([`StepOutcome::is_comparable`]).
pub fn diff_results(a: &StepOutcome, sa: &CpuState, b: &StepOutcome, sb: &CpuState) -> Vec<String> {
    if !a.is_comparable() || !b.is_comparable() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if a.fault_kind() != b.fault_kind() {
        out.push(format!("outcome: {a:?} vs {b:?}"));
    }
    out.extend(sa.diff(sb));
    out
}

/// One Armv8.1-M reference CPU. The guest runs in Non-secure unprivileged
/// Thread mode with the FPU enabled (CONTROL.FPCA = 1); faults do not enter
/// a handler, they end the step with [`StepOutcome::Fault`].
///
/// Arguments out of range and memory accesses to unmapped pages are caller
/// bugs and panic.
pub trait ArmMOracle {
    fn backend_name(&self) -> &'static str;

    /// Back to the reset state: registers zero, xPSR = T, FPSCR.LTPSIZE = 4,
    /// VPR = 0, CONTROL = nPRIV | FPCA, monitor closed. Mappings stay.
    fn reset(&mut self);

    /// r0–r15; r13 is the current stack pointer. Writing r15 clears bit 0.
    fn set_r(&mut self, n: u32, v: u32);
    fn get_r(&self, n: u32) -> u32;

    /// NZCVQ, GE, EPSR (T, IT/ICI/ECI). IPSR reads 0 and ignores writes.
    fn set_xpsr(&mut self, v: u32);
    fn get_xpsr(&self) -> u32;

    /// q0–q7, which are also d0–d15 and s0–s31.
    fn set_q(&mut self, n: u32, v: u128);
    fn get_q(&self, n: u32) -> u128;

    /// Includes LTPSIZE.
    fn set_fpscr(&mut self, v: u32);
    fn get_fpscr(&self) -> u32;

    /// P0 and MASK01/MASK23.
    fn set_vpr(&mut self, v: u32);
    fn get_vpr(&self) -> u32;

    /// nPRIV always reads 1. Writing SPSEL does not switch stack pointers.
    fn set_control(&mut self, v: u32);
    fn get_control(&self) -> u32;

    /// Open the local exclusive monitor as an LDREX of `size` bytes (1, 2 or
    /// 4) at `addr` would, or close it with `None`. Memory contents do not
    /// matter: a STREX to the marked address succeeds.
    fn set_exclusive(&mut self, mark: Option<(u32, u32)>);
    /// Address marked by the monitor, or `None` when it is closed.
    fn get_exclusive(&self) -> Option<u32>;

    /// Map `[addr, addr + len)`, rounded out to 4 KiB pages, with
    /// [`PROT_READ`] / [`PROT_WRITE`] / [`PROT_EXEC`]. Remapping changes only
    /// the permissions; newly mapped pages read as zero.
    fn map(&mut self, addr: u32, len: u32, prot: u32);
    fn unmap(&mut self, addr: u32, len: u32);

    /// Debug access: ignores guest permissions, but the pages must be mapped.
    fn write_mem(&mut self, addr: u32, data: &[u8]);
    fn read_mem(&self, addr: u32, len: usize) -> Vec<u8>;

    /// Execute the instruction at pc.
    fn step(&mut self) -> StepOutcome;

    fn snapshot(&self) -> CpuState {
        CpuState {
            r: std::array::from_fn(|i| self.get_r(i as u32)),
            xpsr: self.get_xpsr(),
            q: std::array::from_fn(|i| self.get_q(i as u32)),
            fpscr: self.get_fpscr(),
            vpr: self.get_vpr(),
            control: self.get_control(),
            exclusive: self.get_exclusive(),
        }
    }

    /// Load everything [`snapshot`](Self::snapshot) captures except the
    /// exclusive monitor, which also needs an access size: use
    /// [`set_exclusive`](Self::set_exclusive).
    fn restore(&mut self, s: &CpuState) {
        self.set_control(s.control);
        for (i, &v) in s.r.iter().enumerate() {
            self.set_r(i as u32, v);
        }
        self.set_xpsr(s.xpsr);
        for (i, &v) in s.q.iter().enumerate() {
            self.set_q(i as u32, v);
        }
        self.set_fpscr(s.fpscr);
        self.set_vpr(s.vpr);
    }
}

type Handle = *mut c_void;

struct Api {
    api_version: unsafe extern "C" fn() -> c_int,
    last_error: unsafe extern "C" fn() -> *const c_char,
    create: unsafe extern "C" fn(*const c_char) -> Handle,
    destroy: unsafe extern "C" fn(Handle),
    reset: unsafe extern "C" fn(Handle) -> c_int,
    get_r: unsafe extern "C" fn(Handle, u32) -> u32,
    set_r: unsafe extern "C" fn(Handle, u32, u32) -> c_int,
    get_xpsr: unsafe extern "C" fn(Handle) -> u32,
    set_xpsr: unsafe extern "C" fn(Handle, u32) -> c_int,
    get_q: unsafe extern "C" fn(Handle, u32, *mut u64, *mut u64) -> c_int,
    set_q: unsafe extern "C" fn(Handle, u32, u64, u64) -> c_int,
    get_d: unsafe extern "C" fn(Handle, u32) -> u64,
    set_d: unsafe extern "C" fn(Handle, u32, u64) -> c_int,
    get_s: unsafe extern "C" fn(Handle, u32) -> u32,
    set_s: unsafe extern "C" fn(Handle, u32, u32) -> c_int,
    get_fpscr: unsafe extern "C" fn(Handle) -> u32,
    set_fpscr: unsafe extern "C" fn(Handle, u32) -> c_int,
    get_vpr: unsafe extern "C" fn(Handle) -> u32,
    set_vpr: unsafe extern "C" fn(Handle, u32) -> c_int,
    get_control: unsafe extern "C" fn(Handle) -> u32,
    set_control: unsafe extern "C" fn(Handle, u32) -> c_int,
    get_exclusive: unsafe extern "C" fn(Handle, *mut u32) -> c_int,
    set_exclusive: unsafe extern "C" fn(Handle, u32, u32) -> c_int,
    map: unsafe extern "C" fn(Handle, u32, u32, u32) -> c_int,
    unmap: unsafe extern "C" fn(Handle, u32, u32) -> c_int,
    write_mem: unsafe extern "C" fn(Handle, u32, *const c_void, usize) -> c_int,
    read_mem: unsafe extern "C" fn(Handle, u32, *mut c_void, usize) -> c_int,
    step: unsafe extern "C" fn(Handle, *mut RawStep) -> c_int,
    flush_tb: unsafe extern "C" fn(Handle) -> c_int,
}

pub fn dll_path() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("ARMM_ORACLE_DLL") {
        return Ok(PathBuf::from(p));
    }
    match option_env!("ARMM_ORACLE_DLL_DIR") {
        Some(dir) => Ok(PathBuf::from(dir).join("armm_oracle.dll")),
        None => Err(format!(
            "qemu-armm-oracle: oracle DLL not built: {}",
            option_env!("ARMM_ORACLE_NOT_BUILT").unwrap_or("unknown reason")
        )),
    }
}

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    pub struct Library(*mut c_void);

    // The module handle is process-wide and never unloaded.
    unsafe impl Send for Library {}
    unsafe impl Sync for Library {}

    impl Library {
        /// Dependencies are searched in the DLL's own directory and the
        /// system directories only, never PATH.
        pub fn open(path: &Path) -> Result<Library, String> {
            let abs = std::path::absolute(path).map_err(|e| e.to_string())?;
            let wide: Vec<u16> = abs.as_os_str().encode_wide().chain(Some(0)).collect();
            let h = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
            if h.is_null() {
                let err = unsafe { GetLastError() };
                return Err(format!("LoadLibraryExW({}) failed: error {err}", abs.display()));
            }
            Ok(Library(h))
        }

        pub fn symbol(&self, name: &str) -> Result<*mut c_void, String> {
            let cname: Vec<u8> = name.bytes().chain(Some(0)).collect();
            let p = unsafe { GetProcAddress(self.0, cname.as_ptr()) };
            if p.is_null() {
                Err(format!("symbol {name} not found"))
            } else {
                Ok(p)
            }
        }
    }
}

#[cfg(not(windows))]
mod sys {
    use std::ffi::c_void;
    use std::path::Path;

    pub struct Library;

    impl Library {
        pub fn open(_path: &Path) -> Result<Library, String> {
            Err("only the Windows build of the oracle exists so far".into())
        }

        pub fn symbol(&self, _name: &str) -> Result<*mut c_void, String> {
            unreachable!()
        }
    }
}

fn load_api() -> Result<Api, String> {
    let lib = sys::Library::open(&dll_path()?)?;
    macro_rules! sym {
        ($name:literal) => {
            // SAFETY: the symbol is the C function of that name in
            // armm_oracle.h, whose signature matches the field type.
            unsafe { std::mem::transmute::<*mut c_void, _>(lib.symbol($name)?) }
        };
    }
    let api = Api {
        api_version: sym!("armm_api_version"),
        last_error: sym!("armm_last_error"),
        create: sym!("armm_create"),
        destroy: sym!("armm_destroy"),
        reset: sym!("armm_reset"),
        get_r: sym!("armm_get_r"),
        set_r: sym!("armm_set_r"),
        get_xpsr: sym!("armm_get_xpsr"),
        set_xpsr: sym!("armm_set_xpsr"),
        get_q: sym!("armm_get_q"),
        set_q: sym!("armm_set_q"),
        get_d: sym!("armm_get_d"),
        set_d: sym!("armm_set_d"),
        get_s: sym!("armm_get_s"),
        set_s: sym!("armm_set_s"),
        get_fpscr: sym!("armm_get_fpscr"),
        set_fpscr: sym!("armm_set_fpscr"),
        get_vpr: sym!("armm_get_vpr"),
        set_vpr: sym!("armm_set_vpr"),
        get_control: sym!("armm_get_control"),
        set_control: sym!("armm_set_control"),
        get_exclusive: sym!("armm_get_exclusive"),
        set_exclusive: sym!("armm_set_exclusive"),
        map: sym!("armm_map"),
        unmap: sym!("armm_unmap"),
        write_mem: sym!("armm_write_mem"),
        read_mem: sym!("armm_read_mem"),
        step: sym!("armm_step"),
        flush_tb: sym!("armm_flush_tb"),
    };
    // The library stays loaded for the life of the process.
    std::mem::forget(lib);
    let version = unsafe { (api.api_version)() };
    if version != API_VERSION {
        return Err(format!("DLL API version {version}, expected {API_VERSION}"));
    }
    Ok(api)
}

fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load_api).as_ref().map_err(Clone::clone)
}

/// The QEMU backend of [`ArmMOracle`], plus the low-level API of the DLL.
/// One oracle per process; creating a second one while the first is alive
/// fails. Not `Send`: keep it on one thread at a time.
pub struct Oracle {
    api: &'static Api,
    h: Handle,
}

fn check(api: &Api, rc: c_int, what: &str) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed ({rc}): {}", last_error(api)))
    }
}

fn last_error(api: &Api) -> String {
    unsafe { CStr::from_ptr((api.last_error)()) }.to_string_lossy().into_owned()
}

impl Oracle {
    pub fn new(cpu_model: &str) -> Result<Oracle, String> {
        let api = api()?;
        let model = CString::new(cpu_model).map_err(|e| e.to_string())?;
        let h = unsafe { (api.create)(model.as_ptr()) };
        if h.is_null() {
            return Err(format!("armm_create failed: {}", last_error(api)));
        }
        Ok(Oracle { api, h })
    }

    pub fn backend_name(&self) -> &'static str {
        "qemu"
    }

    pub fn reset(&mut self) {
        check(self.api, unsafe { (self.api.reset)(self.h) }, "reset").unwrap();
    }

    pub fn get_r(&self, n: u32) -> u32 {
        assert!(n < 16);
        unsafe { (self.api.get_r)(self.h, n) }
    }

    pub fn set_r(&mut self, n: u32, v: u32) {
        check(self.api, unsafe { (self.api.set_r)(self.h, n, v) }, "set_r").unwrap();
    }

    pub fn get_xpsr(&self) -> u32 {
        unsafe { (self.api.get_xpsr)(self.h) }
    }

    pub fn set_xpsr(&mut self, v: u32) {
        check(self.api, unsafe { (self.api.set_xpsr)(self.h, v) }, "set_xpsr").unwrap();
    }

    pub fn get_q(&self, n: u32) -> u128 {
        let (mut lo, mut hi) = (0u64, 0u64);
        check(self.api, unsafe { (self.api.get_q)(self.h, n, &mut lo, &mut hi) }, "get_q").unwrap();
        (hi as u128) << 64 | lo as u128
    }

    pub fn set_q(&mut self, n: u32, v: u128) {
        let rc = unsafe { (self.api.set_q)(self.h, n, v as u64, (v >> 64) as u64) };
        check(self.api, rc, "set_q").unwrap();
    }

    pub fn get_d(&self, n: u32) -> u64 {
        assert!(n < 16);
        unsafe { (self.api.get_d)(self.h, n) }
    }

    pub fn set_d(&mut self, n: u32, v: u64) {
        check(self.api, unsafe { (self.api.set_d)(self.h, n, v) }, "set_d").unwrap();
    }

    pub fn get_s(&self, n: u32) -> u32 {
        assert!(n < 32);
        unsafe { (self.api.get_s)(self.h, n) }
    }

    pub fn set_s(&mut self, n: u32, v: u32) {
        check(self.api, unsafe { (self.api.set_s)(self.h, n, v) }, "set_s").unwrap();
    }

    pub fn get_fpscr(&self) -> u32 {
        unsafe { (self.api.get_fpscr)(self.h) }
    }

    pub fn set_fpscr(&mut self, v: u32) {
        check(self.api, unsafe { (self.api.set_fpscr)(self.h, v) }, "set_fpscr").unwrap();
    }

    pub fn get_vpr(&self) -> u32 {
        unsafe { (self.api.get_vpr)(self.h) }
    }

    pub fn set_vpr(&mut self, v: u32) {
        check(self.api, unsafe { (self.api.set_vpr)(self.h, v) }, "set_vpr").unwrap();
    }

    pub fn get_control(&self) -> u32 {
        unsafe { (self.api.get_control)(self.h) }
    }

    pub fn set_control(&mut self, v: u32) {
        check(self.api, unsafe { (self.api.set_control)(self.h, v) }, "set_control").unwrap();
    }

    /// Address marked by the local exclusive monitor, or None if it is closed.
    pub fn get_exclusive(&self) -> Option<u32> {
        let mut addr = 0;
        match unsafe { (self.api.get_exclusive)(self.h, &mut addr) } {
            0 => None,
            1 => Some(addr),
            rc => panic!("get_exclusive failed ({rc}): {}", last_error(self.api)),
        }
    }

    /// Open the monitor for an access of `size` bytes (1, 2 or 4) at
    /// `addr` as LDREX would, or close it with `None`. `addr` must be
    /// mapped; what memory holds there does not affect a later STREX.
    pub fn set_exclusive(&mut self, mark: Option<(u32, u32)>) -> Result<(), String> {
        let (addr, size) = mark.unwrap_or((0, 0));
        check(self.api, unsafe { (self.api.set_exclusive)(self.h, addr, size) }, "set_exclusive")
    }

    pub fn map(&mut self, addr: u32, len: u32, prot: u32) -> Result<(), String> {
        check(self.api, unsafe { (self.api.map)(self.h, addr, len, prot) }, "map")
    }

    pub fn unmap(&mut self, addr: u32, len: u32) -> Result<(), String> {
        check(self.api, unsafe { (self.api.unmap)(self.h, addr, len) }, "unmap")
    }

    pub fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), String> {
        let rc = unsafe {
            (self.api.write_mem)(self.h, addr, data.as_ptr().cast(), data.len())
        };
        check(self.api, rc, "write_mem")
    }

    pub fn read_mem(&self, addr: u32, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        let rc = unsafe { (self.api.read_mem)(self.h, addr, buf.as_mut_ptr().cast(), len) };
        check(self.api, rc, "read_mem")?;
        Ok(buf)
    }

    pub fn step_raw(&mut self) -> RawStep {
        let mut out = RawStep::default();
        check(self.api, unsafe { (self.api.step)(self.h, &mut out) }, "step").unwrap();
        out
    }

    pub fn step(&mut self) -> StepOutcome {
        outcome(&self.step_raw())
    }

    pub fn flush_tb(&mut self) {
        check(self.api, unsafe { (self.api.flush_tb)(self.h) }, "flush_tb").unwrap();
    }
}

impl ArmMOracle for Oracle {
    fn backend_name(&self) -> &'static str {
        Oracle::backend_name(self)
    }

    fn reset(&mut self) {
        Oracle::reset(self)
    }

    fn set_r(&mut self, n: u32, v: u32) {
        Oracle::set_r(self, n, v)
    }

    fn get_r(&self, n: u32) -> u32 {
        Oracle::get_r(self, n)
    }

    fn set_xpsr(&mut self, v: u32) {
        Oracle::set_xpsr(self, v)
    }

    fn get_xpsr(&self) -> u32 {
        Oracle::get_xpsr(self)
    }

    fn set_q(&mut self, n: u32, v: u128) {
        Oracle::set_q(self, n, v)
    }

    fn get_q(&self, n: u32) -> u128 {
        Oracle::get_q(self, n)
    }

    fn set_fpscr(&mut self, v: u32) {
        Oracle::set_fpscr(self, v)
    }

    fn get_fpscr(&self) -> u32 {
        Oracle::get_fpscr(self)
    }

    fn set_vpr(&mut self, v: u32) {
        Oracle::set_vpr(self, v)
    }

    fn get_vpr(&self) -> u32 {
        Oracle::get_vpr(self)
    }

    fn set_control(&mut self, v: u32) {
        Oracle::set_control(self, v)
    }

    fn get_control(&self) -> u32 {
        Oracle::get_control(self)
    }

    fn set_exclusive(&mut self, mark: Option<(u32, u32)>) {
        Oracle::set_exclusive(self, mark).unwrap()
    }

    fn get_exclusive(&self) -> Option<u32> {
        Oracle::get_exclusive(self)
    }

    fn map(&mut self, addr: u32, len: u32, prot: u32) {
        Oracle::map(self, addr, len, prot).unwrap()
    }

    fn unmap(&mut self, addr: u32, len: u32) {
        Oracle::unmap(self, addr, len).unwrap()
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) {
        Oracle::write_mem(self, addr, data).unwrap()
    }

    fn read_mem(&self, addr: u32, len: usize) -> Vec<u8> {
        Oracle::read_mem(self, addr, len).unwrap()
    }

    fn step(&mut self) -> StepOutcome {
        Oracle::step(self)
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        unsafe { (self.api.destroy)(self.h) }
    }
}
