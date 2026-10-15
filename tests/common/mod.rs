#![allow(dead_code)]

use qemu_armm_oracle::Oracle;
use std::sync::{Mutex, MutexGuard};

pub const CODE: u32 = 0x0000_8000;
pub const DATA: u32 = 0x0002_0000;
pub const PAGE: u32 = 0x1000;
pub const XPSR_T: u32 = 1 << 24;

static LOCK: Mutex<()> = Mutex::new(());

/// The oracle is one per process; tests take turns. Fields drop in order,
/// so the oracle is destroyed before the lock is released.
pub struct Fixture {
    pub o: Oracle,
    _guard: MutexGuard<'static, ()>,
}

pub fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn fixture() -> Fixture {
    let guard = lock();
    let o = Oracle::new("cortex-m55").expect("create oracle");
    Fixture { o, _guard: guard }
}

/// Thumb code bytes from halfwords as the disassembler prints them.
pub fn thumb(halves: &[u16]) -> Vec<u8> {
    halves.iter().flat_map(|h| h.to_le_bytes()).collect()
}

/// Map a code page and a data page, put `code` at CODE and point pc at it.
pub fn load(o: &mut Oracle, code: &[u8]) {
    o.map(CODE, PAGE, qemu_armm_oracle::PROT_READ | qemu_armm_oracle::PROT_EXEC).unwrap();
    o.map(DATA, PAGE, qemu_armm_oracle::PROT_READ | qemu_armm_oracle::PROT_WRITE).unwrap();
    o.flush_tb();
    o.write_mem(CODE, code).unwrap();
    o.set_r(15, CODE);
    o.set_xpsr(XPSR_T);
}

pub const FLAG_N: u32 = 1 << 31;
pub const FLAG_Z: u32 = 1 << 30;
pub const FLAG_C: u32 = 1 << 29;
pub const FLAG_V: u32 = 1 << 28;
pub const FLAG_Q: u32 = 1 << 27;

/// xPSR bits holding ITSTATE (also ICI/ECI): IT[1:0] at 26:25, IT[7:2] at 15:10.
pub fn it_bits(it: u8) -> u32 {
    ((it as u32 & 3) << 25) | ((it as u32 >> 2) << 10)
}

/// ITAdvance() of the Armv8-M pseudocode.
pub fn it_advance(it: u8) -> u8 {
    if it & 7 == 0 {
        0
    } else {
        (it & 0xe0) | ((it << 1) & 0x1f)
    }
}

/// EPSR.ECI value as xPSR bits: ECI[7:0] = xPSR[26:25, 11:10, 15:12].
pub fn eci_bits(eci: u8) -> u32 {
    ((eci as u32 >> 6) << 25) | (((eci as u32 >> 4) & 3) << 10) | ((eci as u32 & 0xf) << 12)
}

pub fn retire(o: &mut Oracle) {
    let r = o.step_raw();
    assert_eq!(r.kind, qemu_armm_oracle::STEP_RETIRED, "expected retirement: {r:x?}");
}

/// Write `code` at CODE and run its first instruction (pages already mapped).
pub fn run1(o: &mut Oracle, code: &[u16]) {
    o.write_mem(CODE, &thumb(code)).unwrap();
    o.set_r(15, CODE);
    retire(o);
}

pub fn q32(w: [u32; 4]) -> u128 {
    w.iter().rev().fold(0, |acc, &x| acc << 32 | x as u128)
}

pub fn q16(h: [u16; 8]) -> u128 {
    h.iter().rev().fold(0, |acc, &x| acc << 16 | x as u128)
}

pub fn q8(b: [u8; 16]) -> u128 {
    u128::from_le_bytes(b)
}

pub fn w32(q: u128) -> [u32; 4] {
    std::array::from_fn(|i| (q >> (32 * i)) as u32)
}

pub fn w16(q: u128) -> [u16; 8] {
    std::array::from_fn(|i| (q >> (16 * i)) as u16)
}

pub fn w8(q: u128) -> [u8; 16] {
    q.to_le_bytes()
}

pub fn read32(o: &Oracle, addr: u32) -> u32 {
    u32::from_le_bytes(o.read_mem(addr, 4).unwrap().try_into().unwrap())
}

pub fn write32s(o: &mut Oracle, addr: u32, words: &[u32]) {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    o.write_mem(addr, &bytes).unwrap();
}

pub struct Mem {
    pub working_set: usize,
    pub private: usize,
}

#[cfg(windows)]
pub fn mem_usage() -> Mem {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(p: *mut c_void, c: *mut Counters, cb: u32) -> i32;
    }

    let mut c = Counters { cb: std::mem::size_of::<Counters>() as u32, ..Default::default() };
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    assert!(ok != 0);
    Mem { working_set: c.working_set_size, private: c.private_usage }
}

/// Small deterministic PRNG (xorshift64*).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }

    pub fn below(&mut self, n: u32) -> u32 {
        (self.next() % n as u64) as u32
    }
}
