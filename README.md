# qemu-armm-oracle

English | [中文](README.zh-CN.md)

The Armv8.1-M (Cortex-M55) instruction execution part of QEMU, built as an in-process library to serve as a semantic reference (oracle) for differential testing: set registers and memory, execute one instruction, read the result, and get an exception classification. The interface follows `hybrid-x86-oracle`. It is meant to be used as a dev-dependency by the zens Armv8.1-M DSE tests.

```rust
use qemu_armm_oracle::*;

fn movs<O: ArmMOracle>(o: &mut O) {
    o.map(0x1000, 0x1000, PROT_READ | PROT_EXEC);
    o.write_mem(0x1000, &[0x05, 0x20]);          // movs r0, #5
    o.set_r(15, 0x1000);
    o.set_xpsr(1 << 24);                         // the T bit must be set by the caller
    assert!(o.step().is_retired());
    assert_eq!(o.get_r(0), 5);
}

let mut o = Oracle::new("cortex-m55")?;
movs(&mut o);
```

Status: verified (see [Verification](#verification)). Only Windows hosts are supported; Linux support will be added later.

## How it works

- QEMU is a git submodule (`qemu/`, pinned at `8ee6c77`, 11.1.50). Apart from the seven small patches in `patches/`, its **sources are not changed**; this project only adds files.
- `frontend/` is a new frontend modelled on QEMU's linux-user (user mode), but without syscalls, ELF loading or signals. It builds `target/arm`, TCG and the user-mode part of `accel/tcg` into one DLL, with the CPU model `cortex-m55`.
- Guest memory is a flat 4 GB address window; pages are mapped as each test case needs them. Accesses to unmapped pages are caught by a Windows vectored exception handler (VEH) and turned into guest data aborts; the process does not crash.
- The changes to upstream are the patches in `patches/`, applied in order:
  - `0001`: 5 lines added to `meson.build` to hook `frontend/` into QEMU's build.
  - `0002`: a fix in `target/arm/tcg/translate.c` so that an unaligned STREX always raises an alignment fault (the first of the [known QEMU issues](#known-qemu-issues)).
  - `0003`: a fix in the same function so that a plain store does not change the exclusive monitor (the second of the known QEMU issues), plus two lines in `linux-user/arm/` that the oracle does not build.
  - `0004`: one line in `target/arm/tcg/translate-m-nocp.c` so that a Secure VSCCLRM whose D-register list starts at D17 or above clears only VPR instead of hitting an assertion (the third of the known QEMU issues). It only changes system mode; the oracle is Non-secure, where VSCCLRM is UNDEFINED.
  - `0005`: two limits in `target/arm/tcg/mve_helper.c` so that the `#48` forms of SQRSHRL and UQRSHLL give the right result for right shifts of 48 to 64 bits (the fourth of the known QEMU issues).
  - `0006`: an M-profile check in four functions of `target/arm/tcg/translate.c` so that LDREXD, STREXD, LDAEXD and STLEXD are UNDEFINED (the fifth of the known QEMU issues).
  - `0007`: one condition in `trans_PLDW` (`target/arm/tcg/translate.c`) so that PLDW is a memory hint on M-profile CPUs with the Main Extension (the sixth of the known QEMU issues).
- `include/armm_oracle.h` is the C API. `src/lib.rs` is the Rust wrapper (`ArmMOracle` trait, `Oracle`, `StepOutcome`, `FaultKind`, `CpuState`).

## Semantic contract

- The CPU is always in **Non-secure, unprivileged Thread mode** (fixed when QEMU is compiled for user mode). After reset the FPU and MVE are already enabled: CONTROL = 0x5 (FPCA, nPRIV), FPSCR.LTPSIZE = 4.
- Privileged and security-related instructions behave as they do for Non-secure unprivileged code, which makes them stand-ins for what privileged code would see:
  - MRS of MSP, PSP, PRIMASK, BASEPRI, FAULTMASK, MSPLIM and PSPLIM reads 0; MSR to them and to CONTROL is ignored; CPSID/CPSIE do nothing.
  - VMRS/VMSR/VLDR/VSTR of VPR do nothing (P0 works).
  - TT/TTT return 0 and SG does nothing; TTA/TTAT, BXNS/BLXNS, VLSTM/VLLDM and VSCCLRM are UNDEFINED.
  - CCR, FPCCR and FPDSCR stay at their reset values: divide by zero gives 0 and an unaligned LDR/STR is allowed.
  - No stack-limit checks, no EXC_RETURN handling, no default memory map (the XN regions are not enforced).

  Read and write CONTROL, VPR and the other special registers through the API.
- One oracle per process, and calls must not overlap. Run tests one per process (nextest) or behind a global lock. Dropping the oracle and creating a new one gives a clean CPU, memory map and translation cache.
- Set the exclusive monitor explicitly with `set_exclusive` in every test case; otherwise it carries over to the next case. Only the marked address matters, not the memory contents, so it can be set before or after writing memory. As on Cortex-M55, a plain store does not change the monitor. A STREX to an address other than the marked one fails (both outcomes are IMPLEMENTATION DEFINED; the Cortex-M55 monitor holds no address and would store).
- After a memory fault, compare only the fault kind, pc and fault address: LDM and VLDRW/VSTRW leave the parts they already completed, and base writeback never happens.
- A pc at or above `0xffff0000` hits QEMU's Linux kernel-helper trap and returns `Unimplemented`.
- Not supported: PACBTI (not implemented by QEMU: PAC/AUT/BTI are no-ops, and PACG/AUTG/BXAUT execute as SMMUL/SMMLA, so keep them out of random cases), CDE, exception entry and return, lazy FP stacking, MPU. Also keep out LDRD and STRD with Rn = PC and W = 1 (for example `ldrd r11, r12, [pc], #832`): QEMU writes the computed address back to pc, which is a branch. For LDRD (literal) this is one of the CONSTRAINED UNPREDICTABLE behaviours DDI0553 C2.4.86 allows (pre- or post-indexed addressing); UNDEFINED, NOP and executing without writeback are allowed as well. STRD with Rn = PC is UNPREDICTABLE.

Exception classes (`FaultKind`):

| QEMU result | `FaultKind` | Real M-profile |
|---|---|---|
| UNDEFINED / no coprocessor / invalid state | `Undefined` / `NoCoprocessor` / `InvalidState` | UsageFault UNDEFINSTR / NOCP / INVSTATE |
| alignment fault | `Unaligned { addr }` | UsageFault UNALIGNED |
| unmapped or no-permission data access | `DataAbort { addr }` | MemManage or BusFault |
| instruction fetch fault | `PrefetchAbort { addr }` | MemManage or BusFault |
| SVC | `Svc` (pc already past the SVC) | SVCall |
| BKPT | `Bkpt` (pc stays on the BKPT) | DebugMonitor or HardFault |
| anything else | `Unimplemented` (not counted as a difference) | — |

The raw step result (`step_raw`) still carries QEMU's FSR value, which tells unmapped (0x7) from no-permission (0xf) and alignment (0x1); 0x800 marks a write.

### Known QEMU issues

- Fixed here by `patches/0002-unaligned-strex-fault.patch`: in upstream QEMU, an unaligned STREX/STREXH (and STLEX/STLEXH) does not raise an alignment fault when the exclusive monitor does not match the address; it just returns 1 (store failed). The architecture requires an UNALIGNED UsageFault (`ExclusiveMonitorsPass` checks alignment first). Cause: `gen_store_exclusive` in `target/arm/tcg/translate.c`, so upstream system mode and linux-user have the same bug. The patch checks the alignment before the monitor and raises the fault as a store; `tests/s4_exclusive.rs` covers it.
- Fixed here by `patches/0003-plain-store-keeps-exclusive-monitor.patch`: in upstream QEMU, STREX success is decided by comparing memory with the value LDREX read, so a plain store of a different value between LDREX and STREX makes it fail and the same value lets it succeed. The architecture makes it IMPLEMENTATION DEFINED whether a store by the same core that is not a Store-Exclusive changes the local monitor (DDI0553 B9.2), but a real implementation does not decide by data. Cortex-M55 leaves the monitor unchanged (Cortex-M55 TRM, "Internal local exclusive access monitor"). The patch makes QEMU do the same: **a normal store by the same core does not change the local monitor**, and a STREX to the marked address stores and returns 0. This applies to user mode when only one thread runs (code translated without `CF_PARALLEL`), which is always the case for the oracle. With several threads, and always in system mode (round-robin TCG runs several vCPUs in one thread), QEMU keeps the compare, which stands in for the global monitor; so `qemu-system-arm` still behaves the old way. For linux-user the patch also clears the monitor on syscalls and on signal delivery, as Linux does on every return to user space. `tests/s4_exclusive.rs` covers it; a memory fault in a STREX is now also reported as a store.
- Fixed here by `patches/0004-vscclrm-unimplemented-dregs.patch` (system mode only): in upstream QEMU, a Secure VSCCLRM whose D-register list starts at D17 or above (for example `vscclrm {d17, vpr}`) hits an assertion in `trans_VSCCLRM` (`target/arm/tcg/translate-m-nocp.c`) and QEMU exits. The architecture leaves registers above D15 alone on a PE with 16 D registers (the VSCCLRM operation skips them, and DDI0553 B4.3 says VSCCLRM acts as a NOP for unimplemented S or D registers), so such a list clears only VPR. The patch does that. The oracle is Non-secure, where VSCCLRM is UNDEFINED before that code runs, so the oracle's results do not change; `scripts/s5_compare/vscclrm_check.py` checks the fix in Secure state on a patched `qemu-system-arm`.
- Fixed here by `patches/0005-mve-48bit-long-shift-right.patch`: in upstream QEMU, `sqrshrl RdaLo, RdaHi, #48, Rm` with a right shift of 48 to 63 bits, and `uqrshll RdaLo, RdaHi, #48, Rm` with a right shift of 49 to 64 bits (negative bottom byte of Rm), always give 0. The architecture does a rounding shift of the full 64-bit RdaHi:RdaLo and only then saturates to 48 bits, so an input with bits above bit 47 gives a nonzero result: for example 2^62 shifted right by 50 gives 4096, and 2^63 shifted right by 49 (unsigned) gives 16384. Cause: `do_sqrshl48_d` and `do_uqrshl48_d` return 0 early for shifts of `-48` and `-(48 + round)` or more, which is only right for inputs that fit in 48 bits; the patch uses the limits of the 64-bit versions (`-64` and `-(64 + round)`). System mode has the same bug. `tests/s4_mve.rs` covers it, including 4000 random cases of the `#48` and `#64` forms checked against a model of the pseudocode.
- Fixed here by `patches/0006-m-profile-no-doubleword-exclusives.patch`: in upstream QEMU, an M-profile CPU executes LDREXD, STREXD, LDAEXD and STLEXD (for example `ldrexd r2, r3, [r1]`, `e8d1 237f`) as A-profile doubleword exclusives. Armv8-M has none of them: the T32 encoding tables of DDI0553 (C2.3.2.2.2, C2.3.2.2.3) have no sz = 11 row, so the encodings are unallocated (C1.4.1). Cause: `trans_LDREXD_t32`, `trans_STREXD_t32`, `trans_LDAEXD_t32` and `trans_STLEXD_t32` do not check for M-profile; the patch makes them UNDEFINED there. System mode has the same bug. `tests/s4_exclusive.rs` covers it.
- Fixed here by `patches/0007-m-profile-pldw-hint.patch`: in upstream QEMU, an M-profile CPU executes all three forms of PLDW (immediate T1 and T2, register) as LDRH with Rt = 15: it loads a halfword and writes it to pc, which is a branch. For example `pldw [r0, #0x25e]` (`f8b0 f25e`) with the halfword 0x1235 at that address sets pc to 0x1234. DDI0553 has PLDW in the Main Extension (C2.4.140, C2.4.141) as a memory hint that changes no register, and C1.4.3 says an LDRH with Rt = 0b1111 is a memory hint, not a load. Cause: `trans_PLDW` returns `arm_dc_feature(s, ARM_FEATURE_V7MP)`, which M-profile CPUs do not have, so decodetree falls through to `LDRH_ri` / `LDRH_rr`. The patch also accepts `ARM_FEATURE_M_MAIN`. System mode has the same bug. `tests/s4_system.rs` covers it.

## Verification

- **Coverage**: about 200 instructions in 67 tests, with expected values worked out by hand from the DDI0553 pseudocode: T16/T32 including IT blocks; DSP; scalar floating point in single, double and half precision (rounding modes, FZ, FZ16, DN, AHP, cumulative flags); MVE integer and floating point, VPT predication and ECI beat skipping; low-overhead loops including tail predication. Apart from the known QEMU issues above, QEMU matched the architecture in all of them.
- **Comparison**: about 59,000 random cases against gdbstub-driven `qemu-system-arm` (`mps3-an547`, same QEMU commit, set to Non-secure unprivileged with FPCA = 1). The only difference is single-stepping YIELD through gdbstub, which also runs the next instruction. Run in Secure or privileged state instead, every difference traces back to the user-mode stand-ins above.
- **Faults**: 400,000 mixed cases including memory faults ran without a crash, with memory use steady at about 20 MB.
- **Speed**: about 3 µs per case from Rust (set the state, execute one instruction, read it back), against 0.14–2 ms through gdbstub.

## Building

Requirements:

1. MSYS2 (default `C:\msys64`; set `MSYS2_ROOT` if it is elsewhere). In an MSYS2 shell:
   ```
   pacman -S --needed mingw-w64-clang-x86_64-clang mingw-w64-clang-x86_64-meson mingw-w64-clang-x86_64-ninja mingw-w64-clang-x86_64-pkgconf mingw-w64-clang-x86_64-python mingw-w64-clang-x86_64-glib2
   ```
   MSYS2 does not need to be on PATH.
2. git on PATH. The first build needs network access (to fetch the QEMU sources and two meson subprojects).

On `cargo build` / `cargo test`, `build.rs` builds the DLL from source (about 50 s the first time, about 1–2 s after a frontend change) into `OUT_DIR/dist`, together with the 5 runtime DLLs it needs. Loading never searches PATH. `build.rs` does not modify any file in the crate directory.

When a prerequisite is missing, the build does not fail: it only prints a warning, the DLL is not built, and `Oracle::new` returns an error that gives the reason. This covers a non-Windows host, no MSYS2, missing CLANG64 packages, no git on PATH, and no network for the first download of QEMU or its meson subprojects. Tests that use the oracle should skip when they see this error. Once the prerequisite is fixed, the next build tries again; only after installing MSYS2 itself, run `cargo clean -p qemu-armm-oracle` once (or set `MSYS2_ROOT`). Errors from configure or the compile itself still fail the build.

Environment variables:

| Variable | Purpose |
|---|---|
| `MSYS2_ROOT` | MSYS2 install directory |
| `ARMM_ORACLE_QEMU_DIR` | Use this QEMU source tree instead of the submodule (for offline builds) |
| `ARMM_ORACLE_DLL` | Load this DLL at run time instead |

### Developing in this repository

The qemu submodule has `update = none` in `.gitmodules` (otherwise cargo would recursively clone all of QEMU's submodules when fetching this crate as a git dependency), so check it out explicitly. Git for Windows converts line endings to CRLF by default, which breaks QEMU's scripts:

```sh
git -c core.autocrlf=false submodule update --init --checkout qemu
git -C qemu config core.autocrlf false
```

To build by hand without cargo: `scripts/apply-patches.sh` (patches the submodule; `--reset` undoes it), then `scripts/build-oracle.sh` (output in `build/oracle-win/dist/`).

## Using it as a dependency

```toml
[dev-dependencies]
qemu-armm-oracle = { git = "https://github.com/yufengzjj/qemu-armm-oracle.git" }
```

## Following upstream QEMU

Move the submodule to the new commit and run the full `cargo test` (a successful build is not enough; some problems only show up at run time). The patches are applied with `git apply --3way`, which tolerates context drift. When upstream internal interfaces change, the fixes are all in `frontend/`. In a rehearsal against upstream master and the releases back to v10.0.0, the meson patch applied cleanly every time, and the frontend needed 0 lines for master, a few to about 25 lines per release (about 4 months), and about 90 lines for an 18-month gap. `0002` and `0003` change the same function, and `0003` is made on top of `0002`: when one of them is refreshed, regenerate `0003` from a tree with `0001` and `0002` applied. Once upstream has its own fix for the STREX alignment issue, delete `patches/0002-*.patch`; likewise `0003` for the exclusive monitor, `0004` for the VSCCLRM assertion, `0005` for the 48-bit long shifts, `0006` for the doubleword exclusives and `0007` for PLDW. `0004` and `0005` each change a different file and do not depend on the others; `0006` and `0007` change other functions in `translate.c` and apply with or without `0002` and `0003`.

## Layout

| Path | Contents |
|---|---|
| `qemu/` | Upstream QEMU submodule |
| `patches/` | Changes to QEMU: the meson hook, the STREX alignment fix, the exclusive monitor fix, the VSCCLRM fix, the 48-bit long shift fix, the doubleword exclusive fix and the PLDW fix |
| `frontend/` | Oracle frontend (C); `win32/` and `host-win32.c` are the Windows-specific parts |
| `include/armm_oracle.h` | C API |
| `src/lib.rs`, `build.rs` | Rust wrapper and build |
| `tests/` | Rust tests: build and loading (`s1`), execution (`s2`), memory faults (`s3`), per-class coverage (`s4_*`), the trait (`s8`) |
| `scripts/s5_compare/` | Random comparison against gdbstub-driven `qemu-system-arm` (Python); `vscclrm_check.py` checks VSCCLRM in Secure state against the pseudocode |
| `scripts/s0-linux-user/` | M-profile experiment with upstream linux-user `qemu-arm` (WSL) |

## License

GPL-2.0-or-later (QEMU as a whole is distributed under GPL-2.0, so the linked library is treated the same way); see `LICENSE`.
