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

- QEMU is a git submodule (`qemu/`, pinned at `8ee6c77`, 11.1.50). Its **sources are not changed**; this project only adds files.
- `frontend/` is a new frontend modelled on QEMU's linux-user (user mode), but without syscalls, ELF loading or signals. It builds `target/arm`, TCG and the user-mode part of `accel/tcg` into one DLL, with the CPU model `cortex-m55`.
- Guest memory is a flat 4 GB address window; pages are mapped as each test case needs them. Accesses to unmapped pages are caught by a Windows vectored exception handler (VEH) and turned into guest data aborts; the process does not crash.
- The only change to upstream is the one in `patches/`: 5 lines added to `meson.build` to hook `frontend/` into QEMU's build.
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
- Set the exclusive monitor explicitly with `set_exclusive` in every test case (after writing memory: it records the current value); otherwise it carries over to the next case.
- After a memory fault, compare only the fault kind, pc and fault address: LDM and VLDRW/VSTRW leave the parts they already completed, and base writeback never happens.
- A pc at or above `0xffff0000` hits QEMU's Linux kernel-helper trap and returns `Unimplemented`.
- Not supported: PACBTI (not implemented by QEMU: PAC/AUT/BTI are no-ops, and PACG/AUTG/BXAUT execute as SMMUL/SMMLA, so keep them out of random cases), CDE, exception entry and return, lazy FP stacking, MPU.

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

- An unaligned STREX does not raise an alignment fault when the exclusive monitor does not match the address; it just returns 1 (store failed). The architecture requires an UNALIGNED UsageFault (`ExclusiveMonitorsPass`). Cause: `gen_store_exclusive` in `target/arm/tcg/translate.c`; system mode has the same bug.
- STREX success is decided by comparing the memory value: a plain store of a different value between LDREX and STREX makes it fail, the same value lets it succeed. Real implementations do not decide by data. Avoid such cases.
- System mode only: a Secure VSCCLRM whose D-register list starts at D17 or above hits an assertion in `trans_VSCCLRM` (`target/arm/tcg/translate-m-nocp.c`) and QEMU exits. The oracle is Non-secure, so VSCCLRM is UNDEFINED before that code runs.

## Verification

- **Coverage**: about 200 instructions in 54 tests, with expected values worked out by hand from the DDI0553 pseudocode: T16/T32 including IT blocks; DSP; scalar floating point in single, double and half precision (rounding modes, FZ, FZ16, DN, AHP, cumulative flags); MVE integer and floating point, VPT predication and ECI beat skipping; low-overhead loops including tail predication. QEMU matched the architecture in all of them.
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

Without MSYS2 the build does not fail: it only prints a warning, the DLL is not built, and `Oracle::new` returns an error. The same happens on non-Windows hosts. Tests that use the oracle should skip when they see this error.

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

Move the submodule to the new commit and run the full `cargo test` (a successful build is not enough; some problems only show up at run time). The patch is applied with `git apply --3way`, which tolerates context drift. When upstream internal interfaces change, the fixes are all in `frontend/`. In a rehearsal against upstream master and the releases back to v10.0.0, the patch applied cleanly every time, and the frontend needed 0 lines for master, a few to about 25 lines per release (about 4 months), and about 90 lines for an 18-month gap.

## Layout

| Path | Contents |
|---|---|
| `qemu/` | Upstream QEMU submodule |
| `patches/` | Changes to QEMU (only the meson hook) |
| `frontend/` | Oracle frontend (C); `win32/` and `host-win32.c` are the Windows-specific parts |
| `include/armm_oracle.h` | C API |
| `src/lib.rs`, `build.rs` | Rust wrapper and build |
| `tests/` | Rust tests: build and loading (`s1`), execution (`s2`), memory faults (`s3`), per-class coverage (`s4_*`), the trait (`s8`) |
| `scripts/s5_compare/` | Random comparison against gdbstub-driven `qemu-system-arm` (Python) |
| `scripts/s0-linux-user/` | M-profile experiment with upstream linux-user `qemu-arm` (WSL) |

## License

GPL-2.0-or-later (QEMU as a whole is distributed under GPL-2.0, so the linked library is treated the same way); see `LICENSE`.
