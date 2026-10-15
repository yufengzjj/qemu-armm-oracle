# qemu-armm-oracle

[English](README.md) | 中文

从 QEMU 抽出 Armv8.1-M（Cortex-M55）的指令执行部分，编成在进程内调用的库，给差分测试当语义参照（oracle）：设寄存器和内存、执行一条指令、读结果、给出异常分类。接口照 `hybrid-x86-oracle`，供 zens 的 Armv8.1-M DSE 测试作开发依赖使用。

```rust
use qemu_armm_oracle::*;

fn movs<O: ArmMOracle>(o: &mut O) {
    o.map(0x1000, 0x1000, PROT_READ | PROT_EXEC);
    o.write_mem(0x1000, &[0x05, 0x20]);          // movs r0, #5
    o.set_r(15, 0x1000);
    o.set_xpsr(1 << 24);                         // T 位要自己设
    assert!(o.step().is_retired());
    assert_eq!(o.get_r(0), 5);
}

let mut o = Oracle::new("cortex-m55")?;
movs(&mut o);
```

现状：已验证（见“验证”一节）。只支持 Windows 宿主机；Linux 以后要支持。

## 怎么做的

- QEMU 是 git 子模块（`qemu/`，钉在 `8ee6c77`，11.1.50），**源码不改**，只加文件。
- `frontend/` 是新写的前端：仿照 QEMU 的 linux-user（用户态），但没有系统调用、ELF 加载和信号。它把 `target/arm`、TCG 和 `accel/tcg` 的用户态部分编进一个 DLL，CPU 用 `cortex-m55`。
- 客户机内存是一块 4 GB 的平坦地址窗口，用例要用的页再映射。访问没映射的页由 Windows 的向量化异常处理（VEH）接住，转成客户机的数据异常，进程不崩。
- 对上游的改动只有 `patches/` 里的一处：`meson.build` 加 5 行，把 `frontend/` 接进 QEMU 的构建。
- `include/armm_oracle.h` 是 C 接口，`src/lib.rs` 是 Rust 封装（`ArmMOracle` trait、`Oracle`、`StepOutcome`、`FaultKind`、`CpuState`）。

## 语义约定

- CPU 固定处在**非安全、非特权的线程模式**（QEMU 用户态编译时就定了）。复位后 FPU 和 MVE 已经打开：CONTROL = 0x5（FPCA、nPRIV），FPSCR.LTPSIZE = 4。
- 特权和安全相关的指令按非安全、非特权代码的规则执行，相对特权代码看到的结果来说只是替身：
  - MRS 读 MSP、PSP、PRIMASK、BASEPRI、FAULTMASK、MSPLIM、PSPLIM 得 0；MSR 写它们和 CONTROL 被忽略；CPSID/CPSIE 什么都不做。
  - VMRS/VMSR/VLDR/VSTR 访问 VPR 什么都不做（P0 可以）。
  - TT/TTT 返回 0，SG 什么都不做；TTA/TTAT、BXNS/BLXNS、VLSTM/VLLDM、VSCCLRM 是 UNDEFINED。
  - CCR、FPCCR、FPDSCR 保持复位值：除以 0 得 0，不对齐的 LDR/STR 允许。
  - 没有栈界限检查，不处理 EXC_RETURN，没有默认内存映射（不检查 XN 区域）。

  CONTROL、VPR 等特殊寄存器直接用接口读写。
- 一个进程只有一个 oracle，调用不能并发；测试靠一个测试一个进程（nextest）或者全局锁。销毁后再创建，CPU、内存映射和翻译缓存都是干净的。
- 每个用例要用 `set_exclusive` 显式设独占监视器（在写完内存之后：它记录当时的值），否则会带到下一个用例。
- 出访存错误后只比异常种类、pc 和出错地址：LDM、VLDRW/VSTRW 会留下已完成的部分，基址写回不会发生。
- pc 在 `0xffff0000` 及以上时会碰到 QEMU 的 Linux 内核辅助页陷阱，返回 `Unimplemented`。
- 不支持：PACBTI（QEMU 没实现：PAC/AUT/BTI 是空操作，PACG/AUTG/BXAUT 会被当成 SMMUL/SMMLA 执行，随机用例要排除）、CDE、异常进出、惰性浮点压栈、MPU。

异常分类（`FaultKind`）：

| QEMU 的结果 | `FaultKind` | 真实 M-profile |
|---|---|---|
| UNDEFINED / 没有协处理器 / 状态无效 | `Undefined` / `NoCoprocessor` / `InvalidState` | UsageFault UNDEFINSTR / NOCP / INVSTATE |
| 对齐错误 | `Unaligned { addr }` | UsageFault UNALIGNED |
| 访问没映射或没权限的数据 | `DataAbort { addr }` | MemManage 或 BusFault |
| 取指错误 | `PrefetchAbort { addr }` | MemManage 或 BusFault |
| SVC | `Svc`（pc 已经越过 SVC） | SVCall |
| BKPT | `Bkpt`（pc 停在 BKPT 上） | DebugMonitor 或 HardFault |
| 其他 | `Unimplemented`（比对时不算差异） | — |

原始的单步结果（`step_raw`）还带着 QEMU 的 FSR 值，可以区分没映射（0x7）、没权限（0xf）和不对齐（0x1）；0x800 表示写。

### 已知的 QEMU 问题

- 地址不对齐的 STREX 在独占监视器和地址不匹配时不报对齐错误，只返回 1（存储失败）。按架构应当是 UNALIGNED UsageFault（`ExclusiveMonitorsPass`）。原因在 `target/arm/tcg/translate.c` 的 `gen_store_exclusive`，系统模式也一样。
- STREX 是否成功按内存里的值判断：LDREX 和 STREX 之间普通存储写了不同的值，STREX 失败；写了相同的值，STREX 成功。真实实现不会按数据决定。不要写这种用例。
- 只影响系统模式：安全状态下 D 寄存器列表从 D17 以上开始的 VSCCLRM 会在 `trans_VSCCLRM`（`target/arm/tcg/translate-m-nocp.c`）里断言失败，QEMU 退出。oracle 是非安全状态，执行到这段代码之前就判为 UNDEFINED。

## 验证

- **覆盖**：约 200 条指令、54 个测试，预期值按 DDI0553 伪代码手算：T16/T32（含 IT 块）；DSP；单、双、半精度标量浮点（舍入模式、FZ、FZ16、DN、AHP、累积异常标志）；MVE 整数和浮点、VPT 谓词、按 ECI 跳过的 beat；低开销循环（含尾部谓词）。QEMU 全部和架构一致。
- **对照**：约 5.9 万个随机用例，和 gdbstub 驱动的 `qemu-system-arm`（`mps3-an547`，同一个 QEMU 提交，设成非安全、非特权、FPCA = 1）对照。唯一的差异是经 gdbstub 单步 YIELD 时会多执行下一条。改成安全状态或特权模式时，所有差异都能归到上面的用户态替身。
- **访存错误**：40 万个混合用例（含访存错误）不崩，内存稳定在约 20 MB。
- **速度**：Rust 直接调用每例约 3 µs（设状态、执行一条、读回），gdbstub 要 0.14–2 ms。

## 构建

要装：

1. MSYS2（默认 `C:\msys64`，装在别处就设 `MSYS2_ROOT`），在 MSYS2 shell 里：
   ```
   pacman -S --needed mingw-w64-clang-x86_64-clang mingw-w64-clang-x86_64-meson mingw-w64-clang-x86_64-ninja mingw-w64-clang-x86_64-pkgconf mingw-w64-clang-x86_64-python mingw-w64-clang-x86_64-glib2
   ```
   MSYS2 不用加进 PATH。
2. PATH 上有 git。首次构建要联网（取 QEMU 源码和两个 meson 子项目）。

`cargo build` / `cargo test` 时 `build.rs` 从源码编出 DLL（首次约 50 秒，改前端后约 1–2 秒），放在 `OUT_DIR/dist`，连同它要的 5 个运行库；加载时不查 PATH。`build.rs` 不改 crate 目录里的任何文件。

没装 MSYS2 时不算构建失败：只出警告，DLL 不编，`Oracle::new` 返回错误。非 Windows 宿主机也是这样。用它的测试看到这个错误应当跳过。

环境变量：

| 变量 | 作用 |
|---|---|
| `MSYS2_ROOT` | MSYS2 安装目录 |
| `ARMM_ORACLE_QEMU_DIR` | 用这个 QEMU 源码树，不用子模块（离线构建时用） |
| `ARMM_ORACLE_DLL` | 运行时改用这个 DLL |

### 在本仓库里开发

`.gitmodules` 里 qemu 子模块设了 `update = none`（不然 cargo 取 git 依赖时会递归拉 QEMU 的全部子模块），所以要显式检出；Git for Windows 默认会把行尾改成 CRLF，QEMU 的脚本就不能执行了：

```sh
git -c core.autocrlf=false submodule update --init --checkout qemu
git -C qemu config core.autocrlf false
```

不经过 cargo、手动编：`scripts/apply-patches.sh`（给子模块打补丁，`--reset` 还原），再 `scripts/build-oracle.sh`（输出到 `build/oracle-win/dist/`）。

## 作为依赖

```toml
[dev-dependencies]
qemu-armm-oracle = { git = "https://github.com/yufengzjj/qemu-armm-oracle.git" }
```

## 跟进上游 QEMU

换子模块的提交，跑一遍 `cargo test`（只编过不够，有的问题运行时才出现）。补丁用 `git apply --3way` 打，上下文有变化也能打上。上游内部接口变了的话，要改的都在 `frontend/` 里。对上游 master 和往前直到 v10.0.0 的各个版本做过演练：补丁每次都能干净地打上；前端跟到 master 改 0 行，每落后一个版本（约 4 个月）几行到二十几行，落后 18 个月约 90 行。

## 目录

| 路径 | 内容 |
|---|---|
| `qemu/` | 上游 QEMU 子模块 |
| `patches/` | 对 QEMU 的改动（只有 meson 钩子） |
| `frontend/` | oracle 前端（C），`win32/` 和 `host-win32.c` 是 Windows 专用的部分 |
| `include/armm_oracle.h` | C 接口 |
| `src/lib.rs`、`build.rs` | Rust 封装和构建 |
| `tests/` | Rust 测试：构建和加载（`s1`）、执行（`s2`）、访存错误（`s3`）、按类覆盖（`s4_*`）、trait（`s8`） |
| `scripts/s5_compare/` | 和 gdbstub 驱动的 `qemu-system-arm` 对照的随机测试（Python） |
| `scripts/s0-linux-user/` | 上游 linux-user `qemu-arm` 的 M-profile 试验（WSL） |

## 许可证

GPL-2.0-or-later（QEMU 整体按 GPL-2.0 发布，链接出来的库也按它处理），见 `LICENSE`。
