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

- QEMU 是 git 子模块（`qemu/`，钉在 `8ee6c77`，11.1.50），除了 `patches/` 里七个小补丁，**源码不改**，只加文件。
- `frontend/` 是新写的前端：仿照 QEMU 的 linux-user（用户态），但没有系统调用、ELF 加载和信号。它把 `target/arm`、TCG 和 `accel/tcg` 的用户态部分编进一个 DLL，CPU 用 `cortex-m55`。
- 客户机内存是一块 4 GB 的平坦地址窗口，用例要用的页再映射。访问没映射的页由 Windows 的向量化异常处理（VEH）接住，转成客户机的数据异常，进程不崩。
- 对上游的改动就是 `patches/` 里的补丁，按顺序打：
  - `0001`：`meson.build` 加 5 行，把 `frontend/` 接进 QEMU 的构建。
  - `0002`：修 `target/arm/tcg/translate.c`，让地址不对齐的 STREX 总是报对齐错误（[已知的 QEMU 问题](#已知的-qemu-问题)第一条）。
  - `0003`：修同一个函数，让普通存储不改变独占监视器（已知的 QEMU 问题第二条）；另外在 `linux-user/arm/` 里加两行，oracle 不编这部分。
  - `0004`：在 `target/arm/tcg/translate-m-nocp.c` 加一行，让安全状态下 D 寄存器列表从 D17 以上开始的 VSCCLRM 只清 VPR，不再断言失败（已知的 QEMU 问题第三条）。只改变系统模式；oracle 是非安全状态，VSCCLRM 是 UNDEFINED。
  - `0005`：改 `target/arm/tcg/mve_helper.c` 里的两个界限，让 `#48` 形式的 SQRSHRL 和 UQRSHLL 右移 48 到 64 位时结果正确（已知的 QEMU 问题第四条）。
  - `0006`：在 `target/arm/tcg/translate.c` 的四个函数里加 M-profile 检查，让 LDREXD、STREXD、LDAEXD、STLEXD 成为 UNDEFINED（已知的 QEMU 问题第五条）。
  - `0007`：在 `trans_PLDW`（`target/arm/tcg/translate.c`）里加一个条件，让带 Main 扩展的 M-profile CPU 把 PLDW 当作内存提示（已知的 QEMU 问题第六条）。
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
- 每个用例要用 `set_exclusive` 显式设独占监视器，否则会带到下一个用例。只有标记的地址起作用，和内存内容无关，所以在写内存之前或之后设都可以。和 Cortex-M55 一样，普通存储不改变监视器。STREX 的地址和标记的地址不同时失败（两种结果都是 IMPLEMENTATION DEFINED；Cortex-M55 的监视器不记地址，会执行存储）。
- 出访存错误后只比异常种类、pc 和出错地址：LDM、VLDRW/VSTRW 会留下已完成的部分，基址写回不会发生。
- pc 在 `0xffff0000` 及以上时会碰到 QEMU 的 Linux 内核辅助页陷阱，返回 `Unimplemented`。
- 不支持：PACBTI（QEMU 没实现：PAC/AUT/BTI 是空操作，PACG/AUTG/BXAUT 会被当成 SMMUL/SMMLA 执行，随机用例要排除）、CDE、异常进出、惰性浮点压栈、MPU。Rn 为 PC 且 W = 1 的 LDRD 和 STRD（例如 `ldrd r11, r12, [pc], #832`）也要排除：QEMU 把算出的地址写回 pc，相当于跳转。对 LDRD（literal），这是 DDI0553 C2.4.86 允许的一种 CONSTRAINED UNPREDICTABLE 行为（按前变址或后变址执行）；UNDEFINED、NOP、执行但不写回也都允许。Rn 为 PC 的 STRD 是 UNPREDICTABLE。

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

- 本项目已用 `patches/0002-unaligned-strex-fault.patch` 修复：上游 QEMU 里，地址不对齐的 STREX/STREXH（以及 STLEX/STLEXH）在独占监视器和地址不匹配时不报对齐错误，只返回 1（存储失败）。按架构应当是 UNALIGNED UsageFault（`ExclusiveMonitorsPass` 先查对齐）。原因在 `target/arm/tcg/translate.c` 的 `gen_store_exclusive`，所以上游的系统模式和 linux-user 也一样。补丁在检查监视器之前先查对齐，按存储报错；`tests/s4_exclusive.rs` 覆盖这一条。
- 本项目已用 `patches/0003-plain-store-keeps-exclusive-monitor.patch` 修复：上游 QEMU 里，STREX 是否成功按内存是否还等于 LDREX 读到的值判断，所以 LDREX 和 STREX 之间普通存储写了不同的值，STREX 失败；写了相同的值，STREX 成功。架构把"同一个核不是 Store-Exclusive 的存储是否改变本地监视器"定为 IMPLEMENTATION DEFINED（DDI0553 B9.2），但真实实现不会按数据决定。Cortex-M55 不改变监视器（Cortex-M55 TRM 的 "Internal local exclusive access monitor"）。补丁让 QEMU 也这样：**同一个核的普通存储不改变本地监视器**，STREX 到标记的地址时执行存储并返回 0。这只用于只有一个线程的用户态（翻译时没有 `CF_PARALLEL`），oracle 总是这种情况。有多个线程时，以及系统模式下（轮转式 TCG 在一个线程里跑多个 vCPU），QEMU 保留比较值的做法，用它代替全局监视器；所以 `qemu-system-arm` 仍是原来的行为。对 linux-user，补丁还在系统调用和投递信号时清除监视器，和 Linux 每次返回用户态时一样。`tests/s4_exclusive.rs` 覆盖这一条；STREX 的访存错误现在也按存储报。
- 本项目已用 `patches/0004-vscclrm-unimplemented-dregs.patch` 修复（只影响系统模式）：上游 QEMU 里，安全状态下 D 寄存器列表从 D17 以上开始的 VSCCLRM（例如 `vscclrm {d17, vpr}`）会在 `trans_VSCCLRM`（`target/arm/tcg/translate-m-nocp.c`）里断言失败，QEMU 退出。按架构，只有 16 个 D 寄存器的处理器上，D15 以上的寄存器不动（VSCCLRM 的操作伪代码跳过它们，DDI0553 B4.3 也规定 VSCCLRM 对没有实现的 S、D 寄存器相当于 NOP），所以这样的列表只清 VPR。补丁就这样做。oracle 是非安全状态，执行到这段代码之前就判为 UNDEFINED，结果不变；`scripts/s5_compare/vscclrm_check.py` 在安全状态下用打了补丁的 `qemu-system-arm` 检查这个修复。
- 本项目已用 `patches/0005-mve-48bit-long-shift-right.patch` 修复：上游 QEMU 里，`sqrshrl RdaLo, RdaHi, #48, Rm` 右移 48 到 63 位、`uqrshll RdaLo, RdaHi, #48, Rm` 右移 49 到 64 位（Rm 的低字节为负）时，结果总是 0。按架构，先对整个 64 位的 RdaHi:RdaLo 做带舍入的移位，再饱和到 48 位，所以输入在第 47 位以上有有效位时结果不是 0：例如 2^62 右移 50 位得 4096，2^63 右移 49 位（无符号）得 16384。原因：`do_sqrshl48_d` 和 `do_uqrshl48_d` 在移位数达到 `-48`、`-(48 + round)` 时提前返回 0，这只对能放进 48 位的输入成立；补丁改用 64 位版本的界限（`-64`、`-(64 + round)`）。系统模式也有这个问题。`tests/s4_mve.rs` 覆盖这一条，包括 `#48` 和 `#64` 形式共 4000 个和伪代码模型对照的随机用例。
- 本项目已用 `patches/0006-m-profile-no-doubleword-exclusives.patch` 修复：上游 QEMU 里，M-profile 的 CPU 会把 LDREXD、STREXD、LDAEXD、STLEXD（例如 `ldrexd r2, r3, [r1]`，`e8d1 237f`）当作 A-profile 的双字独占指令执行。Armv8-M 没有这几条指令：DDI0553 的 T32 编码表（C2.3.2.2.2、C2.3.2.2.3）里没有 sz = 11 这一行，所以这些编码是未分配的（C1.4.1）。原因：`trans_LDREXD_t32`、`trans_STREXD_t32`、`trans_LDAEXD_t32`、`trans_STLEXD_t32` 不检查是不是 M-profile；补丁让它们在 M-profile 上成为 UNDEFINED。系统模式也有这个问题。`tests/s4_exclusive.rs` 覆盖这一条。
- 本项目已用 `patches/0007-m-profile-pldw-hint.patch` 修复：上游 QEMU 里，M-profile 的 CPU 把 PLDW 的三种形式（立即数 T1、T2，寄存器）都当成 Rt = 15 的 LDRH 执行：读一个半字写进 pc，相当于跳转。例如 `pldw [r0, #0x25e]`（`f8b0 f25e`）在该地址存着半字 0x1235 时，pc 变成 0x1234。DDI0553 里 PLDW 属于 Main 扩展（C2.4.140、C2.4.141），是不改任何寄存器的内存提示；C1.4.3 也规定 Rt = 0b1111 的 LDRH 是内存提示，不是加载。原因：`trans_PLDW` 返回 `arm_dc_feature(s, ARM_FEATURE_V7MP)`，M-profile 的 CPU 没有这个特性，decodetree 于是落到 `LDRH_ri` / `LDRH_rr`。补丁让它在有 `ARM_FEATURE_M_MAIN` 时也返回 true。这对 Armv7-M 的 CPU（Cortex-M3、M4、M7）同样正确：Armv7-M 没有 PLDW，Armv7-M 手册（DDI0403E.e，A5.3.8 表 A5-19）把这些编码列为必须按 NOP 执行的未分配内存提示，所以它们原来也有这个问题。系统模式也有这个问题。`tests/s4_system.rs` 覆盖这一条。

## 验证

- **覆盖**：约 200 条指令、67 个测试，预期值按 DDI0553 伪代码手算：T16/T32（含 IT 块）；DSP；单、双、半精度标量浮点（舍入模式、FZ、FZ16、DN、AHP、累积异常标志）；MVE 整数和浮点、VPT 谓词、按 ECI 跳过的 beat；低开销循环（含尾部谓词）。除了上面已知的 QEMU 问题，QEMU 全部和架构一致。
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

缺少前提条件时不算构建失败：只出警告，DLL 不编，`Oracle::new` 返回带原因的错误。包括：非 Windows 宿主机、没装 MSYS2、缺 CLANG64 的包、PATH 上没有 git、首次下载 QEMU 或 meson 子项目时没网。用它的测试看到这个错误应当跳过。条件补齐后，下次构建会重试；只有新装 MSYS2 本身之后要运行一次 `cargo clean -p qemu-armm-oracle`（或者设 `MSYS2_ROOT`）。configure 或编译本身出错仍然算构建失败。

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

换子模块的提交，跑一遍 `cargo test`（只编过不够，有的问题运行时才出现）。补丁用 `git apply --3way` 打，上下文有变化也能打上。上游内部接口变了的话，要改的都在 `frontend/` 里。对上游 master 和往前直到 v10.0.0 的各个版本做过演练：meson 补丁每次都能干净地打上；前端跟到 master 改 0 行，每落后一个版本（约 4 个月）几行到二十几行，落后 18 个月约 90 行。`0002` 和 `0003` 改的是同一个函数，`0003` 是在 `0002` 之上做的：其中一个更新后，要在打了 `0001` 和 `0002` 的源码树上重新生成 `0003`。上游自己修好 STREX 对齐问题以后，删掉 `patches/0002-*.patch`；独占监视器的问题修好以后，同样删掉 `0003`；VSCCLRM 断言的问题修好以后删掉 `0004`；48 位长移位的问题修好以后删掉 `0005`；双字独占指令的问题修好以后删掉 `0006`；PLDW 的问题修好以后删掉 `0007`。`0004` 和 `0005` 各改一个别的文件，不依赖其他补丁；`0006` 和 `0007` 改的是 `translate.c` 里别的函数，打不打 `0002`、`0003` 都能打上。

## 目录

| 路径 | 内容 |
|---|---|
| `qemu/` | 上游 QEMU 子模块 |
| `patches/` | 对 QEMU 的改动：meson 钩子、STREX 对齐修复、独占监视器修复、VSCCLRM 修复、48 位长移位修复、双字独占指令修复和 PLDW 修复 |
| `frontend/` | oracle 前端（C），`win32/` 和 `host-win32.c` 是 Windows 专用的部分 |
| `include/armm_oracle.h` | C 接口 |
| `src/lib.rs`、`build.rs` | Rust 封装和构建 |
| `tests/` | Rust 测试：构建和加载（`s1`）、执行（`s2`）、访存错误（`s3`）、按类覆盖（`s4_*`）、trait（`s8`） |
| `scripts/s5_compare/` | 和 gdbstub 驱动的 `qemu-system-arm` 对照的随机测试（Python）；`vscclrm_check.py` 在安全状态下按伪代码检查 VSCCLRM |
| `scripts/s0-linux-user/` | 上游 linux-user `qemu-arm` 的 M-profile 试验（WSL） |

## 许可证

GPL-2.0-or-later（QEMU 整体按 GPL-2.0 发布，链接出来的库也按它处理），见 `LICENSE`。
