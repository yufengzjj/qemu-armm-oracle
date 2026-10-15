"""Memory layout shared by both sides, and LLVM helpers."""
import os
import subprocess
import tempfile

LLVM_BIN = os.environ.get("S5_LLVM_BIN", r"C:\msys64\clang64\bin")
LLVM_MC = os.path.join(LLVM_BIN, "llvm-mc.exe")
LLVM_OBJCOPY = os.path.join(LLVM_BIN, "llvm-objcopy.exe")
TRIPLE = "thumbv8.1m.main-none-eabi"
MATTR = "+mve.fp,+fp64,+fullfp16,+dsp,+lob"

# Code region: mapped read+execute in the oracle, ITCM on mps3-an547.
# It must reach +-4 KiB around CODE_ADDR for PC-relative loads.
CODE_BASE = 0x1000
CODE_SIZE = 0x3000
CODE_ADDR = 0x2800
CLREX_ADDR = 0x2000

# Data window: the top 16 KiB of the AN547 DTCM (0x20000000-0x2007ffff).
# 0x20080000 and above is unmapped on AN547, so accesses that run off the
# top fault on both sides.
DATA_BASE = 0x2007C000
DATA_SIZE = 0x4000
DATA_END = DATA_BASE + DATA_SIZE

# Regions with nothing behind them in the AN547 CPU address space
# ('info mtree -f', armv7m-container). An access here is a bus error in
# system mode and unmapped in the oracle, so both sides should fault.
AN547_HOLES = [
    (0x00080000, 0x01000000),
    (0x01200000, 0x10000000),
    (0x10080000, 0x11000000),
    (0x11200000, 0x20000000),
    (0x20080000, 0x21000000),
    (0x21400000, 0x28000000),
    (0x28800000, 0x30000000),
    (0x30080000, 0x31000000),
    (0x31400000, 0x38000000),
    (0x38800000, 0x40000000),
]


def in_an547_hole(addr, nonsecure):
    # The AN547 IDAU makes regions with address bit 28 set Secure; a Non-secure access there is a
    # SecureFault, not a bus error.
    if nonsecure and addr >> 28 & 1:
        return False
    return any(lo <= addr < hi for lo, hi in AN547_HOLES)


def assemble(source):
    """Assemble Thumb source placed at address 0 and return the raw bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "a.s")
        obj = os.path.join(tmp, "a.o")
        binf = os.path.join(tmp, "a.bin")
        with open(src, "w") as f:
            f.write(source)
        subprocess.run([LLVM_MC, f"--triple={TRIPLE}", f"-mattr={MATTR}", "-filetype=obj", "-o", obj, src],
                       check=True)
        subprocess.run([LLVM_OBJCOPY, "-O", "binary", "--only-section=.text", obj, binf], check=True)
        with open(binf, "rb") as f:
            return f.read()
