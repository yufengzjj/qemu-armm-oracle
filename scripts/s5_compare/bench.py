"""S6: time per case for the oracle (through ctypes) and the gdbstub, outside the comparison loop.

python scripts/s5_compare/bench.py [--qemu same|installed|PATH]
"""
import argparse
import ctypes
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cases import data_image, generate  # noqa: E402
from common import CODE_ADDR, CODE_BASE, DATA_BASE  # noqa: E402
from oracle import stage_dll  # noqa: E402
from run import QEMUS, OracleSide, SystemSide, base_code_image, code_bytes  # noqa: E402

MOVS_R0_5 = bytes.fromhex("0520")


def summary(name, ts, note=""):
    ts = sorted(ts)
    p99 = ts[min(len(ts) - 1, int(round(0.99 * (len(ts) - 1))))]
    print(f"  {name:58s} n={len(ts):6d} median {statistics.median(ts) * 1e6:9.2f} us  p99 {p99 * 1e6:9.2f} us"
          f"  {note}", flush=True)


def timed(fn, n, warm=200):
    for _ in range(warm):
        fn()
    out = []
    pc = time.perf_counter
    for _ in range(n):
        t0 = pc()
        fn()
        out.append(pc() - t0)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", default="same")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--cases", type=int, default=5000)
    args = ap.parse_args()

    cases = generate(args.cases, args.seed)
    data = data_image(args.seed)
    oside = OracleSide(stage_dll(), data)
    o, lib, h = oside.o, oside.o.lib, oside.o.o
    print("oracle (Python + ctypes):")

    summary("one ctypes call (armm_get_xpsr)", timed(lambda: lib.armm_get_xpsr(h), 100000))

    o.write_mem(CODE_ADDR, MOVS_R0_5 + bytes.fromhex("00bf"))

    def minimal():
        lib.armm_set_r(h, 0, 0)
        lib.armm_set_r(h, 15, CODE_ADDR)
        lib.armm_step(h, o._res_ref)
        lib.armm_get_r(h, 0)
    summary("2 writes + step + 1 read (as the probe script)", timed(minimal, 50000))

    # Same work per case as S2's Rust loop: code bytes, r0-r15, xPSR, q0-q7, FPSCR, VPR in and out.
    q_lo, q_hi = ctypes.byref(ctypes.c_uint64()), ctypes.byref(ctypes.c_uint64())

    def s2_like(case):
        lib.armm_write_mem(h, CODE_ADDR, code_bytes(case), 4)
        st = case["state"]
        for i in range(16):
            lib.armm_set_r(h, i, st["r"][i])
        lib.armm_set_xpsr(h, st["xpsr"])
        for i in range(8):
            lib.armm_set_q(h, i, st["d"][2 * i], st["d"][2 * i + 1])
        lib.armm_set_fpscr(h, st["fpscr"])
        lib.armm_set_vpr(h, st["vpr"])
        lib.armm_step(h, o._res_ref)
        for i in range(16):
            lib.armm_get_r(h, i)
        lib.armm_get_xpsr(h)
        for i in range(8):
            lib.armm_get_q(h, i, q_lo, q_hi)
        lib.armm_get_fpscr(h)
        lib.armm_get_vpr(h)
    ts = []
    for c in cases[:200]:
        s2_like(c)
    pc = time.perf_counter
    for c in cases:
        t0 = pc()
        s2_like(c)
        ts.append(pc() - t0)
    summary("random case, S2-style state (no memory window)", ts, "56 ctypes calls")
    ts = []
    for c in cases:
        st = c["state"]
        oside.o.set_state(st, oside.control)
        enc = code_bytes(c)
        t0 = pc()
        lib.armm_write_mem(h, CODE_ADDR, enc, 4)
        lib.armm_step(h, o._res_ref)
        ts.append(pc() - t0)
    summary("random case, only write code + step (translation included)", ts, "2 ctypes calls")
    o.write_mem(DATA_BASE, data)

    ts = []
    for c in cases:
        ts.append(oside.run(c)["time"])
    summary("random case as in run.py (+ D 16 KiB read and restore)", ts)

    exe, prefix = QEMUS.get(args.qemu, (args.qemu, None))
    print(f"gdbstub ({exe}):")
    sside = SystemSide(exe, prefix, data, False, True)
    q = sside.q
    img = base_code_image()
    img[CODE_ADDR - CODE_BASE:CODE_ADDR - CODE_BASE + 4] = MOVS_R0_5 + bytes.fromhex("00bf")
    q.sync_memory(img, data, data)
    n_r0, n_pc = 0, 15

    def gminimal():
        q.set_reg(n_pc, CODE_ADDR)
        q.set_reg(n_r0, 0)
        q.r.cmd("s")
        q.get_reg(n_r0)
    summary("2 writes + step + 1 read (as the probe script)", timed(gminimal, 3000, warm=50))
    summary("one round trip ('p' of r0)", timed(lambda: q.get_reg(n_r0), 3000, warm=50))

    ts = []
    for c in cases[:2000]:
        r = sside.run(c)
        if r["kind"] != "HARNESS_ERROR":
            ts.append(r["time"])
    summary("random case as in run.py (+ D 16 KiB read and restore)", ts)
    q.close()


if __name__ == "__main__":
    main()
