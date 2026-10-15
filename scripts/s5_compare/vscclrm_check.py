"""Run VSCCLRM forms in Secure state on qemu-system-arm (gdbstub) and check them against the DDI0553B.z pseudocode.

python scripts/s5_compare/vscclrm_check.py                    # build/qemu-system-patched (patches 0001-0004)
python scripts/s5_compare/vscclrm_check.py --qemu same        # build/qemu-system-win (no patches): D17+ lists crash it

Exit status 0 only if every case gives the expected result in both unprivileged and privileged Thread mode.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from classify import normalize_system  # noqa: E402
from common import CODE_ADDR, DATA_BASE, DATA_SIZE, assemble  # noqa: E402
from rsp import RspError  # noqa: E402
from run import QEMUS, base_code_image  # noqa: E402
from sysqemu import SysQemu  # noqa: E402

# (assembler text, or raw halfwords for forms the assembler does not accept; what the case covers)
CASES = [
    ("vscclrm {d17, vpr}", "D list starting at D17"),
    ("vscclrm {d22, d23, d24, d25, vpr}", "D list above D15"),
    ("vscclrm {d31, vpr}", "D list at D31"),
    ((0xECDF, 0x1B00), "D list at D17, no registers"),
    ((0xECDF, 0x4B00), "D list at D20, no registers"),
    ("vscclrm {d16, vpr}", "D list starting at D16"),
    ("vscclrm {d16, d17, d18, vpr}", "D list D16-D18"),
    ("vscclrm {d14, d15, d16, d17, vpr}", "D list crossing D15/D16"),
    ("vscclrm {d15, vpr}", "D list at D15"),
    ("vscclrm {d0, d1, d2, d3, vpr}", "ordinary D list"),
    ((0xEC9F, 0x0B40), "D list D0-D31"),
    ("vscclrm {s0, s1, s2, s3, vpr}", "ordinary S list"),
    ("vscclrm {s5, s6, s7, s8, s9, vpr}", "S list from an odd register"),
    ("vscclrm {s29, s30, s31, vpr}", "S list ending at S31"),
    ("vscclrm {s31, vpr}", "S list at S31"),
    ((0xEC9F, 0xFA04), "S list S30-S33, crossing S31"),
    ("vscclrm {vpr}", "VPR only"),
    ((0xECDF, 0xEB08), "D list D30-D33 (UNPREDICTABLE)"),
]

D_INIT = [0x0101010101010101 * (i + 1) for i in range(16)]
VPR_INIT = 0x00F01234
FPSCR_INIT = 0x00040000  # LTPSIZE = 4
R_INIT = [0x1000 + i for i in range(13)] + [DATA_BASE + DATA_SIZE // 2, 0, CODE_ADDR]


def spec_effect(hw1, hw2):
    """VSCCLRM decode and operation (C2.4.470) on a PE with 16 D registers (VFPSmallRegisterBank() is TRUE).
    Returns None for UNPREDICTABLE, else the set of S registers (0-31) that are zeroed; VPR is always zeroed."""
    D = hw1 >> 6 & 1
    vd = hw2 >> 12 & 0xF
    if hw2 >> 8 & 0xF == 0xB:
        d, regs = D << 4 | vd, hw2 >> 1 & 0x7F
        if d + regs - 1 > 31:
            return None
        return {s for r in range(regs) if d + r < 16 for s in (2 * (d + r), 2 * (d + r) + 1)}
    d, regs = vd << 1 | D, hw2 & 0xFF
    top = d + regs - 1
    if top > 63 or (top > 31 and top % 2 == 0):
        return None
    return {d + r for r in range(regs) if d + r < 32}


def expected_d(cleared):
    out = []
    for i, v in enumerate(D_INIT):
        if 2 * i in cleared:
            v &= 0xFFFFFFFF00000000
        if 2 * i + 1 in cleared:
            v &= 0x00000000FFFFFFFF
        out.append(v)
    return out


def encodings():
    texts = [c for c, _ in CASES if isinstance(c, str)]
    blob = assemble(".syntax unified\n.thumb\n" + "\n".join(texts) + "\n")
    if len(blob) != 4 * len(texts):
        raise SystemExit("unexpected assembler output size")
    out, k = [], 0
    for c, what in CASES:
        if isinstance(c, str):
            hw1, hw2 = struct.unpack("<HH", blob[4 * k:4 * k + 4])
            k += 1
        else:
            hw1, hw2 = c
        out.append((hw1, hw2, what))
    return out


def check_one(q, hw1, hw2):
    """(ok, text) for one case; q is relaunched by the caller if QEMU died."""
    q.write_mem(CODE_ADDR, struct.pack("<HH", hw1, hw2))
    q.set_state({"r": R_INIT, "xpsr": 1 << 24, "d": D_INIT, "fpscr": FPSCR_INIT, "vpr": VPR_INIT})
    res = q.step()
    cleared = spec_effect(hw1, hw2)
    if cleared is None:
        # UNPREDICTABLE: any non-crashing result is allowed; QEMU chooses UNDEFINED.
        kind = normalize_system(res)["kind"]
        return kind == "UNDEFINED", f"UNPREDICTABLE, QEMU: {kind}"
    if res["kind"] != "RETIRED":
        return False, f"expected to retire, got {normalize_system(res)['kind']}{normalize_system(res)['detail']}"
    errs = []
    want_d = expected_d(cleared)
    for i in range(16):
        if res["d"][i] != want_d[i]:
            errs.append(f"d{i} {res['d'][i]:#x} (expected {want_d[i]:#x})")
    if res["vpr"] != 0:
        errs.append(f"vpr {res['vpr']:#x} (expected 0)")
    if res["fpscr"] != FPSCR_INIT:
        errs.append(f"fpscr {res['fpscr']:#x}")
    if res["r"][:15] != R_INIT[:15] or res["r"][15] != CODE_ADDR + 4:
        errs.append("core registers changed")
    if res.get("control_changed"):
        errs.append("CONTROL changed")
    lo, hi = (min(cleared), max(cleared)) if cleared else (None, None)
    what = "clears VPR" + ("" if not cleared else f" and S{lo}" if lo == hi else f" and S{lo}-S{hi}") + \
        (" only" if not cleared else "")
    return not errs, what + ("" if not errs else ": " + "; ".join(errs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", default="patched", help="'patched', 'same', 'installed', or a path")
    args = ap.parse_args()
    exe, prefix = QEMUS.get(args.qemu, (args.qemu, None))
    print(f"system QEMU {exe}, Secure state")
    cases = encodings()
    failures = 0
    for privileged in (False, True):
        q = SysQemu(exe, prefix, privileged=privileged, nonsecure=False)
        img = base_code_image()
        q.launch(img, bytes(DATA_SIZE))
        print("privileged" if privileged else "unprivileged")
        for hw1, hw2, what in cases:
            try:
                ok, text = check_one(q, hw1, hw2)
            except RspError as e:
                try:
                    code = q.proc.wait(timeout=5)
                except Exception:
                    code = None
                ok = False
                text = f"QEMU died ({e})" if code is None else \
                    f"QEMU exited with {code & 0xFFFFFFFF:#x}: {q.stderr_text()[-160:]}"
                q.launch(img, bytes(DATA_SIZE))
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {hw1:04x} {hw2:04x}  {what}: {text}")
        q.close()
    print(f"{failures} failed" if failures else "all passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
