"""S5/S6: run the same random cases through armm_oracle.dll and through qemu-system-arm's gdbstub.

python scripts/s5_compare/run.py --count 10000 --seed 1
python scripts/s5_compare/run.py --seed 1 --only 123 -v        # rerun and print one case
python scripts/s5_compare/run.py --qemu installed --count 2000  # QEMU 9.2.50 in C:\\Program Files\\qemu
python scripts/s5_compare/run.py --qemu patched --secure --templates sys --count 3000  # system/security insns
"""
import argparse
import collections
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cases import TEMPLATES, data_image, generate  # noqa: E402
from classify import classify, classify_harness_error, normalize_system  # noqa: E402
from common import (CLREX_ADDR, CODE_ADDR, CODE_BASE, CODE_SIZE, DATA_BASE, DATA_END, DATA_SIZE,  # noqa: E402
                    in_an547_hole)
from oracle import PROT_EXEC, PROT_READ, PROT_WRITE, Oracle, stage_dll  # noqa: E402
from rsp import RspError  # noqa: E402
from sysqemu import CONTROL_FPCA, CONTROL_NPRIV, SysQemu, diff_runs  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
QEMUS = {
    "same": (os.path.join(ROOT, "build", "qemu-system-win", "qemu-system-arm.exe"), r"C:\msys64\clang64\bin"),
    "patched": (os.path.join(ROOT, "build", "qemu-system-patched", "qemu-system-arm.exe"), r"C:\msys64\clang64\bin"),
    "installed": (r"C:\Program Files\qemu\qemu-system-arm.exe", None),
}
CLREX = bytes.fromhex("bff32f8f")
NOP = bytes.fromhex("00bf")


def code_bytes(case):
    enc = case["enc"]
    return enc if len(enc) == 4 else enc + NOP


def base_code_image():
    img = bytearray(CODE_SIZE)
    img[CLREX_ADDR - CODE_BASE:CLREX_ADDR - CODE_BASE + 4] = CLREX
    # NOPs after the case instruction: the gdbstub single-step over YIELD also runs the next one.
    img[CODE_ADDR + 4 - CODE_BASE:CODE_ADDR + 16 - CODE_BASE] = NOP * 6
    return img


def is_store_exclusive(case):
    return case["text"].split()[0].startswith(("strex", "stlex"))


def pre_step(case):
    """Instruction run at CLREX_ADDR before the case to put the exclusive monitor in a known state:
    the matching LDREX (monitor open on the STREX address) or CLREX (closed)."""
    return case["state"].get("ldrex") or (CLREX if is_store_exclusive(case) else None)


class OracleSide:
    def __init__(self, dll, data):
        self.o = Oracle(dll)
        self.o.map(CODE_BASE, CODE_SIZE, PROT_READ | PROT_EXEC)
        self.o.map(DATA_BASE, DATA_SIZE, PROT_READ | PROT_WRITE)
        self.o.write_mem(CODE_BASE, base_code_image())
        self.data = data
        self.o.write_mem(DATA_BASE, data)
        self.control = CONTROL_NPRIV | CONTROL_FPCA

    def run(self, case):
        o = self.o
        t0 = time.perf_counter()
        o.write_mem(CODE_ADDR, code_bytes(case))
        o.close_exclusive()
        pre = case["state"].get("ldrex")
        if pre:
            o.write_mem(CLREX_ADDR, pre)
            o.set_state(case["state"], self.control)
            o.lib.armm_set_r(o.o, 15, CLREX_ADDR)
            o.step()
            o.write_mem(CLREX_ADDR, CLREX)
        o.set_state(case["state"], self.control)
        res = o.step()
        res.update(o.read_state())
        res["data"] = o.read_mem(DATA_BASE, DATA_SIZE)
        for lo, hi in diff_runs(res["data"], self.data):
            o.write_mem(DATA_BASE + lo, self.data[lo:hi])
        res["time"] = time.perf_counter() - t0
        return res


class SystemSide:
    def __init__(self, exe, path_prefix, data, privileged, nonsecure):
        self.q = SysQemu(exe, path_prefix, privileged, nonsecure)
        self.data = data
        self.code = base_code_image()
        self.q.launch(self.code, data)
        self.data_after = data
        self.relaunches = 0
        self.privileged = privileged

    def relaunch(self):
        self.relaunches += 1
        self.q.launch(base_code_image(), self.data)
        self.data_after = self.data

    def run(self, case):
        q = self.q
        img = base_code_image()
        img[CODE_ADDR - CODE_BASE:CODE_ADDR - CODE_BASE + 4] = code_bytes(case)
        pre = pre_step(case)
        if pre:
            img[CLREX_ADDR - CODE_BASE:CLREX_ADDR - CODE_BASE + 4] = pre
        t0 = time.perf_counter()
        try:
            q.sync_memory(img, self.data, self.data_after)
            if pre:
                st = case["state"]
                q.set_core(st["r"][:15] + [CLREX_ADDR], st["xpsr"])
                r = q.step()
                if r.get("frame_unreadable") or r.get("control_changed"):
                    raise RspError("pre-step left an unusable state")
                q.sync_memory(img, self.data, r.get("data"))
            q.set_state(case["state"])
            res = q.step()
        except RspError as e:
            try:
                code = q.proc.wait(timeout=2)
            except Exception:
                code = None
            err = str(e)
            if code is not None:
                err += f" (QEMU exited with {code & 0xFFFFFFFF:#x}: {q.stderr_text()[-300:]})"
            self.relaunch()
            return {"kind": "HARNESS_ERROR", "error": err, "time": time.perf_counter() - t0}
        res["time"] = time.perf_counter() - t0
        self.data_after = res.get("data")
        mn = case["text"].split()[0]
        if res.get("halted") or res.get("control_changed") or res.get("frame_unreadable") or \
                (self.privileged and mn.startswith(("msr", "cps"))):
            res["relaunched"] = True
            self.relaunch()
        return res


def skip_reason(case, ores, nonsecure):
    """Cases whose oracle run touched memory that the two sides do not share."""
    if ores["kind"] != "DATA_ABORT":
        return None
    a = ores["fault_addr"]
    fs = ores["fsr"] & 0xF
    if fs == 0x1:
        return None
    if fs == 0xF:
        return "write to the code region (read-only in the oracle, ITCM RAM in system mode)"
    if DATA_BASE <= a < DATA_END or in_an547_hole(a, nonsecure):
        return None
    return "address outside the shared window, mapped (or Secure) on AN547"


REG_NAMES = [f"r{i}" for i in range(13)] + ["sp", "lr", "pc"]


def compare(case, o, s, control_mask):
    """List of (field, oracle value, system value) that differ, or [] if they agree."""
    sn = normalize_system(s)
    diffs = []
    if o["kind"] != sn["kind"]:
        diffs.append(("kind", o["kind"] + oracle_detail(o), sn["kind"] + sn["detail"]))
        return diffs, sn
    if o["kind"] == "RETIRED":
        for i in range(16):
            if o["r"][i] != s["r"][i]:
                diffs.append((REG_NAMES[i], o["r"][i], s["r"][i]))
        if o["xpsr"] != s["xpsr"]:
            diffs.append(("xpsr", o["xpsr"], s["xpsr"]))
        for i in range(16):
            if o["d"][i] != s["d"][i]:
                diffs.append((f"d{i}", o["d"][i], s["d"][i]))
        for f in ("fpscr", "vpr"):
            if o[f] != s[f]:
                diffs.append((f, o[f], s[f]))
        if (o["control"] & control_mask) != (s["control"] & control_mask):
            diffs.append(("control", o["control"], s["control"]))
        if s["data"] is not None:
            for lo, hi in diff_runs(o["data"], s["data"], gap=4):
                diffs.append((f"mem[{DATA_BASE + lo:#x}+{hi - lo}]", o["data"][lo:hi].hex(),
                              s["data"][lo:hi].hex()))
        return diffs, sn
    if sn["pc"] is None:
        diffs.append(("pc", o["pc"], "stack frame not readable"))
    elif o["pc"] != sn["pc"]:
        diffs.append(("pc", o["pc"], sn["pc"]))
    if o["kind"] in ("DATA_ABORT", "PREFETCH_ABORT"):
        if sn.get("addr") is not None and o["fault_addr"] != sn["addr"]:
            diffs.append(("fault_addr", o["fault_addr"], sn["addr"]))
        if sn.get("fault_type") and sn["fault_type"] != oracle_fault_type(o):
            diffs.append(("fault_type", oracle_fault_type(o), sn["fault_type"]))
    elif sn["pc"] is not None:
        for i in range(13):
            if o["r"][i] != s["r"][i]:
                diffs.append((REG_NAMES[i], o["r"][i], s["r"][i]))
    return diffs, sn


def oracle_fault_type(o):
    return {0x1: "alignment", 0x7: "unmapped", 0xF: "permission"}.get(o["fsr"] & 0xF, f"fsr{o['fsr']:#x}")


def oracle_detail(o):
    if o["kind"] in ("DATA_ABORT", "PREFETCH_ABORT"):
        return f"({oracle_fault_type(o)} @{o['fault_addr']:#x})"
    return ""


def fmt(v):
    return f"{v:#x}" if isinstance(v, int) else str(v)


def state_text(st):
    lines = ["  " + " ".join(f"{REG_NAMES[i]}={st['r'][i]:#010x}" for i in range(0, 8)),
             "  " + " ".join(f"{REG_NAMES[i]}={st['r'][i]:#010x}" for i in range(8, 16)),
             f"  xpsr={st['xpsr']:#010x} fpscr={st['fpscr']:#010x} vpr={st['vpr']:#010x}",
             "  " + " ".join(f"d{i}={st['d'][i]:#018x}" for i in range(0, 4)),
             "  " + " ".join(f"d{i}={st['d'][i]:#018x}" for i in range(4, 8)),
             "  " + " ".join(f"d{i}={st['d'][i]:#018x}" for i in range(8, 12)),
             "  " + " ".join(f"d{i}={st['d'][i]:#018x}" for i in range(12, 16))]
    return "\n".join(lines)


def case_text(case):
    return f"#{case['id']} {case['enc'][:case['size']].hex()} {case['text']} [{case['tmpl']}/{case['cat']}]"


def pct(values, p):
    v = sorted(values)
    if not v:
        return float("nan")
    k = min(len(v) - 1, max(0, int(round(p / 100 * (len(v) - 1)))))
    return v[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--qemu", default="same",
                    help="'same' (build/qemu-system-win), 'patched' (build/qemu-system-patched, patches applied), "
                         "'installed', or a path")
    ap.add_argument("--privileged", action="store_true", help="run the system side privileged (default: nPRIV=1)")
    ap.add_argument("--secure", action="store_true", help="run the system side in Secure state (default: Non-secure)")
    ap.add_argument("--only", type=int, nargs="*", help="run only these case ids")
    ap.add_argument("--templates", nargs="*", help="generate cases from these templates only (e.g. sys)")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "s5"))
    ap.add_argument("--dll", default=None, help="armm_oracle.dll to load (default: copy of build/oracle-win/dist)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    t_gen = time.perf_counter()
    cases = generate(args.count if not args.only else max(args.only) + 1, args.seed, templates=args.templates)
    t_gen = time.perf_counter() - t_gen
    if args.only:
        cases = [cases[i] for i in args.only]
    print(f"generated {len(cases)} cases in {t_gen:.1f} s", flush=True)

    exe, prefix = QEMUS.get(args.qemu, (args.qemu, None))
    dll = args.dll or stage_dll()
    data = data_image(args.seed)
    oside = OracleSide(dll, data)
    sside = SystemSide(exe, prefix, data, args.privileged, not args.secure)

    os.makedirs(args.out, exist_ok=True)
    qname = args.qemu if args.qemu in QEMUS else os.path.basename(os.path.dirname(exe))
    tag = (f"seed{args.seed}-n{len(cases)}-{qname}-{'s' if args.secure else 'ns'}"
           f"{'-priv' if args.privileged else ''}{'-' + '+'.join(args.templates) if args.templates else ''}")
    out_diffs = open(os.path.join(args.out, f"diffs-{tag}.txt"), "w")

    stats = collections.Counter()
    per_cat = collections.defaultdict(collections.Counter)
    per_tmpl = collections.Counter()
    outcomes = collections.Counter()
    mapped = collections.Counter()
    causes = collections.defaultdict(list)
    skipped = collections.defaultdict(list)
    t_or, t_sys = [], []
    t_split = collections.defaultdict(list)
    relaunch_why = collections.Counter()
    t_start = time.perf_counter()
    for n, case in enumerate(cases):
        per_tmpl[case["tmpl"]] += 1
        o = oside.run(case)
        t_or.append(o["time"])
        why = skip_reason(case, o, not args.secure)
        if why:
            skipped[why].append(case["id"])
            per_cat[case["cat"]]["skipped"] += 1
            continue
        s = sside.run(case)
        if s["kind"] == "HARNESS_ERROR":
            cause = classify_harness_error(case, s)
            causes[cause].append((case, [("error", o["kind"], s["error"])], o, s))
            per_cat[case["cat"]]["harness"] += 1
            stats["harness"] += 1
            out_diffs.write(f"{case_text(case)}\n  cause: {cause[0]}: {cause[1]}\n  error: {s['error']}\n")
            out_diffs.write(state_text(case["state"]) + "\n\n")
            continue
        if s.get("relaunched"):
            relaunch_why[case["text"].split()[0]] += 1
        t_sys.append(s["time"])
        t_split[("oracle", "retired" if o["kind"] == "RETIRED" else "fault")].append(o["time"])
        t_split[("system", "retired" if s["kind"] == "RETIRED" else "fault")].append(s["time"])
        # The oracle always runs unprivileged, so nPRIV is a known difference on a privileged system side.
        diffs, sn = compare(case, o, s, 6 if args.privileged else 7)
        outcomes[o["kind"]] += 1
        if sn.get("mapped") and o["kind"] == sn["kind"]:
            mapped[sn["mapped"]] += 1
        if not diffs:
            per_cat[case["cat"]]["same"] += 1
            stats["same"] += 1
            continue
        cause = classify(case, o, s, sn, diffs, args.privileged, args.secure, args.qemu not in ("same", "patched"))
        causes[cause].append((case, diffs, o, s))
        per_cat[case["cat"]]["differ"] += 1
        stats["differ"] += 1
        out_diffs.write(f"{case_text(case)}\n  cause: {cause[0]}: {cause[1]}\n")
        for f, a, b in diffs:
            out_diffs.write(f"  {f}: oracle {fmt(a)} system {fmt(b)}\n")
        out_diffs.write(state_text(case["state"]) + "\n\n")
        if args.verbose:
            print(case_text(case), cause, [(f, fmt(a), fmt(b)) for f, a, b in diffs])
        if (n + 1) % 1000 == 0:
            print(f"  {n + 1} cases, {time.perf_counter() - t_start:.0f} s", flush=True)
    t_total = time.perf_counter() - t_start
    sside.q.close()
    out_diffs.close()

    if args.verbose and len(cases) <= 20:
        for case in cases:
            print(case_text(case))
            print(state_text(case["state"]))

    report = []
    report.append(f"seed {args.seed}, {len(cases)} cases, system QEMU {exe}, system side "
                  f"{'privileged' if args.privileged else 'unprivileged'} "
                  f"{'Secure' if args.secure else 'Non-secure'} Thread mode")
    report.append("system-side reset values: " + ", ".join(f"{k} {v:#x}" for k, v in sside.q.reset_ccr.items()))
    report.append(f"total {t_total:.1f} s, QEMU launches {sside.q.launches} "
                  f"(relaunched after: {', '.join(f'{k} {v}' for k, v in relaunch_why.most_common()) or '-'})")
    report.append("templates: " + ", ".join(f"{t} {per_tmpl[t]}" for t, _ in TEMPLATES))
    n_it = sum(1 for c in cases if c["state"]["xpsr"] & (3 << 25 | 0x3F << 10))
    n_strex = sum(1 for c in cases if is_store_exclusive(c))
    n_open = sum(1 for c in cases if c["state"].get("ldrex"))
    n_ltp = sum(1 for c in cases if (c["state"]["fpscr"] >> 16 & 7) != 4)
    report.append(f"state: IT/ECI bits set {n_it}, LTPSIZE != 4 {n_ltp}, STREX/STLEX {n_strex} "
                  f"(monitor opened by LDREX {n_open}, closed by CLREX {n_strex - n_open}), "
                  f"llvm-mc soft-fail (UNPREDICTABLE) encodings {sum(1 for c in cases if c['soft'])}")
    report.append("\nper decoded class: total / same / differ / skipped / harness")
    for cat in sorted(per_cat):
        c = per_cat[cat]
        tot = sum(c.values())
        report.append(f"  {cat:10s} {tot:6d} {c['same']:6d} {c['differ']:6d} {c['skipped']:6d} {c['harness']:4d}")
    report.append("\noracle outcome of compared cases: " + ", ".join(f"{k} {v}" for k, v in outcomes.most_common()))
    report.append("fault class pairs matched by mapping: " + ", ".join(f"{k} {v}" for k, v in mapped.most_common()))
    report.append("\nskipped (not run on the system side):")
    for why, ids in skipped.items():
        report.append(f"  {len(ids):5d}  {why}  (e.g. #{ids[0]})")
    report.append(f"\ncompared {stats['same'] + stats['differ']}: same {stats['same']}, differ {stats['differ']}; "
                  f"system-side errors {stats['harness']}")
    unexplained = sum(len(v) for k, v in causes.items() if k[0] in ("UNEXPLAINED", "HARNESS"))
    report.append(f"unexplained differences and harness errors: {unexplained}")
    report.append("\ndifferences by cause:")
    for (group, cause), items in sorted(causes.items(), key=lambda kv: (kv[0][0] != "UNEXPLAINED", -len(kv[1]))):
        case, diffs, o, s = items[0]
        report.append(f"  {len(items):5d}  [{group}] {cause}")
        report.append(f"         e.g. {case_text(case)}: " +
                      "; ".join(f"{f} oracle {fmt(a)} system {fmt(b)}" for f, a, b in diffs[:4]))
        if group == "UNEXPLAINED":
            for case, diffs, o, s in items[:20]:
                report.append(f"         {case_text(case)}: " +
                              "; ".join(f"{f} oracle {fmt(a)} system {fmt(b)}" for f, a, b in diffs[:6]))
    report.append("\ntime per case (set state + step + read registers and data window):")
    rows = [("oracle (ctypes)", t_or), ("gdbstub", t_sys)]
    rows += [(f"{side} {kind}", ts) for (side, kind), ts in sorted(t_split.items())]
    for name, ts in rows:
        if ts:
            report.append(f"  {name:16s} n={len(ts):6d} median {statistics.median(ts) * 1e6:9.1f} us  "
                          f"p99 {pct(ts, 99) * 1e6:9.1f} us  mean {statistics.mean(ts) * 1e6:9.1f} us")
    text = "\n".join(report)
    print(text)
    with open(os.path.join(args.out, f"report-{tag}.txt"), "w") as f:
        f.write(text + "\n")
    with open(os.path.join(args.out, f"times-{tag}.json"), "w") as f:
        json.dump({"oracle": t_or, "system": t_sys}, f)


if __name__ == "__main__":
    main()
