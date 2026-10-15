"""Map system-mode exceptions to oracle step kinds, and explain differences."""
import re

UFSR_BITS = [(0, "UNDEFINSTR"), (1, "INVSTATE"), (2, "INVPC"), (3, "NOCP"), (4, "STKOF"), (8, "UNALIGNED"),
             (9, "DIVBYZERO")]
BFSR_BITS = [(0, "IBUSERR"), (1, "PRECISERR"), (2, "IMPRECISERR"), (3, "UNSTKERR"), (4, "STKERR"), (5, "LSPERR")]
MMFSR_BITS = [(0, "IACCVIOL"), (1, "DACCVIOL"), (3, "MUNSTKERR"), (4, "MSTKERR"), (5, "MLSPERR")]
SFSR_BITS = [(0, "INVEP"), (1, "INVIS"), (2, "INVER"), (3, "AUVIOL"), (4, "INVTRAN"), (5, "LSPERR"),
             (7, "LSERR")]


def bits(value, table):
    return [name for b, name in table if value >> b & 1]


def normalize_system(s):
    """Oracle-style view of a system-mode result: kind, pc, fault address."""
    if s["kind"] == "RETIRED":
        return {"kind": "RETIRED", "detail": ""}
    exc, cfsr = s["exc"], s["cfsr"]
    ufsr = bits(cfsr >> 16, UFSR_BITS)
    bfsr = bits(cfsr >> 8 & 0xFF, BFSR_BITS)
    mmfsr = bits(cfsr & 0xFF, MMFSR_BITS)
    sfsr = bits(s["sfsr"], SFSR_BITS) if exc == 7 else []
    flags = ufsr + bfsr + mmfsr + sfsr
    name = s["exc_name"]
    detail = f"({name} {'|'.join(flags) or ''} hfsr={s['hfsr']:#x})"
    n = {"kind": name.upper(), "detail": detail, "pc": s["stacked_pc"], "flags": flags}
    if exc == 11:
        n.update(kind="SVC", mapped="SVCall -> SVC")
    elif exc == 3 and cfsr == 0 and s["hfsr"] & (1 << 30):
        n.update(kind="BKPT", mapped="HardFault (escalated DebugMonitor) -> BKPT")
    elif "UNDEFINSTR" in ufsr:
        n.update(kind="UNDEFINED", mapped="UsageFault UNDEFINSTR -> UNDEFINED")
    elif "NOCP" in ufsr:
        n.update(kind="NO_COPROCESSOR", mapped="UsageFault NOCP -> NO_COPROCESSOR")
    elif "INVSTATE" in ufsr:
        n.update(kind="INVALID_STATE", mapped="UsageFault INVSTATE -> INVALID_STATE")
    elif "UNALIGNED" in ufsr:
        n.update(kind="DATA_ABORT", fault_type="alignment", addr=None,
                 mapped="UsageFault UNALIGNED -> DATA_ABORT fsr 0x1")
    elif "PRECISERR" in bfsr:
        n.update(kind="DATA_ABORT", fault_type="unmapped", addr=s["bfar"] if cfsr & 0x8000 else None,
                 mapped="BusFault PRECISERR -> DATA_ABORT fsr 0x7/0x807")
    elif "DACCVIOL" in mmfsr:
        n.update(kind="DATA_ABORT", fault_type="permission", addr=s["mmfar"] if cfsr & 0x80 else None,
                 mapped="MemManage DACCVIOL -> DATA_ABORT fsr 0xf/0x80f")
    elif "IBUSERR" in bfsr or "IACCVIOL" in mmfsr:
        n.update(kind="PREFETCH_ABORT", addr=None, mapped="IBUSERR/IACCVIOL -> PREFETCH_ABORT")
    return n


SECURE_ONLY = ("tta", "ttat", "bxns", "blxns", "vlldm", "vlstm", "vscclrm")
SECURE_FP_SYSREG = ("fpcxts", "fpcxtns")
PRIV_SYSREG_MOVES = ("mrs", "msr")
SECURE = "Secure state in system mode vs Non-secure in user mode"
PRIV = "privileged system mode vs unprivileged user mode"
SYSEXC = "exception entry exists only in system mode"
GDBSTEP = "gdbstub single-step in system mode"
VERSION = "different QEMU version on the system side"


def reg_index(name):
    return {"sp": 13, "lr": 14, "pc": 15}.get(name) if not name[1:].isdigit() else int(name[1:])


def classify(case, o, s, sn, diffs, privileged, secure, other_version=False):
    """(cause group, cause) for a difference; cause group 'UNEXPLAINED' if no rule matches.
    other_version: the system QEMU is not the oracle's commit."""
    text = case["text"]
    mn = text.split()[0]
    ops = text[len(mn):]
    tokens = set(re.findall(r"[a-z_0-9]+", ops))
    fields = {f for f, _, _ in diffs}
    rd = ops.split(",")[0].strip()
    rd_field = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}.get(rd, rd)
    ok, sk = o["kind"], sn["kind"]

    if mn.startswith("yield") and fields == {"pc"} and ok == sk == "RETIRED" and s["r"][15] == o["pc"] + 2:
        return GDBSTEP, ("YIELD: the gdbstub single-step also runs the next instruction (a NOP here), because "
                         "EXCP_YIELD leaves cpu_exec without EXCP_DEBUG; the oracle stops after YIELD")
    if other_version and ok == "DATA_ABORT" and (o["fsr"] & 0xF) == 1 and \
            (sk == "RETIRED" or sn.get("fault_type") not in (None, "alignment")) and \
            re.match(r"^v(ldr|str)[bhwd]|^v(ld|st)[24]", mn):
        return VERSION, ("MVE load/store alignment checks were added in QEMU 10.1 (f8436889a0, 56249f3e6c, ...); "
                         "the older system QEMU does not check")
    if fields == {"pc"} and s.get("frame_unreadable"):
        return SYSEXC, ("SP was loaded before the data abort (LDM/POP with SP in the list); stacking to that SP "
                        "failed (STKERR), so the stacked pc is not available")
    if ok == "UNDEFINED" and sk != "UNDEFINED":
        if mn in SECURE_ONLY:
            return SECURE, f"{mn.upper()} is Secure-only: UNDEFINED in Non-secure, executes in Secure"
        if tokens & set(SECURE_FP_SYSREG):
            return SECURE, "FPCXT_S/FPCXT_NS access (VMRS/VMSR/VLDR/VSTR) is Secure-only"
        if privileged and rd == "pc" and re.match(r"^[a-z]+s(\.w)?$", mn) and sk == "RETIRED":
            return PRIV, ("ALU op with S=1 and Rd=PC (ALUExceptionReturn, UNPREDICTABLE on M-profile): UNDEFINED "
                          "when unprivileged, QEMU runs it as an exception return when privileged")
    if mn in ("tt", "ttt") and fields == {rd_field}:
        if secure:
            return SECURE, "TT/TTT result has the S and SRVALID bits only in Secure state"
        if privileged:
            return PRIV, ("TT/TTT run by privileged code returns the MPU view (R, RW bits); the user-mode stub "
                          "returns 0 (m_helper.c v7m_tt, CONFIG_USER_ONLY)")
    if mn == "sg" and fields == {"xpsr"}:
        return SECURE, "SG in Secure state clears the IT bits; in Non-secure it is a NOP"
    if mn == "mrs" and "control" in tokens and fields == {rd_field}:
        i = reg_index(rd_field)
        x = o["r"][i] ^ s["r"][i]
        if x & ~0x9 == 0 and (secure or not x & 8) and (privileged or not x & 1):
            group = "; ".join(g for g, on in ((SECURE, secure), (PRIV, privileged)) if on)
            return group, "MRS CONTROL: SFPA (bit 3) exists only in Secure state, nPRIV (bit 0) is 1 in the oracle"
    if mn == "mrs" and "control_ns" in tokens and fields == {rd_field} and secure:
        return SECURE, ("MRS CONTROL_NS: unprivileged Secure code can read it (m_helper.c v7m_mrs); Non-secure "
                        "code and the user-mode stub read 0")
    if "vpr" in tokens and mn in ("vmrs", "vmsr", "vldr", "vstr") and privileged:
        return PRIV, ("VPR access (VMRS/VMSR/VLDR/VSTR VPR) is a no-op when unprivileged; QEMU system mode "
                      "also keeps the reserved VPR bits on write")
    if mn in PRIV_SYSREG_MOVES and privileged and fields <= {rd_field, "xpsr", "control", "sp"}:
        return PRIV, (f"{mn.upper()} of a special register: user mode reads 0 / ignores the write "
                      "(m_helper.c CONFIG_USER_ONLY), privileged system mode uses the real register")
    return "UNEXPLAINED", "UNEXPLAINED"


def classify_harness_error(case, s):
    mn = case["text"].split()[0]
    if mn == "vscclrm" and "trans_VSCCLRM: assertion failed" in s["error"]:
        return SECURE, ("QEMU bug (fixed by patches/0004): VSCCLRM whose D-register list starts at D17 or above "
                        "aborts system-mode QEMU (assert in trans_VSCCLRM); in Non-secure user mode it is UNDEFINED "
                        "before that code")
    return "HARNESS", "harness error on the system side"
