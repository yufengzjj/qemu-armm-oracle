"""Random single-instruction cases: encodings filtered by llvm-mc, random initial state."""
import os
import random
import re
import struct
import subprocess
import tempfile

import capstone
from capstone import arm as csarm

from common import (CODE_ADDR, DATA_BASE, DATA_END, DATA_SIZE, LLVM_MC, MATTR, TRIPLE)

# Template weights. "raw" words are not filtered and exercise UNDEFINED.
TEMPLATES = [
    ("t16", 13), ("t32dp", 12), ("dsp", 10), ("vfp", 14), ("mve", 18), ("ldst", 16), ("branch", 6),
    ("sys", 3), ("raw", 8),
]


def gen_encoding(rng, tmpl):
    """Return (bytes, size) for one candidate of the given template."""
    r = rng.getrandbits
    if tmpl == "t16":
        while True:
            hw = r(16)
            if (hw >> 11) not in (0x1D, 0x1E, 0x1F):
                return struct.pack("<H", hw), 2
    if tmpl == "raw":
        hw1, hw2 = r(16), r(16)
        size = 4 if (hw1 >> 11) in (0x1D, 0x1E, 0x1F) else 2
        return struct.pack("<HH", hw1, hw2), size
    if tmpl == "t32dp":
        k = rng.randrange(3)
        if k == 0:    # data processing, modified / plain immediate
            hw1, hw2 = 0xF000 | r(11), r(15)
        elif k == 1:  # data processing, shifted register
            hw1, hw2 = 0xEA00 | r(9), r(16)
        else:         # data processing, register
            hw1, hw2 = 0xFA00 | r(8), 0xF000 | r(12)
    elif tmpl == "dsp":
        k = rng.randrange(3)
        if k == 0:    # parallel add/sub, saturating add/sub, misc
            hw1, hw2 = 0xFA80 | r(7), 0xF000 | r(12)
        elif k == 1:  # multiply, multiply-accumulate, long multiply, divide
            hw1, hw2 = 0xFB00 | r(8), r(16)
        else:         # saturate, bitfield
            hw1, hw2 = 0xF300 | r(8), r(15)
    elif tmpl == "vfp":
        cp = rng.choice([0x9, 0xA, 0xA, 0xB, 0xB])
        k = rng.randrange(3)
        if k == 0:    # VFP data processing and register moves
            hw1 = 0xEE00 | r(8)
        elif k == 1:  # v8 FP: VSEL, VMAXNM, VRINT, VCVT{A,N,P,M}
            hw1 = 0xFE00 | r(8)
        else:         # 64-bit transfers, VLDR/VSTR/VLDM/VSTM
            hw1 = 0xEC00 | r(9)
        hw2 = (r(16) & ~0x0F00) | (cp << 8)
    elif tmpl == "mve":
        k = rng.choices(range(5), [35, 30, 25, 5, 5])[0]
        if k == 0:    # vector data processing in the Advanced SIMD space
            hw1, hw2 = rng.choice([0xEF00, 0xFF00]) | r(8), r(16)
        elif k == 1:  # vector data processing in the coprocessor 14/15 space
            hw1, hw2 = rng.choice([0xEE00, 0xFE00]) | r(8), (r(16) & ~0x0F00) | rng.choice([0xE, 0xF]) << 8
        elif k == 2:  # loads and stores, gather/scatter, VLD2/VLD4
            hw1, hw2 = rng.choice([0xEC00, 0xFC00]) | r(9), (r(16) & ~0x0E00) | 0x0E00
        elif k == 3:  # VCTP, DLSTP, WLSTP, LETP, LCTP
            hw1, hw2 = 0xF000 | r(7), rng.choice([0xE801, 0xE001, 0xC001 | r(11) << 1, 0xC001 | r(11) << 1])
        else:         # 64-bit scalar shifts (ASRL, LSLL, UQRSHL, ...)
            hw1, hw2 = 0xEA50 | r(4), r(16)
        if k < 3 and rng.random() < 0.8:
            # Q registers have 3-bit numbers: clear D, N, M and the low bit of Vd, Vn, Vm.
            hw1 &= ~(1 << 6 | 1 << 0)
            hw2 &= ~(1 << 12 | 1 << 7 | 1 << 5 | 1 << 0)
    elif tmpl == "ldst":
        k = rng.choices(range(6), [20, 20, 20, 15, 15, 10])[0]
        if k == 5:    # LDREX/STREX, LDAEX/STLEX and their byte/halfword forms
            if rng.random() < 0.5:
                hw1, hw2 = rng.choice([0xE840, 0xE850]) | r(4), r(16)
            else:
                hw1 = rng.choice([0xE8C0, 0xE8D0]) | r(4)
                hw2 = r(4) << 12 | 0xF00 | rng.choice([4, 5, 0xC, 0xD, 0xE]) << 4 | r(4)
            return struct.pack("<HH", hw1, hw2), 4
        if k == 0:    # T16 loads/stores, PUSH/POP, LDM/STM
            hw = rng.choice([0x5000 | r(12), 0x6000 | r(12), 0x7000 | r(12), 0x8000 | r(12), 0x9000 | r(12),
                             0xB400 | r(9), 0xBC00 | r(9), 0xC000 | r(12), 0x4800 | r(11)])
            return struct.pack("<H", hw), 2
        if k in (1, 2):   # load/store single
            hw1, hw2 = 0xF800 | r(9), r(16)
        elif k == 3:  # LDM/STM, LDRD/STRD, exclusives, TBB
            hw1, hw2 = 0xE800 | r(9), r(16)
        else:         # VLDR/VSTR/VLDM/VSTM/VPUSH/VPOP
            hw1, hw2 = 0xEC00 | r(9), (r(16) & ~0x0F00) | (rng.choice([0x9, 0xA, 0xB]) << 8)
    elif tmpl == "branch":
        hw1, hw2 = 0xF000 | r(11), 0x8000 | r(15)
    elif tmpl == "sys":
        # Instructions whose result depends on privilege or security state.
        k = rng.randrange(10)
        if k == 0:    # MRS
            hw1, hw2 = 0xF3EF, 0x8000 | r(4) << 8 | rng.choice([0, 1, 2, 3, 5, 6, 7, 8, 9, 0xA, 0xB, 0x10, 0x11,
                                                                0x12, 0x13, 0x14, 0x88, 0x89, 0x8A, 0x8B, 0x90,
                                                                0x91, 0x93, 0x94, 0x98, r(8)])
        elif k == 1:  # MSR
            hw1, hw2 = 0xF380 | r(4), 0x8800 | rng.choice([0, 0x400, 0x800, 0xC00]) | rng.choice(
                [0, 1, 2, 3, 8, 9, 0xA, 0xB, 0x10, 0x11, 0x14, 0x88, 0x89, 0x94, r(8)])
        elif k == 2:  # TT, TTT, TTA, TTAT
            hw1, hw2 = 0xE840 | r(4), 0xF000 | r(4) << 8 | r(2) << 6
        elif k == 3:  # SG, BXNS, BLXNS
            choice = rng.randrange(3)
            if choice == 0:
                return bytes.fromhex("7fe97fe9"), 4
            return struct.pack("<H", (0x4704 if choice == 1 else 0x4784) | r(4) << 3), 2
        elif k in (4, 5):  # VMRS / VMSR of FPSCR, FPSCR_nzcvqc, VPR, P0, FPCXTNS, FPCXTS
            reg = rng.choice([1, 2, 0xC, 0xD, 0xE, 0xF])
            hw1, hw2 = (0xEEF0 if k == 4 else 0xEEE0) | reg, r(4) << 12 | 0x0A10
        elif k == 6:  # VLDR/VSTR of FP system registers
            hw1, hw2 = 0xEC00 | r(9), (r(16) & ~0x0F00) | 0x0F00
        elif k == 7:  # VLLDM, VLSTM, VSCCLRM, CLRM
            hw1, hw2 = rng.choice([(0xEC30 | r(4), 0x0A00), (0xEC20 | r(4), 0x0A00),
                                   (0xECDF | r(1) << 6, r(4) << 12 | rng.choice([0x0A00, 0x0B00]) | r(8)),
                                   (0xE89F, r(16) & ~0x2000)])
        elif k == 8:  # CPS
            return struct.pack("<H", 0xB660 | r(1) << 4 | r(2)), 2
        else:         # hints, barriers, CLREX, DBG, PLD/PLI
            hw1, hw2 = 0xF3AF, 0x8000 | r(8)
    else:
        raise ValueError(tmpl)
    return struct.pack("<HH", hw1, hw2), 4


def is_it(enc, size):
    hw = enc[0] | enc[1] << 8
    return size == 2 and (hw & 0xFF00) == 0xBF00 and (hw & 0xF) != 0


def llvm_filter(cands):
    """Return, for each (enc, size), None if llvm-mc rejects it, else (text, soft_fail)."""
    lines = []
    owner = []
    for i, (enc, size) in enumerate(cands):
        lines.append("[" + " ".join(f"0x{b:02x}" for b in enc[:size]) + "]")
        owner.append(i)
        if is_it(enc, size):
            # llvm-mc carries IT state across lines; let the block run out on NOPs.
            for _ in range(4):
                lines.append("[0x00 0xbf]")
                owner.append(None)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "in.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        p = subprocess.run([LLVM_MC, "--disassemble", f"--triple={TRIPLE}", f"-mattr={MATTR}", path],
                           capture_output=True, text=True)
    bad, soft = set(), set()
    for m in re.finditer(r":(\d+):\d+: warning: (invalid|potentially undefined)", p.stderr):
        (bad if m.group(2) == "invalid" else soft).add(int(m.group(1)) - 1)
    out = [ln.strip() for ln in p.stdout.splitlines() if ln.startswith("\t") and not ln.startswith("\t.")]
    res = [None] * len(cands)
    k = 0
    for ln, who in enumerate(owner):
        if ln in bad:
            continue
        text = out[k].replace("\t", " ")
        k += 1
        if who is not None:
            res[who] = (text, ln in soft)
    if k != len(out):
        raise RuntimeError(f"llvm-mc output has {len(out)} lines, expected {k}")
    return res


_cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS | capstone.CS_MODE_V8)
_cs.detail = True


def cs_decode(enc, addr=CODE_ADDR):
    for insn in _cs.disasm(enc, addr, count=1):
        return insn
    return None


DSP_RE = re.compile(r"^(q|uq|sh|uh|s|u)(add|sub|asx|sax)(8|16)|^q(d?add|d?sub)$|^sml|^smu|^smm|^smul|^usada?8|"
                    r"^(s|u)sat16|^(s|u)xtab?16|^sel$|^pkh")
MVE_ONLY = re.compile(r"^(vpst|vpt|vctp|vpsel|vpnot|vmlav|vmlsdav|vmladav|vaddv|vaddlv|vmlaldav|vmlsldav|vrmlal|"
                      r"vrmlsl|vabav|vmaxv|vminv|vmaxav|vminav|vmaxnmv|vminnmv|vmaxnmav|vminnmav|vidup|vddup|viwdup|"
                      r"vdwdup|vld2|vld4|vst2|vst4|vldr[bhwd]|vstr[bhwd]|vshlc|vadc|vsbc|vqdmlad|vqdmlsd|"
                      r"vqrdmlad|vqrdmlsd|vcadd|vcmla|vhcadd|vbrsr|vmovl|vmovn|vqmovn|vqmovun|vmullb|vmullt|"
                      r"vqdmullb|vqdmullt|vshllb|vshllt|vshrn|vrshrn|vqshrn|vqrshrn|vqshrun|vqrshrun|vcvtb|vcvtt|"
                      r"vfmas|vmlas|vqdmlash|vqrdmlash|vqdmlah|vqrdmlah|vmulh|vrmulh|vclz|vcls|vrev|"
                      r"wlstp|dlstp|letp|lctp|"
                      r"asrl|lsll|lsrl|sqrshr|sqshl|srshr|uqrshl|uqshl|urshr|sqrshrl|uqrshll|uqshll|sqshll|"
                      r"srshrl|urshrl)")
SYS_RE = re.compile(r"^(mrs|msr|cps|svc|bkpt|udf|wfi|wfe|sev|yield|nop|dmb|dsb|isb|sg|tt|bxns|blxns|clrex|"
                    r"csdb|ssbb|pssbb|esb|hint|vlldm|vlstm|vscclrm|clrm|dbg|pld|pli|pac|aut|bti)")
BRANCH_RE = re.compile(r"^(b|bl|blx|bx|cbn?z|tbb|tbh|it|le|wls|dls|bf|bfl|bfx|bflx|bfcsel)(\.w|\.n)?"
                       r"(eq|ne|hs|cs|lo|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?(\.w|\.n)?$|^(it|ite|itt|itee|ittt|"
                       r"itte|itet|itett)")


def category(text, size):
    """Instruction class by decoded mnemonic (llvm-mc text)."""
    mn = text.split()[0]
    ops = text[len(mn):]
    if mn.startswith("v") or MVE_ONLY.match(mn) or mn in ("vscclrm",):
        if re.search(r"\bq\d", ops) or MVE_ONLY.match(mn):
            return "mve"
        if mn in ("vlldm", "vlstm", "vscclrm"):
            return "system"
        if re.match(r"^v(ldr|str|ldm|stm|push|pop)", mn):
            return "vfp-ldst"
        if ".f16" in mn or ".f16" in ops or re.search(r"\.(f16|s16|u16)\b", mn) and "f16" in text:
            return "vfp-f16"
        if re.search(r"\bd\d", ops) or ".f64" in mn:
            return "vfp-f64"
        return "vfp-f32"
    if SYS_RE.match(mn):
        return "system"
    if re.match(r"^(mcr|mrc|cdp|ldc|stc|mcrr|mrrc)", mn):
        return "coproc"
    if BRANCH_RE.match(mn):
        return "branch"
    if "[" in ops or re.match(r"^(ldm|stm|push|pop|ldr|str|lda|stl|ldrex|strex)", mn):
        return "ldst"
    if DSP_RE.match(mn):
        return "dsp"
    return "t16" if size == 2 else "t32"


SPECIAL32 = [0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x80000001, 0x7FFFFFFE, 0xFFFF, 0x8000, 0x7FFF,
             0xFFFF0000, 0x00010000, 0xFFFFFFFE, 0x55555555, 0xAAAAAAAA]
FP32 = [0x00000000, 0x80000000, 0x3F800000, 0xBF800000, 0x7F800000, 0xFF800000, 0x7FC00000, 0xFFC00000,
        0x7FA00000, 0x00000001, 0x807FFFFF, 0x00800000, 0x7F7FFFFF, 0x4F000000, 0xCF000000, 0x3F000000,
        0x4B000000, 0x3FC00000, 0x40490FDB]
FP16 = [0x0000, 0x8000, 0x3C00, 0xBC00, 0x7C00, 0xFC00, 0x7E00, 0x7D00, 0x0001, 0x83FF, 0x0400, 0x7BFF,
        0x3800, 0x3E00, 0x5640]
FP64 = [0x0000000000000000, 0x8000000000000000, 0x3FF0000000000000, 0xBFF0000000000000, 0x7FF0000000000000,
        0xFFF0000000000000, 0x7FF8000000000000, 0x7FF4000000000000, 0x0000000000000001, 0x0010000000000000,
        0x7FEFFFFFFFFFFFFF, 0x41E0000000000000, 0x3FE0000000000000, 0x4330000000000000]

DATA_MID_LO = DATA_BASE + 0x1000
DATA_MID_HI = DATA_BASE + 0x3000


def rand_word(rng):
    k = rng.random()
    if k < 0.35:
        return rng.getrandbits(32)
    if k < 0.50:
        return rng.randrange(-32, 33) & 0xFFFFFFFF
    if k < 0.70:
        return rng.choice(SPECIAL32)
    if k < 0.85:
        return data_ptr(rng)
    return rng.choice(FP32)


def data_ptr(rng, align=None):
    """An address for a memory operand: mostly well inside the data window."""
    k = rng.random()
    if k < 0.78:
        a = rng.randrange(DATA_MID_LO, DATA_MID_HI)
    elif k < 0.90:
        a = DATA_END - rng.randrange(1, 0x81)
    elif k < 0.95:
        a = DATA_END + rng.randrange(0, 0x10000)
    else:
        return rng.getrandbits(32)
    if align is None:
        align = rng.choice([1, 2, 4, 4, 4, 8, 8, 16])
    return a & ~(align - 1)


def small_index(rng):
    return rng.randrange(-16, 65) & 0xFFFFFFFF


def rand_lane32(rng):
    k = rng.random()
    if k < 0.45:
        return rng.getrandbits(32)
    if k < 0.70:
        return rng.choice(FP32) ^ (rng.getrandbits(3) if rng.random() < 0.2 else 0)
    if k < 0.85:
        return rng.choice(FP16) | rng.choice(FP16) << 16
    return rng.choice(SPECIAL32)


def rand_d(rng):
    if rng.random() < 0.15:
        return rng.choice(FP64)
    return rand_lane32(rng) | rand_lane32(rng) << 32


def rand_fpscr(rng):
    v = rng.getrandbits(5) << 27                       # NZCV, QC
    if rng.random() < 0.1:
        v |= 1 << 26                                   # AHP
    if rng.random() < 0.3:
        v |= 1 << 25                                   # DN
    if rng.random() < 0.3:
        v |= 1 << 24                                   # FZ
    if rng.random() < 0.5:
        v |= rng.randrange(1, 4) << 22                 # RMode
    if rng.random() < 0.3:
        v |= 1 << 19                                   # FZ16
    v |= (4 if rng.random() < 0.75 else rng.randrange(0, 4)) << 16   # LTPSIZE
    for b in (0, 1, 2, 3, 4, 7):                       # cumulative exception flags
        if rng.random() < 0.3:
            v |= 1 << b
    return v


def rand_vpr(rng):
    if rng.random() < 0.3:
        return 0
    return rng.getrandbits(16) | rng.getrandbits(4) << 16 | rng.getrandbits(4) << 20


def rand_xpsr(rng):
    v = rng.getrandbits(5) << 27 | rng.getrandbits(4) << 16 | 1 << 24
    if rng.random() < 0.12:
        it = rng.randrange(0, 15) << 4 | rng.randrange(1, 16)
        v |= (it & 3) << 25 | (it >> 2) << 10
    return v


MULTI_RE = re.compile(r"^(ldm|stm|vldm|vstm|vlldm|vlstm)")


def build_state(rng, insn, case):
    """Random state; registers used as addresses by insn point into the data window."""
    r = [rand_word(rng) for _ in range(13)]
    sp = (DATA_BASE + 0x1800 + rng.randrange(0, 0x1000)) & ~(3 if rng.random() < 0.2 else 7)
    lr = rand_word(rng) if rng.random() < 0.8 else (0x1000 + rng.randrange(0x3000)) | 1
    d = [rand_d(rng) for _ in range(16)]
    regs = r + [sp, lr, CODE_ADDR]

    def set_reg(reg, value_fn, lane_fn=None):
        name = insn.reg_name(reg) if reg else None
        if not name:
            return
        if name.startswith("q") and name[1:].isdigit():
            n = int(name[1:])
            lanes = [lane_fn() for _ in range(4)]
            d[2 * n] = lanes[0] | lanes[1] << 32
            d[2 * n + 1] = lanes[2] | lanes[3] << 32
            return
        idx = {"sb": 9, "sl": 10, "fp": 11, "ip": 12, "sp": 13, "lr": 14, "pc": 15}.get(name)
        if idx is None and name.startswith("r") and name[1:].isdigit():
            idx = int(name[1:])
        if idx is not None and idx < 13 or idx == 14:
            regs[idx] = value_fn()

    if insn is not None:
        mn = insn.mnemonic
        mems = [op for op in insn.operands if op.type == csarm.ARM_OP_MEM]
        for op in mems:
            set_reg(op.mem.base, lambda: data_ptr(rng), lambda: data_ptr(rng))
            if op.mem.index:
                set_reg(op.mem.index, lambda: small_index(rng), lambda: rng.randrange(0, 0x100))
        if not mems and MULTI_RE.match(mn) and insn.operands and insn.operands[0].type == csarm.ARM_OP_REG:
            set_reg(insn.operands[0].reg, lambda: data_ptr(rng, 4), None)
    xpsr = rand_xpsr(rng)
    mn = case["text"].split()[0]
    if LOB_RE.match(mn):
        xpsr &= ~(3 << 25 | 0x3F << 10)
    st = {"r": regs, "xpsr": xpsr, "d": d, "fpscr": rand_fpscr(rng), "vpr": rand_vpr(rng), "ldrex": None}
    pre = ldrex_for(case["enc"]) if case["size"] == 4 and mn.startswith(("strex", "stlex")) else None
    if pre and rng.random() < 0.5:
        hw1, hw2 = struct.unpack("<HH", pre)
        addr = (regs[hw1 & 0xF] + ((hw2 & 0xFF) * 4 if hw1 & 0xFFF0 == 0xE850 else 0)) & 0xFFFFFFFF
        if DATA_BASE <= addr < DATA_END - 4:
            st["ldrex"] = pre
    return st


LOB_RE = re.compile(r"^(le|letp|lctp|wls|wlstp|dls|dlstp)$")


def ldrex_for(enc):
    """The LDREX/LDAEX encoding with the same size and address as a STREX/STLEX encoding, or None."""
    hw1, hw2 = struct.unpack("<HH", enc[:4])
    rn = hw1 & 0xF
    if rn == 15:
        return None
    if hw1 & 0xFFF0 == 0xE840:
        return struct.pack("<HH", 0xE850 | rn, hw2 | 0x0F00)
    if hw1 & 0xFFF0 == 0xE8C0 and hw2 & 0x0F00 == 0x0F00 and (hw2 >> 4 & 0xF) in (4, 5, 0xC, 0xD, 0xE):
        return struct.pack("<HH", 0xE8D0 | rn, hw2 | 0x000F)
    return None


def is_pacbti_alias(enc, size):
    """PACG, AUTG, BXAUT: without PACBTI QEMU runs them as SMMUL/SMMLA/SMMLAR with Ra or Rd = 15."""
    if size != 4:
        return False
    hw1, hw2 = struct.unpack("<HH", enc[:4])
    if hw1 & 0xFFF0 == 0xFB60 and hw2 & 0xF0F0 == 0xF000:
        return True
    return hw1 & 0xFFF0 == 0xFB50 and hw2 & 0x0FE0 == 0x0F00


# A candidate from these templates is kept only if it decodes to this class.
REQUIRED = {"mve": "mve", "vfp": "vfp", "dsp": "dsp"}


def data_image(seed):
    return random.Random(f"data-{seed}").randbytes(DATA_SIZE)


def generate(n, seed, batch=4000):
    """Return n cases. Deterministic for a given (n, seed)."""
    rng = random.Random(seed)
    names = [t for t, _ in TEMPLATES]
    weights = [w for _, w in TEMPLATES]
    cases = []
    while len(cases) < n:
        tmpls = rng.choices(names, weights, k=batch)
        cands = [gen_encoding(rng, t) for t in tmpls]
        checked = llvm_filter([c for c, t in zip(cands, tmpls) if t != "raw"])
        it = iter(checked)
        for t, (enc, size) in zip(tmpls, cands):
            if is_pacbti_alias(enc, 4 if (enc[1] >> 3) in (0x1D, 0x1E, 0x1F) else 2):
                if t != "raw":
                    next(it)
                continue
            if t == "raw":
                insn = cs_decode(enc)
                text = f"{insn.mnemonic} {insn.op_str}".strip() if insn else "(undecodable)"
                size = insn.size if insn else size
                cases.append({"tmpl": t, "enc": enc, "size": size, "text": text, "soft": False,
                              "cat": "raw"})
            else:
                chk = next(it)
                if chk is None:
                    continue
                cat = category(chk[0], size)
                if t in REQUIRED and not cat.startswith(REQUIRED[t]):
                    continue
                insn = cs_decode(enc)
                cases.append({"tmpl": t, "enc": enc, "size": size, "text": chk[0], "soft": chk[1],
                              "cat": cat, "cs": insn is not None})
            if len(cases) == n:
                break
    for i, c in enumerate(cases):
        srng = random.Random(f"{seed}-{i}")
        c["id"] = i
        c["state"] = build_state(srng, cs_decode(c["enc"]), c)
    return cases
