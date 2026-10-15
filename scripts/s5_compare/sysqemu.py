"""Drive qemu-system-arm (mps3-an547, cortex-m55) through the gdbstub, one instruction per case.

Default state of the guest when a case starts: Non-secure, unprivileged Thread mode, MSP, FPU enabled
for both security states, CONTROL.FPCA = 1, as close to the oracle as the machine allows.
"""
import os
import socket
import struct
import subprocess
import tempfile

from common import CODE_BASE, DATA_BASE, DATA_SIZE, assemble
from rsp import Rsp, RspError, RspTimeout

SETUP = 0x100
LANDING = 0x300
NS_SETUP = 0x320
HANDLERS = 0x400
NUM_VECTORS = 64
RECOVER = 0x800
S_VECTORS = 0xC00
S_TRAP = 0xE00
SECURE_ALIAS = 0x10000000

CONTROL_NPRIV = 1
CONTROL_FPCA = 4
CONTROL_SFPA = 8

EXC_NAMES = {2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault", 6: "UsageFault", 7: "SecureFault",
             11: "SVCall", 12: "DebugMonitor", 14: "PendSV", 15: "SysTick"}

SECURE_SETUP_COMMON = """
    ldr r0, =0xe000ed88   @ CPACR_S: CP10/CP11 full access
    ldr r1, [r0]
    orr r1, r1, #0xf00000
    str r1, [r0]
    ldr r0, =0xe000ed24   @ SHCSR_S: enable MemManage, BusFault, UsageFault, SecureFault
    ldr r1, [r0]
    orr r1, r1, #0xf0000
    str r1, [r0]
"""


def guest_image(control, nonsecure):
    """ITCM contents below CODE_BASE: vector tables, setup code, fault recovery."""
    vec = [".word 0x2007e000"] + [f".word {HANDLERS + 4 * n + 1:#x}" for n in range(1, NUM_VECTORS)]
    handlers = ["b.w recover"] * NUM_VECTORS
    if nonsecure:
        setup = SECURE_SETUP_COMMON + f"""
    ldr r0, =0xe002ed88   @ CPACR_NS
    ldr r1, [r0]
    orr r1, r1, #0xf00000
    str r1, [r0]
    ldr r0, =0xe000ed8c   @ NSACR: CP10/CP11 usable from Non-secure
    ldr r1, [r0]
    orr r1, r1, #0xc00
    str r1, [r0]
    ldr r0, =0xe002ed24   @ SHCSR_NS: enable MemManage, BusFault, UsageFault
    ldr r1, [r0]
    orr r1, r1, #0x70000
    str r1, [r0]
    ldr r0, =0xe000ed08   @ VTOR_S: Secure exceptions go to a trap in the Secure alias of ITCM
    ldr r1, ={SECURE_ALIAS + S_VECTORS:#x}
    str r1, [r0]
    ldr r0, =0xe002ed08   @ VTOR_NS
    movs r1, #0
    str r1, [r0]
    ldr r0, =0xe000ed0c   @ AIRCR: BFHFNMINS, so BusFault and HardFault go to Non-secure
    ldr r1, =0x05fa2000
    str r1, [r0]
    ldr r0, =0xe000edd0   @ SAU_CTRL: ALLNS; the IDAU then makes 0x0xxxxxxx and 0x2xxxxxxx Non-secure
    movs r1, #2
    str r1, [r0]
    dsb sy
    isb sy
    ldr r0, ={NS_SETUP:#x}
    bxns r0
    .ltorg
"""
        ns_part = f"""
.org {NS_SETUP:#x}
    movs r0, #{control}
    msr control, r0
    isb sy
    b landing
"""
        stacked_xpsr = 0x01000000
        clear_sfsr = ""
        s_part = f"""
.org {S_VECTORS:#x}
{chr(10).join(f".word {SECURE_ALIAS + S_TRAP + 1:#x}" for _ in range(NUM_VECTORS))}
.org {S_TRAP:#x}
s_trap:
    b s_trap
"""
    else:
        setup = SECURE_SETUP_COMMON + f"""
    ldr r0, =0xe000ed08   @ VTOR
    movs r1, #0
    str r1, [r0]
    dsb sy
    isb sy
    movs r0, #{control}
    msr control, r0
    isb sy
    b landing
    .ltorg
"""
        ns_part = ""
        stacked_xpsr = 0x01100000
        clear_sfsr = """
    ldr r1, =0xe000ede4   @ SFSR
    ldr r2, [r1]
    str r2, [r1]
"""
        s_part = ""
    src = f"""
.syntax unified
.thumb
.text
.org 0
{chr(10).join(vec)}
.org {SETUP:#x}
{setup}
.org {LANDING:#x}
landing:
    b landing
{ns_part}
.org {HANDLERS:#x}
{chr(10).join(handlers)}
.org {RECOVER:#x}
recover:
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    ldr r1, =landing
    str r1, [r0, #24]     @ stacked return address
    ldr r1, ={stacked_xpsr:#x}
    str r1, [r0, #28]     @ stacked xPSR: T, Thread mode (bit 20 restores CONTROL_S.SFPA in Secure state)
    ldr r1, =0xe000ed28   @ clear CFSR, HFSR, DFSR (write 1 to clear)
    ldr r2, [r1]
    str r2, [r1]
    ldr r2, [r1, #4]
    str r2, [r1, #4]
    ldr r2, [r1, #8]
    str r2, [r1, #8]
{clear_sfsr}
    bx lr
    .ltorg
{s_part}
"""
    return assemble(src)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SysQemu:
    def __init__(self, exe, path_prefix=None, privileged=False, nonsecure=True):
        self.exe = exe
        self.env = dict(os.environ)
        if path_prefix:
            self.env["PATH"] = path_prefix + os.pathsep + self.env["PATH"]
        self.nonsecure = nonsecure
        # The gdbstub reads CONTROL as seen from the current security state; SFPA only exists in Secure.
        self.control = CONTROL_FPCA | (0 if nonsecure else CONTROL_SFPA) | (0 if privileged else CONTROL_NPRIV)
        self.image = guest_image(self.control, nonsecure)
        self.proc = None
        self.r = None
        self.launches = 0
        self.code_shadow = None
        self.data_shadow = None
        self.halt_timeout = 0.5
        self.reset_ccr = None

    def stderr_text(self):
        """What QEMU wrote to stderr since the last launch (e.g. an assertion message)."""
        self.errlog.seek(0)
        return self.errlog.read().decode(errors="replace").strip()

    def close(self):
        if self.r:
            self.r.close()
            self.r = None
        if self.proc:
            self.proc.kill()
            self.proc.wait()
            self.proc = None

    def launch(self, code_image, data_image):
        """Start QEMU and run the setup code; code_image/data_image are the
        initial contents of the code region and the data window."""
        self.close()
        port = free_port()
        self.errlog = tempfile.TemporaryFile()
        self.proc = subprocess.Popen([self.exe, "-M", "mps3-an547", "-cpu", "cortex-m55", "-S",
                                      "-gdb", f"tcp:127.0.0.1:{port}", "-nographic", "-monitor", "none",
                                      "-serial", "none"],
                                     env=self.env, stdout=subprocess.DEVNULL, stderr=self.errlog)
        self.r = Rsp(port)
        self.r.start()
        self.launches += 1
        rm = self.r.register_map()
        self.regmap = rm
        self.d_nums = [rm[f"d{i}"][0] for i in range(16)]
        self.n_fpscr = rm["fpscr"][0]
        self.n_vpr = rm["vpr"][0]
        self.n_control = rm["control"][0]
        if self.reset_ccr is None:
            self.reset_ccr = {name: struct.unpack("<I", self.read_mem(addr, 4))[0]
                              for name, addr in (("CCR_S", 0xE000ED14), ("CCR_NS", 0xE002ED14),
                                                 ("FPCCR_S", 0xE000EF34), ("FPDSCR_S", 0xE000EF3C))}
        self.write_mem(0, self.image)
        self.write_mem(CODE_BASE, code_image)
        self.write_mem(DATA_BASE, data_image)
        self.code_shadow = bytearray(code_image)
        self.data_shadow = bytearray(data_image)
        setup_pc = SETUP | (SECURE_ALIAS if self.nonsecure else 0)
        self.set_core([0] * 13 + [DATA_BASE + DATA_SIZE // 2, 0, setup_pc], 1 << 24)
        self.r.cmd(f"Z0,{LANDING:x},2")
        stop = self.r.cmd("c")
        pc = self.read_core()[0][15]
        if pc != LANDING:
            raise RspError(f"setup did not reach the landing pad: stop {stop}, pc {pc:#x}")
        ctl = self.get_reg(self.n_control)
        if ctl != self.control:
            raise RspError(f"CONTROL after setup is {ctl:#x}, expected {self.control:#x}")

    def mem_chunk(self):
        """Bytes per m/M packet: hex doubles the size, and the stub drops packets over PacketSize."""
        return min(0x4000, (self.r.packet_size - 64) // 2)

    def write_mem(self, addr, data):
        step = self.mem_chunk()
        for off in range(0, len(data), step):
            chunk = data[off:off + step]
            rep = self.r.cmd(f"M{addr + off:x},{len(chunk):x}:" + chunk.hex())
            if rep != "OK":
                raise RspError(f"M {addr + off:#x}: {rep}")

    def read_mem(self, addr, size):
        out = bytearray()
        step = self.mem_chunk()
        for off in range(0, size, step):
            n = min(step, size - off)
            rep = self.r.cmd(f"m{addr + off:x},{n:x}")
            if rep.startswith("E") and len(rep) == 3:
                raise RspError(f"m {addr + off:#x}: {rep}")
            out += bytes.fromhex(rep)
        return bytes(out)

    def read_word(self, addr):
        try:
            return struct.unpack("<I", self.read_mem(addr, 4))[0]
        except RspError:
            return None

    def set_reg(self, num, value, size=4):
        rep = self.r.cmd(f"P{num:x}=" + value.to_bytes(size, "little").hex())
        if rep != "OK":
            raise RspError(f"P{num:x}: {rep}")

    def get_reg(self, num):
        return int.from_bytes(bytes.fromhex(self.r.cmd(f"p{num:x}")), "little")

    def set_core(self, regs, xpsr):
        rep = self.r.cmd("G" + struct.pack("<17I", *regs, xpsr).hex())
        if rep != "OK":
            raise RspError(f"G: {rep}")

    def read_core(self):
        vals = struct.unpack("<17I", bytes.fromhex(self.r.cmd("g")))
        return list(vals[:16]), vals[16]

    def set_state(self, st):
        self.set_core(st["r"], st["xpsr"])
        for i, v in enumerate(st["d"]):
            self.set_reg(self.d_nums[i], v, 8)
        self.set_reg(self.n_fpscr, st["fpscr"])
        self.set_reg(self.n_vpr, st["vpr"])

    def step(self):
        self.r.send("s")
        self.r.s.settimeout(self.halt_timeout)
        halted = False
        try:
            stop = self.r.read_packet().decode()
        except RspTimeout:
            # WFI halts the CPU even when single-stepping; interrupt it.
            self.r.s.settimeout(5.0)
            self.r.s.sendall(b"\x03")
            stop = self.r.read_packet().decode()
            halted = True
        finally:
            self.r.s.settimeout(5.0)
        if not (stop.startswith("T") or stop.startswith("S")):
            raise RspError(f"unexpected stop reply {stop!r}")
        regs, xpsr = self.read_core()
        pc = regs[15]
        # A branch may also land on these addresses; only Handler mode (IPSR != 0) means an exception.
        if xpsr & 0x1FF and HANDLERS <= pc < HANDLERS + 4 * NUM_VECTORS:
            return self._exception(regs, xpsr)
        if xpsr & 0x1FF and pc == SECURE_ALIAS + S_TRAP:
            return self._secure_exception(regs, xpsr)
        res = {"kind": "RETIRED", "r": regs, "xpsr": xpsr, "halted": halted}
        res["d"] = [self.get_reg(n) for n in self.d_nums]
        res["fpscr"] = self.get_reg(self.n_fpscr)
        res["vpr"] = self.get_reg(self.n_vpr)
        res["control"] = self.get_reg(self.n_control)
        if res["control"] != self.control:
            res["control_changed"] = True
        try:
            res["data"] = self.read_mem(DATA_BASE, DATA_SIZE)
        except RspError:
            # Only after a change of security state, which control_changed already reports.
            res["data"] = None
        return res

    def _exception(self, regs, xpsr):
        exc = (regs[15] - HANDLERS) // 4
        sp = regs[13]
        cfsr, hfsr, dfsr, mmfar, bfar = struct.unpack("<5I", self.read_mem(0xE000ED28, 20))
        res = {"kind": "EXCEPTION", "exc": exc, "exc_name": EXC_NAMES.get(exc, f"exc{exc}"), "xpsr": xpsr,
               "cfsr": cfsr, "hfsr": hfsr, "dfsr": dfsr, "mmfar": mmfar, "bfar": bfar,
               "sfsr": self.read_word(0xE000EDE4) or 0}
        try:
            frame = struct.unpack("<8I", self.read_mem(sp, 32))
        except RspError:
            # The instruction changed SP (e.g. LDM with SP in the list) before faulting, and
            # stacking to the new SP failed; the recovery stub cannot run either.
            res.update(r=regs, stacked_pc=None, frame_unreadable=True)
            return res
        # v8.1-M zeroes r0-r3 and r12 on exception entry; take them from the stack frame.
        res.update(r=list(frame[:4]) + regs[4:12] + [frame[4]], stacked_lr=frame[5], stacked_pc=frame[6],
                   stacked_xpsr=frame[7])
        stop = self.r.cmd("c")
        regs2, xpsr2 = self.read_core()
        if regs2[15] != LANDING or (xpsr2 & 0x1FF) != 0:
            raise RspError(f"recovery did not return to the landing pad: stop {stop}, pc {regs2[15]:#x}, "
                           f"xpsr {xpsr2:#x}")
        if self.get_reg(self.n_control) != self.control:
            res["control_changed"] = True
        return res

    def _secure_exception(self, regs, xpsr):
        """An exception taken to Secure state; no recovery, the caller relaunches QEMU."""
        exc = xpsr & 0x1FF
        res = {"kind": "EXCEPTION", "exc": exc, "exc_name": "Secure " + EXC_NAMES.get(exc, f"exc{exc}"),
               "xpsr": xpsr, "r": regs, "stacked_pc": None, "secure_exception": True,
               "frame_unreadable": True}
        for name, addr in (("cfsr", 0xE000ED28), ("hfsr", 0xE000ED2C), ("dfsr", 0xE000ED30),
                           ("mmfar", 0xE000ED34), ("bfar", 0xE000ED38), ("sfsr", 0xE000EDE4),
                           ("sfar", 0xE000EDE8)):
            res[name] = self.read_word(addr) or 0
        return res

    def sync_memory(self, code_image, data_image, data_after):
        """Bring the code region and data window back to the given images."""
        self._restore(CODE_BASE, self.code_shadow, code_image)
        if data_after is None:
            data_after = self.read_mem(DATA_BASE, DATA_SIZE)
        self.data_shadow[:] = data_after
        self._restore(DATA_BASE, self.data_shadow, data_image)

    def _restore(self, base, shadow, image):
        for lo, hi in diff_runs(shadow, image):
            self.write_mem(base + lo, image[lo:hi])
            shadow[lo:hi] = image[lo:hi]


def diff_runs(a, b, gap=16):
    """Ranges [lo, hi) where a and b differ, merging runs closer than gap bytes."""
    runs = []
    n = len(b)
    if a == b:
        return runs
    i = 0
    while i < n:
        if a[i] == b[i]:
            if a[i:i + 256] == b[i:i + 256]:
                i += 256
            else:
                i += 1
            continue
        lo = i
        last = i
        while i < n and i - last <= gap:
            if a[i] != b[i]:
                last = i
            i += 1
        runs.append((lo, last + 1))
        i = last + 1
    return runs
