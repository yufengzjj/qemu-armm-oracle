"""Probe QEMU's Cortex-M55 through the gdbstub: register set, MVE state, single-step of one MVE insn.

Needs qemu-system-arm (mps3-an547), and the capstone and keystone Python packages.
"""
import re, socket, struct, subprocess, sys, time
import capstone

QEMU = r"C:\Program Files\qemu\qemu-system-arm.exe"
PORT = 12355


class Rsp:
    def __init__(self, port):
        for _ in range(50):
            try:
                self.s = socket.create_connection(("127.0.0.1", port))
                break
            except OSError:
                time.sleep(0.1)
        self.s.settimeout(5)
        self.buf = b""
        self.ack = True

    def _read_packet(self):
        while True:
            m = re.search(rb"\$([^#]*)#[0-9a-fA-F]{2}", self.buf)
            if m:
                self.buf = self.buf[m.end():]
                if self.ack:
                    self.s.sendall(b"+")
                return m.group(1)
            self.buf += self.s.recv(65536)

    def cmd(self, body):
        data = body.encode() if isinstance(body, str) else body
        pkt = b"$" + data + b"#" + b"%02x" % (sum(data) & 0xFF)
        self.s.sendall(pkt)
        return self._read_packet().decode(errors="replace")


def xfer(r, annex):
    out, off = "", 0
    while True:
        rep = r.cmd(f"qXfer:features:read:{annex}:{off:x},fff")
        out += rep[1:]
        off += len(rep) - 1
        if rep[0] == "l":
            return out


def main():
    p = subprocess.Popen([QEMU, "-M", "mps3-an547", "-cpu", "cortex-m55", "-S", "-gdb", f"tcp::{PORT}",
                          "-nographic", "-monitor", "none", "-serial", "none"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        r = Rsp(PORT)
        print("qSupported:", r.cmd("qSupported:xmlRegisters=arm"))
        print("NoAck:", r.cmd("QStartNoAckMode"))
        r.ack = False
        top = xfer(r, "target.xml")
        regs = []
        for inc in ["target.xml"] + re.findall(r'href="([^"]+)"', top):
            x = top if inc == "target.xml" else xfer(r, inc)
            feats = re.findall(r'<feature name="([^"]+)"', x)
            names = re.findall(r'<reg name="([^"]+)" bitsize="(\d+)"(?:[^>]*regnum="(\d+)")?', x)
            print(f"{inc}: features={feats} regs={[n for n, _, _ in names]}")
            regs += names
        regnum, nums = {}, 0
        for n, bits, rn in regs:
            nums = int(rn) if rn else nums
            regnum[n] = (nums, int(bits))
            nums += 1

        def wreg(name, val):
            n, bits = regnum[name]
            return r.cmd(f"P{n:x}=" + val.to_bytes(bits // 8, "little").hex())

        def rreg(name):
            n, bits = regnum[name]
            return int.from_bytes(bytes.fromhex(r.cmd(f"p{n:x}")), "little")

        code = bytes.fromhex("22ef4408") + bytes.fromhex("0520")  # vadd.i32 q0, q1, q2 ; movs r0, #5
        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS | capstone.CS_MODE_V8)
        for i in cs.disasm(code, 0x100):
            print(f"  capstone: {i.address:#x} {i.mnemonic} {i.op_str}")
        print("code write:", r.cmd("M100,%x:" % len(code) + code.hex()))
        dregs = [k for k in regnum if re.fullmatch(r"d\d+", k)]
        print("d regs exposed:", len(dregs), "vpr:", "vpr" in regnum, "fpscr:", "fpscr" in regnum)
        wreg("d2", 0x00000002_00000001)
        wreg("d3", 0x00000004_00000003)
        wreg("d4", 0x00000020_00000010)
        wreg("d5", 0x00000040_00000030)
        # Vector table: every handler is `b .` at 0x200, so a fault stops there instead of locking up.
        vt = struct.pack("<I", 0x20001000) + struct.pack("<I", 0x201) * 63
        r.cmd("M0,%x:" % len(vt) + vt.hex())
        r.cmd("M200,2:fee7")
        wreg("sp", 0x20001000)
        # A gdbstub write to CPACR does not stick (reads back 0), so the guest enables CP10/CP11 itself.
        import keystone
        ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
        setup, _ = ks.asm("movw r1, #0xed88; movt r1, #0xe000; mov.w r0, #0xf00000; str r0, [r1]; dsb sy; isb sy", 0x180)
        r.cmd("M180,%x:" % len(setup) + bytes(setup).hex())
        wreg("pc", 0x180)
        wreg("xpsr", 1 << 24)
        r.cmd("Z0,%x,2" % (0x180 + len(setup)))
        print("setup run:", r.cmd("c"), "pc", hex(rreg("pc")))
        r.cmd("z0,%x,2" % (0x180 + len(setup)))
        wreg("pc", 0x100)
        wreg("xpsr", 1 << 24)
        t0 = time.perf_counter()
        print("step:", r.cmd("s"))
        t1 = time.perf_counter()
        rd = lambda a: struct.unpack("<I", bytes.fromhex(r.cmd("m%x,4" % a)))[0]
        print(f"after vadd: pc={rreg('pc'):#x} xpsr={rreg('xpsr'):#x} CFSR={rd(0xE000ED28):#x} HFSR={rd(0xE000ED2C):#x} "
              f"CPACR={rd(0xE000ED88):#x} NSACR={rd(0xE000ED8C):#x} FPCCR={rd(0xE000EF34):#x}")
        print(f"  d0={rreg('d0'):#018x} d1={rreg('d1'):#018x}  (step {1000*(t1-t0):.2f} ms)")
        print("step:", r.cmd("s"))
        print(f"after movs: pc={rreg('pc'):#x} r0={rreg('r0')} xpsr={rreg('xpsr'):#x}")
        # Round-trip cost of one reset-step-read cycle.
        t0 = time.perf_counter()
        for _ in range(200):
            wreg("pc", 0x102)
            wreg("r0", 0)
            r.cmd("s")
            rreg("r0")
        print(f"200 x (2 writes + step + read): {1000*(time.perf_counter()-t0)/200:.2f} ms each")
    finally:
        p.kill()


if __name__ == "__main__":
    main()
