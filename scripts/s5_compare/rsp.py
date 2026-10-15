"""Minimal GDB remote serial protocol client (no-ack mode), as in qemu_m55_gdbstub_probe.py."""
import re
import socket
import time


class RspError(Exception):
    pass


class RspTimeout(RspError):
    pass


class Rsp:
    def __init__(self, port, timeout=5.0):
        last = None
        for _ in range(100):
            try:
                self.s = socket.create_connection(("127.0.0.1", port))
                break
            except OSError as e:
                last = e
                time.sleep(0.1)
        else:
            raise RspError(f"cannot connect to gdbstub on port {port}: {last}")
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.settimeout(timeout)
        self.buf = b""
        self.ack = True

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def read_packet(self):
        while True:
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and len(self.buf) >= end + 3:
                    body = self.buf[start + 1:end]
                    self.buf = self.buf[end + 3:]
                    if self.ack:
                        self.s.sendall(b"+")
                    return body
            try:
                chunk = self.s.recv(1 << 20)
            except socket.timeout:
                raise RspTimeout("gdbstub timeout")
            except OSError as e:
                raise RspError(f"gdbstub connection lost: {e}")
            if not chunk:
                raise RspError("gdbstub connection closed")
            self.buf += chunk

    def send(self, body):
        data = body.encode() if isinstance(body, str) else body
        try:
            self.s.sendall(b"$" + data + b"#" + b"%02x" % (sum(data) & 0xFF))
        except OSError as e:
            raise RspError(f"gdbstub connection lost: {e}")

    def cmd(self, body):
        self.send(body)
        return self.read_packet().decode(errors="replace")

    def start(self):
        rep = self.cmd("qSupported:xmlRegisters=arm")
        m = re.search(r"PacketSize=([0-9a-fA-F]+)", rep)
        self.packet_size = int(m.group(1), 16) if m else 4096
        self.cmd("QStartNoAckMode")
        self.ack = False

    def xfer(self, annex):
        out, off = "", 0
        while True:
            rep = self.cmd(f"qXfer:features:read:{annex}:{off:x},fff")
            out += rep[1:]
            off += len(rep) - 1
            if rep[0] == "l":
                return out

    def register_map(self):
        """Map register name -> (gdb regnum, bit size) from the target description."""
        top = self.xfer("target.xml")
        regs = []
        for inc in re.findall(r'href="([^"]+)"', top):
            x = self.xfer(inc)
            for tag in re.findall(r"<reg [^>]*>", x):
                name = re.search(r'name="([^"]+)"', tag).group(1)
                bits = int(re.search(r'bitsize="(\d+)"', tag).group(1))
                rn = re.search(r'regnum="(\d+)"', tag)
                regs.append((name, bits, int(rn.group(1)) if rn else None))
        regmap, num = {}, 0
        for name, bits, rn in regs:
            num = rn if rn is not None else num
            regmap[name] = (num, bits)
            num += 1
        return regmap

    def monitor(self, text):
        self.send("qRcmd," + text.encode().hex())
        out = ""
        while True:
            rep = self.read_packet().decode(errors="replace")
            if rep.startswith("O") and rep != "OK":
                out += bytes.fromhex(rep[1:]).decode(errors="replace")
                continue
            return rep, out
