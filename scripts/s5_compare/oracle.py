"""ctypes binding for armm_oracle.dll (include/armm_oracle.h, API version 2)."""
import ctypes as C
import os
import shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DIST = os.path.join(ROOT, "build", "oracle-win", "dist")
LOCAL = os.path.join(ROOT, "build", "s5-oracle")

LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x100
LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x1000

KINDS = ["RETIRED", "UNDEFINED", "NO_COPROCESSOR", "INVALID_STATE", "DATA_ABORT", "PREFETCH_ABORT", "SVC",
         "BKPT", "OTHER"]

PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4


class StepResult(C.Structure):
    _fields_ = [("kind", C.c_uint32), ("excp", C.c_int32), ("pc", C.c_uint32), ("fault_addr", C.c_uint32),
                ("fsr", C.c_uint32), ("reserved", C.c_uint32)]


def stage_dll(src=DIST, dst=LOCAL):
    """Copy the dist folder so that loading it does not lock the build output."""
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        s, d = os.path.join(src, name), os.path.join(dst, name)
        if not os.path.exists(d) or os.path.getmtime(s) != os.path.getmtime(d) \
                or os.path.getsize(s) != os.path.getsize(d):
            shutil.copy2(s, d)
    return os.path.join(dst, "armm_oracle.dll")


class Oracle:
    def __init__(self, dll_path, cpu="cortex-m55"):
        # Full path plus these flags: dependencies come from the DLL's own folder, never from PATH.
        self.lib = lib = C.CDLL(dll_path, winmode=LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
        P, U32, U64, I = C.c_void_p, C.c_uint32, C.c_uint64, C.c_int
        sig = {
            "armm_api_version": (I, []), "armm_last_error": (C.c_char_p, []),
            "armm_create": (P, [C.c_char_p]), "armm_destroy": (None, [P]), "armm_reset": (I, [P]),
            "armm_get_r": (U32, [P, C.c_uint]), "armm_set_r": (I, [P, C.c_uint, U32]),
            "armm_get_xpsr": (U32, [P]), "armm_set_xpsr": (I, [P, U32]),
            "armm_get_q": (I, [P, C.c_uint, C.POINTER(U64), C.POINTER(U64)]),
            "armm_set_q": (I, [P, C.c_uint, U64, U64]),
            "armm_get_d": (U64, [P, C.c_uint]), "armm_set_d": (I, [P, C.c_uint, U64]),
            "armm_get_fpscr": (U32, [P]), "armm_set_fpscr": (I, [P, U32]),
            "armm_get_vpr": (U32, [P]), "armm_set_vpr": (I, [P, U32]),
            "armm_get_control": (U32, [P]), "armm_set_control": (I, [P, U32]),
            "armm_get_exclusive": (I, [P, C.POINTER(U32)]), "armm_set_exclusive": (I, [P, U32, C.c_uint]),
            "armm_map": (I, [P, U32, U32, U32]), "armm_unmap": (I, [P, U32, U32]),
            "armm_write_mem": (I, [P, U32, C.c_char_p, C.c_size_t]),
            "armm_read_mem": (I, [P, U32, C.c_char_p, C.c_size_t]),
            "armm_step": (I, [P, C.POINTER(StepResult)]), "armm_flush_tb": (I, [P]),
        }
        for name, (res, args) in sig.items():
            f = getattr(lib, name)
            f.restype, f.argtypes = res, args
        ver = lib.armm_api_version()
        if ver != 2:
            raise RuntimeError(f"armm_oracle API version {ver}, this harness expects 2")
        self.o = lib.armm_create(cpu.encode())
        if not self.o:
            raise RuntimeError("armm_create: " + lib.armm_last_error().decode())
        self.res = StepResult()
        self._res_ref = C.byref(self.res)

    def check(self, rc, what):
        if rc != 0:
            raise RuntimeError(f"{what}: rc {rc}: {self.lib.armm_last_error().decode()}")

    def map(self, addr, size, prot):
        self.check(self.lib.armm_map(self.o, addr, size, prot), "armm_map")

    def write_mem(self, addr, data):
        self.check(self.lib.armm_write_mem(self.o, addr, bytes(data), len(data)), "armm_write_mem")

    def read_mem(self, addr, size):
        buf = C.create_string_buffer(size)
        self.check(self.lib.armm_read_mem(self.o, addr, buf, size), "armm_read_mem")
        return buf.raw

    def set_state(self, st, control):
        lib, o = self.lib, self.o
        for i, v in enumerate(st["r"]):
            lib.armm_set_r(o, i, v)
        lib.armm_set_xpsr(o, st["xpsr"])
        for i, v in enumerate(st["d"]):
            lib.armm_set_d(o, i, v)
        lib.armm_set_fpscr(o, st["fpscr"])
        lib.armm_set_vpr(o, st["vpr"])
        lib.armm_set_control(o, control)

    def close_exclusive(self):
        self.check(self.lib.armm_set_exclusive(self.o, 0, 0), "armm_set_exclusive")

    def step(self):
        self.check(self.lib.armm_step(self.o, self._res_ref), "armm_step")
        r = self.res
        return {"kind": KINDS[r.kind], "excp": r.excp, "pc": r.pc, "fault_addr": r.fault_addr, "fsr": r.fsr}

    def read_state(self):
        lib, o = self.lib, self.o
        return {"r": [lib.armm_get_r(o, i) for i in range(16)], "xpsr": lib.armm_get_xpsr(o),
                "d": [lib.armm_get_d(o, i) for i in range(16)], "fpscr": lib.armm_get_fpscr(o),
                "vpr": lib.armm_get_vpr(o), "control": lib.armm_get_control(o)}
