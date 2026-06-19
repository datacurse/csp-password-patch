"""Minimal Windows debugger: launch an exe, report the first real exception's
address (RVA + which section of the main image)."""
import ctypes
import sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
INFINITE = 0xFFFFFFFF
CREATE_PROCESS_DEBUG_EVENT = 3
EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5

SECTIONS = [("sec0", 0x1000, 0x40ca000), ("sec1", 0x40cb000, 0xcfb000), ("sec2", 0x4dc6000, 0x4b9000),
            ("sec3", 0x527f000, 0x20a000), ("sec4", 0x5489000, 0x3000), ("sec5", 0x548c000, 0x377000),
            ("sec6", 0x5803000, 0x6c000), ("sec7", 0x586f000, 0x377000), ("sec8", 0x5be6000, 0x589000),
            ("sec9", 0x616f000, 0x3bf000), (".idata2", 0x652e000, 0xf000)]


def sec_of(rva):
    for n, a, s in SECTIONS:
        if a <= rva < a + s:
            return n
    return "?"


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def main():
    exe = sys.argv[1]
    cwd = sys.argv[2] if len(sys.argv) > 2 else None
    si = STARTUPINFO(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, None, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                            ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print("CreateProcess failed", ctypes.get_last_error()); return

    buf = (ctypes.c_ubyte * 4096)()
    base = 0
    count = 0
    while True:
        if not k32.WaitForDebugEvent(ctypes.byref(buf), INFINITE):
            break
        code = struct_u32(buf, 0)
        pid = struct_u32(buf, 4)
        tid = struct_u32(buf, 8)
        cont = DBG_CONTINUE
        if code == CREATE_PROCESS_DEBUG_EVENT:
            base = struct_u64(buf, 40)
            print("image base =", hex(base))
        elif code == EXCEPTION_DEBUG_EVENT:
            exc_code = struct_u32(buf, 16)
            exc_addr = struct_u64(buf, 32)
            firstchance = struct_u32(buf, 168)
            # ignore initial breakpoint
            if exc_code in (0x80000003, 0x4000001F) and count == 0:
                count += 1
                cont = DBG_CONTINUE
            else:
                rva = exc_addr - base if base else 0
                where = sec_of(rva) if 0 <= rva < 0x6600000 else "OUTSIDE-IMAGE"
                print(f"EXCEPTION code={hex(exc_code)} addr={hex(exc_addr)} rva={hex(rva)} sec={where} firstchance={firstchance}")
                # let first-chance propagate; capture again if repeats -> stop after 2
                count += 1
                if count > 3 or firstchance == 0:
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
                cont = DBG_EXCEPTION_NOT_HANDLED
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print("process exited")
            break
        k32.ContinueDebugEvent(pid, tid, cont)


def struct_u32(buf, off):
    return int.from_bytes(bytes(buf[off:off + 4]), "little")


def struct_u64(buf, off):
    return int.from_bytes(bytes(buf[off:off + 8]), "little")


if __name__ == "__main__":
    main()
