"""Find code xrefs to decrypted strings in CLIPStudioPaint memory."""
from __future__ import annotations

import argparse
import ctypes
import json
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def get_module_base(pid: int) -> int:
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess failed")
    try:
        hmods = (ctypes.c_void_p * 1024)()
        needed = wintypes.DWORD()
        psapi.EnumProcessModulesEx(
            h, ctypes.byref(hmods), ctypes.sizeof(hmods), ctypes.byref(needed), LIST_MODULES_ALL
        )
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        name_buf = ctypes.create_unicode_buffer(MAX_PATH)
        for i in range(count):
            mod = hmods[i]
            if not mod:
                continue
            psapi.GetModuleBaseNameW(h, ctypes.c_void_p(mod), name_buf, MAX_PATH)
            if name_buf.value.lower() == "clipstudiopaint.exe":
                return int(mod)
    finally:
        kernel32.CloseHandle(h)
    raise RuntimeError("Module not found")


def read_memory(pid: int, address: int, size: int) -> bytes:
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess failed")
    try:
        buf = (ctypes.c_char * size)()
        n = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(
            h, ctypes.c_void_p(address), buf, size, ctypes.byref(n)
        ):
            raise OSError(f"ReadProcessMemory failed at {hex(address)}")
        return bytes(buf[: n.value])
    finally:
        kernel32.CloseHandle(h)


def rva_to_file_offset(pe_data: bytes, rva: int) -> int | None:
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    num = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size
    for i in range(num):
        off = sec + i * 40
        va = struct.unpack_from("<I", pe_data, off + 12)[0]
        vsize = struct.unpack_from("<I", pe_data, off + 8)[0]
        raw_ptr = struct.unpack_from("<I", pe_data, off + 20)[0]
        raw_size = struct.unpack_from("<I", pe_data, off + 16)[0]
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return raw_ptr + (rva - va)
    return None


def find_rip_relative_xrefs(code: bytes, code_rva: int, target_rva: int) -> list[int]:
    hits: list[int] = []
    for i in range(len(code) - 7):
        # LEA r64, [rip+disp32]: 48 8D xx yy yy yy yy  (modrm 0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D)
        b0, b1, b2 = code[i], code[i + 1], code[i + 2]
        if b0 == 0x48 and b1 == 0x8D and (b2 & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", code, i + 3)[0]
            instr_rva = code_rva + i
            next_rva = instr_rva + 7
            ref_rva = next_rva + disp
            if ref_rva == target_rva:
                hits.append(instr_rva)
        # MOV r64, [rip+disp32]: 48 8B xx
        if b0 == 0x48 and b1 == 0x8B and (b2 & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", code, i + 3)[0]
            instr_rva = code_rva + i
            next_rva = instr_rva + 7
            ref_rva = next_rva + disp
            if ref_rva == target_rva:
                hits.append(instr_rva)
    return hits


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument(
        "--exe",
        type=Path,
        default=Path(
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
        ),
    )
    parser.add_argument("--launch", action="store_true")
    args = parser.parse_args()

    pid = args.pid
    if args.launch:
        proc = subprocess.Popen([str(args.exe)], cwd=str(args.exe.parent))
        pid = proc.pid
        time.sleep(8)
    if pid is None:
        print("Provide --pid or --launch")
        sys.exit(1)

    pe_data = args.exe.read_bytes()
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", pe_data, pe_off + 24 + 56)[0]
    base = get_module_base(pid)
    mem = read_memory(pid, base, size_of_image)

    needle = b"Application requires password to start"
    str_rva = mem.find(needle)
    if str_rva < 0:
        print("Password string not found in module memory")
        sys.exit(1)

    print(f"module_base={hex(base)} string_rva={hex(str_rva)}")

    # Scan executable sections for xrefs
    num = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size
    all_xrefs: list[dict] = []
    for i in range(num):
        off = sec + i * 40
        va = struct.unpack_from("<I", pe_data, off + 12)[0]
        vsize = struct.unpack_from("<I", pe_data, off + 8)[0]
        name = pe_data[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace")
        if va + vsize > len(mem):
            continue
        section = mem[va : va + vsize]
        xrefs = find_rip_relative_xrefs(section, va, str_rva)
        for xref in xrefs:
            file_off = rva_to_file_offset(pe_data, xref)
            all_xrefs.append(
                {
                    "section": name or f"sec{i}",
                    "xref_rva": hex(xref),
                    "file_offset": hex(file_off) if file_off else None,
                    "bytes": mem[xref : xref + 16].hex(),
                }
            )

    out = Path(__file__).resolve().parents[1] / "tools" / "output" / "xrefs_password_string.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_xrefs, indent=2), encoding="utf-8")
    print(f"Found {len(all_xrefs)} xref(s)")
    for x in all_xrefs:
        print(x)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
