"""Scan process memory for pointers to decrypted itzmx strings."""
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
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
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


def read_memory(pid: int, address: int, size: int) -> bytes | None:
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        buf = (ctypes.c_char * size)()
        n = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(
            h, ctypes.c_void_p(address), buf, size, ctypes.byref(n)
        ):
            return None
        return bytes(buf[: n.value])
    finally:
        kernel32.CloseHandle(h)


def scan_pointer_refs(pid: int, target_addr: int) -> list[dict]:
    needle = struct.pack("<Q", target_addr)
    hits: list[dict] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess failed")
    try:
        while kernel32.VirtualQueryEx(
            h, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ):
            base = mbi.BaseAddress or 0
            region_size = int(mbi.RegionSize)
            readable = (
                mbi.State == MEM_COMMIT
                and (mbi.Protect & PAGE_NOACCESS) == 0
                and (mbi.Protect & PAGE_GUARD) == 0
            )
            if readable and region_size > 0:
                data = read_memory(pid, base, region_size)
                if data:
                    start = 0
                    while True:
                        idx = data.find(needle, start)
                        if idx == -1:
                            break
                        hits.append(
                            {
                                "pointer_address": hex(base + idx),
                                "region_base": hex(base),
                                "protect": hex(mbi.Protect),
                                "context": data[max(0, idx - 32) : idx + 40].hex(),
                            }
                        )
                        start = idx + 8
            next_addr = base + region_size
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(h)
    return hits


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--launch", action="store_true")
    parser.add_argument(
        "--exe",
        type=Path,
        default=Path(
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
        ),
    )
    args = parser.parse_args()

    pid = args.pid
    if args.launch:
        proc = subprocess.Popen([str(args.exe)], cwd=str(args.exe.parent))
        pid = proc.pid
        time.sleep(8)
    if pid is None:
        print("Provide --pid or --launch")
        sys.exit(1)

    base = get_module_base(pid)
    pe = args.exe.read_bytes()
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", pe, pe_off + 24 + 56)[0]
    mem = read_memory(pid, base, size_of_image)
    if not mem:
        raise OSError("Failed to read module memory")

    needle = b"Application requires password to start"
    str_rva = mem.find(needle)
    target = base + str_rva
    print(f"base={hex(base)} str_rva={hex(str_rva)} target={hex(target)}")

    hits = scan_pointer_refs(pid, target)
    out = Path(__file__).resolve().parents[1] / "tools" / "output" / "pointer_refs.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(hits, indent=2), encoding="utf-8")
    print(f"Found {len(hits)} pointer ref(s)")
    for hit in hits[:20]:
        print(hit)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
