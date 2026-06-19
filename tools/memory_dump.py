"""Dump process memory regions and map runtime addresses to PE RVAs."""
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


def find_pid(image_name: str) -> int | None:
    result = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if image_name.lower() in line.lower():
            parts = [p.strip('"') for p in line.split('","')]
            try:
                return int(parts[1])
            except (ValueError, IndexError):
                continue
    return None


def get_module_base(pid: int, module_name: str) -> int | None:
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        hmods = (ctypes.c_void_p * 1024)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(
            h,
            ctypes.byref(hmods),
            ctypes.sizeof(hmods),
            ctypes.byref(needed),
            LIST_MODULES_ALL,
        ):
            return None
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        name_buf = ctypes.create_unicode_buffer(MAX_PATH)
        for i in range(count):
            mod = hmods[i]
            if not mod:
                continue
            psapi.GetModuleBaseNameW(h, ctypes.c_void_p(mod), name_buf, MAX_PATH)
            if name_buf.value.lower() == module_name.lower():
                return int(mod)
    finally:
        kernel32.CloseHandle(h)
    return None


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


def read_memory(pid: int, address: int, size: int) -> bytes | None:
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        buf = (ctypes.c_char * size)()
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            h, ctypes.c_void_p(address), buf, size, ctypes.byref(n)
        )
        if not ok:
            return None
        return bytes(buf[: n.value])
    finally:
        kernel32.CloseHandle(h)


def dump_module_strings(
    pid: int,
    module_base: int,
    pe_path: Path,
    needles: list[bytes],
) -> list[dict]:
    pe_data = pe_path.read_bytes()
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", pe_data, pe_off + 24 + 56)[0]
    mem = read_memory(pid, module_base, size_of_image)
    if mem is None:
        raise OSError("Failed to read module image from process memory")

    out: list[dict] = []
    for needle in needles:
        start = 0
        while True:
            idx = mem.find(needle, start)
            if idx == -1:
                break
            rva = idx
            file_off = rva_to_file_offset(pe_data, rva)
            runtime_addr = module_base + idx
            out.append(
                {
                    "needle": needle.decode("utf-8", errors="replace"),
                    "rva": hex(rva),
                    "runtime_address": hex(runtime_addr),
                    "file_offset": hex(file_off) if file_off is not None else None,
                    "memory_preview": mem[idx : idx + min(len(needle) + 32, 120)].decode(
                        "utf-8", errors="replace"
                    ),
                    "disk_preview": (
                        pe_data[file_off : file_off + 64].hex()
                        if file_off is not None
                        else None
                    ),
                }
            )
            start = idx + 1
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--exe", type=Path, default=Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"))
    parser.add_argument("--launch", action="store_true")
    args = parser.parse_args()

    pid = args.pid
    if args.launch:
        proc = subprocess.Popen([str(args.exe)], cwd=str(args.exe.parent))
        pid = proc.pid
        print(f"Launched pid {pid}, waiting 8s...")
        time.sleep(8)
    elif pid is None:
        pid = find_pid("CLIPStudioPaint.exe")
    if pid is None:
        print("No CLIPStudioPaint.exe process found")
        sys.exit(1)

    base = get_module_base(pid, "CLIPStudioPaint.exe")
    if base is None:
        print(f"Could not get module base for pid {pid}")
        sys.exit(1)

    print(f"pid={pid} module_base={hex(base)}")
    needles = [
        b"Application requires password to start",
        b"Always Free",
        b"lai2 zi4",
        b"Anti-Resale",
        b"itzmx.com",
    ]
    hits = dump_module_strings(pid, base, args.exe, needles)
    out_path = Path(__file__).resolve().parents[1] / "tools" / "output" / "module_string_map.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"pid": pid, "module_base": hex(base), "hits": hits}, indent=2),
        encoding="utf-8",
    )
    for hit in hits:
        print(json.dumps(hit, ensure_ascii=False))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
