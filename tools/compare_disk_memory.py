"""Compare on-disk PE sections with decrypted in-memory image to find patchable regions."""
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

    pe = args.exe.read_bytes()
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", pe, pe_off + 24 + 56)[0]
    base = get_module_base(pid)
    mem = read_memory(pid, base, size_of_image)

    num = struct.unpack_from("<H", pe, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size

    report = []
    for i in range(num):
        off = sec + i * 40
        name = pe[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace") or f"sec{i}"
        va = struct.unpack_from("<I", pe, off + 12)[0]
        vsize = struct.unpack_from("<I", pe, off + 8)[0]
        raw_ptr = struct.unpack_from("<I", pe, off + 20)[0]
        raw_size = struct.unpack_from("<I", pe, off + 16)[0]
        if raw_size == 0 or va + raw_size > len(mem):
            continue
        disk = pe[raw_ptr : raw_ptr + raw_size]
        runtime = mem[va : va + raw_size]
        matches = sum(a == b for a, b in zip(disk, runtime))
        ratio = matches / raw_size if raw_size else 0
        report.append(
            {
                "section": name,
                "va": hex(va),
                "raw_ptr": hex(raw_ptr),
                "raw_size": raw_size,
                "match_ratio": round(ratio, 4),
            }
        )
        print(f"{name:8} match={ratio:.2%} raw_size=0x{raw_size:X}")

    out = Path(__file__).resolve().parents[1] / "tools" / "output" / "disk_vs_memory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
