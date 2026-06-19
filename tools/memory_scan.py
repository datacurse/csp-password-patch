"""Scan a running CLIPStudioPaint process memory for decrypted itzmx strings."""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

TARGET_STRINGS = [
    b"Application requires password to start",
    b"Application requires password",
    b"Always Free",
    b"lai2 zi4",
    b"itzmx",
    b"Anti-Resale",
    b"99A2190A3853635380FAB9A383CF358429ECFDF2873749ADD4B2325537BECA5E",
    b"password to start",
    b"WM_SETTEXT",
    b"\x00Application requires password",
]

TARGET_STRINGS_UTF16 = [s.decode("ascii", errors="ignore").encode("utf-16-le") for s in TARGET_STRINGS if s.isascii()]


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


def find_process(name: str) -> int | None:
    result = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if name.lower() in line.lower():
            parts = [p.strip('"') for p in line.split('","')]
            if parts:
                try:
                    return int(parts[1])
                except (ValueError, IndexError):
                    continue
    return None


def scan_process(pid: int) -> list[dict]:
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(f"OpenProcess failed for pid {pid}: {ctypes.get_last_error()}")

    hits: list[dict] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    try:
        while kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        ):
            base = mbi.BaseAddress or 0
            region_size = int(mbi.RegionSize)
            readable = (
                mbi.State == MEM_COMMIT
                and mbi.Protect & PAGE_NOACCESS == 0
                and mbi.Protect & PAGE_GUARD == 0
            )
            if readable and region_size > 0:
                buffer = (ctypes.c_char * region_size)()
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(base),
                    buffer,
                    region_size,
                    ctypes.byref(bytes_read),
                ):
                    data = bytes(buffer[: bytes_read.value])
                    for needle in TARGET_STRINGS + TARGET_STRINGS_UTF16:
                        idx = data.find(needle)
                        if idx != -1:
                            hits.append(
                                {
                                    "pid": pid,
                                    "address": hex(base + idx),
                                    "region_base": hex(base),
                                    "protect": hex(mbi.Protect),
                                    "needle": needle[:60],
                                }
                            )
            next_addr = base + region_size
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(handle)

    return hits


def launch_and_scan(exe_path: Path, wait_seconds: float = 8.0) -> list[dict]:
    print(f"Launching: {exe_path}")
    proc = subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))
    print(f"Started pid {proc.pid}, waiting {wait_seconds}s for unpack...")
    time.sleep(wait_seconds)

    hits = scan_process(proc.pid)
    print(f"Found {len(hits)} string hit(s) in pid {proc.pid}")
    for hit in hits:
        print(hit)

    print("Leaving process running (close password dialog manually if open).")
    return hits


def main() -> None:
    if len(sys.argv) < 2:
        exe = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")
    else:
        exe = Path(sys.argv[1])

    if len(sys.argv) >= 3 and sys.argv[1] == "--pid":
        hits = scan_process(int(sys.argv[2]))
    elif exe.exists():
        hits = launch_and_scan(exe)
    else:
        pid = find_process("CLIPStudioPaint.exe")
        if pid is None:
            print("CLIPStudioPaint.exe is not running and exe path not found.")
            sys.exit(1)
        hits = scan_process(pid)

    out = Path(__file__).resolve().parents[1] / "tools" / "output" / "memory_scan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    import json

    out.write_text(json.dumps(hits, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
