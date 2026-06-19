"""PE metadata, entropy, and marker scan for CLIPStudioPaint.exe."""
from __future__ import annotations

import math
import struct
import sys
from collections import Counter
from pathlib import Path

MARKERS = [
    b"itzmx",
    b"Application requires password",
    b"Always Free",
    b"Anti-Resale",
    b"99A2190A",
    b"key=",
    b"Config.sqlite",
    b"CELSYS",
    b"CLIPStudioPaint",
    b"password to start",
    b"lai2 zi4",
]

PACKER_SIGS = [
    (b"UPX0", "UPX"),
    (b"UPX1", "UPX"),
    (b".vmp0", "VMProtect"),
    (b"Themida", "Themida"),
    (b".enigma", "Enigma"),
]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def read_pe_sections(data: bytes) -> list[dict]:
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_header_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    section_table = pe_off + 24 + opt_header_size
    sections = []

    for i in range(num_sections):
        off = section_table + i * 40
        name = data[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", data, off + 8)[0]
        virtual_addr = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        sections.append(
            {
                "name": name or f"section_{i}",
                "virtual_size": virtual_size,
                "virtual_addr": virtual_addr,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
            }
        )
    return sections


def scan_markers(data: bytes) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for marker in MARKERS:
        label = marker.decode("utf-8", errors="replace")
        offsets: list[int] = []
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        hits[label] = offsets
    return hits


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]

    result = {
        "path": str(path),
        "size": len(data),
        "machine": hex(machine),
        "arch": "x64" if machine == 0x8664 else "x86/other",
        "optional_magic": hex(magic),
        "entropy_first_1mb": round(entropy(data[: 1024 * 1024]), 3),
        "packers": [name for sig, name in PACKER_SIGS if sig in data],
        "sections": read_pe_sections(data),
        "markers": scan_markers(data),
    }
    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python analyze_exe.py <path-to-CLIPStudioPaint.exe>")
        sys.exit(1)

    info = analyze(Path(sys.argv[1]))
    print(f"File: {info['path']}")
    print(f"Size: {info['size']:,} bytes ({info['size'] / 1024 / 1024:.2f} MB)")
    print(f"Arch: {info['arch']} ({info['machine']})")
    print(f"Entropy (first 1MB): {info['entropy_first_1mb']}")
    print(f"Known packers: {info['packers'] or 'none detected'}")

    print("\nSections:")
    for sec in info["sections"]:
        print(
            f"  {sec['name']:8} "
            f"VA=0x{sec['virtual_addr']:X} "
            f"VSize=0x{sec['virtual_size']:X} "
            f"Raw=0x{sec['raw_ptr']:X} "
            f"RawSize=0x{sec['raw_size']:X}"
        )

    print("\nString markers:")
    for label, offsets in info["markers"].items():
        if offsets:
            print(f"  {label}: {len(offsets)} hit(s) at {[hex(o) for o in offsets[:5]]}")
        else:
            print(f"  {label}: not found")


if __name__ == "__main__":
    main()
