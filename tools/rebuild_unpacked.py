"""Rebuild a clean, unprotected CSP exe from the decrypted dump.

Produces a memory-image-layout PE (FileAlignment == SectionAlignment) where each
section's raw bytes are the decrypted in-memory contents. Sets AddressOfEntryPoint
to the recovered OEP and ImageBase to the dump-run base (relocations are kept, so
ASLR still relocates correctly). Optionally neutralizes the protector-hijacked TLS
directory.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DUMP = REPO / "tools" / "output" / "dump"
ORIG = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")
OUT = REPO / "tools" / "output" / "CLIPStudioPaint.unpacked.exe"
ALIGN = 0x1000


def align_up(v, a):
    return (v + a - 1) & ~(a - 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-tls", action="store_true", help="keep TLS dir (default zeroes it)")
    ap.add_argument("--no-aslr", action="store_true", help="clear DYNAMIC_BASE so it loads at ImageBase (bytes used verbatim)")
    args = ap.parse_args()

    meta = json.loads((DUMP / "dump_meta.json").read_text())
    oep_rva = int(meta["oep_rva"], 16)
    base = int(meta["base"], 16)
    print(f"OEP rva={hex(oep_rva)} dump_base={hex(base)}")

    d = bytearray(ORIG.read_bytes())
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    size_of_image = struct.unpack_from("<I", d, opt + 56)[0]

    secs = []
    for i in range(num):
        o = sectbl + i * 40
        secs.append({
            "i": i,
            "hdr": o,
            "vs": struct.unpack_from("<I", d, o + 8)[0],
            "va": struct.unpack_from("<I", d, o + 12)[0],
        })

    # Header region buffer (first section VA worth of bytes).
    first_va = min(s["va"] for s in secs)
    out = bytearray(size_of_image)
    out[0:first_va] = d[0:first_va]  # original headers + padding

    # Patch optional header in OUT.
    struct.pack_into("<I", out, opt + 16, oep_rva)          # AddressOfEntryPoint
    struct.pack_into("<Q", out, opt + 24, base)             # ImageBase
    struct.pack_into("<I", out, opt + 36, ALIGN)            # FileAlignment
    struct.pack_into("<I", out, opt + 60, align_up(first_va, ALIGN))  # SizeOfHeaders -> >= headers

    if not args.keep_tls:
        struct.pack_into("<I", out, opt + 112 + 9 * 8, 0)      # TLS dir RVA = 0
        struct.pack_into("<I", out, opt + 112 + 9 * 8 + 4, 0)  # TLS dir size = 0
        print("TLS directory zeroed")

    if args.no_aslr:
        dllchar = struct.unpack_from("<H", out, opt + 70)[0]
        dllchar &= ~0x0040  # DYNAMIC_BASE
        dllchar &= ~0x0020  # HIGH_ENTROPY_VA
        struct.pack_into("<H", out, opt + 70, dllchar)
        print(f"cleared DYNAMIC_BASE -> DllCharacteristics={hex(dllchar)}")

    # Lay out sections as memory image.
    for s in secs:
        binp = DUMP / f"sec{s['i']}.bin"
        data = binp.read_bytes() if binp.exists() else b""
        raw_size = align_up(max(len(data), s["vs"]), ALIGN)
        # patch section header: PointerToRawData = VA, SizeOfRawData = raw_size
        struct.pack_into("<I", out, s["hdr"] + 16, raw_size)   # SizeOfRawData
        struct.pack_into("<I", out, s["hdr"] + 20, s["va"])    # PointerToRawData
        end = s["va"] + len(data)
        if end > len(out):
            out.extend(b"\x00" * (end - len(out)))
        out[s["va"]:end] = data
        print(f"  sec{s['i']} va={hex(s['va'])} wrote {len(data)} raw_size={hex(raw_size)}")

    OUT.write_bytes(out)
    print(f"\nWrote {OUT} ({len(out)} bytes)")


if __name__ == "__main__":
    main()
