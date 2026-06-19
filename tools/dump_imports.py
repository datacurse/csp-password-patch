"""Dump the import table of a PE so we can pick a DLL-proxy / injection strategy."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def main(path_str: str) -> None:
    d = Path(path_str).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    is_plus = magic == 0x20B
    dd = opt + (112 if is_plus else 96)
    imp_rva = struct.unpack_from("<I", d, dd + 1 * 8)[0]
    tls_rva = struct.unpack_from("<I", d, dd + 9 * 8)[0]

    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sec = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sec + i * 40
        nm = d[o : o + 8].split(b"\x00")[0].decode("ascii", "replace")
        va = struct.unpack_from("<I", d, o + 12)[0]
        vs = struct.unpack_from("<I", d, o + 8)[0]
        raw = struct.unpack_from("<I", d, o + 20)[0]
        rs = struct.unpack_from("<I", d, o + 16)[0]
        secs.append((nm, va, vs, raw, rs))

    def r2o(rva: int):
        for nm, va, vs, raw, rs in secs:
            if va <= rva < va + max(vs, rs):
                return raw + (rva - va)
        return None

    print(f"magic={hex(magic)} import_rva={hex(imp_rva)} tls_rva={hex(tls_rva)}")
    print("sections:")
    for nm, va, vs, raw, rs in secs:
        print(f"  {nm:8} va={hex(va)} vsize={hex(vs)} raw={hex(raw)} rsize={hex(rs)}")

    if not imp_rva:
        print("No import table RVA")
        return
    off = r2o(imp_rva)
    if off is None:
        print("Import RVA not in a section")
        return
    print("IMPORTS:")
    while True:
        ent = d[off : off + 20]
        if len(ent) < 20 or ent == b"\x00" * 20:
            break
        name_rva = struct.unpack_from("<I", d, off + 12)[0]
        no = r2o(name_rva)
        if no is None:
            break
        end = d.index(b"\x00", no)
        print("  ", d[no:end].decode("ascii", "replace"))
        off += 20


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
    main(target)
