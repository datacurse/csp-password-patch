"""Inspect the decrypted dump: TLS callbacks, import dir, OEP context."""
from __future__ import annotations

import struct
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DUMP = REPO / "tools" / "output" / "dump"
EXE = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")
IMAGE_BASE = 0x140000000
OEP = 0x3781E34


def load_secs():
    d = EXE.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sectbl + i * 40
        secs.append({"i": i, "va": struct.unpack_from("<I", d, o + 12)[0], "vs": struct.unpack_from("<I", d, o + 8)[0]})
    opt = pe + 24
    dd = opt + 112
    tls_rva = struct.unpack_from("<I", d, dd + 9 * 8)[0]
    imp_rva = struct.unpack_from("<I", d, dd + 1 * 8)[0]
    return secs, tls_rva, imp_rva


class Mem:
    def __init__(self, secs):
        self.blobs = {}
        self.secs = secs
        for s in secs:
            p = DUMP / f"sec{s['i']}.bin"
            self.blobs[s["i"]] = p.read_bytes() if p.exists() else b""

    def read(self, rva, n):
        for s in self.secs:
            if s["va"] <= rva < s["va"] + s["vs"]:
                off = rva - s["va"]
                return self.blobs[s["i"]][off : off + n]
        return b""


def main():
    secs, tls_rva, imp_rva = load_secs()
    m = Mem(secs)
    print("tls_rva=", hex(tls_rva), "imp_rva=", hex(imp_rva))

    def sec_of(rva):
        for s in secs:
            if s["va"] <= rva < s["va"] + s["vs"]:
                return s["i"]
        return None

    print("\n=== OEP context ===")
    oep_bytes = m.read(OEP, 32)
    print(f"OEP rva={hex(OEP)} sec={sec_of(OEP)} bytes={oep_bytes.hex()}")

    print("\n=== TLS ===")
    if tls_rva:
        tls = m.read(tls_rva, 40)
        if len(tls) >= 40:
            start, end, idx, cbs = struct.unpack_from("<QQQQ", tls, 0)
            print(f"  AddressOfCallBacks VA={hex(cbs)} rva={hex(cbs - IMAGE_BASE)} sec={sec_of(cbs - IMAGE_BASE)}")
            cb_rva = cbs - IMAGE_BASE
            for k in range(16):
                ent = m.read(cb_rva + k * 8, 8)
                if len(ent) < 8:
                    break
                fn = struct.unpack_from("<Q", ent, 0)[0]
                if fn == 0:
                    break
                frva = fn - IMAGE_BASE
                print(f"    callback[{k}] VA={hex(fn)} rva={hex(frva)} sec={sec_of(frva)}")
    else:
        print("  no TLS")

    print("\n=== import dir (first descriptors) ===")
    off = imp_rva
    for k in range(80):
        ent = m.read(off + k * 20, 20)
        if len(ent) < 20 or ent == b"\x00" * 20:
            break
        name_rva = struct.unpack_from("<I", ent, 12)[0]
        nm = m.read(name_rva, 40).split(b"\x00")[0].decode("ascii", "replace")
        print(f"    {nm}")


if __name__ == "__main__":
    main()
