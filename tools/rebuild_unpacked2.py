"""Rebuild a clean CSP exe from the dump WITH a reconstructed import table.

- Lays decrypted sections out as a memory-image PE (FileAlignment==SectionAlignment).
- Sets OEP, ImageBase=dump base, clears DYNAMIC_BASE (load verbatim at that base),
  keeps TLS.
- Reconstructs the real import table (the protector-resolved IAT at ~0x40cb000):
  builds descriptors with INT (OriginalFirstThunk) + name strings; FirstThunk points
  at the original IAT slots so existing code keeps working. Runs are split around
  null / self-pointer (protector trampoline) slots so the loader never overwrites
  those.
- Appends a new ".idata2" section holding the descriptors/INT/names.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DUMP = REPO / "tools" / "output" / "dump"
ORIG = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")
OUT = REPO / "tools" / "output" / "CLIPStudioPaint.unpacked.exe"
ALIGN = 0x1000
SELF = "CLIPStudioPaint.exe"


def au(v, a=ALIGN):
    return (v + a - 1) & ~(a - 1)


def build_descriptors(iat_regions):
    main = max(iat_regions, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
    runs = []  # list of {dll, ft_rva, names:[...]}
    cur = None

    def close():
        nonlocal cur
        if cur and cur["names"]:
            runs.append(cur)
        cur = None

    for s in main["slots"]:
        nm = s.get("name")
        dll = s.get("dll")
        external = nm and dll and dll.lower() != SELF.lower()
        if external:
            if cur and cur["dll"].lower() == dll.lower() and s["rva"] == cur["ft_rva"] + 8 * len(cur["names"]):
                cur["names"].append(nm)
            else:
                close()
                cur = {"dll": dll, "ft_rva": s["rva"], "names": [nm]}
        else:
            close()
    close()
    return runs


def main():
    meta = json.loads((DUMP / "dump_meta.json").read_text())
    oep_rva = int(meta["oep_rva"], 16)
    base = int(meta["base"], 16)
    iat_regions = json.loads((DUMP / "iat_full.json").read_text())
    runs = build_descriptors(iat_regions)
    nfuncs = sum(len(r["names"]) for r in runs)
    print(f"OEP={hex(oep_rva)} base={hex(base)} descriptors={len(runs)} funcs={nfuncs}")

    d = bytearray(ORIG.read_bytes())
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    size_of_image = struct.unpack_from("<I", d, opt + 56)[0]

    secs = []
    for i in range(nsec):
        o = sectbl + i * 40
        secs.append({"i": i, "hdr": o,
                     "vs": struct.unpack_from("<I", d, o + 8)[0],
                     "va": struct.unpack_from("<I", d, o + 12)[0]})

    first_va = min(s["va"] for s in secs)
    out = bytearray(size_of_image)
    out[0:first_va] = d[0:first_va]

    # Optional header patches.
    struct.pack_into("<I", out, opt + 16, oep_rva)
    struct.pack_into("<Q", out, opt + 24, base)
    struct.pack_into("<I", out, opt + 36, ALIGN)            # FileAlignment
    struct.pack_into("<I", out, opt + 60, au(first_va))     # SizeOfHeaders
    dllchar = struct.unpack_from("<H", out, opt + 70)[0]
    dllchar &= ~0x0040  # DYNAMIC_BASE
    dllchar &= ~0x0020  # HIGH_ENTROPY_VA
    struct.pack_into("<H", out, opt + 70, dllchar)

    # Lay out sections from dump.
    for s in secs:
        binp = DUMP / f"sec{s['i']}.bin"
        data = binp.read_bytes() if binp.exists() else b""
        raw_size = au(max(len(data), s["vs"]))
        struct.pack_into("<I", out, s["hdr"] + 16, raw_size)
        struct.pack_into("<I", out, s["hdr"] + 20, s["va"])
        end = s["va"] + len(data)
        if end > len(out):
            out.extend(b"\x00" * (end - len(out)))
        out[s["va"]:end] = data

    # ---- Build the new import section (.idata2) ----
    new_va = au(len(out))
    # layout: [descriptors][OFT arrays][hint/name blobs][dll names]
    ndesc = len(runs)
    desc_size = (ndesc + 1) * 20
    oft_arrays_size = sum((len(r["names"]) + 1) * 8 for r in runs)

    # name blobs
    name_blob = bytearray()
    name_rva = {}  # func name -> rva offset within blob area (filled later w/ base)
    dllname_off = {}

    blob = bytearray()
    # reserve regions; compute offsets relative to new_va
    off_desc = 0
    off_oft = off_desc + desc_size
    off_names = off_oft + oft_arrays_size

    # build name/hint structs + dll name strings in 'names' area
    names_area = bytearray()

    def add_hintname(fn):
        key = fn
        if key in name_rva:
            return name_rva[key]
        rva = new_va + off_names + len(names_area)
        nb = fn.encode("ascii") + b"\x00"
        if len(nb) % 2:
            nb += b"\x00"
        names_area.extend(struct.pack("<H", 0))  # hint
        names_area.extend(nb)
        name_rva[key] = rva
        return rva

    def add_dllname(dll):
        if dll in dllname_off:
            return dllname_off[dll]
        rva = new_va + off_names + len(names_area)
        nb = dll.encode("ascii") + b"\x00"
        if len(nb) % 2:
            nb += b"\x00"
        names_area.extend(nb)
        dllname_off[dll] = rva
        return rva

    # OFT arrays
    oft_area = bytearray()
    desc_area = bytearray()
    for r in runs:
        oft_rva = new_va + off_oft + len(oft_area)
        for fn in r["names"]:
            hn_rva = add_hintname(fn)
            oft_area.extend(struct.pack("<Q", hn_rva & 0x7FFFFFFF))
        oft_area.extend(struct.pack("<Q", 0))  # null terminator
        dll_rva = add_dllname(r["dll"])
        desc_area.extend(struct.pack("<IIIII", oft_rva, 0, 0, dll_rva, r["ft_rva"]))
    desc_area.extend(struct.pack("<IIIII", 0, 0, 0, 0, 0))  # terminator

    section = bytearray()
    section.extend(desc_area)                       # at off_desc
    assert len(section) == desc_size
    section.extend(oft_area)                         # at off_oft
    assert len(section) == off_names
    section.extend(names_area)                       # at off_names

    sec_raw = au(len(section))
    section.extend(b"\x00" * (sec_raw - len(section)))

    # place section
    if new_va + len(section) > len(out):
        out.extend(b"\x00" * (new_va - len(out)))
        out.extend(section)
    else:
        out[new_va:new_va + len(section)] = section

    # add section header
    new_hdr = sectbl + nsec * 40
    name8 = b".idata2\x00"
    out[new_hdr:new_hdr + 8] = name8
    struct.pack_into("<I", out, new_hdr + 8, sec_raw)       # VirtualSize
    struct.pack_into("<I", out, new_hdr + 12, new_va)       # VirtualAddress
    struct.pack_into("<I", out, new_hdr + 16, sec_raw)      # SizeOfRawData
    struct.pack_into("<I", out, new_hdr + 20, new_va)       # PointerToRawData
    struct.pack_into("<I", out, new_hdr + 36, 0xC0000040)   # RW | initialized data
    struct.pack_into("<H", out, pe + 6, nsec + 1)           # NumberOfSections
    struct.pack_into("<I", out, opt + 56, new_va + sec_raw)  # SizeOfImage

    # data directories: import [1], IAT [12], bound [11]=0
    struct.pack_into("<I", out, opt + 112 + 1 * 8, new_va)       # import dir rva
    struct.pack_into("<I", out, opt + 112 + 1 * 8 + 4, desc_size)
    main = max(iat_regions, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
    struct.pack_into("<I", out, opt + 112 + 12 * 8, main["lo"])
    struct.pack_into("<I", out, opt + 112 + 12 * 8 + 4, main["hi"] - main["lo"])
    struct.pack_into("<I", out, opt + 112 + 11 * 8, 0)
    struct.pack_into("<I", out, opt + 112 + 11 * 8 + 4, 0)

    OUT.write_bytes(out)
    print(f"new .idata2 @ {hex(new_va)} size={hex(sec_raw)}; total file {len(out)} bytes")
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
