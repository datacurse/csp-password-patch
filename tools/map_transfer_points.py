"""Map how execution enters the encrypted itzmx blob (sec8/sec9).

- Prints AddressOfEntryPoint and which section it lives in.
- Parses the TLS directory: callbacks + which section each lands in.
- Scans the UNENCRYPTED sections (disk == memory) for direct rel32 CALL/JMP
  whose target lands inside sec8/sec9. Those are the on-disk hook sites that
  hand control to itzmx and are patchable without touching encrypted bytes.
"""
from __future__ import annotations

import struct
from pathlib import Path

EXE = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")


def main():
    d = EXE.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    image_base = struct.unpack_from("<Q", d, opt + 24)[0]
    entry = struct.unpack_from("<I", d, opt + 16)[0]
    dd = opt + 112
    tls_rva = struct.unpack_from("<I", d, dd + 9 * 8)[0]

    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sectbl + i * 40
        nm = d[o : o + 8].split(b"\x00")[0].decode("ascii", "replace") or f"sec{i}"
        va = struct.unpack_from("<I", d, o + 12)[0]
        vs = struct.unpack_from("<I", d, o + 8)[0]
        raw = struct.unpack_from("<I", d, o + 20)[0]
        rs = struct.unpack_from("<I", d, o + 16)[0]
        chars = struct.unpack_from("<I", d, o + 36)[0]
        secs.append({"i": i, "nm": nm, "va": va, "vs": vs, "raw": raw, "rs": rs, "ch": chars})

    def sec_of(rva):
        for s in secs:
            if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
                return s
        return None

    def r2o(rva):
        s = sec_of(rva)
        if not s or not s["rs"]:
            return None
        if rva - s["va"] >= s["rs"]:
            return None
        return s["raw"] + (rva - s["va"])

    print(f"image_base={hex(image_base)} entry_rva={hex(entry)} entry_sec={sec_of(entry)['nm'] if sec_of(entry) else '?'} (sec idx {sec_of(entry)['i'] if sec_of(entry) else '?'})")
    print(f"tls_dir_rva={hex(tls_rva)} tls_sec={sec_of(tls_rva)['nm'] if sec_of(tls_rva) else '?'}")

    # itzmx blob = the two encrypted sections (by index 8,9 / high entropy). Identify by ratio file if needed; here use indices >=8.
    blob = [s for s in secs if s["i"] in (8, 9)]
    blob_ranges = [(s["va"], s["va"] + max(s["vs"], s["rs"])) for s in blob]
    print("itzmx blob ranges:", [(hex(a), hex(b)) for a, b in blob_ranges])

    def in_blob(rva):
        return any(a <= rva < b for a, b in blob_ranges)

    # Parse TLS callbacks (PE32+: AddressOfCallBacks at offset 24 in TLS dir, VA)
    if tls_rva:
        to = r2o(tls_rva)
        if to is not None:
            cb_va = struct.unpack_from("<Q", d, to + 24)[0]
            print(f"AddressOfCallBacks (VA)={hex(cb_va)} rva={hex(cb_va - image_base)}")
            cbo = r2o(cb_va - image_base)
            if cbo is not None:
                idx = 0
                while True:
                    fn = struct.unpack_from("<Q", d, cbo + idx * 8)[0]
                    if fn == 0:
                        break
                    frva = fn - image_base
                    s = sec_of(frva)
                    print(f"  TLS callback[{idx}] = {hex(fn)} rva={hex(frva)} sec={s['nm'] if s else '?'} in_blob={in_blob(frva)}")
                    idx += 1
                if idx == 0:
                    print("  (no callbacks listed)")

    # Scan unencrypted, executable sections for rel32 CALL (E8) / JMP (E9) into blob.
    print("\nScanning unencrypted exec sections for control transfers into itzmx blob...")
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    hits = []
    for s in secs:
        if s["i"] in (8, 9):
            continue
        if not (s["ch"] & IMAGE_SCN_MEM_EXECUTE):
            continue
        if not s["rs"]:
            continue
        data = d[s["raw"] : s["raw"] + s["rs"]]
        base_rva = s["va"]
        for off in range(0, len(data) - 5):
            op = data[off]
            if op in (0xE8, 0xE9):
                disp = struct.unpack_from("<i", data, off + 1)[0]
                src_rva = base_rva + off
                tgt_rva = src_rva + 5 + disp
                if in_blob(tgt_rva):
                    hits.append((src_rva, tgt_rva, s["nm"], "call" if op == 0xE8 else "jmp"))
        print(f"  scanned {s['nm']} ({len(data)} bytes)")
    print(f"\nTransfers into blob: {len(hits)}")
    for src, tgt, sn, kind in hits[:60]:
        print(f"  {kind} {hex(src)} ({sn}) -> {hex(tgt)}")
    if len(hits) > 60:
        print(f"  ... +{len(hits) - 60} more")


if __name__ == "__main__":
    main()
