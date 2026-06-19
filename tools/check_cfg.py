import struct
from pathlib import Path

for label, p in [("ORIG", Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe")),
                 ("REBUILT", Path(__file__).resolve().parents[1] / "tools/output/CLIPStudioPaint.unpacked.exe")]:
    d = p.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    dllchar = struct.unpack_from("<H", d, opt + 70)[0]
    lc_rva, lc_size = struct.unpack_from("<II", d, opt + 112 + 10 * 8)
    print(f"\n[{label}] DllCharacteristics={hex(dllchar)} GUARD_CF={'YES' if dllchar & 0x4000 else 'no'} "
          f"NX={'Y' if dllchar&0x100 else 'n'} DYNBASE={'Y' if dllchar&0x40 else 'n'}")
    print(f"  LoadConfig dir rva={hex(lc_rva)} size={hex(lc_size)}")
