import struct
from pathlib import Path

DUMP = Path(__file__).resolve().parents[1] / "tools/output/dump"
sec8 = (DUMP / "sec8.bin").read_bytes()
sec8_va = 0x5be6000
base = 0x7ff7e1ae0000

# trampoline entry RVAs seen as IAT self-pointers
offs = [0x6052a3b, 0x6052a40, 0x6052a45, 0x6052a4a, 0x6052a4f, 0x6052a54, 0x6052a59, 0x6052a5e,
        0x6052a63, 0x6052a68, 0x6052a6d, 0x6052a72, 0x6052a77, 0x6052a7c, 0x6052a81, 0x6052a86,
        0x6052a8b, 0x6052a90, 0x6052a9f, 0x6052aa4, 0x6052ab3, 0x6052ab8]

print("raw region 0x6052a30..0x6052ad0:")
start = 0x6052a30
chunk = sec8[start - sec8_va: start - sec8_va + 0xB0]
print(chunk.hex())

print("\nper-stub decode:")
for rva in offs:
    o = rva - sec8_va
    b = sec8[o:o + 6]
    s = f"  {hex(rva)}: {b.hex()}"
    if b and b[0] == 0xE9:
        disp = struct.unpack_from("<i", b, 1)[0]
        tgt = rva + 5 + disp
        s += f"  jmp -> {hex(tgt)} (rva)"
    elif b and b[0] == 0xFF and b[1] == 0x25:
        disp = struct.unpack_from("<i", b, 2)[0]
        s += f"  jmp [rip+{hex(disp)}] -> slot {hex(rva + 6 + disp)}"
    print(s)
