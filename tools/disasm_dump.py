import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DUMP = Path(__file__).resolve().parents[1] / "tools/output/dump"
SECS = [(0x1000, 0x40ca000, 0), (0x40cb000, 0xcfb000, 1), (0x4dc6000, 0x4b9000, 2),
        (0x527f000, 0x20a000, 3), (0x5489000, 0x3000, 4), (0x548c000, 0x377000, 5),
        (0x5803000, 0x6c000, 6), (0x586f000, 0x377000, 7), (0x5be6000, 0x589000, 8), (0x616f000, 0x3bf000, 9)]
blobs = {i: (DUMP / f"sec{i}.bin").read_bytes() for _, _, i in SECS}


def read(rva, n):
    for va, vs, i in SECS:
        if va <= rva < va + vs:
            o = rva - va
            return blobs[i][o:o + n]
    return b""


def disasm(rva, n=30, length=None):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    data = read(rva, length or (n * 8))
    cnt = 0
    for ins in md.disasm(data, rva):
        print(f"  {hex(ins.address)}: {ins.mnemonic} {ins.op_str}")
        cnt += 1
        if cnt >= n:
            break


if __name__ == "__main__":
    rva = int(sys.argv[1], 16)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    print(f"--- disasm from {hex(rva)} ---")
    disasm(rva, n)
