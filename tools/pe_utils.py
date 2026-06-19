"""PE helper utilities for de-itzmx tooling."""
from __future__ import annotations

import struct
from pathlib import Path


def rva_to_file_offset(pe_data: bytes, rva: int) -> int | None:
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    num = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size
    for i in range(num):
        off = sec + i * 40
        va = struct.unpack_from("<I", pe_data, off + 12)[0]
        vsize = struct.unpack_from("<I", pe_data, off + 8)[0]
        raw_ptr = struct.unpack_from("<I", pe_data, off + 20)[0]
        raw_size = struct.unpack_from("<I", pe_data, off + 16)[0]
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return raw_ptr + (rva - va)
    return None


def file_offset_to_rva(pe_data: bytes, file_offset: int) -> int | None:
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    num = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
    sec = pe_off + 24 + opt_size
    for i in range(num):
        off = sec + i * 40
        va = struct.unpack_from("<I", pe_data, off + 12)[0]
        raw_ptr = struct.unpack_from("<I", pe_data, off + 20)[0]
        raw_size = struct.unpack_from("<I", pe_data, off + 16)[0]
        if raw_ptr <= file_offset < raw_ptr + raw_size:
            return va + (file_offset - raw_ptr)
    return None


def read_pe_path(path: Path) -> bytes:
    return path.read_bytes()
