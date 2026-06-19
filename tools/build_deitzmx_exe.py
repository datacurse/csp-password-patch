"""Build de-itzmx patched CLIPStudioPaint.exe from live decrypted sections + patch set."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATCH = REPO_ROOT / "tools" / "patches" / "v420_patch1_868bbc56.json"
DEFAULT_EXE = Path(
    r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
)
DEFAULT_INSTALL = DEFAULT_EXE.parent
OUTPUT_EXE = REPO_ROOT / "tools" / "output" / "CLIPStudioPaint.deitzmx_patched.exe"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def apply_patch_bytes(data: bytearray, patch: dict) -> None:
    offset = int(patch["offset"], 16)
    original = bytes.fromhex(patch["original"])
    patched = bytes.fromhex(patch["patched"])
    current = bytes(data[offset : offset + len(original)])
    if current != original:
        raise ValueError(
            f"Patch {patch['feature']} mismatch at {patch['offset']}:\n"
            f"  expected {original.hex()}\n"
            f"  found    {current.hex()}"
        )
    data[offset : offset + len(patched)] = patched


def build(
    source_exe: Path,
    patch_file: Path,
    output_exe: Path,
    launch_for_dump: bool = True,
) -> Path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from dump_decrypted_sections import dump_sections  # noqa: WPS433

    pid = None
    proc = None
    if launch_for_dump:
        proc = subprocess.Popen([str(source_exe)], cwd=str(source_exe.parent))
        pid = proc.pid
        time.sleep(8)

    if pid is None:
        raise RuntimeError("Could not obtain process pid for section dump")

    patched_data, sections = dump_sections(pid, source_exe)
    patch_set = json.loads(patch_file.read_text(encoding="utf-8"))

    for patch in patch_set["patches"]:
        apply_patch_bytes(patched_data, patch)

    output_exe.parent.mkdir(parents=True, exist_ok=True)
    output_exe.write_bytes(patched_data)

    meta = {
        "source_exe": str(source_exe),
        "patch_file": str(patch_file),
        "output_exe": str(output_exe),
        "sha256": sha256_file(output_exe),
        "decrypted_sections": sections,
        "patches_applied": patch_set["patches"],
    }
    meta_path = output_exe.with_suffix(".json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if proc is not None:
        print(f"Dump source pid {pid} still running; terminate manually if needed.")

    print(f"Built {output_exe}")
    print(f"SHA256: {meta['sha256']}")
    print(f"Metadata: {meta_path}")
    return output_exe


def install(output_exe: Path, install_dir: Path) -> None:
    dst = install_dir / "CLIPStudioPaint.exe"
    backup = install_dir / "CLIPStudioPaint.exe.itzmx_backup"
    if not backup.exists():
        shutil.copy2(dst, backup)
        print(f"Backup: {backup}")
    shutil.copy2(output_exe, dst)
    print(f"Installed patched exe to {dst}")
    print(f"SHA256: {sha256_file(dst)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and optionally install de-itzmx patched CSP")
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--patch-file", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--output", type=Path, default=OUTPUT_EXE)
    parser.add_argument("--install-dir", type=Path, default=DEFAULT_INSTALL)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--no-launch", action="store_true")
    args = parser.parse_args()

    try:
        out = build(
            args.exe,
            args.patch_file,
            args.output,
            launch_for_dump=not args.no_launch,
        )
        if args.install:
            install(out, args.install_dir)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
