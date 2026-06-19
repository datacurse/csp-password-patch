"""Apply version-pinned byte patches to CLIPStudioPaint.exe with backup/verify.

Note: the itzmx v4.2 exe stores anti-resale logic in encrypted sections. Patches in
patches/v420_patch1_868bbc56.json target the *decrypted* image. Use build_deitzmx_exe.py
or the recommended runtime launcher (deitzmx_launcher.py) instead of patching the
encrypted exe directly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATCH_FILE = REPO_ROOT / "tools" / "patches" / "v420_patch1_868bbc56.json"
DEFAULT_INSTALL = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_patch_set(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def apply_patches(
    install_dir: Path,
    patch_file: Path,
    dry_run: bool = False,
) -> None:
    patch_set = load_patch_set(patch_file)
    exe_path = install_dir / "CLIPStudioPaint.exe"
    if not exe_path.exists():
        raise FileNotFoundError(exe_path)

    actual_hash = sha256_file(exe_path)
    expected_hash = patch_set["exe_sha256"].upper()
    if actual_hash != expected_hash:
        raise ValueError(
            f"EXE hash mismatch.\n  expected: {expected_hash}\n  actual:   {actual_hash}"
        )

    patches = patch_set.get("patches", [])
    if not patches:
        raise ValueError("No patches defined in patch file yet.")

    data = bytearray(exe_path.read_bytes())
    for i, patch in enumerate(patches, start=1):
        offset = int(patch["offset"], 0) if isinstance(patch["offset"], str) else patch["offset"]
        original = bytes.fromhex(patch["original"])
        patched = bytes.fromhex(patch["patched"])
        feature = patch.get("feature", "unknown")

        current = bytes(data[offset : offset + len(original)])
        if current != original:
            raise ValueError(
                f"Patch #{i} ({feature}) verification failed at offset 0x{offset:X}.\n"
                f"  expected: {original.hex()}\n"
                f"  found:    {current.hex()}"
            )

        data[offset : offset + len(patched)] = patched
        print(f"Applied patch #{i}: {feature} @ 0x{offset:X}")

    if dry_run:
        print("Dry run complete; no files written.")
        return

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = REPO_ROOT / "backups" / f"pre_patch_{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(exe_path, backup_dir / "CLIPStudioPaint.exe")
    print(f"Backup written to {backup_dir}")

    exe_path.write_bytes(data)
    print(f"Patched {exe_path}")
    print(f"New SHA256: {sha256_file(exe_path)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply de-itzmx patches to CSP")
    parser.add_argument("--install-dir", type=Path, default=DEFAULT_INSTALL)
    parser.add_argument("--patch-file", type=Path, default=DEFAULT_PATCH_FILE)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        apply_patches(args.install_dir, args.patch_file, dry_run=args.dry_run)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
