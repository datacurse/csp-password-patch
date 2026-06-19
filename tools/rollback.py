"""Restore CLIPStudioPaint.exe from baseline backup."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_BACKUP = REPO_ROOT / "backups" / "v420_patch1_868bbc56"
DEFAULT_INSTALL = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def rollback(install_dir: Path, backup_dir: Path) -> None:
    src = backup_dir / "CLIPStudioPaint.exe"
    dst = install_dir / "CLIPStudioPaint.exe"
    if not src.exists():
        raise FileNotFoundError(f"Backup exe not found: {src}")
    if not install_dir.exists():
        raise FileNotFoundError(f"Install dir not found: {install_dir}")

    shutil.copy2(src, dst)
    print(f"Restored {dst}")
    print(f"SHA256: {sha256_file(dst)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rollback CSP exe to baseline backup")
    parser.add_argument("--install-dir", type=Path, default=DEFAULT_INSTALL)
    parser.add_argument("--backup-dir", type=Path, default=BASELINE_BACKUP)
    args = parser.parse_args()

    try:
        rollback(args.install_dir, args.backup_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
