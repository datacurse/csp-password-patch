"""Verify installed CSP matches expected v4.2.0 Patch1 fingerprint."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "backups" / "v420_patch1_868bbc56" / "manifest.json"

DEFAULT_INSTALL_DIR = Path(
    r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found: {MANIFEST_PATH}")
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def find_key_files(install_dir: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    exe = install_dir / "CLIPStudioPaint.exe"
    if exe.exists():
        found["CLIPStudioPaint.exe"] = exe

    for path in install_dir.glob("*.txt"):
        name = path.name
        if "Anti-Resale" in name or "itzmx" in name or "防倒卖" in name:
            found[name] = path
    return found


def verify(install_dir: Path | None = None) -> bool:
    install_dir = install_dir or DEFAULT_INSTALL_DIR
    manifest = load_manifest()
    expected = manifest["files"]
    found = find_key_files(install_dir)

    ok = True
    print(f"Install dir: {install_dir}")
    print(f"Expected version: {manifest['version']}")
    print()

    for expected_name, meta in expected.items():
        match_path = None
        if expected_name in found:
            match_path = found[expected_name]
        elif expected_name == "CLIPStudioPaint.exe" and "CLIPStudioPaint.exe" in found:
            match_path = found["CLIPStudioPaint.exe"]
        else:
            for actual_name, path in found.items():
                if expected_name.endswith(".txt") and actual_name.endswith(".txt"):
                    if sha256_file(path) == meta["sha256"]:
                        match_path = path
                        break

        if match_path is None:
            print(f"MISSING: {expected_name}")
            ok = False
            continue

        digest = sha256_file(match_path)
        size = match_path.stat().st_size
        if digest == meta["sha256"] and size == meta["size"]:
            safe_name = match_path.name.encode("ascii", "backslashreplace").decode("ascii")
            print(f"OK  {safe_name}")
            print(f"    SHA256 {digest}")
        else:
            print(f"FAIL {match_path.name}")
            print(f"    expected SHA256 {meta['sha256']}")
            print(f"    actual   SHA256 {digest}")
            print(f"    expected size {meta['size']}, actual {size}")
            ok = False

    return ok


def main() -> None:
    install_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INSTALL_DIR
    if verify(install_dir):
        print("\nVerification passed.")
        sys.exit(0)
    print("\nVerification failed.")
    sys.exit(1)


if __name__ == "__main__":
    main()
