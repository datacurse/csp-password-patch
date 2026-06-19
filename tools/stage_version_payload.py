"""Stage bundled proxy payload for a CSP version (run before PyInstaller build)."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROXY_OUT = REPO / "tools" / "output" / "proxy"
BUILD_PROXY = REPO / "tools" / "build_proxy.py"


def stage(version: str, rebuild: bool) -> Path:
    dest = REPO / "versions" / version / "proxy"
    # Always rebuild: the hook's password is per-version, so each version must
    # regenerate deitzmx_hook.js with --csp-version. (`rebuild` kept for compat.)
    subprocess.run(
        [
            sys.executable,
            str(BUILD_PROXY),
            "--target",
            "SHFolder",
            "--source-dir",
            r"C:\Windows\System32",
            "--csp-version",
            version,
        ],
        check=True,
        cwd=str(REPO),
    )

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    for name in PROXY_OUT.iterdir():
        if name.is_file() and not name.name.endswith("_test.js"):
            shutil.copy2(name, dest / name.name)

    required = ("deitzmx.dll", "deitzmx.config", "deitzmx_hook.js", "SHFolder.dll")
    missing = [n for n in required if not (dest / n).is_file()]
    if missing:
        raise SystemExit(f"staging incomplete, missing: {', '.join(missing)}")
    print(f"Staged {dest} ({len(list(dest.iterdir()))} files)")
    return dest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="4.2.0")
    ap.add_argument("--rebuild", action="store_true", help="Run build_proxy.py first")
    args = ap.parse_args()
    stage(args.version, args.rebuild)


if __name__ == "__main__":
    main()
