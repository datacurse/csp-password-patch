"""Validate de-itzmx patched CSP launch behavior."""
from __future__ import annotations

import argparse
import ctypes
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

user32 = ctypes.WinDLL("user32", use_last_error=True)
FindWindowW = user32.FindWindowW
FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
FindWindowW.restype = wintypes.HWND

PASSWORD_TITLE = "Application requires password to start"


def password_window_exists() -> bool:
    hwnd = FindWindowW(None, PASSWORD_TITLE)
    return bool(hwnd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate CSP launch without password dialog")
    parser.add_argument(
        "--exe",
        type=Path,
        default=Path(
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
        ),
    )
    parser.add_argument("--wait", type=float, default=12.0)
    args = parser.parse_args()

    if not args.exe.exists():
        print(f"Missing exe: {args.exe}")
        sys.exit(1)

    print(f"Launching {args.exe}")
    proc = subprocess.Popen([str(args.exe)], cwd=str(args.exe.parent))
    print(f"pid={proc.pid}, monitoring {args.wait}s for password dialog...")

    deadline = time.time() + args.wait
    seen = False
    while time.time() < deadline:
        if password_window_exists():
            seen = True
            break
        if proc.poll() is not None:
            print(f"Process exited early with code {proc.returncode}")
            sys.exit(2)
        time.sleep(0.5)

    if seen:
        print(f"FAIL: Password dialog '{PASSWORD_TITLE}' appeared")
        sys.exit(1)

    print("PASS: No password dialog detected during monitoring window")
    print("Leaving process running; close manually.")
    sys.exit(0)


if __name__ == "__main__":
    main()
