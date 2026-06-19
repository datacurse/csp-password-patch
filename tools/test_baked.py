"""Test the import-injected (baked) CSP exe in a throwaway copy of the install dir.

Copies the install dir to %TEMP%\csp_baked_test, drops in the baked exe + gadget +
config + hook, launches it WITHOUT any external launcher, then watches top-level
windows to confirm the password dialog is auto-dismissed and the main app appears.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BAKED = REPO / "tools" / "output" / "baked"
INSTALL = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")
TEST_DIR = Path(os.environ["TEMP"]) / "csp_baked_test"

user32 = ctypes.WinDLL("user32", use_last_error=True)
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
IsWindowVisible = user32.IsWindowVisible
GetClassNameW = user32.GetClassNameW
GetWindowThreadProcessId = user32.GetWindowThreadProcessId


def list_windows(pid: int):
    out = []

    def cb(hwnd, _):
        wpid = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value != pid:
            return True
        n = GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        GetWindowTextW(hwnd, buf, n + 1)
        cls = ctypes.create_unicode_buffer(256)
        GetClassNameW(hwnd, cls, 256)
        out.append((bool(IsWindowVisible(hwnd)), cls.value, buf.value))
        return True

    EnumWindows(EnumWindowsProc(cb), 0)
    return out


def robocopy(src: Path, dst: Path):
    dst.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["robocopy", str(src), str(dst), "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:1", "/W:1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main():
    print("Copying install dir to test sandbox (this can take a bit)...")
    robocopy(INSTALL, TEST_DIR)

    # Drop the baked artifacts.
    shutil.copy2(BAKED / "CLIPStudioPaint.exe", TEST_DIR / "CLIPStudioPaint.exe")
    shutil.copy2(BAKED / "deitzmx.dll", TEST_DIR / "deitzmx.dll")
    shutil.copy2(REPO / "tools" / "frida_deitzmx.js", TEST_DIR / "deitzmx_hook.js")
    hook = TEST_DIR / "deitzmx_hook.js"
    (TEST_DIR / "deitzmx.config").write_text(
        '{\n  "interaction": {\n    "type": "script",\n'
        f'    "path": "{str(hook).replace(chr(92), chr(92)*2)}",\n'
        '    "on_change": "reload"\n  }\n}\n',
        encoding="utf-8",
    )

    exe = TEST_DIR / "CLIPStudioPaint.exe"
    print("Launching baked exe (no external launcher):", exe)
    proc = subprocess.Popen([str(exe)], cwd=str(TEST_DIR))

    pw_seen = False
    pw_cleared = False
    main_seen = False
    warning_seen = False
    deadline = time.time() + 45
    while time.time() < deadline:
        if proc.poll() is not None:
            print(f"[!] process exited early code={proc.returncode}")
            break
        wins = list_windows(proc.pid)
        titles = [t for _, _, t in wins if t]
        for vis, cls, title in wins:
            if "Application requires password" in title:
                pw_seen = True
            if "警告" in title or "tamper" in title.lower() or "语言" in title:
                warning_seen = True
            if title.startswith("CLIP STUDIO PAINT") or cls.startswith("Qt"):
                main_seen = True
        if pw_seen and not any("Application requires password" in t for t in titles):
            pw_cleared = True
        print(f"t={int(time.time()):d} pw_seen={pw_seen} pw_cleared={pw_cleared} main={main_seen} warn={warning_seen} titles={titles[:6]}")
        time.sleep(2)

    print("\n=== RESULT ===")
    print("password dialog appeared :", pw_seen)
    print("password auto-cleared    :", pw_cleared)
    print("main window appeared     :", main_seen)
    print("tamper/warning popup     :", warning_seen)

    try:
        proc.terminate()
    except Exception:
        pass


if __name__ == "__main__":
    main()
