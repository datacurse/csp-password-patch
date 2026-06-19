"""End-to-end validation: launch with de-itzmx Frida patches and check behavior."""
from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

import frida

DEFAULT_EXE = Path(
    r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
)
SCRIPT = Path(__file__).resolve().parent / "frida_deitzmx.js"
PASSWORD_TITLE = "Application requires password to start"
WARNING_TITLES = ["警告！", "警告"]
WARNING_TEXT_SNIPPETS = ["语言文件", "串改", "篡改", "完全免费", "出处"]

user32 = ctypes.WinDLL("user32")
FindWindowW = user32.FindWindowW
FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
FindWindowW.restype = wintypes.HWND


def password_visible() -> bool:
    return bool(FindWindowW(None, PASSWORD_TITLE))


def warning_visible() -> bool:
    for title in WARNING_TITLES:
        if FindWindowW(None, title):
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--wait", type=float, default=20.0)
    args = parser.parse_args()

    events: list[dict] = []

    def on_message(message, _data) -> None:
        if message["type"] == "send":
            events.append(message["payload"])

    pid = frida.spawn([str(args.exe)], cwd=str(args.exe.parent))
    session = frida.attach(pid)
    script = session.create_script(SCRIPT.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    frida.resume(pid)

    start = time.time()
    warning_seen = False

    while time.time() - start < args.wait:
        if warning_visible():
            warning_seen = True
        time.sleep(0.25)

    # Judge by end-state: a transiently-visible dialog that we auto-submit is fine.
    hooks_ready = any(ev.get("type") == "ready" for ev in events)
    splash_bypassed = any(ev.get("type") == "bypass_splash_sleep" for ev in events)
    submitted = any(ev.get("type") == "auto_submitted_password" for ev in events)
    password_seen = password_visible()

    alive = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.find(str(pid)) != -1

    session.detach()

    result = {
        "pid": pid,
        "hooks_ready": hooks_ready,
        "splash_bypassed": splash_bypassed,
        "password_submitted": submitted,
        "password_dialog_still_open_at_end": password_seen,
        "warning_dialog_seen": warning_seen,
        "process_alive_after_wait": alive,
        "events": events,
    }

    out = Path(__file__).resolve().parents[1] / "tools" / "output" / "validation_result.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2, ensure_ascii=True))

    if not hooks_ready:
        print("FAIL: Frida hooks did not initialize")
        sys.exit(1)
    if warning_seen:
        print("FAIL: itzmx tamper warning dialog appeared")
        sys.exit(1)
    if password_seen:
        print("FAIL: password dialog still open at end of wait")
        sys.exit(1)
    if not submitted:
        print("FAIL: password was never auto-submitted")
        sys.exit(1)
    if not alive:
        print("FAIL: CSP process exited (crash?) during wait")
        sys.exit(1)
    print("PASS: de-itzmx runtime bypass (password auto-submitted, no warning, CSP alive)")
    sys.exit(0)


if __name__ == "__main__":
    main()
