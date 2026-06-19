"""De-itzmx launcher: start CLIP Studio Paint and auto-handle the itzmx anti-resale layer.

This spawns CSP, injects Frida hooks that:
  - paste + submit the start password via the dialog (clipboard paste = author-safe path)
  - skip the ~3.4s anti-resale splash Sleep
  - auto-dismiss Chinese tamper / marketing dialogs
  - block the random anti-resale document popup (ShellExecuteW)

Once the password is submitted (or a timeout elapses) it detaches and leaves CSP
running, returning your console.

Recommended: run this instead of launching CLIPStudioPaint.exe directly.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import frida

DEFAULT_EXE = Path(
    r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
)
SCRIPT = Path(__file__).resolve().parent / "frida_deitzmx.js"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Launch CLIP Studio Paint without itzmx anti-resale annoyances"
    )
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument(
        "--max-startup",
        type=float,
        default=60.0,
        help="Max seconds to wait for the password handoff before detaching",
    )
    parser.add_argument(
        "--grace",
        type=float,
        default=3.0,
        help="Seconds to keep hooks active after the password is submitted",
    )
    parser.add_argument(
        "--stay",
        action="store_true",
        help="Keep hooks attached for the whole session instead of detaching",
    )
    args = parser.parse_args()

    if not args.exe.exists():
        print(f"Error: CSP exe not found: {args.exe}")
        sys.exit(1)

    state = {"submitted": False}

    def on_message(message, _data) -> None:
        if message["type"] == "send":
            payload = message["payload"]
            print(f"[de-itzmx] {json.dumps(payload, ensure_ascii=True)}")
            if payload.get("type") == "auto_submitted_password":
                state["submitted"] = True
        elif message["type"] == "error":
            print(f"[de-itzmx-error] {message.get('description', message)}")

    print("Starting CLIP Studio Paint with de-itzmx runtime hooks...")
    pid = frida.spawn([str(args.exe)], cwd=str(args.exe.parent))
    session = frida.attach(pid)
    script = session.create_script(SCRIPT.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print(f"CSP launched (pid {pid}).")

    if args.stay:
        print("Holding hooks for the whole session. Press Ctrl+C to detach.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        session.detach()
        return

    deadline = time.time() + args.max_startup
    while time.time() < deadline and not state["submitted"]:
        time.sleep(0.25)

    if state["submitted"]:
        print("Password handled. Keeping hooks briefly, then detaching...")
        time.sleep(args.grace)
    else:
        print("No password dialog handled within timeout (already authenticated today?).")

    session.detach()
    print("Detached. CLIP Studio Paint continues running.")


if __name__ == "__main__":
    main()
