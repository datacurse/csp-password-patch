"""Spawn CSP with recon_state.js and summarize the daily-auth state it touches."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
SCRIPT = Path(__file__).with_name("recon_state.js").read_text(encoding="utf-8")

events = []


def on_message(msg, data):
    if msg.get("type") == "send":
        events.append(msg["payload"])
    else:
        print("ERR", msg)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    pid = frida.spawn([EXE])
    session = frida.attach(pid)
    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print(f"spawned pid={pid}, collecting {dur}s...")
    time.sleep(dur)
    try:
        frida.kill(pid)
    except Exception:
        pass

    # Summarize
    def dump(kind):
        rows = [e for e in events if e.get("t") == kind]
        return rows

    print("\n=== password_window ===")
    for e in dump("password_window"):
        print(" ", e)
    print("\n=== clock reads ===")
    seen = set()
    for e in dump("clock"):
        k = (e["api"], e["date"])
        if k not in seen:
            seen.add(k); print(" ", e)
    print("\n=== reg_query / reg_getvalue (deduped) ===")
    seen = set()
    for e in events:
        if e.get("t") in ("reg_query", "reg_getvalue"):
            k = (e.get("key"), e.get("sub", ""), e.get("val"))
            if k in seen:
                continue
            seen.add(k)
            print(" ", e.get("key"), "|", e.get("sub", ""), "|", e.get("val"), "=>", str(e.get("data"))[:80])
    print("\n=== reg_set ===")
    for e in dump("reg_set"):
        print(" ", e.get("key"), "|", e.get("val"), "=>", str(e.get("data"))[:80])
    print("\n=== interesting files (deduped) ===")
    seen = set()
    for e in dump("file_open"):
        p = e.get("path")
        if p in seen:
            continue
        seen.add(p); print(" ", p)


if __name__ == "__main__":
    main()
