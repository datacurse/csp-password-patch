"""Launch CSP with Frida de-itzmx hooks (spawn + attach)."""
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
DEFAULT_SCRIPT = Path(__file__).resolve().parent / "frida_deitzmx.js"
OUTPUT_LOG = Path(__file__).resolve().parents[1] / "tools" / "output" / "frida_events.jsonl"


def on_message(message, _data, log_file) -> None:
    if message["type"] == "send":
        payload = message["payload"]
        line = json.dumps(payload, ensure_ascii=True)
        print(f"[frida] {line}")
        log_file.write(line + "\n")
        log_file.flush()
    elif message["type"] == "error":
        err = message.get("description", str(message))
        print(f"[frida-error] {err}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch CSP with de-itzmx runtime hooks")
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--script", type=Path, default=DEFAULT_SCRIPT)
    parser.add_argument("--attach", type=int, help="Attach to existing pid")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()

    source = args.script.read_text(encoding="utf-8")
    OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)

    if args.attach:
        session = frida.attach(args.attach)
        print(f"Attached to pid {args.attach}")
        pid = args.attach
    else:
        pid = frida.spawn([str(args.exe)], cwd=str(args.exe.parent))
        session = frida.attach(pid)
        print(f"Spawned pid {pid}")

    with OUTPUT_LOG.open("a", encoding="utf-8") as log_file:
        script = session.create_script(source)
        script.on("message", lambda m, d: on_message(m, d, log_file))
        script.load()

        if not args.attach:
            frida.resume(pid)
            print(f"Resumed pid {pid}")

        print(f"Hooks active for {args.timeout}s (log: {OUTPUT_LOG})...")
        try:
            time.sleep(args.timeout)
        except KeyboardInterrupt:
            pass

    session.detach()
    print("Detached.")


if __name__ == "__main__":
    main()
