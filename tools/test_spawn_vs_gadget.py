"""Decisive test: does frida loaded via spawn (later) survive where gadget (early) dies?

Spawns the (unmodified) temp-copy exe with frida and a minimal marker script, then
checks if the process keeps running. If spawn survives but the import-gadget exits 1,
the trigger is early/loader-lock presence of frida, not detection per se.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import frida

TEST_DIR = Path(os.environ["TEMP"]) / "csp_baked_test"
EXE = TEST_DIR / "CLIPStudioPaint.exe"  # whatever is currently there

SCRIPT = """
try {
  var f = new File('%s', 'w');
  f.write('spawn frida ran ' + Date.now());
  f.flush(); f.close();
} catch (e) { }
""" % str(TEST_DIR / "spawn_ran.txt").replace("\\", "\\\\")


def main():
    marker = TEST_DIR / "spawn_ran.txt"
    if marker.exists():
        marker.unlink()
    print("spawning", EXE)
    pid = frida.spawn([str(EXE)], cwd=str(TEST_DIR))
    session = frida.attach(pid)
    script = session.create_script(SCRIPT)
    script.load()
    frida.resume(pid)

    alive = False
    for i in range(8):
        time.sleep(1)
        try:
            frida.attach(pid)  # raises if dead
            alive = True
        except Exception:
            alive = False
            print(f"t={i} process DEAD")
            break
        print(f"t={i} alive")
    print("marker written:", marker.exists())
    print("RESULT: spawn-frida survived =", alive)
    try:
        frida.kill(pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
