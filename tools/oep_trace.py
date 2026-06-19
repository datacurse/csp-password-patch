"""OEP finder for the itzmx-protected CSP.

Strategy: spawn suspended via Frida (itzmx tolerates post-loader injection).
Before resume, strip EXECUTE from the original (unencrypted, ratio==1.0) code
sections while leaving the protector stub (sec8/sec9) executable. When the stub
finishes decrypting and jumps into the original code, a DEP execute-fault fires;
we log the address + first bytes, re-arm just that page, and continue. The first
few transitions reveal TLS callbacks and the real OEP (CRT startup).
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"


def parse_sections(path: str):
    d = Path(path).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    entry = struct.unpack_from("<I", d, opt + 16)[0]
    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sectbl + i * 40
        va = struct.unpack_from("<I", d, o + 12)[0]
        vs = struct.unpack_from("<I", d, o + 8)[0]
        ch = struct.unpack_from("<I", d, o + 36)[0]
        secs.append({"i": i, "va": va, "vs": vs, "ch": ch})
    return entry, secs


JS_TEMPLATE = """
'use strict';
var BASE = Process.enumerateModules()[0].base;
// guard ranges (rva, size) for original exec sections
var GUARD = %s;
var faults = [];
var MAXLOG = 25;

function inGuard(addr) {
  var off = addr.sub(BASE);
  var o = off.toUInt32 ? off.toUInt32() : parseInt(off.toString(), 16);
  for (var i = 0; i < GUARD.length; i++) {
    if (o >= GUARD[i][0] && o < GUARD[i][0] + GUARD[i][1]) return true;
  }
  return false;
}

Process.setExceptionHandler(function (d) {
  try {
    if (d.type === 'access-violation' && d.memory && d.memory.operation === 'execute') {
      var a = d.memory.address;
      if (inGuard(a)) {
        var rva = a.sub(BASE);
        var bytes = '';
        try { bytes = a.readByteArray(16); } catch (e) {}
        if (faults.length < MAXLOG) {
          send({ t: 'fault', rva: rva.toString(), abs: a.toString() }, bytes);
        }
        // re-arm just this page
        var page = a.and(ptr('0xfffffffffffff000'));
        try { Memory.protect(page, 0x1000, 'rwx'); } catch (e) {}
        faults.push(a.toString());
        return true;
      }
    }
  } catch (e) {
    send({ t: 'handler_err', e: String(e) });
  }
  return false;
});

// Log when the protector changes protections back on our guarded ranges.
try {
  var vp = Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect');
  Interceptor.attach(vp, {
    onEnter: function (a) {
      var addr = a[0];
      var rva = addr.sub(BASE);
      var o = parseInt(rva.toString(), 16);
      if (o >= 0 && o < 0x6172000) {
        send({ t: 'vprotect', rva: rva.toString(), size: a[1].toInt32(), newprot: a[2].toInt32() });
      }
    },
  });
} catch (e) { send({ t: 'vp_err', e: String(e) }); }

// Strip execute from guard ranges now (pre-resume).
for (var i = 0; i < GUARD.length; i++) {
  try {
    Memory.protect(BASE.add(GUARD[i][0]), GUARD[i][1], 'rw-');
    send({ t: 'guard_set', rva: GUARD[i][0], size: GUARD[i][1] });
  } catch (e) {
    send({ t: 'guard_err', rva: GUARD[i][0], e: String(e) });
  }
}
send({ t: 'armed' });
"""


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    entry, secs = parse_sections(EXE)
    # original exec sections = indices 0,1,2,6 (ratio 1.0, executable). Exclude 8,9 (stub).
    guard = []
    for s in secs:
        if s["i"] in (0, 1, 2, 6) and (s["ch"] & 0x20000000):
            guard.append([s["va"], s["vs"]])
    print("entry_rva=", hex(entry))
    print("guard ranges:", [(hex(a), hex(b)) for a, b in guard])

    js = JS_TEMPLATE % repr(guard)
    faults = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "fault":
                b = data.hex() if data else ""
                faults.append((p["rva"], p["abs"], b))
                print(f"FAULT rva={p['rva']} abs={p['abs']} bytes={b}")
            elif p.get("t") == "vprotect":
                print(f"VPROTECT rva={p['rva']} size={p['size']} newprot={hex(p['newprot'])}")
            elif p.get("t") in ("armed", "guard_err", "handler_err", "vp_err"):
                print(p)
        else:
            print("ERR", msg)

    detached = {"reason": None}

    def on_detached(reason, *a):
        detached["reason"] = reason
        print("!! DETACHED:", reason)

    pid = frida.spawn([EXE])
    session = frida.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print("resumed; collecting faults...")
    for _ in range(dur):
        time.sleep(1)
        if detached["reason"]:
            break
    try:
        frida.kill(pid)
    except Exception:
        pass

    print("\n=== FIRST TRANSITIONS INTO ORIGINAL CODE ===")
    for rva, ab, b in faults[:25]:
        print(f"  rva={rva} bytes={b}")


if __name__ == "__main__":
    main()
