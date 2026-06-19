"""Find OEP and dump the decrypted image at OEP.

The protector unpacks, then calls VirtualProtect(sec0 -> EXECUTE_READ) and jumps
to the original entry. We hook VirtualProtect and, right after it restores sec0 to
executable, re-strip execute. The protector's jmp OEP then faults (DEP); in the
exception handler we record OEP and dump every section straight from the now-fully-
decrypted memory image, then signal Python to kill.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
DUMPDIR = Path(__file__).resolve().parents[1] / "tools" / "output" / "dump"


def parse(path):
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
        secs.append({
            "i": i,
            "va": struct.unpack_from("<I", d, o + 12)[0],
            "vs": struct.unpack_from("<I", d, o + 8)[0],
            "ch": struct.unpack_from("<I", d, o + 36)[0],
        })
    return entry, secs


JS = """
'use strict';
var BASE = Process.enumerateModules()[0].base;
var GUARD = %s;          // [[rva,size],...] original exec sections
var SEC0 = %s;           // [rva,size] of sec0
var ALLSECS = %s;        // [[idx,rva,vsize],...] for dumping
var DUMPDIR = %s;        // string path with double backslashes
var dumped = false;

function inGuard(addr) {
  var o = parseInt(addr.sub(BASE).toString(), 16);
  for (var i = 0; i < GUARD.length; i++)
    if (o >= GUARD[i][0] && o < GUARD[i][0] + GUARD[i][1]) return true;
  return false;
}

function stripSec0() {
  try { Memory.protect(BASE.add(SEC0[0]), SEC0[1], 'rw-'); } catch (e) {}
}

function dumpAll(oepRva) {
  if (dumped) return;
  dumped = true;
  for (var i = 0; i < ALLSECS.length; i++) {
    var idx = ALLSECS[i][0], rva = ALLSECS[i][1], vs = ALLSECS[i][2];
    if (vs === 0) continue;
    var path = DUMPDIR + '\\\\sec' + idx + '.bin';
    try {
      var f = new File(path, 'wb');
      var done = 0;
      var CH = 0x400000;
      while (done < vs) {
        var n = Math.min(CH, vs - done);
        var buf = BASE.add(rva + done).readByteArray(n);
        if (buf === null) { break; }
        f.write(buf);
        done += n;
      }
      f.close();
      send({ t: 'dumped_sec', idx: idx, bytes: done });
    } catch (e) {
      send({ t: 'dump_err', idx: idx, e: String(e) });
    }
  }
  send({ t: 'oep', rva: oepRva });
}

Process.setExceptionHandler(function (d) {
  if (d.type === 'access-violation' && d.memory && d.memory.operation === 'execute') {
    var a = d.memory.address;
    if (inGuard(a)) {
      var rva = a.sub(BASE).toString();
      var b = '';
      try { b = a.readByteArray(16); } catch (e) {}
      send({ t: 'fault', rva: rva }, b);
      dumpAll(rva);
      // re-arm this page so it can continue (we'll be killed shortly).
      try { Memory.protect(a.and(ptr('0xfffffffffffff000')), 0x1000, 'rwx'); } catch (e) {}
      return true;
    }
  }
  return false;
});

// Re-strip sec0 right after the protector restores it to executable.
try {
  var vp = Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect');
  Interceptor.attach(vp, {
    onEnter: function (a) {
      this.addr = a[0]; this.newp = a[2].toInt32();
    },
    onLeave: function () {
      // sec0 made executable (0x10/0x20/0x40)? re-strip so OEP jmp faults.
      var o = parseInt(this.addr.sub(BASE).toString(), 16);
      if (o === SEC0[0] && (this.newp === 0x10 || this.newp === 0x20 || this.newp === 0x40)) {
        send({ t: 'restripping' });
        stripSec0();
      }
    },
  });
} catch (e) { send({ t: 'vp_err', e: String(e) }); }

for (var i = 0; i < GUARD.length; i++) {
  try { Memory.protect(BASE.add(GUARD[i][0]), GUARD[i][1], 'rw-'); } catch (e) {}
}
send({ t: 'armed', base: BASE.toString() });
"""


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    DUMPDIR.mkdir(parents=True, exist_ok=True)
    for f in DUMPDIR.glob("sec*.bin"):
        f.unlink()
    entry, secs = parse(EXE)
    guard = [[s["va"], s["vs"]] for s in secs if s["i"] in (0, 1, 2, 6) and (s["ch"] & 0x20000000)]
    sec0 = next([s["va"], s["vs"]] for s in secs if s["i"] == 0)
    allsecs = [[s["i"], s["va"], s["vs"]] for s in secs]

    js = JS % (
        repr(guard),
        repr(sec0),
        repr(allsecs),
        repr(str(DUMPDIR).replace("\\", "\\\\")),
    )

    state = {"oep": None, "detached": None, "base": None}

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "fault":
                print("FAULT (OEP candidate) rva=", p["rva"], "bytes=", data.hex() if data else "")
            elif t == "oep":
                state["oep"] = p["rva"]
                print("*** OEP =", p["rva"])
            elif t == "dumped_sec":
                print(f"  dumped sec{p['idx']} ({p['bytes']} bytes)")
            elif t == "armed":
                state["base"] = p.get("base")
                print("armed; base=", p.get("base"))
            elif t in ("restripping", "dump_err", "vp_err"):
                print(p)
        else:
            print("ERR", msg)

    def on_detached(reason, *a):
        state["detached"] = reason
        print("!! detached:", reason)

    pid = frida.spawn([EXE])
    session = frida.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print("resumed...")
    for _ in range(dur):
        time.sleep(1)
        if state["oep"] or state["detached"]:
            time.sleep(2)
            break
    try:
        frida.kill(pid)
    except Exception:
        pass
    print("\nOEP:", state["oep"], "BASE:", state["base"])
    print("Dump dir:", DUMPDIR)
    for f in sorted(DUMPDIR.glob("sec*.bin")):
        print("  ", f.name, f.stat().st_size)
    meta = DUMPDIR / "dump_meta.json"
    import json
    meta.write_text(json.dumps({"oep_rva": state["oep"], "base": state["base"], "entry_rva": hex(entry)}), encoding="utf-8")
    print("wrote", meta)


if __name__ == "__main__":
    main()
