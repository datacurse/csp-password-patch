"""Full IAT reconstruction for the protector-resolved CSP imports.

1. Scan unpacked code (sec0/1/2) for FF15/FF25 indirect call/jmp targets -> the
   set of real IAT slot RVAs the protector fills at runtime.
2. Cluster them into contiguous IAT regions.
3. At OEP, read every 8-byte slot in those regions and resolve the pointer back to
   its owning module export (name or ordinal). Null slots are kept as separators.
4. Write iat_full.json for the rebuilder.
"""
from __future__ import annotations

import json
import struct
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
DUMP = Path(__file__).resolve().parents[1] / "tools" / "output" / "dump"
OUT = DUMP / "iat_full.json"


def parse(path):
    d = Path(path).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sectbl + i * 40
        secs.append({"i": i, "va": struct.unpack_from("<I", d, o + 12)[0],
                     "vs": struct.unpack_from("<I", d, o + 8)[0],
                     "ch": struct.unpack_from("<I", d, o + 36)[0]})
    return secs


def find_iat_slots(secs):
    targets = set()
    for idx in (0, 1, 2):
        b = (DUMP / f"sec{idx}.bin").read_bytes()
        base = next(s["va"] for s in secs if s["i"] == idx)
        for off in range(len(b) - 6):
            if b[off] == 0xFF and b[off + 1] in (0x15, 0x25):
                disp = struct.unpack_from("<i", b, off + 2)[0]
                tgt = base + off + 6 + disp
                targets.add(tgt)
    return targets


def cluster(targets, gap=0x400):
    s = sorted(targets)
    regions = []
    lo = prev = s[0]
    for r in s[1:]:
        if r - prev > gap:
            regions.append((lo, prev))
            lo = r
        prev = r
    regions.append((lo, prev))
    # keep in-image regions with enough slots (real IAT), expand hi by 8
    IMG = 0x6530000
    big = [(a, b + 8) for a, b in regions if (b - a) >= 0x40 and 0x1000 <= a < IMG and b < IMG]
    return big


JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var GUARD = %s, SEC0 = %s, REGIONS = %s;
var done = false; var cache = {};
function inGuard(a){var o=parseInt(a.sub(BASE).toString(),16);for(var i=0;i<GUARD.length;i++)if(o>=GUARD[i][0]&&o<GUARD[i][0]+GUARD[i][1])return true;return false;}
function resolve(p){
  if(p.isNull()) return null;
  var m = Process.findModuleByAddress(p);
  if(!m) return {dll:null,name:null,addr:p.toString()};
  if(!cache[m.name]){cache[m.name]={};try{m.enumerateExports().forEach(function(e){cache[m.name][e.address.toString()]=e.name;});}catch(e){}}
  return {dll:m.name, name: cache[m.name][p.toString()]||null, off:p.sub(m.base).toString()};
}
function go(){
  if(done) return; done=true;
  var out=[];
  for(var i=0;i<REGIONS.length;i++){
    var lo=REGIONS[i][0], hi=REGIONS[i][1];
    var slots=[];
    for(var rva=lo; rva<hi; rva+=8){
      var p;
      try { p = BASE.add(rva).readPointer(); }
      catch(e){ slots.push({rva:rva, bad:1}); continue; }
      if(p.isNull()){ slots.push({rva:rva, n:1}); }
      else { var r=resolve(p); slots.push({rva:rva, dll:r?r.dll:null, name:r?r.name:null, off:r?r.off:null}); }
    }
    out.push({lo:lo, hi:hi, slots:slots});
  }
  send({t:'iat', regions:out});
}
Process.setExceptionHandler(function(d){
  if(d.type==='access-violation'&&d.memory&&d.memory.operation==='execute'&&inGuard(d.memory.address)){
    try{go();}catch(e){send({t:'err',e:String(e)});}
    try{Memory.protect(d.memory.address.and(ptr('0xfffffffffffff000')),0x1000,'rwx');}catch(e){}
    return true;
  }
  return false;
});
try{var vp=Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect');
Interceptor.attach(vp,{onEnter:function(a){this.addr=a[0];this.np=a[2].toInt32();},onLeave:function(){var o=parseInt(this.addr.sub(BASE).toString(),16);if(o===SEC0[0]&&(this.np===0x10||this.np===0x20||this.np===0x40)){try{Memory.protect(BASE.add(SEC0[0]),SEC0[1],'rw-');}catch(e){}}}});}catch(e){}
for(var i=0;i<GUARD.length;i++){try{Memory.protect(BASE.add(GUARD[i][0]),GUARD[i][1],'rw-');}catch(e){}}
send({t:'armed'});
"""


def main():
    secs = parse(EXE)
    targets = find_iat_slots(secs)
    regions = cluster(targets)
    print(f"FF15/FF25 unique targets={len(targets)}; IAT regions:")
    for a, b in regions:
        print(f"  {hex(a)} - {hex(b)} ({(b-a)//8} slots)")

    guard = [[s["va"], s["vs"]] for s in secs if s["i"] in (0, 1, 2, 6) and (s["ch"] & 0x20000000)]
    sec0 = next([s["va"], s["vs"]] for s in secs if s["i"] == 0)
    js = JS % (repr(guard), repr(sec0), repr([[a, b] for a, b in regions]))

    res = {"regions": None}

    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "iat":
                res["regions"] = p["regions"]
                print("captured regions:", len(p["regions"]))
            elif p.get("t") in ("armed", "err"):
                print(p)
        else:
            print("ERR", m)

    pid = frida.spawn([EXE])
    s = frida.attach(pid)
    sc = s.create_script(js)
    sc.on("message", on_msg)
    sc.load()
    frida.resume(pid)
    for _ in range(20):
        time.sleep(1)
        if res["regions"] is not None:
            time.sleep(1)
            break
    try:
        frida.kill(pid)
    except Exception:
        pass

    if res["regions"] is None:
        print("FAILED")
        return
    OUT.write_text(json.dumps(res["regions"]), encoding="utf-8")
    tot = sum(len(r["slots"]) for r in res["regions"])
    named = sum(1 for r in res["regions"] for s in r["slots"] if s.get("name"))
    nulls = sum(1 for r in res["regions"] for s in r["slots"] if s.get("n"))
    unres = sum(1 for r in res["regions"] for s in r["slots"] if (not s.get("n")) and not s.get("name"))
    dlls = {}
    for r in res["regions"]:
        for s in r["slots"]:
            if s.get("dll"):
                dlls[s["dll"]] = dlls.get(s["dll"], 0) + 1
    print(f"slots={tot} named={named} nulls={nulls} unresolved={unres} dlls={len(dlls)}")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
