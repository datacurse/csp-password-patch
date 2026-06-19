"""Resolve the protector's IAT-hook trampolines to their real APIs.

At OEP, for each IAT slot that points back into the main image (a protector hook
trampoline in sec8), follow the live jmp/indirect-jmp chain until it leaves the
main module into a system DLL, then resolve that to dll!export. Writes
hooks_map.json: { "<ft_rva_hex>": {"dll":..., "name":...}, ... }.
"""
from __future__ import annotations

import json
import struct
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
DUMP = Path(__file__).resolve().parents[1] / "tools" / "output" / "dump"
OUT = DUMP / "hooks_map.json"
SEC8_LO, SEC8_HI = 0x5BE6000, 0x616F000


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


def gather_hook_slots():
    regs = json.loads((DUMP / "iat_full.json").read_text())
    main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
    slots = []
    for s in main["slots"]:
        off = s.get("off")
        if (not s.get("n")) and (not s.get("name")) and off:
            rva = int(off, 16)
            if SEC8_LO <= rva < SEC8_HI:
                slots.append(s["rva"])
    return slots


JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var GUARD = %s, SEC0 = %s, SLOTS = %s;
var done = false; var cache = {};
var MAIN = Process.enumerateModules()[0];
function inGuard(a){var o=parseInt(a.sub(BASE).toString(),16);for(var i=0;i<GUARD.length;i++)if(o>=GUARD[i][0]&&o<GUARD[i][0]+GUARD[i][1])return true;return false;}
function inMain(p){ return p.compare(MAIN.base)>=0 && p.compare(MAIN.base.add(MAIN.size))<0; }
function resolveExport(p){
  var m=Process.findModuleByAddress(p); if(!m) return null;
  if(!cache[m.name]){cache[m.name]={};try{m.enumerateExports().forEach(function(e){cache[m.name][e.address.toString()]=e.name;});}catch(e){}}
  return {dll:m.name, name:cache[m.name][p.toString()]||null, off:p.sub(m.base).toString()};
}
function follow(addr){
  for(var i=0;i<40;i++){
    if(!inMain(addr)){ return resolveExport(addr); }
    var b0,b1,b2;
    try{ b0=addr.readU8(); b1=addr.add(1).readU8(); b2=addr.add(2).readU8(); }catch(e){ return null; }
    if(b0===0xE9){ addr=addr.add(5).add(addr.add(1).readS32()); }
    else if(b0===0xEB){ addr=addr.add(2).add(addr.add(1).readS8()); }
    else if(b0===0xFF && b1===0x25){ var p=addr.add(6).add(addr.add(2).readS32()); addr=p.readPointer(); }
    else if(b0===0x48 && b1===0xFF && b2===0x25){ var p=addr.add(7).add(addr.add(3).readS32()); addr=p.readPointer(); }
    else { return null; }
  }
  return null;
}
function go(){
  if(done) return; done=true;
  var map={};
  for(var i=0;i<SLOTS.length;i++){
    var ft=SLOTS[i];
    var entry;
    try{ entry=BASE.add(ft).readPointer(); }catch(e){ continue; }
    var r=follow(entry);
    map[ft.toString(16)] = r ? {dll:r.dll, name:r.name, off:r.off} : null;
  }
  send({t:'hooks', map:map});
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
    guard = [[s["va"], s["vs"]] for s in secs if s["i"] in (0, 1, 2, 6) and (s["ch"] & 0x20000000)]
    sec0 = next([s["va"], s["vs"]] for s in secs if s["i"] == 0)
    slots = gather_hook_slots()
    print("hook slots to resolve:", [hex(x) for x in slots])
    js = JS % (repr(guard), repr(sec0), repr(slots))

    res = {"map": None}

    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "hooks":
                res["map"] = p["map"]
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
        if res["map"] is not None:
            time.sleep(1)
            break
    try:
        frida.kill(pid)
    except Exception:
        pass

    if res["map"] is None:
        print("FAILED")
        return
    OUT.write_text(json.dumps(res["map"]), encoding="utf-8")
    for k, v in res["map"].items():
        print(f"  0x{k} -> {v}")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
