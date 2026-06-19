"""Reconstruct the import table by resolving the runtime IAT at OEP.

Halts at OEP (same DEP-guard trick), reads each import descriptor's FirstThunk
array straight from memory, resolves every resolved pointer back to its owning
module export name, and writes iat_map.json for the rebuilder to synthesize a
proper INT + name table.
"""
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
OUT = Path(__file__).resolve().parents[1] / "tools" / "output" / "dump" / "iat_map.json"


def parse(path):
    d = Path(path).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    num = struct.unpack_from("<H", d, pe + 6)[0]
    osz = struct.unpack_from("<H", d, pe + 20)[0]
    sectbl = pe + 24 + osz
    secs = []
    for i in range(num):
        o = sectbl + i * 40
        secs.append({"i": i, "va": struct.unpack_from("<I", d, o + 12)[0],
                     "vs": struct.unpack_from("<I", d, o + 8)[0],
                     "ch": struct.unpack_from("<I", d, o + 36)[0]})
    imp_rva = struct.unpack_from("<I", d, opt + 112 + 1 * 8)[0]
    return secs, imp_rva


JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var GUARD = %s, SEC0 = %s, IMP = %s;
var done = false;
var cache = {};

function inGuard(a){var o=parseInt(a.sub(BASE).toString(),16);for(var i=0;i<GUARD.length;i++)if(o>=GUARD[i][0]&&o<GUARD[i][0]+GUARD[i][1])return true;return false;}

function resolve(p){
  var m = Process.findModuleByAddress(p);
  if(!m) return {dll:null, name:null, addr:p.toString()};
  if(!cache[m.name]){
    cache[m.name]={};
    try{ m.enumerateExports().forEach(function(e){ cache[m.name][e.address.toString()]=e.name; }); }catch(e){}
  }
  return {dll:m.name, name: cache[m.name][p.toString()] || null, addr:p.toString(), off:p.sub(m.base).toString()};
}

function doResolve(){
  if(done) return; done=true;
  var descs=[];
  var k=0;
  while(true){
    var d = BASE.add(IMP + k*20);
    var oft = d.readU32(), name_rva = d.add(12).readU32(), ft = d.add(16).readU32();
    if(oft===0 && name_rva===0 && ft===0) break;
    var dll = BASE.add(name_rva).readUtf8String();
    var funcs=[]; var j=0;
    while(true){
      var slot = BASE.add(ft + j*8);
      var val = slot.readPointer();
      if(val.isNull()) break;
      var r = resolve(val);
      funcs.push(r);
      j++;
      if(j>5000) break;
    }
    descs.push({dll:dll, ft_rva:ft, oft:oft, funcs:funcs});
    k++;
    if(k>200) break;
  }
  send({t:'iat', descs:descs});
}

Process.setExceptionHandler(function(d){
  if(d.type==='access-violation' && d.memory && d.memory.operation==='execute' && inGuard(d.memory.address)){
    try{ doResolve(); }catch(e){ send({t:'err', e:String(e)}); }
    try{ Memory.protect(d.memory.address.and(ptr('0xfffffffffffff000')),0x1000,'rwx'); }catch(e){}
    return true;
  }
  return false;
});

try{
  var vp=Process.getModuleByName('kernel32.dll').getExportByName('VirtualProtect');
  Interceptor.attach(vp,{onEnter:function(a){this.addr=a[0];this.np=a[2].toInt32();},onLeave:function(){
    var o=parseInt(this.addr.sub(BASE).toString(),16);
    if(o===SEC0[0]&&(this.np===0x10||this.np===0x20||this.np===0x40)){ try{Memory.protect(BASE.add(SEC0[0]),SEC0[1],'rw-');}catch(e){} }
  }});
}catch(e){}
for(var i=0;i<GUARD.length;i++){try{Memory.protect(BASE.add(GUARD[i][0]),GUARD[i][1],'rw-');}catch(e){}}
send({t:'armed'});
"""


def main():
    secs, imp_rva = parse(EXE)
    guard = [[s["va"], s["vs"]] for s in secs if s["i"] in (0, 1, 2, 6) and (s["ch"] & 0x20000000)]
    sec0 = next([s["va"], s["vs"]] for s in secs if s["i"] == 0)
    js = JS % (repr(guard), repr(sec0), repr(imp_rva))

    result = {"descs": None}

    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "iat":
                result["descs"] = p["descs"]
                print("got IAT map:", len(p["descs"]), "descriptors")
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
        if result["descs"] is not None:
            time.sleep(1)
            break
    try:
        frida.kill(pid)
    except Exception:
        pass

    if result["descs"] is None:
        print("FAILED to capture IAT")
        return
    OUT.write_text(json.dumps(result["descs"]), encoding="utf-8")
    # summary
    total = sum(len(d["funcs"]) for d in result["descs"])
    unresolved = sum(1 for d in result["descs"] for f in d["funcs"] if not f.get("name"))
    print(f"descriptors={len(result['descs'])} funcs={total} unresolved_names={unresolved}")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
