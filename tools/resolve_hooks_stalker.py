"""Resolve protector IAT-hook wrappers to real APIs via runtime Stalker tracing.

Runs the NORMAL (protector-active) process. After the protector has decrypted and
filled the IAT, hooks each hook-wrapper entry; on first invocation it Stalkers the
thread and records the first call that lands in a system module (= the real API).
Maps each hooked IAT slot (ft_rva) to dll!name and writes hooks_map.json.
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


def hook_slots():
    regs = json.loads((DUMP / "iat_full.json").read_text())
    main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
    out = {}
    for s in main["slots"]:
        off = s.get("off")
        if (not s.get("n")) and (not s.get("name")) and off:
            rva = int(off, 16)
            if SEC8_LO <= rva < SEC8_HI:
                out[s["rva"]] = rva  # ft_rva -> trampoline rva
    return out


JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var MAIN = Process.enumerateModules()[0];
var SLOTS = %s;        // [[ft_rva, tramp_rva], ...]
var resolved = {};     // ft_rva -> dll!name
var following = {};
function inMain(p){ return p.compare(MAIN.base)>=0 && p.compare(MAIN.base.add(MAIN.size))<0; }
var cache = {};
function exp(p){ var m=Process.findModuleByAddress(p); if(!m||m.name===MAIN.name) return null;
  if(!cache[m.name]){cache[m.name]={};try{m.enumerateExports().forEach(function(e){cache[m.name][e.address.toString()]=e.name;});}catch(e){}}
  return {dll:m.name, name:cache[m.name][p.toString()]||('+'+p.sub(m.base))}; }

var armed=false;
function tryArm(){
  if(armed) return;
  // wait until the protector has filled the IAT with the (sec8) trampoline ptrs
  var probe;
  try{ probe = BASE.add(SLOTS[0][0]).readPointer(); }catch(e){ return; }
  if(probe.isNull() || !inMain(probe)) return;
  armed=true;
  send({t:'arming'});
  arm();
}
function arm(){
  var n=0;
  SLOTS.forEach(function(pair){
    var ft=pair[0], tr=pair[1];
    if(resolved[ft]!==undefined) return;
    var entry;
    try{ entry = BASE.add(ft).readPointer(); }catch(e){ return; }
    if(!inMain(entry)) { return; } // already real?
    try {
      Interceptor.attach(entry, { onEnter: function(){
        if(resolved[ft]!==undefined) return;
        var tid=this.threadId;
        if(following[tid]) return;
        following[tid]=true;
        var got=false;
        Stalker.follow(tid, { events:{call:true}, onReceive:function(data){
          if(got) return;
          var ev=Stalker.parse(data,{annotate:false});
          for(var i=0;i<ev.length;i++){
            var target=ptr(ev[i][1]);
            if(!inMain(target)){ var r=exp(target); if(r){ resolved[ft]=r.dll+'!'+r.name; got=true; send({t:'res', ft:ft.toString(16), v:resolved[ft]}); break; } }
          }
        }});
        this._unf=function(){ try{Stalker.unfollow(tid);}catch(e){} following[tid]=false; };
      }, onLeave: function(){ if(this._unf) this._unf(); }});
      n++;
    } catch(e){}
  });
  send({t:'armed', hooked:n});
}
var iv = setInterval(tryArm, 2);
setTimeout(function(){ clearInterval(iv); }, %d);
"""


def main():
    slots = hook_slots()
    pairs = [[ft, tr] for ft, tr in slots.items()]
    print("slots:", [hex(x) for x in slots])
    js = JS % (repr(pairs), 20000)

    resolved = {}

    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "res":
                resolved[p["ft"]] = p["v"]
                print(f"  resolved 0x{p['ft']} -> {p['v']}")
            else:
                print(p)
        else:
            print("ERR", m)

    pid = frida.spawn([EXE])
    s = frida.attach(pid)
    sc = s.create_script(js)
    sc.on("message", on_msg)
    sc.load()
    frida.resume(pid)
    time.sleep(25)
    try:
        frida.kill(pid)
    except Exception:
        pass

    # merge with any existing
    full = {hex(ft)[2:]: None for ft in slots}
    full.update(resolved)
    OUT.write_text(json.dumps(full), encoding="utf-8")
    print(f"\nresolved {len(resolved)}/{len(slots)}")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
