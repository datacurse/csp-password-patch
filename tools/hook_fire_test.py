"""Check which of the 22 virtualized trampolines actually get invoked, and try to
capture the real API via Stalker on first invocation."""
import json
import time
from pathlib import Path
import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
DUMP = Path(__file__).resolve().parents[1] / "tools/output/dump"
regs = json.loads((DUMP / "iat_full.json").read_text())
main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
SLOTS = [s["rva"] for s in main["slots"] if (not s.get("n")) and (not s.get("name")) and s.get("off") and 0x5BE6000 <= int(s["off"], 16) < 0x616F000]

JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var MAIN = Process.enumerateModules()[0];
var SLOTS = %s;
var cache={}; var resolved={}; var fired={};
function inMain(p){return p.compare(MAIN.base)>=0&&p.compare(MAIN.base.add(MAIN.size))<0;}
function exp(p){var m=Process.findModuleByAddress(p);if(!m||m.name===MAIN.name)return null;
  if(!cache[m.name]){cache[m.name]={};try{m.enumerateExports().forEach(function(e){cache[m.name][e.address.toString()]=e.name;});}catch(e){}}
  return m.name+'!'+(cache[m.name][p.toString()]||('+'+p.sub(m.base)));}
var armed=false;
function arm(){
  if(armed) return; var probe; try{probe=BASE.add(SLOTS[0]).readPointer();}catch(e){return;}
  if(probe.isNull()||!inMain(probe)) return; armed=true; send({t:'armed'});
  SLOTS.forEach(function(ft){
    var entry; try{entry=BASE.add(ft).readPointer();}catch(e){return;}
    try{ Interceptor.attach(entry,{onEnter:function(){
      if(!fired[ft]){fired[ft]=1; send({t:'fire', ft:ft.toString(16)});}
      if(resolved[ft]) return;
      var tid=this.threadId; var got=false;
      try{ Stalker.follow(tid,{events:{call:true}, onReceive:function(data){
        if(got||resolved[ft])return; var ev=Stalker.parse(data,{annotate:false});
        for(var i=0;i<ev.length;i++){var t=ptr(ev[i][1]); if(!inMain(t)){var r=exp(t); if(r){resolved[ft]=r;got=true;send({t:'res',ft:ft.toString(16),v:r});break;}}}
      }}); this._u=function(){try{Stalker.unfollow(tid);}catch(e){}}; }catch(e){send({t:'stkerr',e:String(e)});}
    }, onLeave:function(){ if(this._u){Stalker.flush(); this._u();} }});}catch(e){send({t:'atterr',ft:ft.toString(16),e:String(e)});}
  });
}
var iv=setInterval(arm,2); setTimeout(function(){clearInterval(iv);},15000);
"""


def main():
    fired = set(); res = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]; t = p.get("t")
            if t == "fire": fired.add(p["ft"]); print("FIRE 0x"+p["ft"])
            elif t == "res": res[p["ft"]] = p["v"]; print("  RES 0x"+p["ft"]+" -> "+p["v"])
            elif t in ("armed","stkerr","atterr"): print(p)
        else: print("ERR", m)
    pid = frida.spawn([EXE]); s = frida.attach(pid)
    sc = s.create_script(JS % repr(SLOTS)); sc.on("message", on_msg); sc.load()
    frida.resume(pid); time.sleep(18)
    try: frida.kill(pid)
    except Exception: pass
    print(f"\nfired {len(fired)}/{len(SLOTS)}, resolved {len(res)}")


if __name__ == "__main__":
    main()
