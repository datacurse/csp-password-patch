"""Read the 22 hooked IAT slots in the normal process at +Ns and resolve them."""
import json
import time
from pathlib import Path
import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
DUMP = Path(__file__).resolve().parents[1] / "tools/output/dump"

regs = json.loads((DUMP / "iat_full.json").read_text())
main = max(regs, key=lambda r: sum(1 for s in r["slots"] if s.get("name")))
SLOTS = []
for s in main["slots"]:
    off = s.get("off")
    if (not s.get("n")) and (not s.get("name")) and off and 0x5BE6000 <= int(off, 16) < 0x616F000:
        SLOTS.append(s["rva"])

JS = r"""
'use strict';
var BASE = Process.enumerateModules()[0].base;
var MAIN = Process.enumerateModules()[0];
var SLOTS = %s;
var cache={};
function inMain(p){return p.compare(MAIN.base)>=0&&p.compare(MAIN.base.add(MAIN.size))<0;}
function exp(p){var m=Process.findModuleByAddress(p);if(!m)return {dll:'?',name:'?'};
  if(!cache[m.name]){cache[m.name]={};try{m.enumerateExports().forEach(function(e){cache[m.name][e.address.toString()]=e.name;});}catch(e){}}
  return {dll:m.name,name:cache[m.name][p.toString()]||('+'+p.sub(m.base)),inmain:m.name===MAIN.name};}
rpc.exports.read = function(){
  var out={};
  SLOTS.forEach(function(ft){ try{var p=BASE.add(ft).readPointer(); var r=exp(p); out[ft.toString(16)]={dll:r.dll,name:r.name,inmain:r.inmain};}catch(e){out[ft.toString(16)]={err:String(e)};} });
  return out;
};
"""


def main():
    pid = frida.spawn([EXE])
    s = frida.attach(pid)
    sc = s.create_script(JS % repr(SLOTS))
    sc.load()
    frida.resume(pid)
    for t in (3, 6, 10):
        time.sleep(t if t == 3 else t - 3)
        try:
            r = sc.exports_sync.read() if hasattr(sc, "exports_sync") else sc.exports.read()
        except Exception as e:
            print("read err", e); continue
        inmain = sum(1 for v in r.values() if v.get("inmain"))
        print(f"\n=== t~{t}s : {inmain}/{len(r)} still point into main (VM trampoline) ===")
        for k, v in r.items():
            print(f"  0x{k} -> {v}")
    try:
        frida.kill(pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
