"""Hook exit/exception-dispatch paths to find why the rebuilt exe dies."""
import sys
import time
import frida

JS = r"""
'use strict';
var mods = Process.enumerateModules();
function whereis(a){
  for (var i=0;i<mods.length;i++){var m=mods[i];if(a.compare(m.base)>=0&&a.compare(m.base.add(m.size))<0)return m.name+'+'+a.sub(m.base);}
  return a.toString();
}
function bt(ctx){
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0,12).map(whereis); } catch(e){ return []; }
}
function hook(mod, fn, f){ try{ Interceptor.attach(Process.getModuleByName(mod).getExportByName(fn), f); }catch(e){ send({t:'hookerr',fn:fn,e:String(e)}); } }

hook('kernel32.dll','UnhandledExceptionFilter', { onEnter:function(a){
  try{
    var ep=a[0]; var rec=ep.readPointer();
    var code=rec.readU32(); var addr=rec.add(16).readPointer();
    send({t:'UEF', code:code.toString(16), addr:whereis(addr), bt:bt(this.context)});
  }catch(e){ send({t:'UEFerr',e:String(e)});}
}});

['kernelbase.dll','kernel32.dll'].forEach(function(m){
  hook(m,'TerminateProcess',{onEnter:function(a){ send({t:'TerminateProcess', code:a[1].toInt32(), bt:bt(this.context)}); }});
});
hook('ntdll.dll','RtlExitUserProcess',{onEnter:function(a){ send({t:'RtlExitUserProcess', code:a[0].toInt32(), bt:bt(this.context)}); }});
hook('ntdll.dll','RtlRaiseException',{onEnter:function(a){
  try{ var rec=a[0]; send({t:'RtlRaiseException', code:rec.readU32().toString(16), addr:whereis(rec.add(16).readPointer()), bt:bt(this.context)});}catch(e){}
}});
hook('kernel32.dll','RaiseException',{onEnter:function(a){ send({t:'RaiseException', code:a[0].toInt32().toString(16), bt:bt(this.context)}); }});

// also frida exception handler as fallback
Process.setExceptionHandler(function(d){
  send({t:'exc', type:d.type, op:d.memory?d.memory.operation:null, pc:whereis(d.context.pc), addr:d.memory?whereis(d.memory.address):null});
  return false;
});
send({t:'ready'});
"""


def main():
    exe = sys.argv[1]; cwd = sys.argv[2] if len(sys.argv) > 2 else None
    det = {"r": None}
    def on_msg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") in ("UEF", "TerminateProcess", "RtlExitUserProcess", "RtlRaiseException", "RaiseException", "exc"):
                print("\n>>>", p.get("t"), "code=", p.get("code"), "addr=", p.get("addr"), "pc=", p.get("pc"))
                for f in p.get("bt", []) or []:
                    print("     ", f)
            else:
                print(p)
        else:
            print("ERR", m)
    pid = frida.spawn([exe], cwd=cwd)
    s = frida.attach(pid)
    s.on("detached", lambda r, *a: det.update(r=r) or print("DETACHED:", r))
    sc = s.create_script(JS); sc.on("message", on_msg); sc.load()
    frida.resume(pid)
    for _ in range(15):
        time.sleep(1)
        if det["r"]:
            break
    try: frida.kill(pid)
    except Exception: pass


if __name__ == "__main__":
    main()
