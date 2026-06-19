"""Spawn an exe under Frida and report the first crash location."""
import sys
import time
import frida

JS = r"""
'use strict';
var mods = Process.enumerateModules();
function whereis(addr) {
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    if (addr.compare(m.base) >= 0 && addr.compare(m.base.add(m.size)) < 0) {
      return m.name + '+' + addr.sub(m.base).toString();
    }
  }
  return 'unknown ' + addr.toString();
}
var count = 0;
Process.setExceptionHandler(function (d) {
  count++;
  if (count > 5) return false;
  var info = { t: 'exc', type: d.type, pc: whereis(d.context.pc) };
  if (d.memory) { info.op = d.memory.operation; info.addr = whereis(d.memory.address); }
  send(info);
  return false; // let it crash so we see the first real one
});
send({ t: 'ready', main: mods[0].name + ' base=' + mods[0].base });
"""


def main():
    exe = sys.argv[1]
    cwd = sys.argv[2] if len(sys.argv) > 2 else None

    def on_msg(m, d):
        if m.get("type") == "send":
            print(m["payload"])
        else:
            print("ERR", m)

    det = {"r": None}
    pid = frida.spawn([exe], cwd=cwd)
    s = frida.attach(pid)
    s.on("detached", lambda reason, *a: det.update(r=reason) or print("DETACHED:", reason))
    sc = s.create_script(JS)
    sc.on("message", on_msg)
    sc.load()
    frida.resume(pid)
    for _ in range(15):
        time.sleep(1)
        if det["r"]:
            break
    try:
        frida.kill(pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
