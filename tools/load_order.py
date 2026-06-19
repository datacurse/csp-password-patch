"""Capture DLL load order/timing for install-dir DLLs by hooking ntdll!LdrLoadDll.
Frida.spawn injects before the entry point, so even static-import loads are seen.
Earliest-loading app-local DLLs are the best search-order-proxy targets."""
import time
from pathlib import Path

import frida

INSTALL = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
EXE = INSTALL + r"\CLIPStudioPaint.exe"

JS = r"""
'use strict';
var t0 = Date.now();
var seen = {};
var LdrLoadDll = Module.getGlobalExportByName ? null : null;
var addr = Process.getModuleByName('ntdll.dll').getExportByName('LdrLoadDll');
Interceptor.attach(addr, {
  onEnter: function (args) {
    // LdrLoadDll(PWSTR PathToFile, PULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE)
    try {
      var us = args[2];
      var len = us.readU16();
      var buf = us.add(8).readPointer();
      var name = buf.readUtf16String(len / 2);
      if (name && !seen[name.toLowerCase()]) {
        seen[name.toLowerCase()] = 1;
        send({ dt: Date.now() - t0, name: name });
      }
    } catch (e) {}
  }
});
send({ dt: 0, name: '__ready__' });
"""


def main():
    rows = []

    def on_msg(m, d):
        if m.get("type") == "send":
            rows.append(m["payload"])
        else:
            print("ERR", m)

    pid = frida.spawn([EXE])
    s = frida.attach(pid)
    sc = s.create_script(JS)
    sc.on("message", on_msg)
    sc.load()
    frida.resume(pid)
    time.sleep(8)
    try:
        frida.kill(pid)
    except Exception:
        pass

    inst = INSTALL.lower()
    print("Install-dir DLLs by load time (ms after first load):\n")
    for r in rows:
        n = r["name"]
        if n == "__ready__":
            continue
        low = n.lower()
        # name may be bare or full path
        if inst in low or ("\\" not in n):
            tag = "LOCAL" if inst in low else "(bare)"
            print(f"  +{r['dt']:5} ms  {tag}  {n}")


if __name__ == "__main__":
    main()
