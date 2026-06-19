"""Run with the clock already advanced (prompt day). frida.spawn CSP, then:
  1) log every DLL load (LdrLoadDll) with timing, to find what loads BEFORE the
     password dialog (candidate proxy targets that aren't gated behind auth);
  2) run the proven frida_deitzmx.js to confirm the suppression hooks dismiss the
     password/splash on a real prompt day.
Reports the load timeline up to the password, the suppression events, and whether
CSP reached its main window."""
import ctypes
import time
from ctypes import wintypes
from pathlib import Path

import frida

INSTALL = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
EXE = INSTALL + r"\CLIPStudioPaint.exe"
HOOK = Path(__file__).with_name("frida_deitzmx.js").read_text(encoding="utf-8")

LOADER_JS = r"""
'use strict';
var t0 = Date.now();
var seen = {};
var addr = Process.getModuleByName('ntdll.dll').getExportByName('LdrLoadDll');
Interceptor.attach(addr, { onEnter: function (args) {
  try {
    var us = args[2]; var len = us.readU16(); var buf = us.add(8).readPointer();
    var name = buf.readUtf16String(len / 2);
    if (name && !seen[name.toLowerCase()]) { seen[name.toLowerCase()] = 1;
      send({ k: 'load', dt: Date.now() - t0, name: name }); }
  } catch (e) {}
}});
send({ k: 'loader_ready' });
"""

events = []
pwd_event_time = [None]
t_start = [0.0]


def on_loader(m, d):
    if m.get("type") == "send":
        events.append(m["payload"])


def on_hook(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        p["_t"] = time.time() - t_start[0]
        events.append({"k": "hook", **p})
        if p.get("type") in ("auto_submitted_password", "password_pasted"):
            if pwd_event_time[0] is None:
                pwd_event_time[0] = p["_t"]


def main_window_present(pid):
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    EnumWindows = user32.EnumWindows
    EP = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    titles = []

    def cb(h, _):
        wp = wintypes.DWORD()
        user32.GetWindowThreadProcessId(h, ctypes.byref(wp))
        if wp.value == pid and user32.IsWindowVisible(h):
            b = ctypes.create_unicode_buffer(400)
            user32.GetWindowTextW(h, b, 400)
            if b.value:
                titles.append(b.value)
        return True

    EnumWindows(EP(cb), 0)
    return titles


def main():
    t_start[0] = time.time()
    pid = frida.spawn([EXE])
    s = frida.attach(pid)
    s1 = s.create_script(LOADER_JS); s1.on("message", on_loader); s1.load()
    s2 = s.create_script(HOOK); s2.on("message", on_hook); s2.load()
    frida.resume(pid)
    time.sleep(16)
    titles = main_window_present(pid)
    try:
        frida.kill(pid)
    except Exception:
        pass

    pwd_at = None
    for e in events:
        if e.get("k") == "load" and "password" in e.get("name", "").lower():
            pwd_at = e["dt"]

    print("=== DLL loads (install-dir only) up to ~password ===")
    inst = INSTALL.lower()
    for e in events:
        if e.get("k") == "load":
            n = e["name"]
            if inst in n.lower() or "\\" not in n:
                tag = "LOCAL" if inst in n.lower() else ""
                print(f"  +{e['dt']:5} ms {tag:6} {n}")

    print("\n=== suppression (hook) events ===")
    for e in events:
        if e.get("k") == "hook":
            print(f"  +{e['_t']*1000:6.0f} ms  {e.get('type')}  {dict((k,v) for k,v in e.items() if k not in ('k','_t','type'))}")

    print("\npassword auto-handled at:",
          f"{pwd_event_time[0]*1000:.0f} ms" if pwd_event_time[0] else "NOT HANDLED")
    print("CSP visible titled windows at end:", titles)


if __name__ == "__main__":
    main()
