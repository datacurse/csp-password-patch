"""Launch the real (protected) CSP and log all its top-level windows (title+class+
visibility) over time, plus any new child processes (e.g., a browser for the
website). Helps design the native window-watcher."""
import ctypes
import time
from ctypes import wintypes

import frida

EXE = r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"

user32 = ctypes.WinDLL("user32", use_last_error=True)
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
GetWindowTextW = user32.GetWindowTextW
GetClassNameW = user32.GetClassNameW
IsWindowVisible = user32.IsWindowVisible
GetWindowThreadProcessId = user32.GetWindowThreadProcessId


def snapshot(pids):
    seen = []
    def cb(h, _):
        wp = wintypes.DWORD()
        GetWindowThreadProcessId(h, ctypes.byref(wp))
        if wp.value not in pids:
            return True
        t = ctypes.create_unicode_buffer(300); GetWindowTextW(h, t, 300)
        c = ctypes.create_unicode_buffer(120); GetClassNameW(h, c, 120)
        seen.append((bool(IsWindowVisible(h)), c.value, t.value))
        return True
    EnumWindows(EnumWindowsProc(cb), 0)
    return seen


def child_pids(root):
    try:
        import psutil
        p = psutil.Process(root)
        return {root} | {c.pid for c in p.children(recursive=True)}
    except Exception:
        return {root}


def main():
    pid = frida.spawn([EXE])
    frida.resume(pid)
    print("pid", pid)
    prev = set()
    procs_prev = set()
    for i in range(40):
        time.sleep(0.4)
        pids = child_pids(pid)
        newp = pids - procs_prev
        if newp and i > 0:
            try:
                import psutil
                for q in newp:
                    print(f"  [t={i*0.4:.1f}s] NEW PROC {q} {psutil.Process(q).name()}")
            except Exception:
                pass
        procs_prev = pids
        snap = snapshot(pids)
        for vis, cls, title in snap:
            key = (cls, title)
            if key not in prev:
                prev.add(key)
                print(f"  [t={i*0.4:.1f}s] WIN vis={vis} cls={cls!r} title={title!r}")
    try:
        frida.kill(pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
