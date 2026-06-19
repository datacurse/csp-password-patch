"""Launch a given exe and enumerate all its top-level windows + CPU usage."""
import ctypes
import subprocess
import sys
import time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
IsWindowVisible = user32.IsWindowVisible
GetClassNameW = user32.GetClassNameW
GetWindowThreadProcessId = user32.GetWindowThreadProcessId


def wins(pid):
    out = []
    def cb(h, _):
        wp = wintypes.DWORD()
        GetWindowThreadProcessId(h, ctypes.byref(wp))
        if wp.value != pid:
            return True
        n = GetWindowTextLengthW(h)
        b = ctypes.create_unicode_buffer(n + 1)
        GetWindowTextW(h, b, n + 1)
        c = ctypes.create_unicode_buffer(256)
        GetClassNameW(h, c, 256)
        out.append((bool(IsWindowVisible(h)), c.value, b.value))
        return True
    EnumWindows(EnumWindowsProc(cb), 0)
    return out


def main():
    exe = sys.argv[1]
    cwd = sys.argv[2] if len(sys.argv) > 2 else None
    p = subprocess.Popen([exe], cwd=cwd)
    print("pid", p.pid)
    try:
        import psutil
        proc = psutil.Process(p.pid)
        has_psutil = True
    except Exception:
        has_psutil = False
    for i in range(8):
        time.sleep(2)
        if p.poll() is not None:
            print(f"t={i*2} EXITED {p.returncode}")
            return
        cpu = ""
        if has_psutil:
            try:
                cpu = f"cpu={proc.cpu_percent(interval=0.3):.0f}% threads={proc.num_threads()}"
            except Exception:
                pass
        w = wins(p.pid)
        print(f"\n-- t={i*2}s {cpu} windows={len(w)} --")
        for vis, cls, title in w:
            print(f"   vis={vis} cls={cls!r} title={title!r}")
    p.terminate()


if __name__ == "__main__":
    main()
