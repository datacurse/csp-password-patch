"""Launch the (restored, original) CSP and list the DLLs it loads FROM ITS OWN
install dir - these are candidates for search-order proxying (no exe edit needed).
Reports each candidate's export count (fewer = easier to proxy)."""
import time
from pathlib import Path

import frida
import psutil
import lief

INSTALL = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")
EXE = INSTALL / "CLIPStudioPaint.exe"


def main():
    pid = frida.spawn([str(EXE)])
    frida.resume(pid)
    time.sleep(8)
    proc = psutil.Process(pid)
    locals_ = []
    try:
        for m in proc.memory_maps(grouped=False):
            p = Path(m.path)
            try:
                if p.suffix.lower() == ".dll" and p.parent.samefile(INSTALL):
                    locals_.append(p)
            except Exception:
                pass
    except Exception as e:
        print("memory_maps err", e)
    try:
        frida.kill(pid)
    except Exception:
        pass

    seen = {}
    for p in locals_:
        if p.name.lower() in seen:
            continue
        seen[p.name.lower()] = p
    print(f"{len(seen)} unique install-dir DLLs loaded:\n")
    rows = []
    for name, p in seen.items():
        try:
            b = lief.parse(str(p))
            nexp = len(b.exported_functions)
        except Exception:
            nexp = -1
        rows.append((nexp, p.name))
    for nexp, name in sorted(rows):
        print(f"  exports={nexp:5}  {name}")


if __name__ == "__main__":
    main()
