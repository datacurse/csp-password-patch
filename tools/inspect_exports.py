import sys
from pathlib import Path
import lief

INSTALL = Path(r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT")

for name in sys.argv[1:]:
    p = INSTALL / name
    b = lief.parse(str(p))
    exp = b.get_export()
    if exp is None:
        print(f"\n=== {name}: no export table ===")
        continue
    ents = list(exp.entries)
    print(f"\n=== {name}  dll_name={exp.name}  entries={len(ents)} ===")
    for e in ents[:50]:
        fwd = f" -> {e.forward_information}" if e.is_forwarded else ""
        nm = e.name if e.name else "(noname)"
        print(f"  ord={e.ordinal:5} name={nm}{fwd}")
    if len(ents) > 50:
        print(f"  ... (+{len(ents)-50} more)")
