import sys
from pathlib import Path
import lief

SRC = Path(r"C:\Windows\System32")
for name in sys.argv[1:]:
    p = SRC / name
    b = lief.parse(str(p))
    exp = b.get_export()
    if exp is None:
        print(f"{name}: no exports"); continue
    ents = list(exp.entries)
    noname = [e for e in ents if not e.name]
    fwd = [e for e in ents if e.is_forwarded]
    print(f"\n=== {name}  dll_name={exp.name}  entries={len(ents)} noname={len(noname)} forwarded={len(fwd)} ===")
    for e in ents[:12]:
        f = f" -> {e.forward_information}" if e.is_forwarded else ""
        print(f"  @{e.ordinal} {e.name or '(noname)'}{f}")
    if len(ents) > 12:
        print(f"  ... +{len(ents)-12} more")
